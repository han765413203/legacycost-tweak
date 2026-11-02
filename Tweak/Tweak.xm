//
//  Tweak.xm
//  负之遗产 (LegacyCostCHN) 1.0.9 —— iOS 15.x arm64 越狱修改器
//
//  海鸥出品。
//
//  原理（这版跟之前的 hook 方案完全不同，那套已经废了）：
//
//    PLAYER_C 是个 **静态类**，所有玩家数据都是静态字段，落在 __DATA 里的固定地址。
//    材料是 CodeStage ACTk 的 ObscuredInt（16 字节）：
//        +0x00 currentCryptoKey (int)
//        +0x04 hiddenValue      (int)   ← 真实值 = hiddenValue ^ currentCryptoKey
//        +0x08 fakeValue        (int)   ← 明文副本，防篡改用
//        +0x0C inited           (bool)
//
//    所以根本不用 hook。算好地址，定时把 hiddenValue / fakeValue 写进去就行。
//    写之前先验证：inited==1 且 fakeValue == hiddenValue^key，对不上就不动手。
//
//  RVA 来源：扫全二进制的 ADRP+ADD，找到唯一一个能让 PLAYER_C 的 20 个字段偏移
//  全部命中的基址 0x103ec4910。20/20，不是蒙的。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dispatch/dispatch.h>
#include <string.h>
#include <stdint.h>

// ============================================================================
// 存档静态字段（RVA = vmaddr - 0x100000000）
// ============================================================================
#define RVA_STATIC_BASE      0x3ec4910ULL   // PLAYER_C 静态字段块基址

#define RVA_PL_MATERIAL      0x3ec4b50ULL   // ObscuredLong  材料
#define RVA_PL_MATPOINT      0x3ec4c40ULL   // ObscuredInt   物质点数
#define RVA_PL_GRASS         0x3ec4e70ULL   // ObscuredInt   草
#define RVA_PL_WOOD          0x3ec4e80ULL   // ObscuredInt   木
#define RVA_PL_CLOTH         0x3ec4e90ULL   // ObscuredInt   布
#define RVA_PL_IRON          0x3ec4ea0ULL   // ObscuredInt   铁
#define RVA_PL_STONE         0x3ec4eb0ULL   // ObscuredInt   石
#define RVA_PL_SOUL          0x3ec4ec0ULL   // ObscuredInt   魂
#define RVA_PL_LEGACY        0x3ec4ed0ULL   // ObscuredLong  遗产宝石
#define RVA_PL_ORBK          0x3ec4ef0ULL   // ObscuredInt   宝珠/光珠

// ============================================================================
// 日志
// ============================================================================
static NSString *gLogPath = @"/var/mobile/Documents/LegacyCost.log";

static void FileLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:gLogPath]) {
        [s writeToFile:gLogPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } else {
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:gLogPath];
        [fh seekToEndOfFile];
        [fh writeData:[s dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    }
}

// ============================================================================
// 配置
// ============================================================================
static NSString *kCfgPath = @"/var/mobile/Library/Preferences/com.seagull.legacycost.plist";
static NSMutableDictionary *gCfg = nil;

static void DefaultConfig(void) {
    gCfg = [@{
        @"enabled"     : @YES,
        @"matValue"    : @999999,
        @"legacyValue" : @999999,
        @"orbValue"    : @999999,
        @"interval"    : @0.5,
        @"hideMenu"    : @NO,
    } mutableCopy];
}

static void LoadConfig(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:kCfgPath];
    DefaultConfig();
    if (d) [gCfg addEntriesFromDictionary:d];
    else [gCfg writeToFile:kCfgPath atomically:YES];
}

static void SaveConfig(void) { [gCfg writeToFile:kCfgPath atomically:YES]; }

// ============================================================================
// 镜像基址
// ============================================================================
static uintptr_t gBase = 0, gEnd = 0;

static void InitImageBase(void) {
    const struct mach_header_64 *hdr = (const struct mach_header_64 *)_dyld_get_image_header(0);
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    if (!hdr) return;
    uintptr_t vm = 0, vs = 0;
    const uint8_t *p = (const uint8_t *)hdr + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (strcmp(sg->segname, "__TEXT") == 0) { vm = sg->vmaddr; vs = sg->vmsize; break; }
        }
        p += lc->cmdsize;
    }
    if (!vm) { vm = 0x100000000ULL; vs = 0x4000000ULL; }
    gBase = vm + slide;
    gEnd  = gBase + vs;
}

static inline void *Addr(uint64_t rva) { return (void *)(gBase + rva); }

static BOOL AddrSane(uint64_t rva) {
    uintptr_t a = gBase + rva;
    return a >= gBase && a < gEnd;
}

// ============================================================================
// ObscuredInt / ObscuredLong 读写
// ============================================================================
typedef struct { int32_t key, hidden, fake; uint8_t inited; } OILayout;
typedef struct { int64_t key, hidden, fake; uint8_t inited; } OLLayout;

// 验证这个地址是不是一个"活着"的 ObscuredInt
static BOOL ProbeObscuredInt(void *a, int32_t *outVal) {
    if (!a) return NO;
    OILayout *p = (OILayout *)a;
    int32_t key = p->key, hidden = p->hidden, fake = p->fake;
    uint8_t ini = p->inited;
    if (ini != 1) return NO;
    int32_t v = hidden ^ key;
    if (v < 0 || v > 1000000000) return NO;   // 合理范围
    if (fake != v) return NO;                  // fakeValue 必须等于明文
    if (outVal) *outVal = v;
    return YES;
}

static BOOL ProbeObscuredLong(void *a, int64_t *outVal) {
    if (!a) return NO;
    OLLayout *p = (OLLayout *)a;
    int64_t key = p->key, hidden = p->hidden, fake = p->fake;
    uint8_t ini = p->inited;
    if (ini != 1) return NO;
    int64_t v = hidden ^ key;
    if (v < 0 || v > 1000000000000LL) return NO;
    if (fake != v) return NO;
    if (outVal) *outVal = v;
    return YES;
}

static void WriteObscuredInt(void *a, int32_t v) {
    OILayout *p = (OILayout *)a;
    int32_t key = p->key;
    p->hidden = v ^ key;
    p->fake   = v;
    p->inited = 1;
}

static void WriteObscuredLong(void *a, int64_t v) {
    OLLayout *p = (OLLayout *)a;
    int64_t key = p->key;
    p->hidden = v ^ key;
    p->fake   = v;
    p->inited = 1;
}

// ============================================================================
// 材料表
// ============================================================================
typedef struct {
    const char *name;
    uint64_t    rva;
    int         isLong;
    const char *cfgKey;
} MatEntry;

static const MatEntry kMats[] = {
    { "PL_GRASS",    RVA_PL_GRASS,   0, "matValue"    },
    { "PL_WOOD",     RVA_PL_WOOD,    0, "matValue"    },
    { "PL_CLOTH",    RVA_PL_CLOTH,   0, "matValue"    },
    { "PL_IRON",     RVA_PL_IRON,    0, "matValue"    },
    { "PL_STONE",    RVA_PL_STONE,   0, "matValue"    },
    { "PL_SOUL",     RVA_PL_SOUL,    0, "matValue"    },
    { "PL_ORBK",     RVA_PL_ORBK,    0, "orbValue"    },
    { "PL_MATERIAL", RVA_PL_MATERIAL,1, "matValue"    },
    { "PL_MATPOINT", RVA_PL_MATPOINT,0, "matValue"    },
    { "PL_LEGACY",   RVA_PL_LEGACY,  1, "legacyValue" },
    { NULL, 0, 0, NULL }
};

static int gOkCount = 0;
static int gWriteCount = 0;

// 一次性验证：所有材料地址是否都是合法的 ObscuredInt
static BOOL VerifyAddresses(void) {
    int ok = 0, total = 0;
    NSMutableString *detail = [NSMutableString string];
    for (int i = 0; kMats[i].name; i++) {
        total++;
        if (!AddrSane(kMats[i].rva)) {
            [detail appendFormat:@"  %-12s RVA 越界\n", kMats[i].name];
            continue;
        }
        void *a = Addr(kMats[i].rva);
        BOOL good;
        if (kMats[i].isLong) {
            int64_t v = 0; good = ProbeObscuredLong(a, &v);
            if (good) [detail appendFormat:@"  %-12s = %lld  OK\n", kMats[i].name, v];
        } else {
            int32_t v = 0; good = ProbeObscuredInt(a, &v);
            if (good) [detail appendFormat:@"  %-12s = %d  OK\n", kMats[i].name, v];
        }
        if (good) ok++;
        else [detail appendFormat:@"  %-12s 校验失败\n", kMats[i].name];
    }
    gOkCount = ok;
    FileLog(@"\n===== 地址校验 %d/%d =====\n%@\n", ok, total, detail);
    return ok >= total - 1;   // 允许一个失败
}

// 写一轮
static void ApplyOnce(void) {
    if (![gCfg[@"enabled"] boolValue]) return;

    int32_t matVal = (int32_t)[gCfg[@"matValue"] longLongValue];
    int32_t orbVal = (int32_t)[gCfg[@"orbValue"] longLongValue];
    int64_t legVal = [gCfg[@"legacyValue"] longLongValue];

    int wrote = 0;
    for (int i = 0; kMats[i].name; i++) {
        if (!AddrSane(kMats[i].rva)) continue;
        void *a = Addr(kMats[i].rva);

        if (kMats[i].isLong) {
            int64_t cur = 0;
            if (!ProbeObscuredLong(a, &cur)) continue;
            int64_t target = [kMats[i].cfgKey isEqualToString:@"legacyValue"] ? legVal : (int64_t)matVal;
            if (cur != target) { WriteObscuredLong(a, target); wrote++; }
        } else {
            int32_t cur = 0;
            if (!ProbeObscuredInt(a, &cur)) continue;
            int32_t target = [kMats[i].cfgKey isEqualToString:@"orbValue"] ? orbVal : matVal;
            if (cur != target) { WriteObscuredInt(a, target); wrote++; }
        }
    }
    if (wrote) {
        gWriteCount += wrote;
        if (gWriteCount <= 40) FileLog(@"[Apply] 写入 %d 个字段 (累计 %d)\n", wrote, gWriteCount);
    }
}

// ============================================================================
// 悬浮菜单
// ============================================================================
@interface LCMenuVC : UIViewController <UITableViewDataSource, UITableViewDelegate>
@property (nonatomic, strong) UITableView *table;
@end

@implementation LCMenuVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"负之遗产 修改器";
    self.view.backgroundColor = [UIColor colorWithWhite:0.08 alpha:1.0];
    self.table = [[UITableView alloc] initWithFrame:self.view.bounds style:UITableViewStyleInsetGrouped];
    self.table.dataSource = self;
    self.table.delegate = self;
    self.table.backgroundColor = [UIColor clearColor];
    self.table.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self.view addSubview:self.table];
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"关闭" style:UIBarButtonItemStyleDone
                                        target:self action:@selector(onClose)];
}

- (void)onClose { [self dismissViewControllerAnimated:YES completion:nil]; }

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tv { return 2; }
- (NSString *)tableView:(UITableView *)tv titleForHeaderInSection:(NSInteger)s {
    return s == 0 ? @"开关" : @"数值（改完立刻生效）";
}
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s {
    return s == 0 ? 1 : 3;
}

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
    c.backgroundColor = [UIColor colorWithWhite:0.15 alpha:1.0];
    c.textLabel.textColor = [UIColor whiteColor];
    c.detailTextLabel.textColor = [UIColor colorWithWhite:0.7 alpha:1.0];

    if (ip.section == 0) {
        c.textLabel.text = @"总开关";
        UISwitch *sw = [[UISwitch alloc] init];
        sw.on = [gCfg[@"enabled"] boolValue];
        [sw addTarget:self action:@selector(swChanged:) forControlEvents:UIControlEventValueChanged];
        c.accessoryView = sw;
    } else {
        NSArray *titles = @[@"材料（草/木/布/铁/石/魂/材料）", @"宝珠 / 光珠", @"遗产宝石"];
        NSArray *keys   = @[@"matValue", @"orbValue", @"legacyValue"];
        c.textLabel.text = titles[ip.row];
        c.textLabel.font = [UIFont systemFontOfSize:(ip.row == 0 ? 13 : 16)];
        c.detailTextLabel.text = [gCfg[keys[ip.row]] stringValue];
        c.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    }
    return c;
}

- (void)swChanged:(UISwitch *)sw { gCfg[@"enabled"] = @(sw.on); SaveConfig(); }

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    if (ip.section != 1) return;
    NSArray *titles = @[@"材料数值", @"宝珠数值", @"遗产宝石"];
    NSArray *keys   = @[@"matValue", @"orbValue", @"legacyValue"];
    UIAlertController *a = [UIAlertController alertControllerWithTitle:titles[ip.row]
                                                              message:@"输入数值"
                                                       preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.keyboardType = UIKeyboardTypeNumberPad;
        tf.text = [gCfg[keys[ip.row]] stringValue];
    }];
    [a addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        NSString *t = a.textFields.firstObject.text;
        if (t.length) { gCfg[keys[ip.row]] = @([t longLongValue]); SaveConfig(); [tv reloadData]; }
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

@end

@interface LCPassthroughView : UIView
@end
@implementation LCPassthroughView
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    return (v == self) ? nil : v;
}
@end

@interface LCOverlayVC : UIViewController
@property (nonatomic, strong) UIButton *btn;
@end

@implementation LCOverlayVC
- (void)loadView {
    self.view = [[LCPassthroughView alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.view.backgroundColor = [UIColor clearColor];
}
- (void)viewDidLoad {
    [super viewDidLoad];
    CGFloat sz = 56;
    self.btn = [UIButton buttonWithType:UIButtonTypeCustom];
    self.btn.frame = CGRectMake(18, 150, sz, sz);
    self.btn.layer.cornerRadius = sz / 2;
    self.btn.backgroundColor = [UIColor colorWithRed:0.85 green:0.15 blue:0.15 alpha:0.9];
    self.btn.layer.borderWidth = 2.0;
    self.btn.layer.borderColor = [UIColor whiteColor].CGColor;
    [self.btn setTitle:@"鸥" forState:UIControlStateNormal];
    [self.btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.btn.titleLabel.font = [UIFont boldSystemFontOfSize:24];
    [self.btn addTarget:self action:@selector(onTap) forControlEvents:UIControlEventTouchUpInside];
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(onPan:)];
    [self.btn addGestureRecognizer:pan];
    [self.view addSubview:self.btn];
}
- (void)onTap {
    LCMenuVC *vc = [LCMenuVC new];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    nav.modalPresentationStyle = UIModalPresentationFormSheet;
    [self presentViewController:nav animated:YES completion:nil];
}
- (void)onPan:(UIPanGestureRecognizer *)g {
    CGPoint t = [g translationInView:self.view];
    CGPoint c = self.btn.center;
    self.btn.center = CGPointMake(c.x + t.x, c.y + t.y);
    [g setTranslation:CGPointZero inView:self.view];
}
@end

static UIWindow *gOverlayWin = nil;

static void SetupOverlay(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (gOverlayWin) return;
        UIWindowScene *scene = nil;
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]) { scene = (UIWindowScene *)s; break; }
        }
        if (!scene) return;
        gOverlayWin = [[UIWindow alloc] initWithWindowScene:scene];
        gOverlayWin.frame = scene.coordinateSpace.bounds;
        gOverlayWin.windowLevel = UIWindowLevelAlert + 200;
        gOverlayWin.backgroundColor = [UIColor clearColor];
        gOverlayWin.rootViewController = [LCOverlayVC new];
        gOverlayWin.hidden = NO;
    });
}

// ============================================================================
// 入口
// ============================================================================
__attribute__((constructor))
static void LegacyCostInit(void) {
    @autoreleasepool {
        LoadConfig();
        InitImageBase();
        FileLog(@"\n==== 负之遗产修改器启动 base=0x%lx ====\n", (unsigned long)gBase);

        // 等游戏初始化完再开始（PLAYER_C 静态字段要等 IL2CPP 起来才有值）
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            if (!VerifyAddresses()) {
                FileLog(@"!! 地址校验没过，放弃写入。可能版本不对。\n");
                return;
            }
            FileLog(@"地址校验通过 (%d 个字段)\n", gOkCount);

            double iv = [gCfg[@"interval"] doubleValue];
            if (iv <= 0.05) iv = 0.5;
            dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                                             dispatch_get_global_queue(0, 0));
            dispatch_source_set_timer(timer,
                dispatch_time(DISPATCH_TIME_NOW, (int64_t)(iv * NSEC_PER_SEC)),
                (uint64_t)(iv * NSEC_PER_SEC), (uint64_t)(0.05 * NSEC_PER_SEC));
            dispatch_source_set_event_handler(timer, ^{ ApplyOnce(); });
            dispatch_resume(timer);
            FileLog(@"定时器已启动，间隔 %.2fs\n", iv);
        });

        if (![gCfg[@"hideMenu"] boolValue]) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ SetupOverlay(); });
        }
    }
}
