//
//  Tweak.xm
//  负之遗产 (LegacyCostCHN) 1.0.9 —— iOS 15.x arm64e 越狱修改器
//
//  海鸥出品。这游戏是 Unity IL2CPP + CodeStage ACTk 混淆 + 自研 XPlayerPrefs 加密存档，
//  三层防护，一层层剥。
//
//  原理：
//    1. EncryptedPlayerPrefs 是存档读写的必经之路 —— hook 它的 Get/Set 就能改一切持久化数值
//    2. ObscuredInt/Float/Long 是内存混淆 —— hook InternalDecrypt 能拿到明文
//    3. CheckEncryption 是篡改检测 —— 直接让它永远返回 true
//    4. "cheater" 标记 —— 读的时候强制 0，写的时候直接吞掉
//
//  依赖：设备上有 ElleKit / CydiaSubstrate / libhooker 任一即可（本 Tweak 自己 dlopen，不硬链接）
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dispatch/dispatch.h>
#include <string.h>
#include <stdint.h>

#include "offsets.h"

// ============================================================================
// 日志
// ============================================================================
#define TAG "[LegacyCost]"
static BOOL gVerbose = YES;
#define LOG(fmt, ...) do { if (gVerbose) NSLog(@TAG " " fmt, ##__VA_ARGS__); } while (0)

static NSString *gLogPath = @"/var/mobile/Documents/LegacyCost.log";
static NSLock   *gLogLock = nil;

static void FileLog(NSString *fmt, ...) {
    if (!gLogLock) gLogLock = [NSLock new];
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    [gLogLock lock];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:gLogPath]) {
        [s writeToFile:gLogPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } else {
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:gLogPath];
        [fh seekToEndOfFile];
        [fh writeData:[s dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    }
    [gLogLock unlock];
}

// ============================================================================
// Substrate 动态加载 —— 不硬链接，rootless / roothide 都能活
// ============================================================================
typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);
static MSHookFunction_t pMSHookFunction = NULL;

static BOOL LoadSubstrate(void) {
    if (pMSHookFunction) return YES;

    const char *paths[] = {
        "@executable_path/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
        "/var/jb/usr/lib/libsubstrate.dylib",
        "/usr/lib/libsubstrate.dylib",
        "/var/jb/usr/lib/libellekit.dylib",
        "/usr/lib/libellekit.dylib",
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        void *h = dlopen(paths[i], RTLD_NOW | RTLD_GLOBAL);
        if (!h) continue;
        pMSHookFunction = (MSHookFunction_t)dlsym(h, "MSHookFunction");
        if (pMSHookFunction) {
            LOG("substrate 加载成功: %s", paths[i]);
            return YES;
        }
    }
    LOG("!! 找不到 MSHookFunction，hook 全部失效");
    return NO;
}

// ============================================================================
// 镜像基址 / 地址换算
// ============================================================================
static uintptr_t gImageBase = 0;   // 主二进制 vmaddr 基准（0x100000000 + slide）
static uintptr_t gImageEnd  = 0;

static void InitImageBase(void) {
    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    if (!hdr) return;

    uintptr_t textVM = 0, textSize = 0;
    const uint8_t *p = (const uint8_t *)hdr + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                textVM = seg->vmaddr;
                textSize = seg->vmsize;
                break;
            }
        }
        p += lc->cmdsize;
    }
    if (!textVM) { textVM = 0x100000000ULL; textSize = 0x4000000ULL; }
    gImageBase = textVM + slide;
    gImageEnd  = gImageBase + textSize;
    LOG("image base = 0x%lx  end = 0x%lx", (unsigned long)gImageBase, (unsigned long)gImageEnd);
}

static inline void *RVA(uint64_t off) {
    return (void *)(gImageBase + off);
}

static BOOL RVASane(uint64_t off) {
    uintptr_t a = gImageBase + off;
    return (a >= gImageBase && a < gImageEnd);
}

// 通用 hook 封装：地址不合法就跳过，绝不硬上
static BOOL HookRVA(const char *name, uint64_t off, void *replace, void **orig) {
    if (!pMSHookFunction) return NO;
    if (!RVASane(off)) {
        LOG("跳过 %s：RVA 0x%llx 越界（版本不匹配？）", name, off);
        return NO;
    }
    pMSHookFunction(RVA(off), replace, orig);
    LOG("已 hook %s @ RVA 0x%llx", name, off);
    return YES;
}

// ============================================================================
// Il2CppString -> NSString
//   struct Il2CppString { void *klass; void *monitor; int32_t length; uint16_t chars[]; }
// ============================================================================
static NSString *I2S(void *str) {
    if (!str) return nil;
    uintptr_t base = (uintptr_t)str;
    int32_t len = *(int32_t *)(base + 0x10);
    if (len <= 0 || len > 4096) return nil;
    const uint16_t *chars = (const uint16_t *)(base + 0x14);
    return [NSString stringWithCharacters:chars length:(NSUInteger)len];
}

// ============================================================================
// 配置
// ============================================================================
static NSString *kCfgPath = @"/var/mobile/Library/Preferences/com.seagull.legacycost.plist";
static NSMutableDictionary *gCfg = nil;

static void DefaultConfig(void) {
    gCfg = [@{
        @"enabled"      : @YES,
        // 材料：草 / 木 / 布 / 铁 / 石 / 魂 / 宝珠 / 材料
        @"matOn"        : @YES,
        @"matValue"     : @999999,
        // 金币
        @"goldOn"       : @YES,
        @"goldValue"    : @9999999,
        // 经验
        @"expOn"        : @YES,
        @"expValue"     : @9999999,
        // 遗产宝石
        @"legacyOn"     : @YES,
        @"legacyValue"  : @999999,
        @"killCheater"  : @YES,
        @"logKeys"      : @YES,
        @"alsoAccum"    : @NO,
        @"hookObscured" : @NO,
        @"hideMenu"     : @NO,
    } mutableCopy];
}

static void LoadConfig(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:kCfgPath];
    DefaultConfig();
    if (d) {
        [gCfg addEntriesFromDictionary:d];
    } else {
        // 首次运行把默认配置落盘，方便你在 Filza 里直接改 enabled=false 关掉
        [gCfg writeToFile:kCfgPath atomically:YES];
    }
}

static void SaveConfig(void) {
    [gCfg writeToFile:kCfgPath atomically:YES];
}

// ============================================================================
// 键名规则 —— 全部从 global-metadata 字面量表扒出来的真实存档键
// ============================================================================
typedef NS_ENUM(int, KeyCat) {
    KeyCatNone = 0,
    KeyCatGold,       // PL_GOLD / PL_GOLD_ALL
    KeyCatExp,        // PL_EXP  / PL_EXP_ALL
    KeyCatLegacy,     // PL_LEGACY / PL_LEGACY_ALL   遗产宝石
    KeyCatMaterial,   // PL_MATERIAL                 材料
    KeyCatGrass,      // PL_GRASS                    草
    KeyCatWood,       // PL_WOOD                     木
    KeyCatCloth,      // PL_CLOTH                    布
    KeyCatIron,       // PL_IRON                     铁
    KeyCatStone,      // PL_STONE                    石
    KeyCatSoul,       // PL_SOUL                     魂
    KeyCatOrb,        // PL_ORBK                     宝珠/光珠
    KeyCatMatPoint,   // PL_MATERIAL_POINT           物质点数
    KeyCatCheater,    // cheater                     作弊标记
};

// 精确键表。左边是存档里的原始键名，右边是分类。
// 注意 "_A" 结尾的是"历史累计"统计量，动了会触发成就判定，默认不碰。
typedef struct { const char *key; KeyCat cat; } KeyRule;

static const KeyRule kRules[] = {
    { "PL_MATERIAL",        KeyCatMaterial },
    { "PL_GRASS",           KeyCatGrass    },
    { "PL_WOOD",            KeyCatWood     },
    { "PL_CLOTH",           KeyCatCloth    },
    { "PL_IRON",            KeyCatIron     },
    { "PL_STONE",           KeyCatStone    },
    { "PL_SOUL",            KeyCatSoul     },
    { "PL_ORBK",            KeyCatOrb      },
    { "PL_MATERIAL_POINT",  KeyCatMatPoint },
    { "PL_GOLD",            KeyCatGold     },
    { "PL_GOLD_ALL",        KeyCatGold     },
    { "PL_EXP",             KeyCatExp      },
    { "PL_EXP_ALL",         KeyCatExp      },
    { "PL_LEGACY",          KeyCatLegacy   },
    { "PL_LEGACY_ALL",      KeyCatLegacy   },
    { NULL, KeyCatNone }
};

// 材料类：草/木/布/铁/石/魂/宝珠/材料 全归这一档，共用一个开关和一个数值
static BOOL IsMaterialCat(KeyCat c) {
    switch (c) {
        case KeyCatMaterial:
        case KeyCatGrass:
        case KeyCatWood:
        case KeyCatCloth:
        case KeyCatIron:
        case KeyCatStone:
        case KeyCatSoul:
        case KeyCatOrb:
            return YES;
        default:
            return NO;
    }
}

static NSString *CatName(KeyCat c) {
    switch (c) {
        case KeyCatGold:     return @"gold";
        case KeyCatExp:      return @"exp";
        case KeyCatLegacy:   return @"legacy";
        case KeyCatMaterial: return @"material";
        case KeyCatGrass:    return @"grass";
        case KeyCatWood:     return @"wood";
        case KeyCatCloth:    return @"cloth";
        case KeyCatIron:     return @"iron";
        case KeyCatStone:    return @"stone";
        case KeyCatSoul:     return @"soul";
        case KeyCatOrb:      return @"orb";
        case KeyCatMatPoint: return @"matpoint";
        case KeyCatCheater:  return @"cheater";
        default:             return @"none";
    }
}

static KeyCat ClassifyKey(NSString *key) {
    if (!key.length) return KeyCatNone;

    // 1) 精确匹配（最靠谱，先查表）
    const char *cstr = key.UTF8String;
    if (cstr) {
        for (int i = 0; kRules[i].key; i++) {
            if (strcmp(cstr, kRules[i].key) == 0) return kRules[i].cat;
        }
    }

    // "_A" 结尾的是历史累计统计量，动了会触发成就判定，默认跳过
    if ([key hasSuffix:@"_A"] && ![gCfg[@"alsoAccum"] boolValue]) return KeyCatNone;

    // 2) 模糊兜底，防着游戏换版本改了键名
    NSString *k = [key lowercaseString];
    if ([k containsString:@"cheater"]) return KeyCatCheater;
    if ([k containsString:@"orbk"] || [k containsString:@"orb"]) return KeyCatOrb;
    if ([k containsString:@"grass"]) return KeyCatGrass;
    if ([k containsString:@"wood"])  return KeyCatWood;
    if ([k containsString:@"cloth"]) return KeyCatCloth;
    if ([k containsString:@"iron"])  return KeyCatIron;
    if ([k containsString:@"stone"]) return KeyCatStone;
    if ([k containsString:@"soul"])  return KeyCatSoul;
    if ([k containsString:@"legacy"]) return KeyCatLegacy;
    if ([k containsString:@"gold"] || [k containsString:@"money"]) return KeyCatGold;
    if ([k isEqualToString:@"exp"] || [k containsString:@"exp_all"]) return KeyCatExp;
    if ([k containsString:@"material"]) return KeyCatMaterial;

    return KeyCatNone;
}

static long long TargetValue(KeyCat c) {
    if (IsMaterialCat(c)) return [gCfg[@"matValue"]    longLongValue];
    switch (c) {
        case KeyCatMatPoint: return [gCfg[@"matValue"]    longLongValue];
        case KeyCatGold:     return [gCfg[@"goldValue"]   longLongValue];
        case KeyCatExp:      return [gCfg[@"expValue"]    longLongValue];
        case KeyCatLegacy:   return [gCfg[@"legacyValue"] longLongValue];
        default:             return 0;
    }
}

static BOOL CatEnabled(KeyCat c) {
    if (![gCfg[@"enabled"] boolValue]) return NO;
    if (IsMaterialCat(c) || c == KeyCatMatPoint) return [gCfg[@"matOn"] boolValue];
    switch (c) {
        case KeyCatGold:   return [gCfg[@"goldOn"]   boolValue];
        case KeyCatExp:    return [gCfg[@"expOn"]    boolValue];
        case KeyCatLegacy: return [gCfg[@"legacyOn"] boolValue];
        default:           return NO;
    }
}

// ============================================================================
// 原始函数指针
// ============================================================================
static int32_t (*orig_GetInt)(void *key, int32_t def, void *m);
static int32_t (*orig_GetInt1)(void *key, void *m);
static float   (*orig_GetFloat)(void *key, float def, void *m);
static float   (*orig_GetFloat1)(void *key, void *m);
static void   *(*orig_GetString)(void *key, void *def, void *m);
static void    (*orig_SetInt)(void *key, int32_t v, void *m);
static void    (*orig_SetFloat)(void *key, float v, void *m);
static void    (*orig_SetString)(void *key, void *v, void *m);
static BOOL    (*orig_CheckEncryption)(void *s, void *m);
static int32_t (*orig_OI_InternalDecrypt)(void *self, void *m);
static float   (*orig_OF_InternalDecrypt)(void *self, void *m);
static int64_t (*orig_OL_InternalDecrypt)(void *self, void *m);

// ============================================================================
// Hook 实现
// ============================================================================
static int32_t Hook_GetInt(void *key, int32_t def, void *m) {
    int32_t ret = orig_GetInt ? orig_GetInt(key, def, m) : def;
    NSString *k = I2S(key);
    KeyCat c = ClassifyKey(k);

    if ([gCfg[@"logKeys"] boolValue] && k.length)
        FileLog(@"[GetInt]    %@ = %d  <%s>\n", k, ret, [CatName(c) UTF8String]);

    if (c == KeyCatCheater && [gCfg[@"killCheater"] boolValue]) return 0;
    if (c != KeyCatNone && CatEnabled(c)) {
        long long v = TargetValue(c);
        if (v != 0) return (int32_t)v;
    }
    return ret;
}

static int32_t Hook_GetInt1(void *key, void *m) {
    int32_t ret = orig_GetInt1 ? orig_GetInt1(key, m) : 0;
    NSString *k = I2S(key);
    KeyCat c = ClassifyKey(k);

    if ([gCfg[@"logKeys"] boolValue] && k.length)
        FileLog(@"[GetInt1]   %@ = %d  <%s>\n", k, ret, [CatName(c) UTF8String]);

    if (c == KeyCatCheater && [gCfg[@"killCheater"] boolValue]) return 0;
    if (c != KeyCatNone && CatEnabled(c)) {
        long long v = TargetValue(c);
        if (v != 0) return (int32_t)v;
    }
    return ret;
}

static float Hook_GetFloat(void *key, float def, void *m) {
    float ret = orig_GetFloat ? orig_GetFloat(key, def, m) : def;
    NSString *k = I2S(key);
    KeyCat c = ClassifyKey(k);

    if ([gCfg[@"logKeys"] boolValue] && k.length)
        FileLog(@"[GetFloat]  %@ = %f  <%s>\n", k, ret, [CatName(c) UTF8String]);

    if (c != KeyCatNone && CatEnabled(c)) {
        long long v = TargetValue(c);
        if (v != 0) return (float)v;
    }
    return ret;
}

static float Hook_GetFloat1(void *key, void *m) {
    float ret = orig_GetFloat1 ? orig_GetFloat1(key, m) : 0.0f;
    NSString *k = I2S(key);
    KeyCat c = ClassifyKey(k);

    if ([gCfg[@"logKeys"] boolValue] && k.length)
        FileLog(@"[GetFloat1] %@ = %f\n", k, ret);

    if (c != KeyCatNone && CatEnabled(c)) {
        long long v = TargetValue(c);
        if (v != 0) return (float)v;
    }
    return ret;
}

static void *Hook_GetString(void *key, void *def, void *m) {
    NSString *k = I2S(key);
    if ([gCfg[@"logKeys"] boolValue] && k.length)
        FileLog(@"[GetString] %@\n", k);
    return orig_GetString ? orig_GetString(key, def, m) : def;
}

static void Hook_SetInt(void *key, int32_t v, void *m) {
    NSString *k = I2S(key);
    KeyCat c = ClassifyKey(k);

    if ([gCfg[@"logKeys"] boolValue] && k.length)
        FileLog(@"[SetInt]    %@ <- %d  <%s>\n", k, v, [CatName(c) UTF8String]);

    // 只处理 cheater 标记；其余写入一律放行，别往存档里灌脏值
    if (c == KeyCatCheater && [gCfg[@"killCheater"] boolValue]) {
        if (orig_SetInt) orig_SetInt(key, 0, m);
        return;
    }
    if (orig_SetInt) orig_SetInt(key, v, m);
}

static void Hook_SetFloat(void *key, float v, void *m) {
    NSString *k = I2S(key);
    KeyCat c = ClassifyKey(k);

    if ([gCfg[@"logKeys"] boolValue] && k.length)
        FileLog(@"[SetFloat]  %@ <- %f  <%s>\n", k, v, [CatName(c) UTF8String]);

    // 写入放行，不做覆盖
    if (orig_SetFloat) orig_SetFloat(key, v, m);
}

static void Hook_SetString(void *key, void *v, void *m) {
    NSString *k = I2S(key);
    if ([gCfg[@"logKeys"] boolValue] && k.length)
        FileLog(@"[SetString] %@\n", k);
    if (orig_SetString) orig_SetString(key, v, m);
}

// 篡改检测永远通过 —— 这游戏 CheckEncryption 返回 false 就会把存档判死
// 注意：不调原函数。IL2CPP 静态/实例方法 ABI 不确定，调错了直接崩。
static BOOL Hook_CheckEncryption(void *s, void *m) {
    return YES;
}

// 内存混淆层 —— 拿明文，可选放大
static int32_t Hook_OI_InternalDecrypt(void *self, void *m) {
    int32_t v = orig_OI_InternalDecrypt ? orig_OI_InternalDecrypt(self, m) : 0;
    return v;
}

static float Hook_OF_InternalDecrypt(void *self, void *m) {
    float v = orig_OF_InternalDecrypt ? orig_OF_InternalDecrypt(self, m) : 0.0f;
    return v;
}

static int64_t Hook_OL_InternalDecrypt(void *self, void *m) {
    int64_t v = orig_OL_InternalDecrypt ? orig_OL_InternalDecrypt(self, m) : 0;
    return v;
}

// ============================================================================
// 安装所有 hook
// ============================================================================
static void InstallHooks(void) {
    if (!LoadSubstrate()) return;

    HookRVA("EPP.GetInt",      RVA_EPP_GET_INT,       (void *)Hook_GetInt,       (void **)&orig_GetInt);
    HookRVA("EPP.GetInt1",     RVA_EPP_GET_INT1,      (void *)Hook_GetInt1,      (void **)&orig_GetInt1);
    HookRVA("EPP.GetFloat",    RVA_EPP_GET_FLOAT,     (void *)Hook_GetFloat,     (void **)&orig_GetFloat);
    HookRVA("EPP.GetFloat1",   RVA_EPP_GET_FLOAT1,    (void *)Hook_GetFloat1,    (void **)&orig_GetFloat1);
    HookRVA("EPP.GetString",   RVA_EPP_GET_STRING,    (void *)Hook_GetString,    (void **)&orig_GetString);
    HookRVA("EPP.SetInt",      RVA_EPP_SET_INT,       (void *)Hook_SetInt,       (void **)&orig_SetInt);
    HookRVA("EPP.SetFloat",    RVA_EPP_SET_FLOAT,     (void *)Hook_SetFloat,     (void **)&orig_SetFloat);
    HookRVA("EPP.SetString",   RVA_EPP_SET_STRING,    (void *)Hook_SetString,    (void **)&orig_SetString);
    HookRVA("EPP.CheckEnc",    RVA_EPP_CHECK_ENCRYPTION, (void *)Hook_CheckEncryption, (void **)&orig_CheckEncryption);

    // 内存混淆层的 hook 默认不装 —— ABI 有风险，而且拿到明文也没地方用。
    // 要调试再打开：plist 里加 hookObscured = true
    if ([gCfg[@"hookObscured"] boolValue]) {
        HookRVA("OI.InternalDecrypt", RVA_OI_INTERNAL_DECRYPT, (void *)Hook_OI_InternalDecrypt, (void **)&orig_OI_InternalDecrypt);
        HookRVA("OF.InternalDecrypt", RVA_OF_INTERNAL_DECRYPT, (void *)Hook_OF_InternalDecrypt, (void **)&orig_OF_InternalDecrypt);
        HookRVA("OL.InternalDecrypt", RVA_OL_INTERNAL_DECRYPT, (void *)Hook_OL_InternalDecrypt, (void **)&orig_OL_InternalDecrypt);
    }

    FileLog(@"==== hooks 安装完成 @ %@ ====\n", [NSDate date]);
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
        [[UIBarButtonItem alloc] initWithTitle:@"关闭"
                                         style:UIBarButtonItemStyleDone
                                        target:self
                                        action:@selector(onClose)];
    self.navigationItem.leftBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"存配置"
                                         style:UIBarButtonItemStylePlain
                                        target:self
                                        action:@selector(onSaveCfg)];
}

- (void)onClose { [self dismissViewControllerAnimated:YES completion:nil]; }

- (void)onSaveCfg {
    SaveConfig();
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"已保存"
                                                              message:@"配置写入成功，重进游戏生效"
                                                       preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tv { return 2; }

- (NSString *)tableView:(UITableView *)tv titleForHeaderInSection:(NSInteger)s {
    return s == 0 ? @"开关" : @"数值";
}

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s {
    return s == 0 ? 4 : 4;
}

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                                               reuseIdentifier:nil];
    c.backgroundColor = [UIColor colorWithWhite:0.15 alpha:1.0];
    c.textLabel.textColor = [UIColor whiteColor];
    c.detailTextLabel.textColor = [UIColor colorWithWhite:0.7 alpha:1.0];

    if (ip.section == 0) {
        NSArray *titles = @[@"总开关", @"材料全满", @"清除 cheater 标记", @"记录键名日志"];
        NSArray *keys   = @[@"enabled", @"matOn", @"killCheater", @"logKeys"];
        c.textLabel.text = titles[ip.row];
        UISwitch *sw = [[UISwitch alloc] init];
        sw.on = [gCfg[keys[ip.row]] boolValue];
        sw.tag = ip.row;
        [sw addTarget:self action:@selector(swChanged:) forControlEvents:UIControlEventValueChanged];
        c.accessoryView = sw;
    } else {
        NSArray *titles = @[@"材料（草/木/布/铁/石/魂/宝珠）", @"金币", @"经验", @"遗产宝石"];
        NSArray *keys   = @[@"matValue", @"goldValue", @"expValue", @"legacyValue"];
        NSArray *onKeys = @[@"matOn", @"goldOn", @"expOn", @"legacyOn"];
        c.textLabel.text = titles[ip.row];
        c.textLabel.font = [UIFont systemFontOfSize:(ip.row == 0 ? 14 : 16)];
        c.detailTextLabel.text = [NSString stringWithFormat:@"%@%@",
                                  [gCfg[onKeys[ip.row]] boolValue] ? @"开 · " : @"关 · ",
                                  gCfg[keys[ip.row]]];
        c.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    }
    return c;
}

- (void)swChanged:(UISwitch *)sw {
    NSArray *keys = @[@"enabled", @"matOn", @"killCheater", @"logKeys"];
    gCfg[keys[sw.tag]] = @(sw.on);
    SaveConfig();
    [self.table reloadData];
}

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    if (ip.section != 1) return;

    NSArray *titles = @[@"材料数值", @"金币", @"经验", @"遗产宝石"];
    NSArray *keys   = @[@"matValue", @"goldValue", @"expValue", @"legacyValue"];
    NSArray *onKeys = @[@"matOn", @"goldOn", @"expOn", @"legacyOn"];

    UIAlertController *a = [UIAlertController
        alertControllerWithTitle:titles[ip.row]
                         message:@"输入数值（留空=不改）"
                  preferredStyle:UIAlertControllerStyleAlert];

    [a addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.keyboardType = UIKeyboardTypeNumberPad;
        tf.text = [gCfg[keys[ip.row]] stringValue];
    }];
    [a addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *act) {
        NSString *t = a.textFields.firstObject.text;
        if (t.length) {
            gCfg[keys[ip.row]] = @([t longLongValue]);
            gCfg[onKeys[ip.row]] = @YES;
            SaveConfig();
            [tv reloadData];
        }
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

@end

// ---- 悬浮按钮 ----
// 穿透视图：空白处不吃事件，只有按钮才拦，不然整屏点不动
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
    self.view.backgroundColor = [UIColor clearColor];

    CGFloat sz = 56;
    self.btn = [UIButton buttonWithType:UIButtonTypeCustom];
    self.btn.frame = CGRectMake(18, 150, sz, sz);
    self.btn.layer.cornerRadius = sz / 2;
    self.btn.backgroundColor = [UIColor colorWithRed:0.85 green:0.15 blue:0.15 alpha:0.9];
    self.btn.layer.borderWidth = 2.0;
    self.btn.layer.borderColor = [UIColor whiteColor].CGColor;
    self.btn.layer.shadowColor = [UIColor blackColor].CGColor;
    self.btn.layer.shadowOpacity = 0.5;
    self.btn.layer.shadowRadius = 4;
    self.btn.layer.shadowOffset = CGSizeMake(0, 2);
    [self.btn setTitle:@"鸥" forState:UIControlStateNormal];
    [self.btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.btn.titleLabel.font = [UIFont boldSystemFontOfSize:24];
    [self.btn addTarget:self action:@selector(onTap) forControlEvents:UIControlEventTouchUpInside];

    UIPanGestureRecognizer *pan =
        [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(onPan:)];
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
        if (!scene) {
            FileLog(@"[UI] 拿不到 UIWindowScene，悬浮窗跳过\n");
            return;
        }

        gOverlayWin = [[UIWindow alloc] initWithWindowScene:scene];
        gOverlayWin.frame = scene.coordinateSpace.bounds;
        gOverlayWin.windowLevel = UIWindowLevelAlert + 200;
        gOverlayWin.backgroundColor = [UIColor clearColor];
        gOverlayWin.rootViewController = [LCOverlayVC new];
        gOverlayWin.hidden = NO;

        FileLog(@"[UI] 悬浮按钮已就位\n");
    });
}

// ============================================================================
// 入口
// ============================================================================
__attribute__((constructor))
static void LegacyCostInit(void) {
    @autoreleasepool {
        LoadConfig();

        NSString *ver = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
        FileLog(@"\n==== 负之遗产 修改器启动  v%@ ====\n", ver ?: @"?");
        if (ver && ![ver isEqualToString:@GAME_VERSION_EXPECTED]) {
            FileLog(@"!! 版本不匹配：期望 %s，实际 %@ —— RVA 可能全错，已中止\n",
                    GAME_VERSION_EXPECTED, ver);
            LOG("版本不匹配 %@ != %s，不装 hook", ver, GAME_VERSION_EXPECTED);
            return;
        }

        InitImageBase();
        InstallHooks();

        if (![gCfg[@"hideMenu"] boolValue]) {
            // 等 UI 起来再挂悬浮窗
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ SetupOverlay(); });
        }
    }
}
