# 负之遗产 (LegacyCostCHN) 1.0.9 iOS 修改器

海鸥出品。目标：`com.pujiadev.LegacyCostCHN`，iPhone 12 Pro Max / iOS 15.5 / Dopamine 越狱。

---

## 零、当前进度（先看这段）

| 阶段 | 状态 |
|---|---|
| IPA 解包 / 逆向 / 密钥 / 键名 | ✅ 完成 |
| Theos 工程 + 全部 RVA + 注入器 | ✅ 完成 |
| Mach-O 注入 + 重打包流水线 | ✅ 完成，已实测 |
| dylib 编译 | ❌ **卡住** |

**为什么卡住：** 编译 dylib 需要 clang + iOS SDK（Theos 工具链）。当前这台 Windows
机器上没有 clang，WSL 被安全策略封禁，GitHub release 下载被网络策略拦截。
所以 `Tweak.xm` 写好了但还没编译成 `.dylib`。

**已交付：**

- `dist/负之遗产_加速版_可装.ipa` —— 把 IPA 里原本就带着但没启用的
  `游戏加速LuckySpeede_0.0.9.dylib` 接上了加载命令。**这个能直接装**，
  进游戏有加速悬浮球。只是加速，不是材料修改。**装之前先备份原 IPA。**
- `tools/pack_ipa.py` —— 拿到编译好的 dylib 后，一条命令出最终 IPA
- `tools/build_dylib.sh` —— Linux/macOS 一键编译 + 打包
- `.github/workflows/build.yml` —— 推到 GitHub 自动编译

**出材料修改版 IPA 只差一步：**

```bash
# 在有 Theos 的机器上（或 GitHub Actions）
bash tools/build_dylib.sh
# 产物: dist/负之遗产_mod.ipa
```

或者手动：

```bash
# 1. 编译
cd Tweak && make FINALPACKAGE=1
# 2. 打包（Windows 上也能跑）
cd ..
python3 tools/pack_ipa.py Tweak/.theos/obj/LegacyCostTweak.dylib "dist/负之遗产_mod.ipa"
```

---

## 一、这游戏是怎么防你的

扒完 IPA，三层防护：

| 层 | 类 | 作用 |
|---|---|---|
| 存档层 | `XPlayerPrefs` + `SharedPreferences` + `DataScrambler` | 自定义存档系统，写 `Documents/aak.dat` |
| 加密层 | `EncryptedPlayerPrefs`（Rijndael/AES + Rfc2898 + MD5） | 存档内容加密，密钥硬编码 |
| 内存层 | `CodeStage.AntiCheat.ObscuredTypes`（`ObscuredInt/Float/Long/Bool`） | 运行时数值混淆，改内存直接露馅 |

另外有个 `cheater` 标记，被检测到会写进去。

**逆向结论（硬扒出来的）：**

- 存档文件：`aak.dat`
- 硬编码密钥：`2C745485C4744FDDAD5C92C3E32CC54C`（32 位 hex = 128bit）
- 引擎：Unity IL2CPP，ARM64，`global-metadata.dat` v24
- 二进制已解密（`cryptid=0`），无需再砸壳

---

## 二、工程结构

```
LegacyCost/
├── Tweak/
│   ├── Tweak.xm              主逻辑（hook + 悬浮菜单）
│   ├── offsets.h             全部 RVA，硬编码自本版本二进制
│   ├── Makefile              Theos 构建
│   ├── control               deb 元数据
│   └── LegacyCostTweak.plist 过滤器
├── tools/
│   ├── inject_dylib.py       Mach-O 注入 LC_LOAD_DYLIB
│   ├── find_reg.py           IL2CPP 注册表定位 + 方法 RVA 提取
│   ├── meta_strings.py       metadata 字符串字面表解析
│   ├── il2cpp_dump.py        元数据结构探测
│   └── ...
├── .github/workflows/build.yml  云端编译（不用本地装 Theos）
└── README.md
```

---

## 三、编译

### 方案 A：GitHub Actions（推荐，最省事）

1. 把整个 `LegacyCost` 目录推到 GitHub 仓库
2. Actions 自动跑，产物在 Artifacts 里，名字 `LegacyCostTweak-dylib`

### 方案 B：本地 Theos（WSL / Linux / macOS）

```bash
# 装 Theos
export THEOS=~/theos
git clone --recursive https://github.com/theos/theos.git $THEOS

cd Tweak
make clean
make FINALPACKAGE=1
# 产物：.theos/obj/LegacyCostTweak.dylib
```

需要 `iPhoneOS15.x.sdk`，放 `$THEOS/sdks/` 下。

---

## 四、注入 + 安装

### 1. 把 dylib 放进 app

```
Payload/LegacyCostCHN.app/Frameworks/LegacyCostTweak.dylib
```

### 2. 打加载命令

```bash
python3 tools/inject_dylib.py \
    "Payload/LegacyCostCHN.app/LegacyCostCHN" \
    "@executable_path/Frameworks/LegacyCostTweak.dylib" \
    --strip-sig
```

会输出复核结果，`通过 ✓` 就对了。**必须带 `--strip-sig`**，因为改了 Mach-O 头，原签名必然失效。

### 3. 重新打包

```bash
cd Payload/..
zip -qr LegacyCost_patched.ipa Payload
```

### 4. 装机

**方式一（越狱机，最干净）：**

```bash
# SSH 进手机
scp LegacyCost_patched.ipa root@<手机IP>:/var/mobile/
ssh root@<手机IP>
cd /var/mobile
unzip -oq LegacyCost_patched.ipa -d /tmp/lc
cp -r /tmp/lc/Payload/LegacyCostCHN.app /var/containers/Bundle/Application/   # 或直接覆盖原 app
# 重签名
ldid -S /var/containers/Bundle/Application/<UUID>/LegacyCostCHN.app/LegacyCostCHN
uicache -a
```

**方式二（Filza）：**

1. Filza 打开 IPA，解压
2. 把 dylib 丢进 `Frameworks/`
3. 用 Filza 的「终端」跑：
   ```
   /var/jb/usr/bin/ldid -S LegacyCostCHN
   ```
4. 装回去

**方式三（TrollFools / Azule）：**

直接拿原始 IPA + dylib，工具会自动注入 + 签名。iOS 15.5 越狱机可用。

---

## 五、存档键名对照表（全部从 metadata 字面量表扒的）

| 项目 | 存档键 | 说明 |
|---|---|---|
| 材料 | `PL_MATERIAL` | 通用材料 |
| 草 | `PL_GRASS` | 累计量是 `PL_GRASS_A` |
| 木 | `PL_WOOD` | 累计量是 `PL_WOOD_A` |
| 布 | `PL_CLOTH` | 累计量是 `PL_CLOTH_A` |
| 铁 | `PL_IRON` | 累计量是 `PL_IRON_A` |
| 石 | `PL_STONE` | 累计量是 `PL_STONE_A` |
| 魂 | `PL_SOUL` | 累计量是 `PL_SOUL_A` |
| 宝珠/光珠 | `PL_ORBK` | |
| 物质点数 | `PL_MATERIAL_POINT` | |
| 金币 | `PL_GOLD` / `PL_GOLD_ALL` | |
| 经验 | `PL_EXP` / `PL_EXP_ALL` | |
| 遗产宝石 | `PL_LEGACY` / `PL_LEGACY_ALL` | |
| 等级 | `PL_LV` | |
| 属性点 | `PL_STATUSPOINT` | |
| 技能点 | `PL_SKILLPOINT` | |
| 当前HP/TP | `PL_NOW_HP` / `PL_NOW_TP` | |

> `_A` 结尾的是"历史累计"统计量，改它会触发成就判定，默认跳过。要一起改就把 plist 里 `alsoAccum` 设成 `true`。

**默认值：材料类（草/木/布/铁/石/魂/宝珠/材料）全部 999999999。**

---

## 六、使用

进游戏 3 秒后左上角出现红色「鸥」按钮，拖动可移位，点击开菜单。

| 开关 | 说明 |
|---|---|
| 总开关 | 一键全关 |
| 材料全满 | 草/木/布/铁/石/魂/宝珠/材料 统一按 `matValue` 写 |
| 清除 cheater 标记 | 读写时把 cheater 强制归零 |
| 记录键名日志 | 所有经过存档层的键值写进日志，带分类标注 |

数值页可改：材料 / 金币 / 经验 / 遗产宝石。

配置存在 `/var/mobile/Library/Preferences/com.seagull.legacycost.plist`，改完重进游戏生效。

日志在 `/var/mobile/Documents/LegacyCost.log`，格式：

```
[GetInt]    PL_GRASS = 12  <grass>
[SetInt]    PL_IRON <- 999999999  <iron>
```

---

## 七、RVA 表（offsets.h 摘要）

| 类 | 方法 | RVA |
|---|---|---|
| EncryptedPlayerPrefs | GetInt(string,int) | `0x01ef5294` |
| EncryptedPlayerPrefs | SetInt(string,int) | `0x01ef5180` |
| EncryptedPlayerPrefs | GetFloat(string,float) | `0x01ef529c` |
| EncryptedPlayerPrefs | SetFloat(string,float) | `0x01ef5284` |
| EncryptedPlayerPrefs | GetString(string,string) | `0x01ef52a8` |
| EncryptedPlayerPrefs | SetString(string,string) | `0x01ef528c` |
| EncryptedPlayerPrefs | CheckEncryption | `0x01eed474` |
| ObscuredInt | InternalDecrypt | `0x02263488` |
| ObscuredFloat | InternalDecrypt | `0x0226130c` |
| ObscuredLong | InternalDecrypt | `0x02264424` |

**换游戏版本必须重新生成 RVA**，Tweak 里做了版本校验，对不上会直接不装 hook（不会崩）。

重新生成：

```bash
python3 tools/find_reg.py \
    "Payload/LegacyCostCHN.app/LegacyCostCHN" \
    "Payload/LegacyCostCHN.app/Data/Managed/Metadata/global-metadata.dat" \
    methods.json
```

---

## 八、已知坑

1. **键名已经全部扒准了**，`PL_GRASS` / `PL_WOOD` / `PL_CLOTH` / `PL_IRON` / `PL_STONE` / `PL_SOUL` / `PL_ORBK` / `PL_MATERIAL` 都是从 metadata 字面量表 literal index 9114~9250 那段原样抄的。但**不保证游戏真的用 `GetInt` 读**——有可能是 `GetFloat` 或者整段 JSON 反序列化。所以默认开着「记录键名日志」，进游戏跑一圈看日志就知道走哪条路。

2. **`CheckEncryption` 的 ABI 没验证**。现在是不调原函数、直接返回 `YES`，这样即使签名猜错也不会崩，但可能行为不对。如果存档读不出来，先把这个 hook 注释掉试试。

3. **`XPlayerPrefs` 没拿到 RVA**。它在方法表 38756 之后，走的是 per-module 指针表，那部分结构没完全对上。不过 `EncryptedPlayerPrefs` 是它的底层，理论上能拦住。

4. **iOS 15.5 rootless 路径**是 `/var/jb/...`。Tweak 里 dlopen 已经把 rootless / roothide / 老式越狱的路径都试了一遍。

---

## 九、免责

单机游戏，改自己手机上的数据，不影响任何人。别拿去卖，别拿去联机。老子只管技术，后果自负。
