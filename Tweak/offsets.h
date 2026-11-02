//
// offsets.h —— 负之遗产 1.0.9 (com.pujiadev.LegacyCostCHN) ARM64 RVA 表
//
// 全部 RVA 都是从 IPA 主二进制里硬扒出来的，基准 = vmaddr - 0x100000000
// 运行期地址 = _dyld_get_image_vmaddr_slide(0) + 0x100000000 + RVA
//
// 换游戏版本必须重新生成，别他妈偷懒直接套。
//
#ifndef LEGACY_OFFSETS_H
#define LEGACY_OFFSETS_H

#define GAME_VERSION_EXPECTED  "1.0.9"

// ---------------- EncryptedPlayerPrefs ----------------
// 存档加密层，游戏所有持久化数值都从这走
#define RVA_EPP_MD5                 0x01ef5054ULL   // Md5(string)
#define RVA_EPP_SAVE_ENCRYPTION     0x01ef5064ULL   // SaveEncryption(string)
#define RVA_EPP_CHECK_ENCRYPTION    0x01eed474ULL   // CheckEncryption(string)
#define RVA_EPP_SET_INT             0x01ef5180ULL   // SetInt(string key, int val)
#define RVA_EPP_SET_FLOAT           0x01ef5284ULL   // SetFloat(string key, float val)
#define RVA_EPP_SET_STRING          0x01ef528cULL   // SetString(string key, string val)
#define RVA_EPP_GET_INT             0x01ef5294ULL   // GetInt(string key, int def)
#define RVA_EPP_GET_FLOAT           0x01ef529cULL   // GetFloat(string key, float def)
#define RVA_EPP_GET_STRING          0x01ef52a8ULL   // GetString(string key, string def)
#define RVA_EPP_GET_INT1            0x01ef5594ULL   // GetInt(string key)
#define RVA_EPP_GET_FLOAT1          0x01ef5650ULL   // GetFloat(string key)
#define RVA_EPP_GET_STRING1         0x01ef5728ULL   // GetString(string key)
#define RVA_EPP_HAS_KEY             0x01ef53c4ULL   // HasKey(string key)
#define RVA_EPP_DELETE_KEY          0x01ef5798ULL   // DeleteKey(string key)

// ---------------- ObscuredInt ----------------
#define RVA_OI_DECRYPT_A            0x02263298ULL   // Decrypt(int)
#define RVA_OI_DECRYPT_B            0x02261cbcULL   // Decrypt(int, int)
#define RVA_OI_INTERNAL_DECRYPT     0x02263488ULL   // InternalDecrypt() -> int
#define RVA_OI_GET_ENCRYPTED        0x02261ee8ULL
#define RVA_OI_SET_ENCRYPTED        0x0226347cULL
#define RVA_OI_ENCRYPT_A            0x02261a90ULL
#define RVA_OI_ENCRYPT_B            0x0226328cULL

// ---------------- ObscuredFloat ----------------
#define RVA_OF_DECRYPT_A            0x02261074ULL
#define RVA_OF_DECRYPT_B            0x02262e88ULL
#define RVA_OF_INTERNAL_DECRYPT     0x0226130cULL   // -> float
#define RVA_OF_ENCRYPT_A            0x02262d0cULL
#define RVA_OF_ENCRYPT_B            0x0225e5d8ULL

// ---------------- ObscuredLong ----------------
#define RVA_OL_DECRYPT_A            0x02263a48ULL
#define RVA_OL_DECRYPT_B            0x02263f50ULL
#define RVA_OL_INTERNAL_DECRYPT     0x02264424ULL   // -> int64

// ---------------- ObscuredBool ----------------
#define RVA_OB_DECRYPT_A            0x0225e4a4ULL
#define RVA_OB_DECRYPT_B            0x0225e5e0ULL
#define RVA_OB_INTERNAL_DECRYPT     0x0225ed28ULL

// ---------------- SharedPreferences ----------------
#define RVA_SP_SET_STRING           0x022233cccULL
#define RVA_SP_GET_STRING           0x022233f70ULL
#define RVA_SP_SET_INT              0x022234140ULL
#define RVA_SP_GET_INT              0x022234ba8ULL
#define RVA_SP_SET_FLOAT            0x022235128ULL
#define RVA_SP_GET_FLOAT            0x022235424ULL
#define RVA_SP_HAS_KEY              0x022235cb8ULL
#define RVA_SP_DELETE_ALL           0x022228620ULL
#define RVA_SP_OVERWRITE_SAVE       0x02223a184ULL
#define RVA_SP_GET_SAVE_FILE        0x02223ace8ULL
#define RVA_SP_GET_SAVE_PATH        0x02223b098ULL
#define RVA_SP_SAVE                 0x02223e2d8ULL
#define RVA_SP_WRITE_SAVE           0x02223e4bcULL

// ---------------- 存档常量（从 metadata 字面量表扒的） ----------------
#define SAVE_FILE_NAME   "aak.dat"
#define SAVE_CODEWORD    "2C745485C4744FDDAD5C92C3E32CC54C"

// ---------------- 存档键名（literal index 9114~9250 一整段都是） ----------------
//   材料/资源
//     PL_MATERIAL        材料
//     PL_GRASS           草      PL_GRASS_A    草(累计)
//     PL_WOOD            木      PL_WOOD_A     木(累计)
//     PL_CLOTH           布      PL_CLOTH_A    布(累计)
//     PL_IRON            铁      PL_IRON_A     铁(累计)
//     PL_STONE           石      PL_STONE_A    石(累计)
//     PL_SOUL            魂      PL_SOUL_A     魂(累计)
//     PL_ORBK            宝珠/光珠
//     PL_MATERIAL_POINT  物质点数
//   货币/成长
//     PL_GOLD / PL_GOLD_ALL
//     PL_EXP  / PL_EXP_ALL
//     PL_LEGACY / PL_LEGACY_ALL     遗产宝石
//     PL_LV                         等级
//     PL_STATUSPOINT / PL_SKILLPOINT
//     PL_NOW_HP / PL_NOW_TP
//   其他
//     PL_NAME_E, PL_ID, PL_TIME, PL_RC, PL_D, cheater, ftimes ...
//
//   注意：_A 结尾的是"历史累计"统计量，改它会触发成就判定，默认不动。

#endif // LEGACY_OFFSETS_H
