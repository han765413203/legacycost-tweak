#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打包器：拿编译好的 dylib，一键出最终 IPA

用法:
    python3 tools/pack_ipa.py <dylib路径> [输出ipa路径]

例:
    python3 tools/pack_ipa.py LegacyCostTweak.dylib 负之遗产_mod.ipa

做的事:
    1. 解压原始 IPA
    2. dylib 拷进 Frameworks/
    3. 主二进制加 LC_LOAD_DYLIB + 清签名
    4. 重新压成 IPA
"""
import os
import sys
import shutil
import struct
import subprocess
import zipfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_IPA = os.path.join(ROOT, "LegacyCost.ipa")
BUNDLE_ID = "LegacyCostCHN"
DYLIB_NAME = "LegacyCostTweak.dylib"
DYLIB_LOAD_PATH = "@executable_path/Frameworks/" + DYLIB_NAME


def add_load_command(binary_path, dylib_path, strip_sig=True):
    data = bytearray(open(binary_path, 'rb').read())
    magic, cputype, cpusub, ft, ncmds, szcmds, flags, _ = struct.unpack_from('<IiiIIIII', data, 0)
    if magic != 0xFEEDFACF:
        raise SystemExit(f"不是 64 位 Mach-O: 0x{magic:08x}")

    # 遍历加载命令
    cmds = []
    secs = []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        cmds.append((off, cmd, cmdsize))
        if cmd == 0x19:  # LC_SEGMENT_64
            nsects = struct.unpack_from('<I', data, off + 64)[0]
            soff = off + 72
            for _j in range(nsects):
                s_off = struct.unpack_from('<I', data, soff + 48)[0]
                s_size = struct.unpack_from('<Q', data, soff + 32)[0]
                if s_off > 0:
                    secs.append((s_off, s_size))
                soff += 80
        off += cmdsize

    # 已注入？
    for o, c, cs in cmds:
        if c == 0xC:
            nameoff = struct.unpack_from('<I', data, o + 8)[0]
            s = data[o + nameoff:o + cs].split(b'\x00')[0].decode('latin1')
            if s == dylib_path:
                print(f"  [跳过] 已存在加载命令: {s}")
                return

    lc_end = 32 + szcmds
    first_sec = min((s[0] for s in secs if s[0] > 0), default=None)
    if first_sec is None:
        raise SystemExit("找不到 section 偏移")
    slack = first_sec - lc_end

    name = dylib_path.encode() + b'\x00'
    cmdsize = (24 + len(name) + 7) & ~7
    if cmdsize > slack:
        raise SystemExit(f"头部空隙不够: 需要 {cmdsize}, 只有 {slack}")

    buf = bytearray(cmdsize)
    struct.pack_into('<II', buf, 0, 0xC, cmdsize)
    struct.pack_into('<I', buf, 8, 24)
    struct.pack_into('<I', buf, 12, 2)
    struct.pack_into('<I', buf, 16, 0x10000)
    struct.pack_into('<I', buf, 20, 0x10000)
    buf[24:24 + len(name)] = name
    data[lc_end:lc_end + cmdsize] = buf

    struct.pack_into('<I', data, 16, ncmds + 1)
    struct.pack_into('<I', data, 20, szcmds + cmdsize)

    if strip_sig:
        for o, c, cs in cmds:
            if c == 0x1D:  # LC_CODE_SIGNATURE
                struct.pack_into('<II', data, o + 8, 0, 0)

    open(binary_path, 'wb').write(data)
    print(f"  [OK] 已注入 {dylib_path}  (ncmds {ncmds}->{ncmds+1})")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    dylib = sys.argv[1]
    out_ipa = sys.argv[2] if len(sys.argv) > 2 else "负之遗产_mod.ipa"

    if not os.path.isfile(dylib):
        raise SystemExit(f"找不到 dylib: {dylib}")
    if not os.path.isfile(SRC_IPA):
        raise SystemExit(f"找不到原始 IPA: {SRC_IPA}")

    print(f"原始 IPA : {SRC_IPA}")
    print(f"dylib    : {dylib}")
    print(f"输出     : {out_ipa}")

    tmp = tempfile.mkdtemp(prefix="lcpack_")
    try:
        print("[1/4] 解压 IPA ...")
        with zipfile.ZipFile(SRC_IPA) as z:
            z.extractall(tmp)

        app = os.path.join(tmp, "Payload", BUNDLE_ID + ".app")
        if not os.path.isdir(app):
            raise SystemExit(f"解压后找不到 app: {app}")

        print("[2/4] 放入 dylib ...")
        fw = os.path.join(app, "Frameworks")
        os.makedirs(fw, exist_ok=True)
        dst = os.path.join(fw, DYLIB_NAME)
        shutil.copy2(dylib, dst)
        print(f"  -> {dst}  ({os.path.getsize(dst)} bytes)")

        print("[3/4] 注入加载命令 ...")
        add_load_command(os.path.join(app, BUNDLE_ID), DYLIB_LOAD_PATH)

        print("[4/4] 重新打包 ...")
        out_path = os.path.abspath(out_ipa)
        if os.path.exists(out_path):
            os.remove(out_path)
        # 先写 zip 再改名，避免 Windows 权限问题
        tmpzip = out_path + ".part"
        with zipfile.ZipFile(tmpzip, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for base, dirs, files in os.walk(tmp):
                for f in files:
                    full = os.path.join(base, f)
                    rel = os.path.relpath(full, tmp)
                    z.write(full, rel)
        shutil.move(tmpzip, out_path)

        size = os.path.getsize(out_path)
        print(f"\n完成: {out_path}  ({size/1024/1024:.1f} MB)")
        print("\n装机前记得重签名：")
        print(f"  ldid -S Payload/{BUNDLE_ID}.app/{BUNDLE_ID}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    main()
