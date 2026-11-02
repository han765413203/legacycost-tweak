#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mach-O LC_LOAD_DYLIB 注入器
把 dylib 塞进 IPA 主二进制的加载命令里

用法:
    python3 inject_dylib.py <主二进制> <dylib相对路径> [--strip-sig]

例:
    python3 inject_dylib.py LegacyCostCHN "@executable_path/Frameworks/LegacyCostTweak.dylib"
"""
import struct
import sys
import os

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO_64 = 0x2C


def align(v, a=8):
    return (v + a - 1) & ~(a - 1)


def parse(data):
    magic, cputype, cpusub, ft, ncmds, szcmds, flags, _ = struct.unpack_from('<IiiIIIII', data, 0)
    if magic != MH_MAGIC_64:
        raise SystemExit(f"不是 64 位 Mach-O（magic=0x{magic:08x}）")
    segs, secs, cmds = [], [], []
    off = 32
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        cmds.append((off, cmd, cmdsize))
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8:off + 24].split(b'\x00')[0].decode('latin1')
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off + 24)
            segs.append((segname, vmaddr, vmsize, fileoff, filesize, off))
            nsects = struct.unpack_from('<I', data, off + 64)[0]
            soff = off + 72
            for _ in range(nsects):
                secname = data[soff:soff + 16].split(b'\x00')[0].decode('latin1')
                addr, size = struct.unpack_from('<QQ', data, soff + 32)
                s_off = struct.unpack_from('<I', data, soff + 48)[0]
                secs.append((segname, secname, addr, size, s_off))
                soff += 80
        off += cmdsize
    return dict(cputype=cputype, filetype=ft, ncmds=ncmds, szcmds=szcmds,
                segs=segs, secs=secs, cmds=cmds)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    path = sys.argv[1]
    dylib_path = sys.argv[2]
    strip_sig = '--strip-sig' in sys.argv

    data = bytearray(open(path, 'rb').read())
    m = parse(data)

    print(f"文件: {path}  ({len(data)} bytes)")
    print(f"ncmds={m['ncmds']}  sizeofcmds={m['szcmds']}")

    # 已有同名 dylib 就跳过
    for off, cmd, cmdsize in m['cmds']:
        if cmd == LC_LOAD_DYLIB:
            nameoff = struct.unpack_from('<I', data, off + 8)[0]
            s = data[off + nameoff:off + cmdsize].split(b'\x00')[0].decode('latin1')
            if s == dylib_path:
                print(f"已经注入过了: {s}")
                return

    # 加密检查
    for off, cmd, cmdsize in m['cmds']:
        if cmd == LC_ENCRYPTION_INFO_64:
            cryptid = struct.unpack_from('<I', data, off + 16)[0]
            if cryptid != 0:
                raise SystemExit("二进制还是加密的，先砸壳！")
            print("加密状态: 已解密 OK")

    # 找加载命令之后的空隙
    lc_end = 32 + m['szcmds']
    first_sec_off = min((s[4] for s in m['secs'] if s[4] > 0), default=None)
    if first_sec_off is None:
        raise SystemExit("找不到第一个 section，放弃")
    slack = first_sec_off - lc_end
    print(f"加载命令结束 0x{lc_end:x}，首个 section 0x{first_sec_off:x}，空隙 {slack} 字节")

    # 构造 LC_LOAD_DYLIB
    name_bytes = dylib_path.encode('utf-8') + b'\x00'
    hdr_size = 24
    cmdsize = align(hdr_size + len(name_bytes), 8)
    if cmdsize > slack:
        raise SystemExit(f"空隙不够：需要 {cmdsize}，只有 {slack}")

    cmd = bytearray(cmdsize)
    struct.pack_into('<II', cmd, 0, LC_LOAD_DYLIB, cmdsize)
    struct.pack_into('<I', cmd, 8, hdr_size)          # dylib.name.offset
    struct.pack_into('<I', cmd, 12, 2)                # timestamp
    struct.pack_into('<I', cmd, 16, 0x10000)          # current_version
    struct.pack_into('<I', cmd, 20, 0x10000)          # compatibility_version
    cmd[hdr_size:hdr_size + len(name_bytes)] = name_bytes

    data[lc_end:lc_end + cmdsize] = cmd

    # 更新头
    struct.pack_into('<I', data, 16, m['ncmds'] + 1)
    struct.pack_into('<I', data, 20, m['szcmds'] + cmdsize)

    # 干掉旧签名（改了头，签名必然失效）
    if strip_sig:
        for off, c, cmdsize_i in m['cmds']:
            if c == LC_CODE_SIGNATURE:
                dataoff, datasize = struct.unpack_from('<II', data, off + 8)
                struct.pack_into('<II', data, off + 8, 0, 0)
                print(f"已清空 LC_CODE_SIGNATURE（原 dataoff=0x{dataoff:x} size=0x{datasize:x}）")

    open(path, 'wb').write(data)
    print(f"注入完成：{dylib_path}")
    print(f"新 ncmds={m['ncmds'] + 1}  sizeofcmds={m['szcmds'] + cmdsize}")

    # 复核
    data2 = open(path, 'rb').read()
    m2 = parse(data2)
    ok = False
    for off, c, cmdsize_i in m2['cmds']:
        if c == LC_LOAD_DYLIB:
            nameoff = struct.unpack_from('<I', data2, off + 8)[0]
            s = data2[off + nameoff:off + cmdsize_i].split(b'\x00')[0].decode('latin1')
            if s == dylib_path:
                ok = True
    print("复核:", "通过 ✓" if ok else "失败 ✗")
    if not ok:
        sys.exit(2)


if __name__ == '__main__':
    main()
