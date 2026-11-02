#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mach-O 加载命令解析器 —— 老子用来扒清楚这破游戏二进制到底被谁动过手脚
"""
import struct
import sys

MH_MAGIC_64 = 0xfeedfacf
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xc
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001f
LC_ENCRYPTION_INFO_64 = 0x2c
LC_CODE_SIGNATURE = 0x1d
LC_ID_DYLIB = 0xd
LC_LOAD_UPWARD_DYLIB = 0x80000023

LOAD_NAMES = {
    LC_LOAD_DYLIB: "LC_LOAD_DYLIB",
    LC_LOAD_WEAK_DYLIB: "LC_LOAD_WEAK_DYLIB",
    LC_REEXPORT_DYLIB: "LC_REEXPORT_DYLIB",
    LC_LOAD_UPWARD_DYLIB: "LC_LOAD_UPWARD_DYLIB",
    LC_ENCRYPTION_INFO_64: "LC_ENCRYPTION_INFO_64",
    LC_CODE_SIGNATURE: "LC_CODE_SIGNATURE",
}


def parse(path):
    with open(path, 'rb') as f:
        data = f.read()

    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, _res = \
        struct.unpack_from('<IiiIIIII', data, 0)

    print(f"=== {path} ===")
    print(f"magic      : 0x{magic:08x} {'(64-bit LE OK)' if magic == MH_MAGIC_64 else '(NOT MH_MAGIC_64!)'}")
    print(f"cputype    : 0x{cputype:x}  (0x100000c = ARM64, 0x1000007 = x86_64)")
    print(f"filetype   : {filetype}  (2=MH_EXECUTE, 6=MH_DYLIB)")
    print(f"ncmds      : {ncmds}")
    print(f"sizeofcmds : {sizeofcmds} bytes")
    print(f"flags      : 0x{flags:x}")
    print(f"header size: 32 bytes, header slack = {32 + 0} -> first cmd at 32")
    print()

    off = 32
    dylibs = []
    segments = []
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        name = LOAD_NAMES.get(cmd)
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8:off + 8 + 16].split(b'\x00')[0].decode('latin1')
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off + 24)
            segments.append((segname, vmaddr, vmsize, fileoff, filesize))
            print(f"[{i:02d}] @0x{off:06x} LC_SEGMENT_64 {segname:<16} vmaddr=0x{vmaddr:x} vmsize=0x{vmsize:x} fileoff=0x{fileoff:x} filesize=0x{filesize:x}")
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB):
            nameoff = struct.unpack_from('<I', data, off + 8)[0]
            s = data[off + nameoff:off + cmdsize].split(b'\x00')[0].decode('latin1')
            dylibs.append(s)
            print(f"[{i:02d}] @0x{off:06x} {name:<20} {s}")
        elif cmd == LC_ENCRYPTION_INFO_64:
            cryptoff, cryptsize, cryptid, pad = struct.unpack_from('<IIII', data, off + 8)
            print(f"[{i:02d}] @0x{off:06x} LC_ENCRYPTION_INFO_64 cryptoff=0x{cryptoff:x} cryptsize=0x{cryptsize:x} cryptid={cryptid} {'<== 已解密(OK)' if cryptid == 0 else '<== 还是加密的,得先砸壳'}")
        elif cmd == LC_CODE_SIGNATURE:
            dataoff, datasize = struct.unpack_from('<II', data, off + 8)
            print(f"[{i:02d}] @0x{off:06x} LC_CODE_SIGNATURE dataoff=0x{dataoff:x} datasize=0x{datasize:x}")
        else:
            print(f"[{i:02d}] @0x{off:06x} cmd=0x{cmd:x} size={cmdsize}")
        off += cmdsize

    print()
    print("=== 已注入的 dylib ===")
    for d in dylibs:
        print("  " + d)
    print()
    print("=== __TEXT 段头部剩余空间 ===")
    text = [s for s in segments if s[0] == '__TEXT']
    if text:
        segname, vmaddr, vmsize, fileoff, filesize = text[0]
        # 找 __TEXT 之后第一个段
        nxt = [s for s in segments if s[3] > fileoff]
        if nxt:
            nxt.sort(key=lambda x: x[3])
            slack = nxt[0][3] - (32 + sizeofcmds)
            print(f"  第一个段之后起点: 0x{nxt[0][3]:x}, 加载命令结束于: 0x{32 + sizeofcmds:x}")
            print(f"  可塞新加载命令的空间: {slack} 字节 {'<== 够用' if slack >= 200 else '<== 不够,得挪 __TEXT'}")
    return data


if __name__ == '__main__':
    parse(sys.argv[1])
