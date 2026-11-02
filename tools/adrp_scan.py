#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARM64 ADRP+ADD 引用扫描
用来定位 il2cpp_codegen_register(&g_CodeRegistration, &g_MetadataRegistration)
"""
import struct
import sys


def sx(v, bits):
    if v & (1 << (bits - 1)):
        return v - (1 << bits)
    return v


def find_adrp_refs(code, base_vm, target_vm, span=8):
    """在 code(bytes) 里找 ADRP+ADD 组合计算出 target_vm 的位置"""
    hits = []
    n = len(code) // 4
    for i in range(n):
        (w,) = struct.unpack_from('<I', code, i * 4)
        if (w & 0x9F000000) != 0x90000000:
            continue
        rd = w & 0x1F
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm = sx((immhi << 2) | immlo, 21)
        pc = base_vm + i * 4
        page = (pc & ~0xFFF) + (imm << 12)
        if page != (target_vm & ~0xFFF):
            continue
        # 往后找 ADD Xd, Xd, #imm12
        for j in range(1, span):
            if i + j >= n:
                break
            (w2,) = struct.unpack_from('<I', code, (i + j) * 4)
            if (w2 & 0x7F800000) == 0x11000000:  # ADD (immediate, 64-bit)
                rn = (w2 >> 5) & 0x1F
                rd2 = w2 & 0x1F
                imm12 = (w2 >> 10) & 0xFFF
                shift = (w2 >> 22) & 0x3
                if rn == rd and rd2 == rd and shift == 0:
                    addr = page + imm12
                    if addr == target_vm:
                        hits.append((pc, i * 4))
                        break
    return hits


def main():
    binpath = sys.argv[1]
    target = int(sys.argv[2], 16)
    data = open(binpath, 'rb').read()

    # 简易 Mach-O 段解析
    magic, cputype, cpusub, ft, ncmds, szcmds, flags, _ = struct.unpack_from('<IiiIIIII', data, 0)
    assert magic == 0xfeedfacf
    segs = []
    secs = []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        if cmd == 0x19:
            segname = data[off + 8:off + 24].split(b'\x00')[0].decode('latin1')
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off + 24)
            segs.append((segname, vmaddr, vmsize, fileoff, filesize))
            nsects = struct.unpack_from('<I', data, off + 64)[0]
            soff = off + 72
            for _j in range(nsects):
                secname = data[soff:soff + 16].split(b'\x00')[0].decode('latin1')
                addr, size = struct.unpack_from('<QQ', data, soff + 32)
                o = struct.unpack_from('<I', data, soff + 48)[0]
                secs.append((segname, secname, addr, size, o))
                soff += 80
        off += cmdsize

    print(f"目标地址 0x{target:x}")
    for segname, secname, addr, size, o in secs:
        if segname != '__TEXT':
            continue
        if secname not in ('__text', 'il2cpp'):
            continue
        code = data[o:o + size]
        hits = find_adrp_refs(code, addr, target)
        if hits:
            print(f"\n[{segname},{secname}] 命中 {len(hits)} 处:")
            for pc, fo in hits[:10]:
                print(f"  vm 0x{pc:x} (file 0x{o+fo:x})")
                # 打印前后指令
                s = max(0, fo - 16 * 4)
                e = min(len(code), fo + 20 * 4)
                for k in range(s // 4, e // 4):
                    (w,) = struct.unpack_from('<I', code, k * 4)
                    mark = ' <<<' if (k * 4) == fo else ''
                    print(f"      0x{addr + k*4:09x}: {w:08x}{mark}")


if __name__ == '__main__':
    main()
