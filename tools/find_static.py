#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
扫 ADRP+ADD 指令对，找出所有被直接寻址的 __DATA 全局变量
用来定位 IL2CPP 静态字段的固定地址
"""
import struct
import sys
from collections import Counter

from rva_dump import MachO, Meta


def sx(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def main():
    mo = MachO(sys.argv[1])
    data = mo.data

    # 可执行区
    ranges = []
    for segname, secname, addr, size, off, fl in mo.secs:
        if segname == '__TEXT' and secname in ('__text', 'il2cpp'):
            ranges.append((addr, size, off))

    # __DATA 段范围（只看 __data / __bss 附近的全局）
    data_ranges = []
    for segname, secname, addr, size, off, fl in mo.secs:
        if segname == '__DATA' and secname in ('__data', '__bss', '__common', '__const'):
            data_ranges.append((addr, addr + size))

    def in_data(a):
        return any(lo <= a < hi for lo, hi in data_ranges)

    hits = Counter()
    detail = {}

    for addr, size, off in ranges:
        code = data[off:off + size]
        n = len(code) // 4
        for i in range(n - 6):
            (w,) = struct.unpack_from('<I', code, i * 4)
            if (w & 0x9F000000) != 0x90000000:      # ADRP
                continue
            rd = w & 0x1F
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = sx((immhi << 2) | immlo, 21)
            pc = addr + i * 4
            page = (pc & ~0xFFF) + (imm << 12)
            # 往后 4 条内找 ADD Xd, Xd, #imm12
            for j in range(1, 5):
                if i + j >= n:
                    break
                (w2,) = struct.unpack_from('<I', code, (i + j) * 4)
                if (w2 & 0x7F800000) != 0x11000000:
                    continue
                rn = (w2 >> 5) & 0x1F
                rd2 = w2 & 0x1F
                imm12 = (w2 >> 10) & 0xFFF
                if rn != rd or rd2 != rd:
                    continue
                target = page + imm12
                if in_data(target):
                    hits[target] += 1
                    detail.setdefault(target, []).append((pc, i * 4, off))
                break

    print(f"扫到 {len(hits)} 个被直接寻址的 __DATA 地址\n")

    # 找静态字段基址：一堆相邻地址，间隔和字段偏移对得上
    addrs = sorted(hits)
    print("=== 0x103ec4000 附近的地址 ===")
    for a in addrs:
        if 0x103ec3000 <= a <= 0x103ec5000:
            print("  0x%x  (引用 %d 次)" % (a, hits[a]))

    print("\n=== 找连续的静态区：地址差值匹配字段偏移 ===")
    # 我们关心的字段偏移（相对 static_fields 起点）
    want = {
        0x030: 'PL_GOLD', 0x110: 'PL_LEGACY_ALL', 0x198: 'PL_EXP',
        0x1d0: 'PL_EXP_ALL', 0x208: 'PL_GOLD_ALL', 0x240: 'PL_MATERIAL',
        0x330: 'PL_MATERIAL_POINT', 0x560: 'PL_GRASS', 0x570: 'PL_WOOD',
        0x580: 'PL_CLOTH', 0x590: 'PL_IRON', 0x5a0: 'PL_STONE',
        0x5b0: 'PL_SOUL', 0x5c0: 'PL_LEGACY', 0x5e0: 'PL_ORBK',
    }
    # 对每个候选基址，看能对上多少个
    for base in addrs:
        score = []
        for off, nm in want.items():
            if (base + off) in hits:
                score.append(nm)
        if len(score) >= 3:
            print("  基址 0x%x -> 命中 %d 个: %s" % (base, len(score), ','.join(score)))


if __name__ == '__main__':
    main()
