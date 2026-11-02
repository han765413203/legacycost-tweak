#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
反推 Il2CppMethodDefinition 的 declaringType 偏移 + 每类方法区间
判据：declaringType 值必须 < 类型数；同一类的方法在表里连续
"""
import struct
import sys

TD_SIZE = 100


def main():
    data = open(sys.argv[1], 'rb').read()
    names = ['stringLiteral', 'stringLiteralData', 'string', 'events', 'properties',
             'methods', 'parameterDefaultValues', 'fieldDefaultValues',
             'fieldAndParameterDefaultValueData', 'fieldMarshaledSizes',
             'parameters', 'fields', 'genericParameters', 'genericParameterConstraints',
             'genericContainers', 'nestedTypes', 'interfaces', 'vtableMethods',
             'interfaceOffsets', 'typeDefinitions', 'images', 'assemblies',
             'fieldRefs', 'referencedAssemblies', 'attributeData', 'attributeDataRange']
    hdr = {}
    off = 8
    for n in names:
        o, c = struct.unpack_from('<ii', data, off)
        hdr[n + 'Off'] = o
        hdr[n + 'Cnt'] = c
        off += 8

    nTypes = hdr['typeDefinitionsCnt'] // TD_SIZE
    mOff = hdr['methodsOff']
    print(f"类型数={nTypes}  方法表={hdr['methodsCnt']} 字节")

    for msize in (44, 48, 52, 56, 40):
        if hdr['methodsCnt'] % msize:
            continue
        n = hdr['methodsCnt'] // msize
        print(f"\n--- 试方法结构 size={msize}, 条目={n} ---")
        for doff in (4, 8, 12, 16, 20, 24):
            decl = []
            bad = 0
            for i in range(n):
                (v,) = struct.unpack_from('<i', data, mOff + i * msize + doff)
                if v < 0 or v >= nTypes:
                    bad += 1
                    if bad > n * 0.02:
                        break
                decl.append(v)
            if bad > n * 0.02:
                continue
            uniq = len(set(decl))
            # 检查连续性
            seen = set()
            runs = 0
            prev = None
            broken = 0
            for v in decl:
                if v != prev:
                    if v in seen:
                        broken += 1
                    seen.add(v)
                    runs += 1
                    prev = v
            print(f"  declOff=+{doff:2d}: 越界={bad} 不同类={uniq} 段数={runs} 重复段={broken}")


if __name__ == '__main__':
    main()
