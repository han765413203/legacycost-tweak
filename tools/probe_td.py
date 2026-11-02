#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
暴力确定 Il2CppTypeDefinition 里 methodStart / method_count 的偏移
判据：methodStart 单调不减、落在 [0, totalMethods]、且 start+count <= totalMethods
"""
import struct
import sys

TD_SIZE = 100
MD_SIZE = 52


def main():
    data = open(sys.argv[1], 'rb').read()
    import re
    # 复用之前验证过的头部偏移
    hdr = {}
    names = ['stringLiteral', 'stringLiteralData', 'string', 'events', 'properties',
             'methods', 'parameterDefaultValues', 'fieldDefaultValues',
             'fieldAndParameterDefaultValueData', 'fieldMarshaledSizes',
             'parameters', 'fields', 'genericParameters', 'genericParameterConstraints',
             'genericContainers', 'nestedTypes', 'interfaces', 'vtableMethods',
             'interfaceOffsets', 'typeDefinitions', 'images', 'assemblies',
             'fieldRefs', 'referencedAssemblies', 'attributeData', 'attributeDataRange']
    off = 8
    for n in names:
        o, c = struct.unpack_from('<ii', data, off)
        hdr[n + 'Off'] = o
        hdr[n + 'Cnt'] = c
        off += 8

    tdOff = hdr['typeDefinitionsOff']
    nTypes = hdr['typeDefinitionsCnt'] // TD_SIZE
    totalMethods = hdr['methodsCnt'] // MD_SIZE
    totalFields_bytes = hdr['fieldsCnt']
    print(f"类型数={nTypes}  方法总数={totalMethods}  字段表字节={totalFields_bytes}")

    cands = []
    for startOff in range(28, 72, 4):
        starts = []
        for i in range(nTypes):
            p = tdOff + i * TD_SIZE + startOff
            (v,) = struct.unpack_from('<i', data, p)
            starts.append(v)
        # 检查范围 + 单调
        if min(starts) < 0 or max(starts) > totalMethods:
            continue
        mono = all(starts[i] <= starts[i + 1] for i in range(nTypes - 1))
        if not mono:
            continue
        for cntOff in range(60, 100, 2):
            counts = []
            for i in range(nTypes):
                p = tdOff + i * TD_SIZE + cntOff
                (v,) = struct.unpack_from('<H', data, p)
                counts.append(v)
            # start+count 不能越界；且 count 平均不能太离谱
            bad = 0
            for i in range(nTypes):
                if starts[i] + counts[i] > totalMethods:
                    bad += 1
            if bad == 0:
                avg = sum(counts) / nTypes
                if 0 < avg < 200:
                    cands.append((startOff, cntOff, starts[-1], sum(counts), avg))
                    print(f"  候选: methodStart@+{startOff}, method_count@+{cntOff} "
                          f"最后start={starts[-1]} 计数和={sum(counts)} 平均={avg:.1f}")

    if not cands:
        print("  !! 没找到候选，换个思路")
        return
    # 最佳：计数和应接近 totalMethods
    cands.sort(key=lambda x: abs(x[3] - totalMethods))
    best = cands[0]
    print(f"\n==> 最靠谱: methodStart@+{best[0]}, method_count@+{best[1]}, "
          f"计数和={best[3]} (方法总数 {totalMethods})")


if __name__ == '__main__':
    main()
