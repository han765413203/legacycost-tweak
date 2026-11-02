#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IL2CPP metadata 布局验证器
不确定 v24 各表的结构体大小，就暴力试 —— 哪个能让 typeDefinitions 的 nameIndex
全部指向合法标识符，哪个就是对的
"""
import struct
import sys
import re

IDENT = re.compile(r'^[A-Za-z_<>`][A-Za-z0-9_<>`\.\[\]]{0,120}$')


def read_cstr(data, off, limit=200):
    end = data.find(b'\x00', off)
    if end < 0 or end - off > limit:
        return None
    try:
        return data[off:end].decode('utf-8')
    except UnicodeDecodeError:
        return None


def parse_header(data):
    sanity, version = struct.unpack_from('<Ii', data, 0)
    names = [
        'stringLiteral', 'stringLiteralData', 'string', 'events', 'properties',
        'methods', 'parameterDefaultValues', 'fieldDefaultValues',
        'fieldAndParameterDefaultValueData', 'fieldMarshaledSizes',
        'parameters', 'fields', 'genericParameters', 'genericParameterConstraints',
        'genericContainers', 'nestedTypes', 'interfaces', 'vtableMethods',
        'interfaceOffsets', 'typeDefinitions', 'images', 'assemblies',
        'fieldRefs', 'referencedAssemblies', 'attributeData', 'attributeDataRange',
    ]
    f = {}
    off = 8
    for n in names:
        o, c = struct.unpack_from('<ii', data, off)
        f[n + 'Off'] = o
        f[n + 'Cnt'] = c
        off += 8
    return version, f


def try_typedefs(data, hdr, str_off, str_cnt, size):
    off = hdr['typeDefinitionsOff']
    cnt = hdr['typeDefinitionsCnt']
    if size <= 0 or cnt % size:
        return -1, 0, None
    n = cnt // size
    ok = 0
    samples = []
    for i in range(min(n, 400)):
        p = off + i * size
        if p + size > len(data):
            break
        nameIdx, nsIdx = struct.unpack_from('<ii', data, p)
        if not (0 <= nameIdx < str_cnt and 0 <= nsIdx < str_cnt):
            continue
        nm = read_cstr(data, str_off + nameIdx)
        ns = read_cstr(data, str_off + nsIdx)
        if nm and IDENT.match(nm) and (ns is not None and (ns == '' or IDENT.match(ns))):
            ok += 1
            if len(samples) < 8:
                samples.append((ns or '') + '.' + nm)
    return ok, n, samples


if __name__ == '__main__':
    path = sys.argv[1]
    data = open(path, 'rb').read()
    ver, hdr = parse_header(data)
    print(f"metadata v{ver}")
    print(f"string heap: 0x{hdr['stringOff']:x} size={hdr['stringCnt']}")
    print(f"typeDefinitions: 0x{hdr['typeDefinitionsOff']:x} size={hdr['typeDefinitionsCnt']}")
    print()
    best = None
    for size in range(32, 129, 4):
        ok, n, samples = try_typedefs(data, hdr, hdr['stringOff'], hdr['stringCnt'], size)
        if ok > 0:
            rate = ok / max(1, min(n, 400))
            if best is None or rate > best[0]:
                best = (rate, size, ok, n, samples)
            if rate > 0.5:
                print(f"size={size:3d}  条目={n:5d}  合法名={ok}/{min(n,400)}  ({rate*100:.0f}%)")
                for s in (samples or [])[:5]:
                    print(f"      {s}")
    print()
    if best:
        print(f"==> 最佳: struct size={best[1]}, 条目数={best[3]}, 命中率={best[0]*100:.0f}%")
