#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IL2CPP global-metadata.dat 字符串字面表解析（修正版）
结构： stringLiteralOffset -> [ (uint32 length, uint32 dataIndex) ] * N
       stringLiteralDataOffset -> 纯 UTF-8 拼接块
"""
import struct
import sys
import json
import re


def parse_header(data):
    sanity, version = struct.unpack_from('<Ii', data, 0)
    assert sanity == 0xFAB11BAF, f"magic 不对: 0x{sanity:08x}"
    fields = {}
    names = [
        'stringLiteral', 'stringLiteralData', 'string', 'events', 'properties',
        'methods', 'parameterDefaultValues', 'fieldDefaultValues',
        'fieldAndParameterDefaultValueData', 'fieldMarshaledSizes',
        'parameters', 'fields', 'genericParameters', 'genericParameterConstraints',
        'genericContainers', 'nestedTypes', 'interfaces', 'vtableMethods',
        'interfaceOffsets', 'typeDefinitions', 'images', 'assemblies',
        'fieldRefs', 'referencedAssemblies', 'attributeData', 'attributeDataRange',
        'unresolvedVirtualCallParameterTypes', 'unresolvedVirtualCallParameterRanges',
        'windowsRuntimeTypeNames', 'windowsRuntimeStrings', 'exportedTypeDefinitions',
    ]
    off = 8
    for n in names:
        if off + 8 > len(data):
            break
        o, c = struct.unpack_from('<ii', data, off)
        fields[n + 'Offset'] = o
        fields[n + 'Count'] = c
        off += 8
    return version, fields


def dump_literals(data, fields):
    lo = fields['stringLiteralOffset']
    lc = fields['stringLiteralCount']
    ldo = fields['stringLiteralDataOffset']
    ldc = fields['stringLiteralDataCount']
    print(f"索引表 : 0x{lo:x} size=0x{lc:x} ({lc//8} 条)")
    print(f"数据块 : 0x{ldo:x} size=0x{ldc:x} ({ldc} bytes)")

    blob = data[ldo:ldo + ldc]
    n = lc // 8
    out = []
    for i in range(n):
        ln, idx = struct.unpack_from('<II', data, lo + i * 8)
        if idx + ln > len(blob):
            out.append(None)
            continue
        raw = blob[idx:idx + ln]
        try:
            s = raw.decode('utf-8')
        except UnicodeDecodeError:
            s = raw.decode('latin1')
        out.append(s)
    print(f"解析出 {len(out)} 条，其中有效 {sum(1 for x in out if x is not None)} 条")
    return out


if __name__ == '__main__':
    path = sys.argv[1]
    with open(path, 'rb') as f:
        data = f.read()
    ver, fields = parse_header(data)
    print(f"metadata v{ver}")
    lits = dump_literals(data, fields)

    outjson = sys.argv[2] if len(sys.argv) > 2 else 'stringliterals.json'
    with open(outjson, 'w', encoding='utf-8') as f:
        json.dump(lits, f, ensure_ascii=False, indent=0)
    print(f"已写入 {outjson}")

    print("\n=== 可疑常量：8-64 位，无中文，字母数字混合 ===")
    seen = set()
    for s in lits:
        if not s or s in seen:
            continue
        seen.add(s)
        if 8 <= len(s) <= 64 and not re.search(r'[\u4e00-\u9fff]', s):
            if re.fullmatch(r'[A-Za-z0-9+/=_\-\.]{8,64}', s) \
               and re.search(r'[0-9]', s) and re.search(r'[A-Za-z]', s):
                print(f"  {s!r} (len={len(s)})")
