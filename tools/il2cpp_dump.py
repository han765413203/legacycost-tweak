#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IL2CPP 元数据全解析 + 注册表定位
输出: 方法名 -> RVA 映射表
"""
import struct
import sys
import re
import json

IDENT = re.compile(r'^[A-Za-z_<>`][A-Za-z0-9_<>`\.\[\]]{0,120}$')


def cstr(data, off, limit=300):
    if off < 0 or off >= len(data):
        return None
    end = data.find(b'\x00', off)
    if end < 0 or end - off > limit:
        return None
    try:
        return data[off:end].decode('utf-8')
    except UnicodeDecodeError:
        return None


class Meta:
    def __init__(self, data):
        self.d = data
        self.sanity, self.version = struct.unpack_from('<Ii', data, 0)
        assert self.sanity == 0xFAB11BAF
        # 标准 v24 头部字段顺序
        names = [
            'stringLiteral', 'stringLiteralData', 'string', 'events', 'properties',
            'methods', 'parameterDefaultValues', 'fieldDefaultValues',
            'fieldAndParameterDefaultValueData', 'fieldMarshaledSizes',
            'parameters', 'fields', 'genericParameters', 'genericParameterConstraints',
            'genericContainers', 'nestedTypes', 'interfaces', 'vtableMethods',
            'interfaceOffsets', 'typeDefinitions', 'images', 'assemblies',
            'fieldRefs', 'referencedAssemblies', 'attributeData', 'attributeDataRange',
        ]
        self.h = {}
        off = 8
        for n in names:
            o, c = struct.unpack_from('<ii', data, off)
            self.h[n + 'Off'] = o
            self.h[n + 'Cnt'] = c
            off += 8
        self.strOff = self.h['stringOff']
        self.strCnt = self.h['stringCnt']

    def string(self, idx):
        return cstr(self.d, self.strOff + idx)

    # ---------- typeDefinitions ----------
    def validate_typedefs(self, size=100):
        off, cnt = self.h['typeDefinitionsOff'], self.h['typeDefinitionsCnt']
        if cnt % size:
            return 0, 0
        n = cnt // size
        ok = 0
        for i in range(min(n, 500)):
            p = off + i * size
            ni, nsi = struct.unpack_from('<ii', self.d, p)
            nm, ns = self.string(ni), self.string(nsi)
            if nm and IDENT.match(nm) and (ns == '' or (ns and IDENT.match(ns))):
                ok += 1
        return ok, n

    def typedef(self, i, size=100):
        p = self.h['typeDefinitionsOff'] + i * size
        f = struct.unpack_from('<' + 'i' * 25, self.d, p)  # 100 字节 = 25 个 int32
        return f

    # ---------- methods ----------
    def validate_methods(self, size):
        off, cnt = self.h['methodsOff'], self.h['methodsCnt']
        if size <= 0 or cnt % size:
            return 0, 0
        n = cnt // size
        ok = 0
        for i in range(min(n, 500)):
            p = off + i * size
            (ni,) = struct.unpack_from('<i', self.d, p)
            nm = self.string(ni)
            if nm and IDENT.match(nm):
                ok += 1
        return ok, n


def probe_method_size(m):
    print("\n=== 探测 Il2CppMethodDefinition 结构大小 ===")
    best = None
    for size in range(24, 81, 4):
        ok, n = m.validate_methods(size)
        if ok and n:
            rate = ok / max(1, min(n, 500))
            if rate > 0.6:
                print(f"  size={size:3d} 条目={n:6d} 合法={ok}/{min(n,500)} ({rate*100:.0f}%)")
            if best is None or rate > best[0]:
                best = (rate, size, n)
    if best:
        print(f"  ==> 最佳 size={best[1]}, 条目={best[2]}, 命中率={best[0]*100:.0f}%")
    return best[1] if best else None


def probe_typedef_fields(m, tsize=100):
    """找 methodStart / method_count 在 typeDefinition 里的偏移"""
    off, cnt = m.h['typeDefinitionsOff'], m.h['typeDefinitionsCnt']
    n = cnt // tsize
    print(f"\n=== 探测 typeDefinition 内 methodStart/method_count 偏移 (共 {n} 个类) ===")

    # 试所有 int32 偏移当作 methodStart，检查单调不减
    results = []
    for moff in range(0, tsize - 4, 4):
        vals = []
        for i in range(n):
            p = off + i * tsize + moff
            (v,) = struct.unpack_from('<i', m.d, p)
            vals.append(v)
        # methodStart 应该单调不减，且落在 [0, 大数]
        mono = all(vals[i] <= vals[i + 1] for i in range(len(vals) - 1))
        if mono and vals[0] == 0 and 0 < vals[-1] < 200000:
            results.append((moff, vals[-1]))
            print(f"  offset {moff:3d}: 单调✓ 最后值={vals[-1]}")
    return results


def main():
    mpath = sys.argv[1]
    m = Meta(open(mpath, 'rb').read())
    print(f"metadata v{m.version}")
    print(f"string heap: 0x{m.strOff:x} size={m.strCnt}")
    print(f"typeDefinitions: 0x{m.h['typeDefinitionsOff']:x} size={m.h['typeDefinitionsCnt']}")
    print(f"methods        : 0x{m.h['methodsOff']:x} size={m.h['methodsCnt']}")
    print(f"fields         : 0x{m.h['fieldsOff']:x} size={m.h['fieldsCnt']}")

    ok, n = m.validate_typedefs(100)
    print(f"\ntypeDefinitions(100B): {n} 个, 合法名 {ok}/{min(n,500)}")

    msize = probe_method_size(m)
    probe_typedef_fields(m)


if __name__ == '__main__':
    main()
