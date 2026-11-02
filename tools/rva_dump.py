#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IL2CPP RVA 提取 + 调用图分析

用法:
    python3 tools/rva_dump.py <主二进制> <global-metadata.dat> [methods.json]
    python3 tools/rva_dump.py <主二进制> <global-metadata.dat> calls <methods.json> <类名> [方法名]
"""
import struct
import sys
import json
import re

TD_SIZE = 100
MD_SIZE = 52
IDENT = re.compile(r'^[A-Za-z_<>`][A-Za-z0-9_<>`\.\[\]]{0,120}$')


class MachO:
    def __init__(self, path):
        self.data = open(path, 'rb').read()
        magic, cputype, cpusub, ft, ncmds, szcmds, flags, _ = \
            struct.unpack_from('<IiiIIIII', self.data, 0)
        assert magic == 0xfeedfacf
        self.base = 0x100000000
        self.segs, self.secs = [], []
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from('<II', self.data, off)
            if cmd == 0x19:
                segname = self.data[off + 8:off + 24].split(b'\x00')[0].decode('latin1')
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', self.data, off + 24)
                self.segs.append((segname, vmaddr, vmsize, fileoff, filesize))
                if segname == '__TEXT':
                    self.base = vmaddr
                nsects = struct.unpack_from('<I', self.data, off + 64)[0]
                soff = off + 72
                for _j in range(nsects):
                    secname = self.data[soff:soff + 16].split(b'\x00')[0].decode('latin1')
                    addr, size = struct.unpack_from('<QQ', self.data, soff + 32)
                    o = struct.unpack_from('<I', self.data, soff + 48)[0]
                    fl = struct.unpack_from('<I', self.data, soff + 64)[0]
                    self.secs.append((segname, secname, addr, size, o, fl))
                    soff += 80
            off += cmdsize

    def vm2file(self, vm):
        for name, vmaddr, vmsize, fileoff, filesize in self.segs:
            # 注意：__TEXT 的 fileoff 就是 0，不能拿它当真假判断
            if filesize and vmaddr <= vm < vmaddr + filesize:
                return fileoff + (vm - vmaddr)
        return None

    def exec_ranges(self):
        return [(s[2], s[2] + s[3]) for s in self.secs
                if s[0] == '__TEXT' and (s[5] & 0x80000000)]

    def is_exec(self, vm):
        return any(a <= vm < b for a, b in self.exec_ranges())

    def rva(self, vm):
        return vm - self.base


class Meta:
    def __init__(self, data):
        self.d = data
        self.sanity, self.version = struct.unpack_from('<Ii', data, 0)
        names = ['stringLiteral', 'stringLiteralData', 'string', 'events', 'properties',
                 'methods', 'parameterDefaultValues', 'fieldDefaultValues',
                 'fieldAndParameterDefaultValueData', 'fieldMarshaledSizes',
                 'parameters', 'fields', 'genericParameters', 'genericParameterConstraints',
                 'genericContainers', 'nestedTypes', 'interfaces', 'vtableMethods',
                 'interfaceOffsets', 'typeDefinitions', 'images', 'assemblies',
                 'fieldRefs', 'referencedAssemblies', 'attributeData', 'attributeDataRange']
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
        if idx < 0 or idx >= self.strCnt:
            return None
        p = self.strOff + idx
        e = self.d.find(b'\x00', p)
        if e < 0:
            return None
        try:
            return self.d[p:e].decode('utf-8')
        except UnicodeDecodeError:
            return None

    def n_types(self):
        return self.h['typeDefinitionsCnt'] // TD_SIZE

    def n_methods(self):
        return self.h['methodsCnt'] // MD_SIZE

    def tdef_name(self, i):
        p = self.h['typeDefinitionsOff'] + i * TD_SIZE
        ni, nsi = struct.unpack_from('<ii', self.d, p)
        return self.string(nsi) or '', self.string(ni) or ''

    def mdef_name(self, i):
        p = self.h['methodsOff'] + i * MD_SIZE
        (ni,) = struct.unpack_from('<i', self.d, p)
        (decl,) = struct.unpack_from('<i', self.d, p + 4)
        return self.string(ni) or '', decl


def find_code_registration(mo):
    """扫 __DATA：count 字段 + 紧跟的指针，指针指向的数组元素大量落在可执行段"""
    for segname, vmaddr, vmsize, fileoff, filesize in mo.segs:
        if segname not in ('__DATA', '__DATA_CONST', '__DATA_DIRTY'):
            continue
        start = fileoff
        end = min(fileoff + filesize, len(mo.data)) - 32
        for p in range(start, end, 8):
            (cnt,) = struct.unpack_from('<I', mo.data, p)
            if not (1000 < cnt < 200000):
                continue
            (ptr,) = struct.unpack_from('<Q', mo.data, p + 8)
            fo = mo.vm2file(ptr)
            if fo is None or fo + 8 > len(mo.data):
                continue
            good = tot = 0
            for k in range(0, min(cnt, 256)):
                if fo + k * 8 + 8 > len(mo.data):
                    break
                (x,) = struct.unpack_from('<Q', mo.data, fo + k * 8)
                if x == 0:
                    continue
                tot += 1
                if mo.is_exec(x):
                    good += 1
            if tot > 200 and good / tot > 0.95:
                return p, cnt, ptr
    return None


def dump_methods(mo, meta, count, ptr_vm):
    fo = mo.vm2file(ptr_vm)
    out = []
    n = min(count, meta.n_methods())
    for i in range(n):
        name, decl = meta.mdef_name(i)
        if not name:
            continue
        ns, tn = meta.tdef_name(decl) if decl < meta.n_types() else ('', '')
        (mp,) = struct.unpack_from('<Q', mo.data, fo + i * 8)
        if mp == 0:
            continue
        out.append({
            'i': i,
            'full': (f"{ns}." if ns else "") + f"{tn}::{name}",
            'cls': tn, 'ns': ns, 'name': name,
            'rva': mo.rva(mp), 'vm': mp,
        })
    return out


def disasm_calls(mo, start_vm, end_vm):
    """只抓 BL/B 目标，够看调用图了"""
    fo = mo.vm2file(start_vm)
    if fo is None:
        return []
    calls = []
    p = start_vm
    while p < end_vm:
        f = mo.vm2file(p)
        if f is None or f + 4 > len(mo.data):
            break
        (w,) = struct.unpack_from('<I', mo.data, f)
        if (w & 0xFC000000) == 0x94000000:          # BL
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            calls.append(('BL', p, p + (imm << 2)))
        elif (w & 0xFC000000) == 0x14000000:        # B
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            calls.append(('B ', p, p + (imm << 2)))
        p += 4
    return calls


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    mo = MachO(sys.argv[1])
    meta = Meta(open(sys.argv[2], 'rb').read())

    if sys.argv[3] == 'calls':
        mj = json.load(open(sys.argv[4], encoding='utf-8'))
        cls_filter = sys.argv[5] if len(sys.argv) > 5 else None
        name_filter = sys.argv[6] if len(sys.argv) > 6 else None

        by_vm = {}
        for m in mj:
            by_vm[m['vm']] = m['full']
        vms = sorted(by_vm)

        targets = [m for m in mj
                   if (cls_filter is None or m['cls'] == cls_filter)
                   and (name_filter is None or m['name'] == name_filter)]
        print(f"匹配 {len(targets)} 个方法\n")

        for m in targets[:12]:
            # 函数长度 = 下一个方法地址 - 自己
            idx = vms.index(m['vm'])
            end = vms[idx + 1] if idx + 1 < len(vms) else m['vm'] + 0x2000
            calls = disasm_calls(mo, m['vm'], min(end, m['vm'] + 0x4000))
            print(f"### {m['full']}  RVA=0x{m['rva']:x}  长度~{end - m['vm']}B  调用 {len(calls)} 次")
            for kind, pc, tgt in calls:
                nm = by_vm.get(tgt)
                tag = nm if nm else f"sub_0x{mo.rva(tgt):x}"
                print(f"    {kind} 0x{mo.rva(pc):08x} -> {tag}")
            print()
        return

    out = sys.argv[3] if len(sys.argv) > 3 else 'methods.json'
    cr = find_code_registration(mo)
    if not cr:
        print("没找到 CodeRegistration")
        sys.exit(1)
    p, cnt, ptr = cr
    print(f"CodeRegistration @file 0x{p:x}  methodPointersCount={cnt}  methodPointers=0x{ptr:x}")
    methods = dump_methods(mo, meta, cnt, ptr)
    print(f"提取 {len(methods)} 个方法")
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(methods, f, ensure_ascii=False)
    print(f"写入 {out}")


if __name__ == '__main__':
    main()
