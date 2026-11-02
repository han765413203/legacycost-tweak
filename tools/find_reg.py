#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mach-O 段表 + IL2CPP 注册表定位 + 方法指针提取
最终产出: 方法全名 -> RVA
"""
import struct
import sys
import json
import re

TD_SIZE = 100
MD_SIZE = 52
IDENT = re.compile(r'^[A-Za-z_<>`][A-Za-z0-9_<>`\.\[\]]{0,120}$')

LC_SEGMENT_64 = 0x19
LC_ENCRYPTION_INFO_64 = 0x2c


# ---------------- Mach-O ----------------
class MachO:
    def __init__(self, path):
        self.data = open(path, 'rb').read()
        magic, cputype, cpusub, ft, ncmds, szcmds, flags, _ = \
            struct.unpack_from('<IiiIIIII', self.data, 0)
        assert magic == 0xfeedfacf, "不是 64 位 Mach-O"
        self.base_vmaddr = None
        self.segs = []   # (name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot)
        self.secs = []   # (segname, secname, addr, size, offset, flags)
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from('<II', self.data, off)
            if cmd == LC_SEGMENT_64:
                segname = self.data[off + 8:off + 24].split(b'\x00')[0].decode('latin1')
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', self.data, off + 24)
                maxprot, initprot = struct.unpack_from('<ii', self.data, off + 56)
                nsects = struct.unpack_from('<I', self.data, off + 64)[0]
                self.segs.append((segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot))
                if segname == '__TEXT':
                    self.base_vmaddr = vmaddr
                soff = off + 72
                for _j in range(nsects):
                    secname = self.data[soff:soff + 16].split(b'\x00')[0].decode('latin1')
                    addr, size = struct.unpack_from('<QQ', self.data, soff + 32)
                    offset = struct.unpack_from('<I', self.data, soff + 48)[0]
                    flags = struct.unpack_from('<I', self.data, soff + 64)[0]
                    self.secs.append((segname, secname, addr, size, offset, flags))
                    soff += 80
            off += cmdsize
        if self.base_vmaddr is None:
            self.base_vmaddr = 0x100000000

    def vm2file(self, vm):
        for name, vmaddr, vmsize, fileoff, filesize, *_ in self.segs:
            if vmaddr <= vm < vmaddr + filesize and fileoff:
                return fileoff + (vm - vmaddr)
        return None

    def file2vm(self, fo):
        for name, vmaddr, vmsize, fileoff, filesize, *_ in self.segs:
            if fileoff <= fo < fileoff + filesize:
                return vmaddr + (fo - fileoff)
        return None

    def rva(self, vm):
        return vm - self.base_vmaddr

    def exec_ranges(self):
        return [(s[2], s[2] + s[3]) for s in self.secs
                if s[0] == '__TEXT' and s[5] & 0x80000000]

    def data_ranges(self):
        return [(s[2], s[2] + s[3]) for s in self.segs if s[0] in ('__DATA', '__DATA_CONST', '__DATA_DIRTY')]


# ---------------- metadata ----------------
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

    def tdef(self, i):
        p = self.h['typeDefinitionsOff'] + i * TD_SIZE
        return self.d[p:p + TD_SIZE]

    def tdef_name(self, i):
        b = self.tdef(i)
        ni, nsi = struct.unpack_from('<ii', b, 0)
        return self.string(nsi) or '', self.string(ni) or ''

    def mdef_name(self, i):
        p = self.h['methodsOff'] + i * MD_SIZE
        (ni,) = struct.unpack_from('<i', self.d, p)
        (decl,) = struct.unpack_from('<i', self.d, p + 4)
        return self.string(ni) or '', decl


def find_code_registration(mo, meta, verbose=True):
    """扫描 __DATA 找 Il2CppCodeRegistration"""
    nMethods = meta.n_methods()
    exec_r = mo.exec_ranges()
    if verbose:
        print(f"\n=== 找 Il2CppCodeRegistration (methodPointersCount 应为 {nMethods}) ===")

    cands = []
    for segname, vmaddr, vmsize, fileoff, filesize, *_ in mo.segs:
        if segname not in ('__DATA', '__DATA_CONST', '__DATA_DIRTY'):
            continue
        start = fileoff
        end = min(fileoff + filesize, len(mo.data))
        for p in range(start, end - 32, 8):
            (cnt,) = struct.unpack_from('<I', mo.data, p)
            if cnt != nMethods:
                continue
            (ptr,) = struct.unpack_from('<Q', mo.data, p + 8)
            if not any(a <= ptr < b for a, b in mo.data_ranges() + mo.exec_ranges()):
                continue
            fo = mo.vm2file(ptr)
            if fo is None or fo + 8 > len(mo.data):
                continue
            # 抽查前 16 个方法指针是否落在可执行段
            good = 0
            tot = 0
            for k in range(0, min(nMethods, 64)):
                if fo + k * 8 + 8 > len(mo.data):
                    break
                (mp,) = struct.unpack_from('<Q', mo.data, fo + k * 8)
                if mp == 0:
                    continue
                tot += 1
                if any(a <= mp < b for a, b in exec_r):
                    good += 1
            if tot and good / tot > 0.8:
                cands.append((p, ptr, good, tot))
                if verbose:
                    print(f"  命中 @file 0x{p:x} methodPointers=0x{ptr:x} "
                          f"可执行率={good}/{tot}")
    if verbose:
        print(f"  ==> {len(cands)} 个候选")
    return cands


def dump_methods(mo, meta, code_reg_fileoff):
    """从 CodeRegistration 取出 methodPointers 数组，拼出 名字->RVA"""
    (ptr,) = struct.unpack_from('<Q', mo.data, code_reg_fileoff + 8)
    fo = mo.vm2file(ptr)
    nMethods = meta.n_methods()

    # 每个 type 的方法区间
    decls = []
    for i in range(nMethods):
        (decl,) = struct.unpack_from('<i', meta.d, meta.h['methodsOff'] + i * MD_SIZE + 4)
        decls.append(decl)

    # 类型 index -> 区间起点
    starts = {}
    prev = None
    for i, d in enumerate(decls):
        if d != prev:
            starts.setdefault(d, i)
            prev = d

    out = []
    for i in range(nMethods):
        name, decl = meta.mdef_name(i)
        if not name:
            continue
        ns, tn = meta.tdef_name(decl) if decl < meta.n_types() else ('', '')
        (mp,) = struct.unpack_from('<Q', mo.data, fo + i * 8)
        if mp == 0:
            continue
        out.append({
            'idx': i,
            'full': (f"{ns}." if ns else "") + f"{tn}::{name}",
            'cls': tn,
            'ns': ns,
            'name': name,
            'rva': mo.rva(mp),
            'vm': mp,
        })
    return out


if __name__ == '__main__':
    binpath = sys.argv[1]
    metapath = sys.argv[2]
    mo = MachO(binpath)
    meta = Meta(open(metapath, 'rb').read())
    print(f"base vmaddr = 0x{mo.base_vmaddr:x}")
    print(f"类型 {meta.n_types()}  方法 {meta.n_methods()}")
    print(f"可执行 section 数: {len(mo.exec_ranges())}")

    cands = find_code_registration(mo, meta)
    if not cands:
        print("没找到 CodeRegistration")
        sys.exit(1)

    best = cands[0]
    methods = dump_methods(mo, meta, best[0])
    print(f"\n提取到 {len(methods)} 个方法")

    outjson = sys.argv[3] if len(sys.argv) > 3 else 'methods.json'
    with open(outjson, 'w', encoding='utf-8') as f:
        json.dump(methods, f, ensure_ascii=False, indent=0)
    print(f"已写入 {outjson}")

    print("\n=== 关键类抽样 ===")
    keys = ('XPlayerPrefs', 'SharedPreferences', 'EncryptedPlayerPrefs', 'ObscuredInt',
            'ObscuredPrefs', 'DataScrambler', 'SaveEncryption')
    for k in keys:
        hits = [m for m in methods if m['cls'] == k]
        if hits:
            print(f"\n-- {k} ({len(hits)} 个方法) --")
            for m in hits[:14]:
                print(f"   RVA 0x{m['rva']:08x}  {m['full']}")
