#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IL2CPP 函数反汇编器（带符号注释）

用法:
    python3 tools/disasm.py <二进制> <metadata> <methods.json> <类名> [方法名]
"""
import struct
import sys
import json
import bisect
import capstone

from rva_dump import MachO, Meta


def load_cstr(mo, vm, limit=120):
    fo = mo.vm2file(vm)
    if fo is None:
        return None
    end = mo.data.find(b'\x00', fo, fo + limit)
    if end < 0:
        return None
    try:
        s = mo.data[fo:end].decode('utf-8')
    except UnicodeDecodeError:
        return None
    return s if s and all(32 <= ord(c) < 127 or c in '\n\t' for c in s) else None


def main():
    binp, metap, mjp, cls = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    namef = sys.argv[5] if len(sys.argv) > 5 else None

    mo = MachO(binp)
    meta = Meta(open(metap, 'rb').read())
    methods = json.load(open(mjp, encoding='utf-8'))

    by_vm = {}
    for m in methods:
        by_vm.setdefault(m['vm'], m['full'])
    vms = sorted(by_vm)

    cstr_ranges = [(s[2], s[2] + s[3]) for s in mo.secs if s[1] in ('__cstring', '__objc_methname')]
    exec_r = mo.exec_ranges()

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True

    targets = [m for m in methods if m['cls'] == cls and (namef is None or m['name'] == namef)]
    if not targets:
        print(f"没找到 {cls}::{namef}")
        return

    for m in targets[:6]:
        i = bisect.bisect_right(vms, m['vm'])
        end = vms[i] if i < len(vms) else m['vm'] + 0x1000
        if end - m['vm'] > 0x6000:
            end = m['vm'] + 0x6000
        fo = mo.vm2file(m['vm'])
        code = mo.data[fo:fo + (end - m['vm'])]

        print(f"\n{'='*78}")
        print(f"### {m['full']}   RVA=0x{m['rva']:08x}   大小≈{end-m['vm']}B")
        print(f"{'='*78}")
        for ins in md.disasm(code, m['vm']):
            extra = ''
            mn, ops = ins.mnemonic, ins.op_str
            if mn in ('bl', 'b') and ins.operands and ins.operands[0].type == capstone.arm64.ARM64_OP_IMM:
                tgt = ins.operands[0].imm
                nm = by_vm.get(tgt)
                extra = '  ; ' + (nm if nm else f"sub_0x{mo.rva(tgt):x}")
            elif mn in ('adrp',) and ins.operands:
                pass
            elif mn == 'add' and ins.operands and len(ins.operands) == 3:
                try:
                    a = ins.operands[1].imm
                    b = ins.operands[2].imm
                    addr = a + b
                    if any(lo <= addr < hi for lo, hi in cstr_ranges):
                        s = load_cstr(mo, addr)
                        if s:
                            extra = f'  ; "{s}"'
                except Exception:
                    pass
            print(f"  0x{mo.rva(ins.address):08x}  {ins.bytes.hex():<8} {mn:<8} {ops}{extra}")


if __name__ == '__main__':
    main()
