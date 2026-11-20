import re
import sys
sys.path.insert(0, 'tools')
from kona import Elf
import capstone

_PATH = 'tmp/fw/mosp12.so'
_e = None
_cache = {}


def elf():
    global _e
    if _e is None:
        _e = Elf(_PATH)
    return _e


def getstr(a, maxlen=60):
    e = elf()
    for s in e.secs:
        if s['size'] and s['offset'] and s['addr'] <= a < s['addr'] + s['size']:
            off = s['offset'] + (a - s['addr'])
            b = e.d[off:off + maxlen]
            idx = b.find(b'\x00')
            if idx >= 0:
                b = b[:idx]
            try:
                txt = b.decode('latin-1')
            except Exception:
                return None
            if len(txt) >= 2 and all(32 <= ord(c) < 127 for c in txt):
                return txt
            return None
    return None


def pcrel(ins):
    """returns pc-relative target address or None"""
    m = ins.mnemonic
    op = ins.op_str
    if m == 'adr':
        m2 = re.match(r'^r\d+, #(-?0x[0-9a-f]+|-?\d+)$', op)
        if m2:
            imm = int(m2.group(1), 0)
            base = (ins.address + 4) & ~3
            return base + imm
        return None
    if m in ('add', 'add.w', 'addw', 'sub', 'sub.w', 'subw'):
        m2 = re.match(r'^r\d+, pc, #(-?0x[0-9a-f]+|-?\d+)$', op)
        if m2:
            imm = int(m2.group(1), 0)
            base = (ins.address + 4) & ~3
            return base + imm if m.startswith('add') else base - imm
    return None


def dis(a, n, annotate=True, f=None, callmap=None):
    e = elf()
    t = e.by['.text']
    b = e.d[t['offset']:t['offset'] + t['size']]
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.skipdata = True
    off = a - t['addr']
    out = []
    for i in md.disasm(b[off:off + n], a):
        s = '%08x  %-10s %-42s' % (i.address, i.mnemonic, i.op_str)
        if annotate:
            tg = pcrel(i)
            if tg is not None:
                st = getstr(tg)
                if st:
                    s += '   ; "%s"' % st
            if i.mnemonic in ('bl', 'blx', 'b', 'b.w', 'bx'):
                op = i.op_str.lstrip('#')
                if op.startswith('0x'):
                    try:
                        tgt = int(op, 16)
                    except ValueError:
                        tgt = None
                    if tgt is not None:
                        nm = e.name_of(tgt)
                        if nm:
                            s += '   ; ' + nm
        out.append(s)
    txt = '\n'.join(out)
    if f:
        f.write(txt + '\n')
    else:
        print(txt)
    return out


def func(name_or_addr, extra=0, **kw):
    e = elf()
    if isinstance(name_or_addr, str):
        for a, s, n in e.syms:
            if n == name_or_addr:
                return dis(a, s + extra, **kw)
        print('not found ' + name_or_addr)
        return []
    return dis(name_or_addr, extra, **kw)


if __name__ == '__main__':
    for x in sys.argv[1:]:
        print('==== ' + x)
        if x.startswith('0x'):
            dis(int(x, 16), 400)
        else:
            func(x)
