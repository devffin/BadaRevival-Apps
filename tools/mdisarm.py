"""Desassembleur ARM annote (bada 2.0) : symboles, chaines pc-relatives.

Les binaires bada 2.0 (BDAgent.exe, Kona.exe, FOsp.so) sont en mode ARM.
Ce script suit les chargements de litteraux pour retrouver les chaines et
les tableaux GOT references, et nomme les appels par les symboles de l'ELF.

usage : python tools/mdisarm.py <fichier> <symbole|0xadresse> [octets]
"""
import re
import struct
import sys

sys.path.insert(0, "tools")
from kona import Elf
import capstone


def wstr(d, addr, secs):
    for s in secs:
        if s["size"] and s["addr"] <= addr < s["addr"] + s["size"]:
            off = s["offset"] + (addr - s["addr"])
            raise StopIteration  # place-holder, jamais utilise


def read_str(e, addr, maxlen=100):
    for s in e.secs:
        if s["size"] and s["addr"] <= addr < s["addr"] + s["size"]:
            off = s["offset"] + (addr - s["addr"])
            b = e.d[off:off + maxlen * 2]
            # chaine UTF-16 (bada 2.0)
            out = []
            i = 0
            while i + 1 < len(b):
                c = b[i] | (b[i + 1] << 8)
                if c == 0:
                    break
                if not (32 <= c < 0x7f):
                    return None
                out.append(chr(c))
                i += 2
            if len(out) >= 3:
                return "".join(out)
            # chaine ASCII
            b = e.d[off:off + maxlen]
            end = b.find(b"\x00")
            if end < 0:
                end = len(b)
            b = b[:end]
            if len(b) >= 3 and all(32 <= c < 0x7f for c in b):
                return b.decode("latin-1")
            return None
    return None


def rodata(e, addr):
    for s in e.secs:
        if s["size"] and s["addr"] <= addr < s["addr"] + s["size"]:
            return s
    return None


def word_at(e, addr):
    for s in e.secs:
        if s["size"] and s["addr"] <= addr < s["addr"] + s["size"]:
            off = s["offset"] + (addr - s["addr"])
            if off + 4 <= len(e.d):
                return struct.unpack("<I", e.d[off:off + 4])[0]
    return None


def main():
    path, arg = sys.argv[1], sys.argv[2]
    extra = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    e = Elf(path)
    t = e.by[".text"]
    b = e.d[t["offset"]:t["offset"] + t["size"]]
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    md.skipdata = True

    if arg.startswith("0x"):
        start = int(arg, 16)
        size = extra or 200
    else:
        start = size = None
        for a, s, n in e.syms:
            if n == arg:
                start = a
                size = s + extra
                break
        if start is None:
            print("symbole introuvable : " + arg)
            return

    off = start - t["addr"]
    regs = {}
    for ins in md.disasm(b[off:off + size], start):
        note = ""
        op = ins.op_str
        a = ins.address
        m = ins.mnemonic
        # ldr rX, [pc, #imm] -> litteral
        mm = re.match(r"^(r\d+|sb|sl|fp|ip|sp|lr), \[pc, #(-?0x[0-9a-f]+|-?\d+)\]$", op)
        if m == "ldr" and mm:
            reg, imm = mm.group(1), int(mm.group(2), 0)
            lit = (a + 8 + imm) & 0xFFFFFFFF
            lit = lit & ~3
            v = word_at(e, lit)
            regs[reg] = ("lit", v, lit)
            st = read_str(e, lit)
            if st:
                note = '"%s"' % st
            elif v is not None:
                note = "lit=%08x @%08x" % (v, lit)
        # adr rX, #imm
        mm = re.match(r"^(r\d+|sb|sl|fp|ip), #(-?0x[0-9a-f]+|-?\d+)$", op)
        if m == "adr" and mm:
            tgt = (a + 8 + int(mm.group(2), 0)) & 0xFFFFFFFF
            st = read_str(e, tgt)
            if st:
                note = '"%s"' % st
            regs[mm.group(1)] = ("addr", tgt, tgt)
        # add rX, pc, rY
        mm = re.match(r"^(r\d+|sb|sl|fp|ip), pc, (r\d+|sb|sl|fp|ip)$", op)
        if m == "add" and mm:
            src = regs.get(mm.group(2))
            if src and src[0] == "lit":
                tgt = (a + 8 + src[1]) & 0xFFFFFFFF
                regs[mm.group(1)] = ("addr", tgt, tgt)
                st = read_str(e, tgt)
                if st:
                    note = '"%s"' % st
                else:
                    note = "-> %08x" % tgt
        # add rX, pc, #imm
        mm = re.match(r"^(r\d+|sb|sl|fp|ip), pc, #(-?0x[0-9a-f]+|-?\d+)$", op)
        if m == "add" and mm:
            tgt = (a + 8 + int(mm.group(2), 0)) & 0xFFFFFFFF
            regs[mm.group(1)] = ("addr", tgt, tgt)
            st = read_str(e, tgt)
            if st:
                note = '"%s"' % st
        # add rX, rY, rZ (suite du motif GOT)
        mm = re.match(r"^(r\d+), (r\d+|sb|sl|fp|ip), (r\d+|sb|sl|fp|ip)$", op)
        if m == "add" and mm:
            b1, b2 = regs.get(mm.group(2)), regs.get(mm.group(3))
            if b1 and b1[0] == "addr" and b2 and b2[0] == "lit":
                tgt = (b1[1] + b2[1]) & 0xFFFFFFFF
                regs[mm.group(1)] = ("addr", tgt, tgt)
                st = read_str(e, tgt)
                if st:
                    note = '"%s"' % st
                else:
                    note = "-> %08x" % tgt
        # ldr rX, [rY, #imm] avec rY deja resolu
        mm = re.match(r"^(r\d+), \[(r\d+), #(-?0x[0-9a-f]+|-?\d+)\]$", op)
        if m == "ldr" and mm and not note:
            src = regs.get(mm.group(2))
            if src and src[0] == "addr":
                tgt = (src[1] + int(mm.group(3), 0)) & 0xFFFFFFFF
                st = read_str(e, tgt)
                if st:
                    note = '"%s"' % st
                v = word_at(e, tgt)
                if v is not None:
                    st2 = read_str(e, v)
                    if st2:
                        note = "-> %08x %r" % (v, st2)
                regs[mm.group(1)] = ("addr", tgt, tgt)
        # appels
        if m in ("bl", "blx") and op.startswith("#"):
            try:
                tgt = int(op.split(",")[0].lstrip("#"), 16)
            except ValueError:
                tgt = None
            if tgt is not None:
                nm = e.name_of(tgt)
                if nm:
                    note = nm
        line = "%08x  %-9s %-42s" % (a, m, op)
        if note:
            line += "   ; " + note
        print(line)


if __name__ == "__main__":
    main()
