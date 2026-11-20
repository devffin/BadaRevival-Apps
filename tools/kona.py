#!/usr/bin/env python3
"""Bada Revival - desassemblage local de Kona.exe (ELF ARM 32 bits).

Utilise capstone (pip install capstone) : c'est le desassembleur de reference
pour retrouver la logique exacte du client, la ou la lecture des BL ne suffit
plus (appels virtuels, tables de saut, vtables).

Modes :
    python kona.py --fn <motif>        desassemble les fonctions qui matchent
    python kona.py --vt <classe>       dump d'une vtable (_ZTV<classe>)
    python kona.py --xref <adresse>    qui charge/stocke cette adresse
    python kona.py --str <motif>       chaines du .rodata qui matchent
    python kona.py --rel <motif>       relocations vers un symbole
"""
import re
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_MEM, ARM_OP_IMM

PATH = r"C:\Users\Compt\Documents\BadaRevive\extract\Kona.exe"


class Elf:
    def __init__(self, path):
        self.d = open(path, "rb").read()
        u16 = lambda o: struct.unpack("<H", self.d[o:o + 2])[0]
        u32 = lambda o: struct.unpack("<I", self.d[o:o + 4])[0]
        shoff, shentsize = u32(32), u16(46)
        shnum, shstrndx = u16(48), u16(50)
        self.secs = []
        for i in range(shnum):
            o = shoff + i * shentsize
            self.secs.append(dict(
                name_off=u32(o), type=u32(o + 4), flags=u32(o + 8),
                addr=u32(o + 12), offset=u32(o + 16), size=u32(o + 20),
                link=u32(o + 24), info=u32(o + 28), entsize=u32(o + 36)))
        tab = self.blob(self.secs[shstrndx])
        for s in self.secs:
            end = tab.find(b"\x00", s["name_off"])
            s["name"] = tab[s["name_off"]:end].decode("latin-1")
        self.by = {s["name"]: s for s in self.secs}

        self.syms = []          # (adresse, taille, nom)
        self.dynsym = []
        ds = self.by[".dynsym"]
        st = self.blob(self.secs[ds["link"]])
        for i in range(ds["size"] // 16):
            o = ds["offset"] + i * 16
            nm, val, size = struct.unpack("<III", self.d[o:o + 12])
            end = st.find(b"\x00", nm) if nm else 0
            name = st[nm:end].decode("latin-1") if nm else ""
            self.dynsym.append(name)
            if nm and size:
                self.syms.append((val & ~1, size, name))
        self.syms.sort()
        self.addr = [a for a, s, n in self.syms]
        self.name_at_map = {}
        for a, s, n in self.syms:
            self.name_at_map[a] = n
        self.plt = self.build_plt()
        self.reloc = self.build_reloc()

    def blob(self, s):
        return self.d[s["offset"]:s["offset"] + s["size"]]

    def build_plt(self):
        rel = self.by[".rel.plt"]
        names = {}
        for i in range(rel["size"] // 8):
            o = rel["offset"] + i * 8
            off, info = struct.unpack("<II", self.d[o:o + 8])
            names[off] = self.dynsym[info >> 8]
        out = {}
        s = self.by[".plt"]
        blob = self.blob(s)
        base = s["addr"]
        for off in range(0, len(blob) - 11, 4):
            i1, i2, i3 = struct.unpack_from("<III", blob, off)
            if (i1 & 0xFFFFF000) != 0xE28FC000:
                continue
            if (i2 & 0xFFFFF000) != 0xE28CC000:
                continue
            if (i3 & 0xFFFFF000) != 0xE5BCF000:
                continue
            got = (base + off + 8 + self.rot(i1 & 0xFFF) +
                   self.rot(i2 & 0xFFF) + (i3 & 0xFFF)) & 0xFFFFFFFF
            if got in names:
                out[base + off] = names[got]
        return out

    @staticmethod
    def rot(imm12):
        r = (imm12 >> 8) * 2
        v = imm12 & 0xFF
        return v if not r else ((v >> r) | (v << (32 - r))) & 0xFFFFFFFF

    def build_reloc(self):
        """adresse -> (type, symbole) pour .rel.dyn et .rel.plt."""
        out = {}
        for nm in (".rel.dyn", ".rel.plt"):
            s = self.by.get(nm)
            if not s:
                continue
            for i in range(s["size"] // 8):
                o = s["offset"] + i * 8
                off, info = struct.unpack("<II", self.d[o:o + 8])
                out[off] = (info & 0xFF, self.dynsym[info >> 8])
        return out

    def name_of(self, addr):
        if addr in self.plt:
            return self.plt[addr]
        import bisect
        i = bisect.bisect_right(self.addr, addr) - 1
        if i >= 0:
            a, s, n = self.syms[i]
            if a <= addr < a + s:
                return n + ("+0x%x" % (addr - a) if addr != a else "")
        return None

    def find(self, rx):
        r = re.compile(rx)
        return [(a, s, n) for a, s, n in self.syms if r.search(n)]

    def read32(self, addr):
        for s in self.secs:
            if s["addr"] <= addr < s["addr"] + s["size"] and s["flags"] & 0x2:
                off = s["offset"] + (addr - s["addr"])
                return struct.unpack_from("<I", self.d, off)[0]
        return None


def demangle_and_annotate(e, ins):
    """Ajoute le nom du symbole vise apres les bl/b et les ldr de vtable."""
    txt = "%08x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str)
    if ins.mnemonic in ("bl", "b", "blx"):
        for op in ins.operands:
            if op.type == ARM_OP_IMM:
                nm = e.name_of(op.imm)
                if nm:
                    txt += "        ; -> %s" % nm
    if ins.mnemonic == "ldr" and len(ins.operands) == 2:
        op = ins.operands[1]
        if op.type == ARM_OP_MEM and op.mem.base == 15:  # ldr rX, [pc, #imm]
            lit = ins.address + 8 + op.mem.disp
            val = e.read32(lit)
            if val is not None:
                nm = e.name_of(val)
                txt += "        ; =0x%08x %s" % (val, nm or "")
    return txt


def main(argv):
    e = Elf(argv[1] if len(argv) > 1 and argv[1].endswith(".exe") else PATH)
    if len(argv) < 3:
        raise SystemExit(__doc__)
    mode, arg = argv[2], argv[3] if len(argv) > 3 else None
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True

    if mode == "--fn":
        hits = e.find(arg)
        if not hits:
            raise SystemExit("aucun symbole")
        for a, size, name in hits:
            sec = None
            for s in e.secs:
                if s["addr"] <= a < s["addr"] + s["size"]:
                    sec = s
            print("=== %s 0x%08x taille %d" % (name, a, size))
            off = sec["offset"] + (a - sec["addr"])
            for ins in md.disasm(e.d[off:off + size], a):
                print("  " + demangle_and_annotate(e, ins))
        return

    if mode == "--vt":
        for a, size, name in e.find("_ZTV.*" + arg):
            print("=== %s 0x%08x taille %d" % (name, a, size))
            n = min(size, 1200) // 4
            for i in range(n):
                sa = a + i * 4
                rel = e.reloc.get(sa)
                if rel and rel[1]:
                    nm = rel[1]
                else:
                    val = e.read32(sa)
                    nm = e.name_of(val) if val else None
                tag = ""
                if i == 0:
                    tag = "  (offset-to-top)"
                elif i == 1:
                    tag = "  (typeinfo)"
                print("  [%3d] +0x%03x  %s%s" % (i, i * 4, nm or "-", tag))
        return

    raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
