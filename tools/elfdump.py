#!/usr/bin/env python3
"""Bada Revival - lecture d'un ELF 32 bits sans binutils ARM.

Usage :
    python3 elfdump.py <fichier> --sections
    python3 elfdump.py <fichier> --symbols [motif]
    python3 elfdump.py <fichier> --strings [motif]     (chaines du .rodata)

Aucune dependance : lecture directe des en-tetes ELF.
"""
import re
import struct
import sys

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNSYM = 11


class Elf:
    def __init__(self, data):
        self.d = data
        if data[:4] != b"\x7fELF":
            raise SystemExit("ce n'est pas un ELF")
        if data[4] != 1:
            raise SystemExit("ELF 64 bits non gere")
        u16 = lambda o: struct.unpack("<H", data[o:o + 2])[0]
        u32 = lambda o: struct.unpack("<I", data[o:o + 4])[0]
        self.machine = u16(18)
        self.shoff = u32(32)
        self.shentsize = u16(46)
        self.shnum = u16(48)
        self.shstrndx = u16(50)
        self.sections = []
        for i in range(self.shnum):
            o = self.shoff + i * self.shentsize
            s = dict(name_off=u32(o), type=u32(o + 4), addr=u32(o + 12),
                     offset=u32(o + 16), size=u32(o + 20), link=u32(o + 24),
                     entsize=u32(o + 36))
            self.sections.append(s)
        tab = self.section_data(self.sections[self.shstrndx])
        for s in self.sections:
            end = tab.find(b"\x00", s["name_off"])
            s["name"] = tab[s["name_off"]:end].decode("latin-1")

    def section_data(self, s):
        return self.d[s["offset"]:s["offset"] + s["size"]]

    def symbols(self):
        for s in self.sections:
            if s["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            strtab = self.section_data(self.sections[s["link"]])
            n = s["size"] // 16
            for i in range(n):
                o = s["offset"] + i * 16
                nm, value, size, info, other, shndx = struct.unpack(
                    "<IIIBBH", self.d[o:o + 16])
                if not nm:
                    continue
                end = strtab.find(b"\x00", nm)
                name = strtab[nm:end].decode("latin-1")
                yield s["name"], name, value, size, info, shndx


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    e = Elf(open(argv[1], "rb").read())
    mode = argv[2]
    pat = re.compile(argv[3], re.I) if len(argv) > 3 else None

    if mode == "--sections":
        print("machine=%d sections=%d" % (e.machine, e.shnum))
        for s in e.sections:
            print("%-20s type=%-3d addr=0x%08x taille=%-8d" %
                  (s["name"], s["type"], s["addr"], s["size"]))
        return

    if mode == "--symbols":
        n = 0
        for tab, name, value, size, info, shndx in e.symbols():
            if pat and not pat.search(name):
                continue
            print("%-8s 0x%08x %6d %s" % (tab, value, size, name))
            n += 1
        print("-- %d symboles" % n)
        return

    if mode == "--strings":
        for s in e.sections:
            if s["name"] not in (".rodata", ".data", ".dynstr"):
                continue
            blk = e.section_data(s)
            for m in re.finditer(rb"[\x20-\x7e]{6,}", blk):
                txt = m.group().decode("latin-1")
                if pat is None or pat.search(txt):
                    print("%s 0x%08x %s" % (s["name"], s["addr"] + m.start(), txt))
        return

    raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
