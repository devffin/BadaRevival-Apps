#!/usr/bin/env python3
"""Bada Revival - inspection de la PLT / relocations d'un ELF ARM 32 bits.

Sert a comprendre la disposition exacte de .plt avant de la resoudre.
Usage : python3 pltdump.py <elf>
"""
import struct
import sys


def sections(d):
    u16 = lambda o: struct.unpack("<H", d[o:o + 2])[0]
    u32 = lambda o: struct.unpack("<I", d[o:o + 4])[0]
    shoff, shentsize = u32(32), u16(46)
    shnum, shstrndx = u16(48), u16(50)
    out = []
    for i in range(shnum):
        o = shoff + i * shentsize
        out.append(dict(name_off=u32(o), type=u32(o + 4), addr=u32(o + 12),
                        offset=u32(o + 16), size=u32(o + 20), link=u32(o + 24),
                        entsize=u32(o + 36)))
    strtab = d[out[shstrndx]["offset"]:out[shstrndx]["offset"] + out[shstrndx]["size"]]
    for s in out:
        end = strtab.find(b"\x00", s["name_off"])
        s["name"] = strtab[s["name_off"]:end].decode("latin-1")
    return out


def main(argv):
    d = open(argv[1], "rb").read()
    secs = sections(d)
    by = dict((s["name"], s) for s in secs)
    for nm in (".plt", ".rel.plt", ".rela.plt", ".dynsym", ".dynstr", ".got", ".rel.dyn"):
        s = by.get(nm)
        if s:
            print("%-10s addr=0x%08x off=0x%08x size=%d entsize=%d link=%d"
                  % (nm, s["addr"], s["offset"], s["size"], s["entsize"], s["link"]))

    s = by.get(".plt")
    if s:
        print("\n-- 96 premiers octets de .plt --")
        blob = d[s["offset"]:s["offset"] + 96]
        for i in range(0, len(blob), 16):
            print("  %08x  %s" % (s["addr"] + i, " ".join("%02x" % b for b in blob[i:i + 16])))
        print("  decode :")
        for i in range(0, min(len(blob), 60), 4):
            print("   %08x  %08x" % (s["addr"] + i, struct.unpack_from("<I", blob, i)[0]))

    ds = by.get(".dynsym")
    names = []
    if ds:
        st = d[by[".dynstr"]["offset"]:by[".dynstr"]["offset"] + by[".dynstr"]["size"]]
        for i in range(ds["size"] // 16):
            o = ds["offset"] + i * 16
            nmoff = struct.unpack("<I", d[o:o + 4])[0]
            end = st.find(b"\x00", nmoff)
            names.append(st[nmoff:end].decode("latin-1") if nmoff else "")

    rel = by.get(".rel.plt")
    if rel:
        print("\n-- .rel.plt : 5 premieres entrees --")
        for i in range(5):
            o = rel["offset"] + i * 8
            r_off, r_info = struct.unpack("<II", d[o:o + 8])
            idx = r_info >> 8
            print("  r_offset=0x%08x r_info=0x%08x sym=%d %s"
                  % (r_off, r_info, idx, names[idx] if idx < len(names) else "?"))


if __name__ == "__main__":
    main(sys.argv)
