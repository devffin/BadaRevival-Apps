#!/usr/bin/env python3
"""Resout les litteraux 'ldr rX,[pc,#imm]' d'une plage d'adresses et affiche
la chaine visee (wide ou ascii). Les litteraux de Kona.exe sont GOT-relatifs :
    valeur = mot a l'adresse du litteral
    cible  = GOT + valeur
Usage: python tools/lits.py <debut> <fin>
"""
import struct
import sys

from kona import Elf

PATH = r"C:\Users\Compt\Documents\BadaRevive\extract\Kona.exe"
GOT = 0x327DE8


def sec_of(e, a):
    for s in e.secs:
        if s["name"] and s["addr"] <= a < s["addr"] + s["size"]:
            return s
    return None


def w32(e, a):
    s = sec_of(e, a)
    if not s:
        return None
    return struct.unpack_from("<I", e.d, s["offset"] + (a - s["addr"]))[0]


def wstr(e, a, n=200):
    s = sec_of(e, a)
    if not s:
        return None
    off = s["offset"] + (a - s["addr"])
    out = []
    for i in range(0, n * 2, 2):
        if off + i + 2 > len(e.d):
            break
        c = struct.unpack_from("<H", e.d, off + i)[0]
        if c == 0:
            break
        out.append(chr(c) if 32 <= c < 0x3000 else "?")
    return "".join(out)


def astr(e, a, n=200):
    s = sec_of(e, a)
    if not s:
        return None
    off = s["offset"] + (a - s["addr"])
    out = []
    for i in range(n):
        if off + i >= len(e.d):
            break
        c = e.d[off + i]
        if c == 0:
            break
        out.append(chr(c) if 32 <= c < 127 else ".")
    return "".join(out)


def main():
    lo = int(sys.argv[1], 16)
    hi = int(sys.argv[2], 16)
    e = Elf(PATH)
    text = [s for s in e.secs if s["name"] == ".text"][0]
    base = text["addr"]
    raw = e.d[text["offset"]:text["offset"] + text["size"]]
    seen = {}
    for a in range(lo, hi, 4):
        w = struct.unpack_from("<I", raw, a - base)[0]
        # ARM: cond 1110, LDR/STR immediate, P=1 U=+ W=0 L=1, Rn=pc(15)
        # encoding: 1110 0101 1001 1111 Rt imm12  -> 0xE59F
        if (w & 0x0F7F0000) == 0x051F0000:
            rt = (w >> 12) & 0xF
            imm = w & 0xFFF
            lit = a + 8 + imm
            off = w32(e, lit)
            if off is None:
                continue
            tgt = (GOT + off) & 0xFFFFFFFF
            if lit in seen:
                continue
            seen[lit] = 1
            print("%08x  ldr r%-2d lit=%08x off=%08x tgt=%08x" % (a, rt, lit, off, tgt))
            print("            W=%s" % ascii(wstr(e, tgt, 120)))
            print("            A=%s" % ascii(astr(e, tgt, 120)))


if __name__ == "__main__":
    main()
