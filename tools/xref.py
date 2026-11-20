#!/usr/bin/env python3
"""Bada Revival - references croisees vers un symbole de Kona.exe.

Usage :
    python tools/xref.py <motif>

Affiche :
  * les symboles dont le nom contient <motif> (adresse, taille) ;
  * les appels directs (bl/blx) vers chacun, avec la fonction appelante ;
  * les references indirectes : litteraux de 32 bits egaux a l'adresse du
    symbole, et relocations .rel.dyn/.rel.plt qui le visent (donc les appels
    via PLT / GOT / vtable).

Sert a repondre a "qui declenche cette fonction ?" sans relancer a la main
les petits scripts jetables de tools/_*.py.
"""
import bisect
import struct
import sys

from kona import Elf

PATH = r"C:\Users\Compt\Documents\BadaRevive\extract\Kona.exe"


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    motif = argv[1]
    e = Elf(PATH)

    targets = [(a, s, n) for a, s, n in e.syms if motif.lower() in n.lower()]
    if not targets:
        raise SystemExit("aucun symbole ne contient %r" % motif)

    text = e.by[".text"]
    blob = e.blob(text)
    base = text["addr"]

    # index adresse -> (debut, taille, nom) pour nommer l'appelant
    starts = e.addr
    syms = e.syms

    def owner(addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i >= 0:
            a, s, n = syms[i]
            if a <= addr < a + s:
                return n
        return "?"

    def calls_to(addr):
        out = []
        for off in range(0, len(blob) - 3, 4):
            w = struct.unpack_from("<I", blob, off)[0]
            if (w & 0x0F000000) != 0x0B000000:
                continue
            imm = w & 0xFFFFFF
            if imm & 0x800000:
                imm -= 0x1000000
            at = base + off
            if ((at + 8 + (imm << 2)) & 0xFFFFFFFF) == addr:
                out.append(at)
        return out

    for a, s, n in targets:
        print("=== %s 0x%08x taille %d" % (n, a, s))
        hits = calls_to(a)
        print("  appels directs : %d" % len(hits))
        for h in hits:
            print("    0x%08x  %s" % (h, owner(h)))
        plt = [pa for pa, pn in e.plt.items() if pn == n]
        for pa in plt:
            ph = calls_to(pa)
            print("  via PLT 0x%08x : %d appel(s)" % (pa, len(ph)))
            for h in ph:
                print("    0x%08x  %s" % (h, owner(h)))
        # litteraux 32 bits
        lits = []
        for sec in e.secs:
            if not sec["size"] or sec["type"] == 0:
                continue
            b = e.blob(sec)
            for off in range(0, len(b) - 3, 4):
                if struct.unpack_from("<I", b, off)[0] == a:
                    lits.append((sec["name"], sec["addr"] + off))
        if lits:
            print("  litteraux : %d" % len(lits))
            for sec, va in lits[:20]:
                print("    %s 0x%08x" % (sec, va))
        # relocations
        rels = [off for off, (t, nm) in e.reloc.items() if nm == n]
        if rels:
            print("  relocations : %d" % len(rels))
            for off in rels[:20]:
                sec = "?"
                for sc in e.secs:
                    if sc["addr"] <= off < sc["addr"] + sc["size"]:
                        sec = sc["name"]
                        break
                print("    %s 0x%08x" % (sec, off))
        print()


if __name__ == "__main__":
    main(sys.argv)
