#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Qui appelle quoi ? (BL directs + stubs PLT resolus)

    python tools/callers.py <motif> [...]

Pour chaque symbole dont le nom contient un des motifs, affiche les sites
d'appel BL (dans .text comme ailleurs) avec la fonction appelante.
Contrairement a _blxref.py, les appels passant par la PLT sont resolus.
"""
import bisect
import struct
import sys

sys.path.insert(0, "tools")
from kona import Elf  # noqa: E402

e = Elf(r"extract\Kona.exe")

# adresse -> nom, pour les symboles definis ET les stubs PLT
targets = {}
for a, sz, n in e.syms:
    targets[a] = n
for a, n in e.plt.items():
    targets[a] = n + " [plt]"

syms = sorted((a, sz, n) for a, sz, n in e.syms)
starts = [a for a, _, _ in syms]


def symof(a):
    i = bisect.bisect_right(starts, a) - 1
    if i < 0:
        return "?"
    return "%s+0x%x" % (syms[i][2], a - syms[i][0])


def demo(n):
    return n.replace("_ZN", "").replace("_ZThn", "thunk:")[:90]


pats = sys.argv[1:]
if not pats:
    raise SystemExit(__doc__)

wanted = {a: n for a, n in targets.items() if any(p in n for p in pats)}
for a in sorted(wanted):
    print("TARGET 0x%08x %s" % (a, demo(wanted[a])))
print()

for s in e.secs:
    if not (s["flags"] & 0x4):  # SHF_EXECINSTR
        continue
    base = s["addr"]
    raw = e.d[s["offset"]:s["offset"] + s["size"]]
    for off in range(0, len(raw) - 4, 4):
        w = struct.unpack_from("<I", raw, off)[0]
        if (w >> 24) != 0xEB:  # BL
            continue
        imm = w & 0xFFFFFF
        if imm & 0x800000:
            imm -= 0x1000000
        tgt = (base + off + 8 + imm * 4) & 0xFFFFFFFF
        if tgt in wanted:
            print("  %08x -> %-70s in %s" % (base + off, demo(wanted[tgt]), symof(base + off)))
