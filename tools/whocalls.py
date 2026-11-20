"""Qui appelle un symbole : BL direct ou via son stub PLT."""
import re, sys
sys.path.insert(0, r"tools")
from kona import Elf
e = Elf(r"extract\Kona.exe")
rx = re.compile(sys.argv[1])
targets = {a: n for a, s, n in e.syms if rx.search(n)}
plt_targets = {pa: nm for pa, nm in e.plt.items() if rx.search(nm)}
print("symboles:", [(hex(a), n) for a, n in targets.items()])
print("plt:", [(hex(a), n) for a, n in plt_targets.items()])
allt = dict(targets); allt.update(plt_targets)
text = e.by[".text"]; blob = e.blob(text); base = text["addr"]
import struct
for off in range(0, len(blob) - 3, 4):
    w = struct.unpack_from("<I", blob, off)[0]
    if (w & 0xFF000000) not in (0xEB000000, 0xEA000000):
        continue
    imm = w & 0xFFFFFF
    if imm & 0x800000:
        imm -= 0x1000000
    t = (base + off + 8 + (imm << 2)) & 0xFFFFFFFF
    if t in allt:
        print("  %08x %s -> %s" % (base + off, "call" if (w & 0xFF000000) == 0xEB000000 else "jump", allt[t]))
