import sys, struct
sys.path.insert(0, r"tools")
from kona import Elf
e = Elf(r"extract\Kona.exe")
t = e.by[".text"]; blob = e.blob(t); base = t["addr"]
rows = []
for line in open(r"extract\konasym.txt", encoding="utf-8", errors="replace"):
    p = line.split()
    if len(p) >= 4 and p[0] == ".dynsym":
        try:
            a = int(p[1], 16); n = int(p[2])
        except ValueError:
            continue
        if n > 0:
            rows.append((a, n, p[3]))
rows.sort()
import bisect
addrs = [r[0] for r in rows]
def owner(a):
    i = bisect.bisect_right(addrs, a) - 1
    while i >= 0:
        aa, nn, nm = rows[i]
        if aa <= a < aa + nn:
            return nm
        i -= 1
    return "?"
def scan(op, mask, imm, label):
    print("### %s [+0x%x]" % (label, imm))
    seen = {}
    for off in range(0, len(blob) - 3, 4):
        w = struct.unpack_from("<I", blob, off)[0]
        if (w & mask) != op:
            continue
        if (w & 0xFFF) != imm:
            continue
        nm = owner(base + off)
        seen[nm] = seen.get(nm, 0) + 1
    for nm, c in sorted(seen.items()):
        print("   %-70s x%d" % (nm, c))
    print()
scan(0xE5C00000, 0xFFF00000, 0x281, "strb")
scan(0xE5D00000, 0xFFF00000, 0x281, "ldrb")
