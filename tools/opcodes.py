import sys, struct
sys.path.insert(0, r"tools")
from kona import Elf
e = Elf(r"extract\Kona.exe")
d = e.d
def cstr(a, n=64):
    for s in e.secs:
        if s["addr"] <= a < s["addr"] + s["size"]:
            o = s["offset"] + (a - s["addr"])
            return d[o:o + n].split(b"\0")[0].decode("ascii", "replace")
    return "?"
def byte(a):
    for s in e.secs:
        if s["addr"] <= a < s["addr"] + s["size"]:
            return d[s["offset"] + (a - s["addr"])]
    return -1
IDS = 0x2d7738
NAMES = 0x2d8ab8
ENT = 0x3140c0
print("%3s %4s %-7s %s" % ("#", "fid", "id", "nom"))
for i in range(78):
    fid = byte(ENT + 12 * i)
    if fid < 0: fid += 256
    print("%3d %4d %-7s %s" % (i, fid, cstr(IDS + 64 * i), cstr(NAMES + 64 * i)))
