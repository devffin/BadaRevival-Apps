import sys
sys.path.insert(0, r"tools")
from kona import Elf
e = Elf(r"extract\Kona.exe")
rows = []
for line in open(r"extract\konasym.txt", encoding="utf-8", errors="replace"):
    p = line.split()
    if len(p) >= 4 and p[0] == ".dynsym":
        try:
            a = int(p[1], 16); n = int(p[2])
        except ValueError:
            continue
        rows.append((a, n, p[3]))
rows.sort()
def enclosing(addr):
    best = None
    for a, n, name in rows:
        if a <= addr < a + max(n, 4):
            if best is None or a > best[0]:
                best = (a, n, name)
    return best
for t in (0x142cec, 0x146090, 0x1401c0, 0x167380):
    print("%08x ->" % t, enclosing(t))
print()
print("=== symboles contenant GetDownloadList / ProductList ===")
for a, n, name in rows:
    if "GetDownloadList" in name or "ProductList" in name:
        print("  %08x %5d %s" % (a, n, name))
