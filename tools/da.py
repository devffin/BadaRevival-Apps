import sys
sys.path.insert(0, r"tools")
from kona import Elf, demangle_and_annotate
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
e = Elf(r"extract\Kona.exe")
md = Cs(CS_ARCH_ARM, CS_MODE_ARM); md.detail = True
def dump(a, n):
    for s in e.secs:
        if s["addr"] <= a < s["addr"] + s["size"]:
            off = s["offset"] + (a - s["addr"])
    print("--- %08x (%d o)" % (a, n))
    end = a + n
    for ins in md.disasm(e.d[off:off + n], a):
        print("  " + demangle_and_annotate(e, ins))
for arg in sys.argv[1:]:
    a, n = arg.split(":")
    dump(int(a, 16), int(n, 16))
