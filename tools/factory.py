import sys, struct, re
sys.path.insert(0, r"tools")
from kona import Elf, demangle_and_annotate
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
e = Elf(r"extract\Kona.exe")
md = Cs(CS_ARCH_ARM, CS_MODE_ARM); md.detail = True
def bytes_at(a, n):
    for s in e.secs:
        if s["addr"] <= a < s["addr"] + s["size"]:
            o = s["offset"] + (a - s["addr"])
            return e.d[o:o + n]
    return b""
def decode(a, n):
    return list(md.disasm(bytes_at(a, n), a))
BASE = 0x3e8
TBL = 0xe0948
N = 0x36 + 1
cases = {}
for idx in range(N):
    got = decode(TBL + 4 * idx, 4)
    if not got:
        continue
    op = got[0].op_str
    if op.startswith("#"):
        cases[BASE + idx] = int(op[1:], 16)
# pour chaque cible, chercher le premier bl vers un constructeur
for fid in sorted(cases):
    tgt = cases[fid]
    if tgt >= 0xe0a24:
        txt = []
        for i in decode(tgt, 40):
            ann = demangle_and_annotate(e, i)
            txt.append(ann.strip())
            if "C1Ev$" in ann or "C2Ev" in ann or "D1Ev" in ann:
                break
        ctor = ""
        for t in txt:
            m = re.search(r"-> (_ZN\d+\w+?)(C1Ev|C2Ev)", t)
            if m:
                ctor = m.group(1)
        print("form=0x%03x (idx %2d) -> %08x  %s" % (fid, fid - BASE, tgt, ctor))
print()
print("--- detail 0x3eb, 0x3ec, 0x3ed, 0x40c ---")
for fid in (0x3eb, 0x3ec, 0x3ed, 0x40c):
    print("form=0x%03x cible %08x" % (fid, cases.get(fid, 0)))
    for i in decode(cases[fid], 48):
        print("     " + demangle_and_annotate(e, i))
