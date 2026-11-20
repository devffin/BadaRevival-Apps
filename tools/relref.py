import sys, re
sys.path.insert(0, r"tools")
from kona import Elf
e = Elf(r"extract\Kona.exe")
rx = re.compile(sys.argv[1])
hits = [(a, t, n) for a, (t, n) in e.reloc.items() if n and rx.search(n)]
print("relocations:", len(hits))
for a, t, n in sorted(hits):
    # section d accueil
    sec = "?"
    for s in e.secs:
        if s["addr"] <= a < s["addr"] + s["size"]:
            sec = s["name"]; break
    print("  %08x type=%d %-12s %s" % (a, t, sec, n))
