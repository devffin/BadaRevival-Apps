import sys, struct
sys.path.insert(0, r"tools")
from kona import Elf
e = Elf(r"extract\Kona.exe")
text = e.by[".text"]; blob = e.blob(text); base = text["addr"]
for imm in (0x3eb, 0x40c, 0x3f9, 0x401):
    print("### movw #0x%x" % imm)
    seen = []
    for off in range(0, len(blob) - 3, 4):
        w = struct.unpack_from("<I", blob, off)[0]
        if (w & 0xFFF0F000) != 0xE3000000:
            continue
        if (w & 0xFFF) != imm or ((w >> 16) & 0xF) != 0:
            continue
        a = base + off
        seen.append((a, e.name_of(a) or "?"))
    for a, n in seen:
        print("   %08x %s" % (a, n))
    print("   total", len(seen))
