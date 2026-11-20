import sys, struct
sys.path.insert(0, r"tools")
from kona import Elf
e = Elf(r"extract\Kona.exe")

def scan(kind, imm, label):
    print("### %s -> %s" % (kind, label))
    n = 0
    for sec in (".text",):
        t = e.by[sec]; blob = e.blob(t); base = t["addr"]
        for off in range(0, len(blob) - 3, 4):
            w = struct.unpack_from("<I", blob, off)[0]
            if kind == "strb" and (w & 0xFFF00000) != 0xE5C00000:
                continue
            if kind == "str" and (w & 0xFFF00000) != 0xE5800000:
                continue
            if kind == "strh" and (w & 0xFFF00000) != 0xE1C000B0:
                continue
            if kind == "strh":
                if (w & 0xFFF) != imm: continue
            else:
                if (w & 0xFFF) != imm: continue
            a = base + off
            print("   %08x  %s" % (a, e.name_of(a) or "?"))
            n += 1
    print("   total", n)

for off in (0x170, 0x171, 0x12c):
    scan("strb", off, "strb [+0x%x]" % off)
scan("str", 0x170, "str [+0x170]")
