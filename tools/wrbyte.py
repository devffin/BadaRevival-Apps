import sys, struct
sys.path.insert(0, r"tools")
from kona import Elf
e = Elf(r"extract\Kona.exe")
text = e.by[".text"]; blob = e.blob(text); base = text["addr"]
targets = {0x304: "0x304 (functionId liste)", 0x2f9: "0x2f9 (contentType)", 0x2fc: "0x2fc (source)"}
# STRB rX, [rY, #imm] : cond 1110 0101 1100 ...  imm12
for imm, label in targets.items():
    print("### ecritures de %s" % label)
    n = 0
    for off in range(0, len(blob) - 3, 4):
        w = struct.unpack_from("<I", blob, off)[0]
        if (w & 0xFFF00000) != 0xE5C00000:
            continue
        if (w & 0xFFF) != imm:
            continue
        a = base + off
        print("   %08x  %s" % (a, e.name_of(a) or "?"))
        n += 1
    print("   total", n)
