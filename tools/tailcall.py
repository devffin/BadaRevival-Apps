import struct, sys
sys.path.insert(0, r"tools")
from kona import Elf
e = Elf(r"extract\Kona.exe")
text = e.by[".text"]; blob = e.blob(text); base = text["addr"]
want = [int(x, 16) for x in sys.argv[1:]]
for imm in want:
    print("### ldr pc, [rX, #0x%x]" % imm)
    for off in range(0, len(blob) - 3, 4):
        w = struct.unpack_from("<I", blob, off)[0]
        if (w & 0xFFF0F000) == 0xE590F000 and (w & 0xFFF) == imm:
            a = base + off
            print("   %08x  %s" % (a, e.name_of(a) or "?"))
