import struct, sys
sys.path.insert(0, r"tools")
from kona import Elf
e = Elf(r"extract\Kona.exe")
text = e.by[".text"]; blob = e.blob(text); base = text["addr"]
want = [int(x, 16) for x in sys.argv[1:]]
for imm in want:
    print("### immediat 0x%x" % imm)
    seen = {}
    for off in range(0, len(blob) - 3, 4):
        w = struct.unpack_from("<I", blob, off)[0]
        # ldr rX, [rY, #imm]  (imm positif, U=1)
        if (w & 0xFFF00000) == 0xE5900000 and (w & 0xFFF) == imm:
            a = base + off
            fn = e.name_of(a) or "?"
            seen.setdefault(fn, 0)
            seen[fn] += 1
    for fn, n in sorted(seen.items(), key=lambda t: -t[1]):
        print("   %4d  %s" % (n, fn))
