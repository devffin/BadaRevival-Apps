"""Désassemble une plage et annote les littéraux qui pointent vers des chaînes.

usage : python tools/dumpfn.py <exe> <debut> <fin> <base_got> [sortie]
"""
import sys
import struct

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
import capstone  # noqa: E402
from kona import Elf  # noqa: E402


def main():
    fn = sys.argv[1]
    start = int(sys.argv[2], 0)
    end = int(sys.argv[3], 0)
    base = int(sys.argv[4], 0)
    dst = sys.argv[5] if len(sys.argv) > 5 else None

    e = Elf(fn)
    t = e.by[".text"]
    text = e.d[t["offset"]:t["offset"] + t["size"]]
    taddr = t["addr"]

    def text_at(addr):
        off = addr - taddr
        if 0 <= off < len(text) - 2:
            return text[off:]
        # segment .data/.rodata inclus dans e.d
        if 0 <= addr < len(e.d) - 2:
            return e.d[addr:]
        return None

    def u16str(addr):
        seg = text_at(addr)
        if seg is None:
            return None
        j = 0
        while j + 1 < len(seg) and seg[j:j + 2] != b"\x00\x00" and j < 200:
            j += 2
        try:
            s = seg[:j].decode("utf-16-le")
        except UnicodeDecodeError:
            return None
        return s if s and s.isprintable() else None

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    seg = text[start - taddr:end - taddr]
    out = []
    for i in md.disasm(seg, start):
        ann = ""
        if i.mnemonic == "ldr" and "[pc" in i.op_str:
            try:
                imm = int(i.op_str.split("#")[1].rstrip("]"), 16)
            except (IndexError, ValueError):
                imm = None
            if imm is not None:
                if imm >= 0x800000:
                    imm -= 0x100000000
                lit = (i.address + imm + 8) & 0xFFFFFFFF
                off = lit - taddr
                if 0 <= off <= len(text) - 4:
                    w = struct.unpack_from("<I", text, off)[0]
                    for cand in (w, (w + base) & 0xFFFFFFFF):
                        s = u16str(cand)
                        if s:
                            ann = '; "%s"' % s
                            break
        out.append("%08x  %-8s %-34s %s" % (i.address, i.mnemonic, i.op_str, ann))
    txt = "\n".join(out)
    if dst:
        open(dst, "w", encoding="utf-8").write(txt)
        print("%d lignes -> %s" % (len(out), dst))
    else:
        print(txt)


if __name__ == "__main__":
    main()
