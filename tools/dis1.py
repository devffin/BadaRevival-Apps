"""Désassemble une fonction d'un ELF bada avec annotations.

usage : python tools/dis1.py <elf> <addr> <taille> [--thumb|--arm] [--all]
Annote : littéraux -> chaîne, bl -> symbole, et code hors .text.
"""
import bisect
import struct
import sys

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
import capstone  # noqa: E402
from kona import Elf  # noqa: E402


def main():
    fn = sys.argv[1]
    start = int(sys.argv[2], 0)
    size = int(sys.argv[3], 0)
    mode = capstone.CS_MODE_THUMB if "--thumb" in sys.argv else capstone.CS_MODE_ARM
    if "--arm" in sys.argv:
        mode = capstone.CS_MODE_ARM
    only_code = "--all" not in sys.argv

    e = Elf(fn)
    secs = [s for s in e.secs if s["size"]]
    syms = {}
    for a, sz, n in e.syms:
        syms[a & ~1] = n
    addrs = sorted(syms)
    plt = {a: n for a, n in e.plt.items()}

    def sym(a):
        a &= ~1
        if a in plt:
            return plt[a]
        k = bisect.bisect_right(addrs, a) - 1
        if k >= 0:
            name = syms[addrs[k]]
            off = a - addrs[k]
            return name if off == 0 else "%s+%#x" % (name, off)
        return None

    def cstr(a):
        for s in secs:
            if s["addr"] <= a < s["addr"] + s["size"]:
                off = s["offset"] + (a - s["addr"])
                b = e.d[off:off + 160]
                i = b.find(b"\x00")
                if i > 1:
                    b = b[:i]
                try:
                    t = b.decode("utf-8")
                except UnicodeDecodeError:
                    return None
                return t if t.isprintable() else None
        return None

    def wstr(a):
        for s in secs:
            if s["addr"] <= a < s["addr"] + s["size"]:
                off = s["offset"] + (a - s["addr"])
                b = e.d[off:off + 160]
                j = 0
                while j + 1 < len(b) and b[j:j + 2] != b"\x00\x00":
                    j += 2
                try:
                    t = b[:j].decode("utf-16-le")
                except UnicodeDecodeError:
                    return None
                return t if t.isprintable() else None
        return None

    md = capstone.Cs(capstone.CS_ARCH_ARM, mode)
    md.skipdata = only_code
    seg = e.bytes_at(start, size) if hasattr(e, "bytes_at") else None
    if seg is None:
        seg = e.d[start:start + size]
    for i in md.disasm(seg, start):
        ann = ""
        if "pc" in i.op_str and i.mnemonic in ("ldr", "add", "adr"):
            try:
                txt = i.op_str
                i1 = txt.index("#")
                imm = int(txt[i1 + 1:].split("]")[0].split(",")[0], 16)
                if i.mnemonic == "ldr":
                    if imm >= 0x800000:
                        imm -= 0x100000000
                    lit = (i.address + imm + 4) & 0xFFFFFFFF
                    off = lit - start + 0
                    # lire dans le fichier via la section
                    w = None
                    for s in secs:
                        if s["addr"] <= lit < s["addr"] + s["size"]:
                            o = s["offset"] + (lit - s["addr"])
                            if o + 4 <= len(e.d):
                                w = struct.unpack_from("<I", e.d, o)[0]
                            break
                    if w is not None:
                        for name, f in (("str", cstr), ("wstr", wstr)):
                            t = f(w)
                            if t:
                                ann = '; %s "%s"' % (name, t)
                                break
                        else:
                            s = sym(w)
                            if s:
                                ann = "; -> " + s
            except (ValueError, IndexError):
                pass
        if i.mnemonic in ("bl", "blx", "b") and i.op_str.startswith("#"):
            try:
                s = sym(int(i.op_str[1:], 16))
                if s:
                    ann = (ann + " " if ann else "; ") + "-> " + s
            except ValueError:
                pass
        print("%08x  %-9s %-40s %s" % (i.address, i.mnemonic, i.op_str, ann))


if __name__ == "__main__":
    main()
