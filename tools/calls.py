#!/usr/bin/env python3
"""Bada Revival - graphe d'appels d'un ELF ARM 32 bits, sans objdump.

Le module est une bibliotheque partagee : tous les appels passent par la PLT.
On resout chaque entree de PLT vers son symbole (.rel.plt + .got), puis on
nomme chaque site d'appel par la fonction qui le contient.

Usage :
    python3 calls.py <elf> --pairs [motif]      couple (appelant, appele)
    python3 calls.py <elf> --callers <motif>    qui appelle <motif>
    python3 calls.py <elf> --tree <motif> [n]   arbre descendant
    python3 calls.py <elf> --body <motif>       octets d'une fonction
    python3 calls.py <elf> --plt                table PLT -> symboles
    python3 calls.py <elf> --stat               couverture des BL
"""
import bisect
import re
import struct
import sys

SHT_SYMTAB = 2
SHT_DYNSYM = 11
SHF_EXECINSTR = 0x4


def arm_imm12(imm12):
    """Immediat tourne ARM : 8 bits rotationnes de 2*rot vers la droite."""
    rot = (imm12 >> 8) * 2
    val = imm12 & 0xFF
    if not rot:
        return val
    return ((val >> rot) | (val << (32 - rot))) & 0xFFFFFFFF


def arm_bl(blob, base):
    """Rend [(adresse, cible, est_un_appel)] pour BL (appel) et B (saut)."""
    out = []
    for off in range(0, len(blob) - 3, 4):
        w = struct.unpack_from("<I", blob, off)[0]
        if (w & 0xFF000000) not in (0xEB000000, 0xEA000000):
            continue
        imm = w & 0xFFFFFF
        if imm & 0x800000:
            imm -= 0x1000000
        out.append((base + off,
                    (base + off + 8 + (imm << 2)) & 0xFFFFFFFF,
                    (w & 0xFF000000) == 0xEB000000))
    return out


class Elf:
    def __init__(self, data):
        self.d = data
        if data[:4] != b"\x7fELF" or data[4] != 1:
            raise SystemExit("ELF 32 bits attendu")
        u16 = lambda o: struct.unpack("<H", data[o:o + 2])[0]
        u32 = lambda o: struct.unpack("<I", data[o:o + 4])[0]
        shoff, shentsize = u32(32), u16(46)
        shnum, shstrndx = u16(48), u16(50)
        self.sections = []
        for i in range(shnum):
            o = shoff + i * shentsize
            self.sections.append(dict(
                name_off=u32(o), type=u32(o + 4), flags=u32(o + 8),
                addr=u32(o + 12), offset=u32(o + 16), size=u32(o + 20),
                link=u32(o + 24), entsize=u32(o + 36)))
        tab = self.blob(self.sections[shstrndx])
        for s in self.sections:
            end = tab.find(b"\x00", s["name_off"])
            s["name"] = tab[s["name_off"]:end].decode("latin-1")

        self.dynsym = []
        ds = self.by_name(".dynsym")
        st = self.blob(self.sections[ds["link"]])
        for i in range(ds["size"] // 16):
            o = ds["offset"] + i * 16
            nm = struct.unpack("<I", data[o:o + 4])[0]
            end = st.find(b"\x00", nm) if nm else 0
            self.dynsym.append(st[nm:end].decode("latin-1") if nm else "")

        self.symtab = []
        for s in self.sections:
            if s["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            st = self.blob(self.sections[s["link"]])
            for i in range(s["size"] // 16):
                o = s["offset"] + i * 16
                nm, value, size = struct.unpack("<III", data[o:o + 12])
                if not nm or not size:
                    continue
                end = st.find(b"\x00", nm)
                self.symtab.append((value & ~1, size, st[nm:end].decode("latin-1")))
        self.symtab.sort()
        self.addrs = [a for a, _, _ in self.symtab]
        self.plt = self.build_plt()

    def blob(self, s):
        return self.d[s["offset"]:s["offset"] + s["size"]]

    def by_name(self, name):
        for s in self.sections:
            if s["name"] == name:
                return s
        return dict(addr=0, offset=0, size=0, link=0, entsize=0, name=name)

    def text(self):
        return [s for s in self.sections if s["flags"] & SHF_EXECINSTR and s["size"]]

    def build_plt(self):
        rel = self.by_name(".rel.plt") if self.by_name(".rel.plt")["size"] else self.by_name(".rela.plt")
        step = rel["entsize"] or (12 if rel["name"] == ".rela.plt" else 8)
        reloc = {}
        for i in range(rel["size"] // step):
            o = rel["offset"] + i * step
            r_off, r_info = struct.unpack("<II", self.d[o:o + 8])
            idx = r_info >> 8
            if idx < len(self.dynsym) and self.dynsym[idx]:
                reloc[r_off] = self.dynsym[idx]
        out = {}
        s = self.by_name(".plt")
        if not s["size"]:
            return out
        blob = self.blob(s)
        base = s["addr"]
        for off in range(0, len(blob) - 11, 4):
            i1, i2, i3 = struct.unpack_from("<III", blob, off)
            if (i1 & 0xFFFFF000) != 0xE28FC000:
                continue
            if (i2 & 0xFFFFF000) != 0xE28CC000:
                continue
            if (i3 & 0xFFFFF000) != 0xE5BCF000:
                continue
            got = (base + off + 8 + arm_imm12(i1 & 0xFFF) +
                   arm_imm12(i2 & 0xFFF) + (i3 & 0xFFF)) & 0xFFFFFFFF
            if got in reloc:
                out[base + off] = reloc[got]
        return out

    def name_of(self, addr):
        """Nom pour une adresse : PLT d'abord, puis table des symboles."""
        if addr in self.plt:
            return self.plt[addr]
        i = bisect.bisect_right(self.addrs, addr) - 1
        if i >= 0:
            a, size, name = self.symtab[i]
            if a <= addr < a + size:
                return name
        return None

    def pairs(self):
        """[(appelant, appele)] deduits des BL, doublons retires."""
        seen, out = set(), []
        for s in self.text():
            for src, tgt, _ in arm_bl(self.blob(s), s["addr"]):
                callee = self.name_of(tgt)
                caller = self.name_of(src)
                if not callee or not caller or caller == callee:
                    continue
                if (caller, callee) in seen:
                    continue
                seen.add((caller, callee))
                out.append((caller, callee))
        return out

    def find(self, rx):
        r = re.compile(rx)
        return sorted(set(n for _, _, n in self.symtab if r.search(n)))


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    e = Elf(open(argv[1], "rb").read())
    mode = argv[2]

    if mode == "--plt":
        for a in sorted(e.plt):
            print("0x%08x %s" % (a, e.plt[a]))
        return

    if mode == "--stat":
        total = hit = 0
        for s in e.text():
            for src, tgt, _ in arm_bl(e.blob(s), s["addr"]):
                total += 1
                hit += 1 if e.name_of(tgt) else 0
        print("%d BL, %d resolus, %d inconnus" % (total, hit, total - hit))
        return

    if mode == "--body":
        for a, sz, n in [(a, sz, n) for a, sz, n in e.symtab if re.search(argv[3], n)][:4]:
            print("=== %s 0x%08x taille %d" % (n, a, sz))
            for s in e.text():
                if s["addr"] <= a < s["addr"] + s["size"]:
                    blob = e.blob(s)[a - s["addr"]:a - s["addr"] + min(sz, 320)]
                    for i in range(0, len(blob), 16):
                        print("   %08x  %s" % (a + i, " ".join("%02x" % b for b in blob[i:i + 16])))
        return

    if mode == "--flow":
        rx = re.compile(argv[3])
        for a, sz, n in [(a, sz, n) for a, sz, n in e.symtab if rx.search(n)][:6]:
            print("=== %s 0x%08x taille %d" % (n, a, sz))
            for s in e.text():
                if s["addr"] <= a < s["addr"] + s["size"]:
                    blob = e.blob(s)[a - s["addr"]:a - s["addr"] + sz]
                    for src, tgt, is_call in arm_bl(blob, a):
                        nm = e.name_of(tgt)
                        print("   %08x  %s %s" % (src, "call" if is_call else "jump",
                                                  nm if nm else "0x%08x ?" % tgt))
        return

    pairs = e.pairs()

    if mode == "--pairs":
        rx = re.compile(argv[3]) if len(argv) > 3 else None
        for caller, callee in pairs:
            if rx is None or rx.search(caller) or rx.search(callee):
                print("%s -> %s" % (caller, callee))
        print("-- %d couples" % len(pairs))
        return

    if mode == "--callers":
        for target in e.find(argv[3])[:6]:
            who = sorted(set(c for c, k in pairs if k == target))
            print("=== %s : %d appelants" % (target, len(who)))
            for w in who:
                print("   ", w)
        return

    if mode == "--tree":
        depth = int(argv[4]) if len(argv) > 4 else 3
        roots = e.find(argv[3])[:2]
        if not roots:
            raise SystemExit("aucun symbole ne correspond")
        kids = {}
        for c, k in pairs:
            kids.setdefault(c, []).append(k)
        seen = set()

        def walk(name, d):
            print("  " * d + name)
            if d >= depth:
                return
            for k in kids.get(name, []):
                if k in seen:
                    print("  " * (d + 1) + k + "  (deja vu)")
                    continue
                seen.add(k)
                walk(k, d + 1)

        for r in roots:
            walk(r, 0)
        return

    raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
