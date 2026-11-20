"""Sites d'appel virtuels, y compris les tail-calls (bx rX / mov pc, rX)."""
import sys
sys.path.insert(0, r"tools")
from kona import Elf
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_MEM, ARM_OP_REG

e = Elf(r"extract\Kona.exe")
md = Cs(CS_ARCH_ARM, CS_MODE_ARM); md.detail = True; md.skipdata = True
text = e.by[".text"]; blob = e.blob(text); base = text["addr"]

MIN_IMM = 0x100
MAX_WALK = 12
CF = {"b", "bl", "bx", "blx", "pop"}

pending = {}   # reg -> (addr, imm, deadline_index)
out = []
idx = 0
for ins in md.disasm(blob, base):
    idx += 1
    mn = ins.mnemonic
    # expiration
    for r in [r for r, (a, i, d) in pending.items() if idx > d]:
        del pending[r]
    if mn == "ldr" and len(ins.operands) == 2:
        dst, src = ins.operands
        if dst.type == ARM_OP_REG:
            pending.pop(dst.reg, None)
            if src.type == ARM_OP_MEM and src.mem.base != 15 and src.mem.disp >= MIN_IMM:
                pending[dst.reg] = (ins.address, src.mem.disp, idx + MAX_WALK)
        continue
    if mn in ("blx", "bx") and len(ins.operands) == 1 and ins.operands[0].type == ARM_OP_REG:
        r = ins.operands[0].reg
        if r in pending and not (mn == "bx" and r == 14):
            a, imm, _ = pending.pop(r)
            out.append((a, imm, ins.address, "tail" if mn == "bx" else "call"))
        else:
            pending.pop(r, None)
        continue
    if mn in ("mov", "add", "sub", "and", "orr", "eor") and len(ins.operands) == 2:
        dst, src = ins.operands
        if dst.type == ARM_OP_REG and src.type == ARM_OP_REG and src.reg == 15:
            r = dst.reg
            if r in pending:
                a, imm, _ = pending.pop(r)
                out.append((a, imm, ins.address, "tail-mov"))
        continue
    if mn in CF:
        for k in list(pending):
            del pending[k]

byimm = {}
for a, imm, site, kind in out:
    byimm.setdefault(imm, []).append((a, site, kind))

for imm in sorted(byimm):
    print("### V+0x%03x  D+0x%03x  (%d sites)" % (imm, imm + 8, len(byimm[imm])))
for imm in sorted(byimm):
    for a, site, kind in byimm[imm]:
        print("%08x  V+0x%03x  %-9s dispatche en %08x  %s"
              % (a, imm, kind, site, e.name_of(a) or "?"))
print("# total sites %d" % len(out), file=sys.stderr)
