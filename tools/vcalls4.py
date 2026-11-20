"""Sites d'appel virtuels avec suivi de registre (invalidation sur ecriture)."""
import sys
sys.path.insert(0, r"tools")
from kona import Elf
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_MEM, ARM_OP_REG

e = Elf(r"extract\Kona.exe")
md = Cs(CS_ARCH_ARM, CS_MODE_ARM); md.detail = True; md.skipdata = True
text = e.by[".text"]; blob = e.blob(text); base = text["addr"]

want = set(int(x, 16) for x in sys.argv[1:]) or None
NOT_DEST = {"cmp", "cmn", "tst", "teq", "str", "strb", "strh", "push", "b", "bl",
            "blx", "bx", "stm", "stmia", "stmdb", "stmea", "svc"}

cur = None
regs = {}
out = []
for ins in md.disasm(blob, base):
    nm = e.name_of(ins.address)
    if nm and not nm.endswith("+0x%x" % 0):
        pass
    # changement de fonction : on vide
    if ins.mnemonic == ".byte":
        continue
    mn = ins.mnemonic
    if mn in ("ldr", "ldrb", "ldrh") and len(ins.operands) == 2:
        dst, src = ins.operands
        if dst.type == ARM_OP_REG:
            regs.pop(dst.reg, None)
            if src.type == ARM_OP_MEM and src.mem.base != 15 and src.mem.disp >= 0x40:
                regs[dst.reg] = (ins.address, src.mem.disp)
        continue
    if mn == "blx" and len(ins.operands) == 1 and ins.operands[0].type == ARM_OP_REG:
        r = ins.operands[0].reg
        if r in regs:
            a, imm = regs[r]
            if want is None or imm in want:
                out.append((a, imm, ins.address))
            regs.pop(r, None)
        continue
    if mn == "bl":
        for k in list(regs):
            if k in (0, 1, 2, 3, 12, 14):
                regs.pop(k, None)
        continue
    # ecriture generique : premier operande registre
    if mn not in NOT_DEST and ins.operands and ins.operands[0].type == ARM_OP_REG:
        regs.pop(ins.operands[0].reg, None)

for a, imm, blx in out:
    print("%08x  V+0x%03x  D+0x%03x  blx %08x   %s" % (a, imm, imm + 8, blx, e.name_of(a) or "?"))
print("# sites: %d" % len(out), file=sys.stderr)
