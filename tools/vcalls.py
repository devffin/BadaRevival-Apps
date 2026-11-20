import sys
sys.path.insert(0, r"tools")
from kona import Elf
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_MEM, ARM_OP_REG
e = Elf(r"extract\Kona.exe")
md = Cs(CS_ARCH_ARM, CS_MODE_ARM); md.detail = True
md.skipdata = True
text = e.by[".text"]; blob = e.blob(text); base = text["addr"]
loads = {}
sites = []
n = 0
for ins in md.disasm(blob, base):
    n += 1
    if ins.mnemonic == "ldr" and len(ins.operands) == 2:
        dst, src = ins.operands
        if dst.type == ARM_OP_REG and src.type == ARM_OP_MEM and src.mem.base != 15 and src.mem.disp >= 0x100:
            loads[dst.reg] = (ins.address, src.mem.disp)
    elif ins.mnemonic == "blx" and len(ins.operands) == 1 and ins.operands[0].type == ARM_OP_REG:
        reg = ins.operands[0].reg
        if reg in loads:
            a, imm = loads[reg]
            if 0 <= ins.address - a <= 8*4:
                sites.append((a, imm, ins.address))
                del loads[reg]
print("instructions", n, file=sys.stderr)
for a, imm, blx in sorted(sites, key=lambda t: t[1]):
    print("%08x  V+0x%03x  D+0x%03x  blx %08x   %s" % (a, imm, imm+8, blx, e.name_of(a) or "?"))
