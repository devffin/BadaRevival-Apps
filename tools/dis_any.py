"""Desassemble une fonction d'un binaire ELF quelconque.

usage : python tools/dis_any.py <fichier> <symbole|0xadresse> [octets]
"""
import sys

sys.path.insert(0, "tools")
import mdis

path = sys.argv[1]
arg = sys.argv[2]
extra = int(sys.argv[3]) if len(sys.argv) > 3 else 0

mdis._PATH = path
mdis._e = None
mdis.func(arg, extra)
