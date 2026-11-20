"""Decompresse tous les .so GCE d'une arborescence et cherche des chaines.

usage : python tools/dec_all.py <racine> <sortie> [motif ...]
"""
import os
import sys
import glob
from concurrent.futures import ProcessPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import gce2elf

ROOT = sys.argv[1]
OUT = sys.argv[2]
PATTERNS = sys.argv[3:] or ["DrmSdc", "normalAppRIRequest", "rightIssueRequest"]


def job(path):
    rel = os.path.relpath(path, ROOT).replace("\\", "/").replace("/", "__")
    out = os.path.join(OUT, rel)
    if os.path.exists(out):
        return (path, out, "cached")
    d = open(path, "rb").read(8)
    if d[:4] == b"\x7fELF":
        open(out, "wb").write(open(path, "rb").read())
        return (path, out, "elf")
    try:
        gce2elf.decompress_file(path, output_dir=OUT, engine_dir=os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "engines"), verbose=False)
    except Exception as e:
        return (path, out, "ERR %s" % e)
    p = os.path.join(OUT, os.path.basename(path) + ".bin")
    if os.path.exists(p) and p != out:
        os.replace(p, out)
    return (path, out, "ok" if os.path.exists(out) else "fail")


def main():
    os.makedirs(OUT, exist_ok=True)
    files = []
    for pat in ("*.so", "*.so.*", "*.exe"):
        files += glob.glob(os.path.join(ROOT, "**", pat), recursive=True)
    files = sorted(set(files))
    print(len(files), "fichiers")
    with ProcessPoolExecutor(max_workers=6) as ex:
        for i, (p, o, st) in enumerate(ex.map(job, files)):
            print("%4d %-60s %s" % (i, os.path.basename(p), st), flush=True)
    print("--- scan ---")
    for f in sorted(glob.glob(os.path.join(OUT, "*"))):
        try:
            d = open(f, "rb").read()
        except Exception:
            continue
        hits = []
        for pat in PATTERNS:
            for enc in (pat.encode(), pat.encode("utf-16-le")):
                if d.find(enc) >= 0:
                    hits.append(pat)
        if hits:
            print(os.path.basename(f), sorted(set(hits)))


if __name__ == "__main__":
    main()
