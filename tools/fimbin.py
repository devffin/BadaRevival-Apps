#!/usr/bin/env python3
"""Bada Revival - lecteur du conteneur "FimBIN" des firmwares bada.

Le fichier shpapp20.app commence par "FimBIN" (UTF-16) puis, a partir de
l'offset 96, enchaine des blocs "DCB:" de 2064 octets :

    offset 0    4 octets   "DCB:"
    offset 4    4 octets   type (1 = fichier, 0 = dossier)
    offset 8    4 octets   taille des donnees
    offset 12   4 octets   taille des metadonnees qui suivent les donnees
    offset 16   2048 octets chemin en UTF-16LE, termine par un zero

Les donnees suivent immediatement le bloc, puis les metadonnees.

Usage :
    python3 fimbin.py <image>                 liste les entrees
    python3 fimbin.py <image> --extract <dir> extrait tout sous <dir>
    python3 fimbin.py <image> --get <chemin>  ecrit un fichier sur la sortie
"""
import os
import struct
import sys

DCB = 2064
PATHLEN = 2048


def entries(data):
    """Parcourt le conteneur et rend (chemin, taille, donnees)."""
    o = 0
    # entete "FimBIN" (UTF-16) puis 80 octets
    start = data.find(b"DCB:")
    if start < 0:
        raise SystemExit("conteneur non reconnu : aucun bloc DCB:")
    o = start
    while o + DCB <= len(data):
        if data[o:o + 4] != b"DCB:":
            raise SystemExit("bloc DCB: absent a l'offset %d" % o)
        kind, size, meta = struct.unpack("<III", data[o + 4:o + 16])
        raw = data[o + 16:o + 16 + PATHLEN]
        path = raw.decode("utf-16-le", "replace").split("\x00")[0]
        payload = data[o + DCB:o + DCB + size]
        yield path, size, kind, payload
        o = o + DCB + size + meta


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    with open(argv[1], "rb") as f:
        data = f.read()

    if len(argv) >= 3 and argv[2] == "--extract":
        root = argv[3]
        n = 0
        for path, size, kind, payload in entries(data):
            if kind == 0:
                continue
            dest = os.path.join(root, path.lstrip("/").replace("/", os.sep))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(payload)
            n += 1
        print("%d fichiers extraits sous %s" % (n, root))
        return

    if len(argv) >= 3 and argv[2] == "--get":
        want = argv[3]
        for path, size, kind, payload in entries(data):
            if path == want:
                sys.stdout.buffer.write(payload)
                return
        raise SystemExit("chemin absent : %s" % want)

    for path, size, kind, payload in entries(data):
        print("%s %10d %s" % ("F" if kind else "D", size, path))


if __name__ == "__main__":
    main(sys.argv)
