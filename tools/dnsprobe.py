#!/usr/bin/env python3
"""Bada Revival - sonde DNS (observation et redirection locale).

Role       : journaliser les noms de domaine demandes par le telephone,
             puis relayer la requete au resolveur reel (aucune coupure).
Dependances: Python 3.7+, stdlib uniquement. Doit ecouter sur le port 53 (root).
Lancement  : sudo python3 dnsprobe.py
Redirection: MAP="nom.samsung.com=192.168.1.21" sudo python3 dnsprobe.py
Arret      : sudo pkill -f dnsprobe.py
Retour     : remettre le DNS du telephone en automatique.
"""
import os
import socket
import struct
import sys
import time

# On ecoute sur l'adresse LAN precise : le proxy DNS de connman occupe deja
# 127.0.0.1:53, et un bind sur 0.0.0.0:53 entrerait en conflit avec lui.
LISTEN = (os.environ.get("BIND", "192.168.1.21"), 53)
UPSTREAM = (os.environ.get("UPSTREAM", "192.168.1.254"), 53)
LOG = os.environ.get("DNSLOG", "/home/user/badarevival/logs/dns.log")
OUR_IP = os.environ.get("OUR_IP", "192.168.1.21")

# Carte de redirection : par defaut le fichier dns-map.txt, relu a chaud des
# qu'il change (aucun redemarrage necessaire). La variable MAP reste un repli.
MAPFILE = os.environ.get("MAPFILE", "/home/user/badarevival/tools/dns-map.txt")

MAP = {}
for item in os.environ.get("MAP", "").split(","):
    if "=" in item:
        name, ip = item.split("=", 1)
        MAP[name.strip().lower().rstrip(".")] = ip.strip()

_map_mtime = None


def load_map():
    """Charge dns-map.txt si le fichier a change depuis le dernier passage.

    Format : une entree par ligne, "nom=ip" ou "nom ip" ; "#" pour commenter.
    """
    global MAP, _map_mtime
    try:
        st = os.stat(MAPFILE)
    except OSError:
        return
    if _map_mtime is not None and st.st_mtime == _map_mtime:
        return
    new = {}
    try:
        with open(MAPFILE, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                if "=" in line:
                    name, ip = line.split("=", 1)
                else:
                    parts = line.split()
                    if len(parts) != 2:
                        continue
                    name, ip = parts
                new[name.strip().lower().rstrip(".")] = ip.strip()
    except OSError:
        return
    _map_mtime = st.st_mtime
    MAP = new
    log("# carte rechargee : %d hotes" % len(MAP))


def parse_qname(data):
    """Extrait le premier nom de domaine d'une requete DNS."""
    try:
        i = 12
        labels = []
        while data[i] != 0:
            ln = data[i]
            labels.append(data[i + 1:i + 1 + ln].decode("ascii", "replace"))
            i += ln + 1
        qtype = struct.unpack("!H", data[i + 1:i + 3])[0]
        return ".".join(labels), qtype, i + 5
    except Exception:
        return None, None, None


_LOGDIR_READY = False


def log(line):
    """Ecrit une ligne dans le journal (le dossier n'est cree qu'une fois)."""
    global _LOGDIR_READY
    try:
        if not _LOGDIR_READY:
            os.makedirs(os.path.dirname(LOG), exist_ok=True)
            _LOGDIR_READY = True
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as exc:
        sys.stderr.write("log: %s\n" % exc)


def build_answer(query, qname_end, ip):
    """Construit une reponse A minimale (TTL 60) pour la requete recue."""
    tid = query[0:2]
    flags = b"\x81\x80"                     # reponse, recursion disponible
    qd = b"\x00\x01"
    an = b"\x00\x01"
    header = tid + flags + qd + an + b"\x00\x00" + b"\x00\x00"
    question = query[12:qname_end]
    answer = b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01" + b"\x00\x00\x00\x3c" + b"\x00\x04"
    answer += socket.inet_aton(ip)
    return header + question + answer


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(LISTEN)
    load_map()
    log("# demarrage %s upstream=%s carte=%s map=%s" % (
        time.strftime("%Y-%m-%dT%H:%M:%S"), UPSTREAM[0], MAPFILE, MAP or "aucune"))
    print("sonde DNS active sur %s:%d -> %s" % (LISTEN[0], LISTEN[1], UPSTREAM[0]))

    while True:
        try:
            data, addr = sock.recvfrom(512)
        except OSError:
            continue
        load_map()
        qname, qtype, qend = parse_qname(data)
        if not qname:
            continue
        log("%s\t%s\t%s\ttype=%s" % (time.strftime("%Y-%m-%dT%H:%M:%S"),
                                     addr[0], qname, qtype))

        target = MAP.get(qname.lower())
        if target and qtype == 1:
            sock.sendto(build_answer(data, qend, target), addr)
            log("%s\t%s\tREDIRIGE vers %s" % (time.strftime("%Y-%m-%dT%H:%M:%S"),
                                              qname, target))
            continue

        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up.settimeout(3)
        try:
            up.sendto(data, UPSTREAM)
            reply, _ = up.recvfrom(4096)
            sock.sendto(reply, addr)
        except Exception:
            log("%s\t%s\tPAS DE REPONSE de %s" % (time.strftime("%Y-%m-%dT%H:%M:%S"),
                                                 qname, UPSTREAM[0]))
        finally:
            up.close()


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("erreur: le port 53 exige root (sudo python3 dnsprobe.py)")
    main()
