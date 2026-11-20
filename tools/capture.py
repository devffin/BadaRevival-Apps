#!/usr/bin/env python3
"""Bada Revival - capture des requetes envoyees par l'application native.

Role       : ecouter 80 et 443, journaliser la connexion complete
             (ligne de requete, en-tetes, corps) puis repondre.
             - HTTP  : requete + corps enregistres, reponse configurable.
             - HTTPS : version TLS et SNI du ClientHello, puis fermeture
                       (aucun certificat n'est presente, rien n'est contourne).
Dependances: Python 3.7+, stdlib. Ports < 1024 => root.
Variables  : CAPLOG   chemin du journal
             REPONSE  fichier contenant la reponse HTTP a renvoyer
             (defaut : 404 vide)
Lancement  : sudo python3 capture.py
Arret      : Ctrl+C
"""
import os
import socket
import struct
import sys
import threading
import time

LOG = os.environ.get("CAPLOG", "/home/user/badarevival/logs/capture.log")
RESP_FILE = os.environ.get("REPONSE", "")
PORTS = [int(p) for p in os.environ.get("PORTS", "80,443").split(",")]
TLS_VER = {0x01: "TLS1.0", 0x02: "TLS1.1", 0x03: "TLS1.2", 0x04: "TLS1.3"}


def log(line):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as exc:
        sys.stderr.write("log: %s\n" % exc)


def parse_sni(data):
    try:
        i = 43
        i += 1 + data[i]
        i += 2 + struct.unpack("!H", data[i:i + 2])[0]
        i += 1 + data[i]
        ext_total = struct.unpack("!H", data[i:i + 2])[0]
        i += 2
        end = i + ext_total
        while i + 4 <= end:
            etype, elen = struct.unpack("!HH", data[i:i + 4])
            i += 4
            if etype == 0 and elen > 5:
                blk = data[i:i + elen]
                nlen = struct.unpack("!H", blk[3:5])[0]
                return blk[5:5 + nlen].decode("ascii", "replace")
            i += elen
    except Exception:
        pass
    return "-"


def recv_until(conn, buf, marker, limit=65536):
    while marker not in buf and len(buf) < limit:
        try:
            chunk = conn.recv(8192)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
    return buf


def read_exact(conn, buf, need, limit=262144):
    while len(buf) < need and len(buf) < limit:
        try:
            chunk = conn.recv(8192)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
    return buf


def load_response():
    if RESP_FILE and os.path.isfile(RESP_FILE):
        with open(RESP_FILE, "rb") as f:
            return f.read()
    return b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def handle(conn, addr, port):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    conn.settimeout(3.0)
    data = b""
    try:
        chunk = conn.recv(8192)
        if chunk:
            data = chunk
    except (socket.timeout, OSError):
        pass

    if not data:
        log("%s\t%s:%d\tCONNEXION VIDE" % (stamp, addr[0], port))
        conn.close()
        return

    if data[0] == 0x16 and len(data) > 5 and data[1] == 0x03:
        ver = TLS_VER.get(data[2], "0x%02x" % data[2])
        log("%s\t%s:%d\tTLS\tversion=%s\tsni=%s\tbits=%d" % (
            stamp, addr[0], port, ver, parse_sni(data), len(data)))
        conn.close()
        return

    data = recv_until(conn, data, b"\r\n\r\n")
    head, sep, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    log("%s\t%s:%d\tHTTP\t%s" % (stamp, addr[0], port, lines[0] if lines else "-"))

    clen = 0
    for ln in lines[1:]:
        if not ln:
            continue
        log("\t\t\t\t%s" % ln)
        if ln.lower().startswith("content-length:"):
            try:
                clen = int(ln.split(":", 1)[1].strip())
            except ValueError:
                clen = 0

    if clen:
        body = read_exact(conn, body, clen)
        log("\t\t\t\t--- CORPS (%d octets attendus, %d recus) ---" % (clen, len(body)))
        txt = body.decode("utf-8", "replace")
        for ln in txt.splitlines():
            log("\t\t\t\t| %s" % ln)

    try:
        conn.sendall(load_response())
    except OSError:
        pass
    conn.close()


def serve(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(16)
    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            continue
        threading.Thread(target=handle, args=(conn, addr, port), daemon=True).start()


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("erreur: les ports 80/443 exigent root (sudo python3 capture.py)")
    log("# capture demarree %s ports=%s reponse=%s" % (
        time.strftime("%Y-%m-%dT%H:%M:%S"), PORTS, RESP_FILE or "404 vide"))
    for p in PORTS:
        threading.Thread(target=serve, args=(p,), daemon=True).start()
    print("capture active sur les ports %s - Ctrl+C pour arreter" % PORTS)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\ncapture arretee")
