#!/usr/bin/env python3
"""Sert les paquets de store/apps/ au goutte a goutte, sans privilege.

Pourquoi : UpgradeKona() (BDAgent) installe /Home/Share/Upgrade/Kona.oap
SANS controle DRM, mais il abandonne sans rien installer si
AppManager::IsRunning("8d7uw8z551") est vrai, c'est-a-dire si Samsung Apps
tourne encore. Sur le test du 13/11 les deux paquets sont arrives en 2 s :
impossible de fermer l'application a temps, d'ou la boite 0xff10 et l'appli
restee en "pause".

Ce serveur se lance en simple utilisateur (pas de sudo, port 8080) et debit
limite, pour laisser ~1 minute a l'utilisateur pour quitter Samsung Apps.
mock.py (root, port 80) continue de servir la boutique normalement.

Usage : python3 store/slowdl.py [port] [Ko/s]
"""
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
APPDIR = os.path.join(BASE, "apps")
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
RATE = (int(sys.argv[2]) if len(sys.argv) > 2 else 16) * 1024


def log(msg):
    print("%s\t%s" % (time.strftime("%Y-%m-%dT%H:%M:%S"), msg), flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        log("GET %s depuis %s" % (self.path, self.client_address[0]))
        if not self.path.startswith("/dl/"):
            self.send_error(404)
            return
        fname = os.path.basename(self.path.split("?", 1)[0])
        path = os.path.join(APPDIR, fname)
        if not os.path.isfile(path):
            log("FICHIER ABSENT : %s" % fname)
            self.send_error(404)
            return
        with open(path, "rb") as f:
            payload = f.read()
        size = len(payload)
        start, end, partial = 0, size - 1, False
        rng = (self.headers.get("Range") or "").strip()
        if rng.lower().startswith("bytes="):
            part = rng[6:].split(",", 1)[0].strip()
            a, _, b = part.partition("-")
            try:
                if a:
                    start = int(a)
                    end = min(int(b), size - 1) if b else size - 1
                else:
                    start = max(0, size - int(b))
                partial = True
            except ValueError:
                start, end, partial = 0, size - 1, False
        chunk = payload[start:end + 1]
        log("ENVOI %s : %d octets%s a %d Ko/s"
            % (fname, len(chunk),
               " (morceau %d-%d/%d)" % (start, end, size) if partial else "",
               RATE // 1024))
        self.send_response(206 if partial else 200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(chunk)))
        self.send_header("Accept-Ranges", "bytes")
        if partial:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        step = max(2048, RATE // 4)
        t0 = time.time()
        try:
            for i in range(0, len(chunk), step):
                self.wfile.write(chunk[i:i + step])
                self.wfile.flush()
                time.sleep(0.25)
        except (BrokenPipeError, ConnectionResetError):
            log("CLIENT PARTI apres %.1f s" % (time.time() - t0))
            return
        log("FINI %s en %.1f s" % (fname, time.time() - t0))


if __name__ == "__main__":
    log("slowdl demarre port=%d debit=%d Ko/s dossier=%s"
        % (PORT, RATE // 1024, APPDIR))
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
