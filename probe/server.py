#!/usr/bin/env python3
"""Bada Revival - serveur de diagnostic navigateur (LAN uniquement).

Role      : servir une page de test de capacites et journaliser l'agent utilisateur.
Dependances: Python 3.7+ (stdlib uniquement).
Lancement : PORT=8080 python3 server.py
Arret     : Ctrl+C ou kill du PID (aucun service systeme installe).
Securite  : lecture seule, aucune ecriture hors de access.log, aucune execution.
"""
import datetime
import http.server
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(BASE, "www")
LOG = os.path.join(BASE, "access.log")
PORT = int(os.environ.get("PORT", "8080"))


class Handler(http.server.SimpleHTTPRequestHandler):
    server_version = "BadaRevivalProbe/0.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    # --- journalisation (sans secret) ---
    def log_message(self, fmt, *args):
        try:
            with open(LOG, "a", encoding="utf-8") as f:
                f.write("%s\t%s\t%s\t%s\n" % (
                    datetime.datetime.now().isoformat(timespec="seconds"),
                    self.client_address[0],
                    self.path,
                    self.headers.get("User-Agent", "-"),
                ))
        except OSError:
            pass

    def list_directory(self, path):
        self.send_error(404, "Not found")
        return None

    # --- page d'echo des en-tetes ---
    def do_GET(self):
        if self.path.split("?")[0] == "/probe":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            out = ["BADA-REVIVAL PROBE OK", ""]
            out.append("chemin: %s" % self.path)
            out.append("adresse: %s" % self.client_address[0])
            out.append("")
            for k, v in self.headers.items():
                out.append("%s: %s" % (k, v))
            self.wfile.write(("\n".join(out) + "\n").encode("utf-8", "replace"))
            return
        return super().do_GET()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    if not os.path.isdir(ROOT):
        sys.exit("dossier www introuvable: %s" % ROOT)
    print("Bada Revival probe sur http://0.0.0.0:%d/ (racine: %s)" % (PORT, ROOT))
    Server(("0.0.0.0", PORT), Handler).serve_forever()
