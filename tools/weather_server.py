#!/usr/bin/env python3
"""Banc météo local pour le widget HsWeather du GT-S5380.

Ecoute sur le port 80 et sert les trois endpoints du widget :

  /widget/samsungmobile/weather-data.asp?location=cityId:<id>&langid=<lang>
  /widget/samsungmobile/city-select.asp?country=<pays>
  /widget/samsungmobile/city-find.asp?location=<texte>

Les reponses sont lues a chaque requete depuis store/responses/ : on peut
donc modifier le XML a chaud sans redemarrer le serveur (contrairement au
mock.py du Pi qui tourne sous root).

Chaque requete est journalisee dans logs/weather.log avec les en-tetes :
ca permet de voir exactement ce que le telephone demande.

Lance avec le pythonw autorise par le pare-feu :
  C:\\users\\compt\\appdata\\local\\python\\pythoncore-3.14-64\\pythonw.exe tools\\weather_server.py
"""

import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESP = os.path.join(ROOT, "store", "responses")
LOGDIR = os.path.join(ROOT, "logs")
LOG = os.path.join(LOGDIR, "weather.log")


def log(msg):
    os.makedirs(LOGDIR, exist_ok=True)
    with open(LOG, "a", encoding="utf-8", errors="replace") as f:
        f.write(msg.rstrip("\n") + "\n")


def load(name, fallback):
    path = os.path.join(RESP, name)
    try:
        with open(path, "rb") as f:
            data = f.read()
        log("\t\tXML depuis %s (%d octets)" % (name, len(data)))
        return data
    except Exception as exc:
        log("\t\tXML absent (%s) -> reponse minimale" % exc)
        return fallback.encode("utf-8")


MIN_WEATHER = ('<?xml version="1.0" encoding="UTF-8"?>'
               '<adc_database/>')


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # journal personnalise ci-dessous

    def _record(self, method):
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        ip = self.client_address[0]
        hdrs = " | ".join("%s: %s" % (k, v) for k, v in self.headers.items())
        log("%s\t%s\t%s\t%s\t%s" % (stamp, ip, method, self.path, hdrs))

    def _emit(self, data, ctype="text/xml; charset=UTF-8"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            self.wfile.write(data)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        self._record("GET")
        base = self.path.split("?", 1)[0]
        if base.endswith("/weather-data.asp"):
            self._emit(load("weather.xml", MIN_WEATHER))
        elif base.endswith("/city-select.asp"):
            self._emit(load("city-select.xml",
                            '<?xml version="1.0" encoding="UTF-8"?><adc_database/>'))
        elif base.endswith("/city-find.asp"):
            self._emit(load("city-find.xml",
                            '<?xml version="1.0" encoding="UTF-8"?><adc_database/>'))
        else:
            log("\t\tCHEMIN INCONNU (404)")
            body = b"NOT FOUND"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        self._record("POST")
        if body:
            log("\t\tCORPS %s" % body[:500].decode("utf-8", "replace"))
        self.do_GET()


def main():
    log("=== DEMARRAGE serveur meteo (port 80) ===")
    srv = ThreadingHTTPServer(("0.0.0.0", 80), Handler)
    log("=== EN ECOUTE sur 0.0.0.0:80 ===")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        log("=== ARRET serveur meteo ===")
        srv.server_close()


if __name__ == "__main__":
    main()
