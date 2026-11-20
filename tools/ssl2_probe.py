#!/usr/bin/env python3
"""Verifie si l'OpenSSL du systeme accepte un ClientHello au format SSLv2.

Le Wave Y envoie exactement ce format sur 443 (80 64 01 03 01 ...). Python le
refuse s'il recoit 0x80 ; on teste donc si c'est Python qui bloque ou
l'OpenSSL sous-jacent. Aucun rapport avec le telephone : on rejoue un hello
forge sur une socket locale haute (4443), sans root.
"""
import socket
import ssl
import threading
import time

CERT = "/home/user/badarevival/store/ospserver.crt"
KEY = "/home/user/badarevival/store/ospserver.key"

# Ciphers observes sur le telephone (17 complets) + 8 classiques pour arriver
# aux 25 annonces par le client (75 octets).
CIPHERS = bytes.fromhex(
    "000039 000038 000035 000016 000013 00000a 0700c0 000033 "
    "000032 00002f 030080 000005 000004 010080 000015 000012 "
    "000009 060040 040080 020080 000003 000002 000001 00000b 00000c"
)
assert len(CIPHERS) == 75, len(CIPHERS)
CHALLENGE = bytes(range(16))
HELLO = (b"\x80" + bytes([2 + 1 + 2 + 2 + 2 + 2 + len(CIPHERS) + 16])
         + b"\x01\x03\x01" + len(CIPHERS).to_bytes(2, "big")
         + b"\x00\x00" + b"\x00\x10" + CIPHERS + CHALLENGE)
assert len(HELLO) == 102, len(HELLO)

resultat = {}


def serveur():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.load_cert_chain(CERT, KEY)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 4443))
    srv.listen(1)
    srv.settimeout(10)
    try:
        raw, _ = srv.accept()
        raw.settimeout(10)
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
            resultat["ok"] = "handshake OK : %s %s" % (
                tls.version(), tls.cipher()[0])
            tls.close()
        except Exception as exc:
            resultat["err"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        srv.close()


t = threading.Thread(target=serveur)
t.start()
time.sleep(0.3)

c = socket.create_connection(("127.0.0.1", 4443), timeout=10)
c.sendall(HELLO)
try:
    reponse = c.recv(2048)
except Exception as exc:
    reponse = b""
    resultat["cli"] = str(exc)
c.close()
t.join(12)

print("hello envoye :", len(HELLO), "octets")
print("reponse brute :", reponse[:16].hex(" "))
print("serveur       :", resultat.get("ok") or resultat.get("err") or "aucun")
if resultat.get("cli"):
    print("client        :", resultat["cli"])
