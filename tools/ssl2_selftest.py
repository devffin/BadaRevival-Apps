#!/usr/bin/env python3
"""Auto-test du terminateur SSLv2 (store/ssl2.py), sans telephone.

Le script joue les deux roles sur la boucle locale :
  * un serveur SSLv2 qui termine la poignee de main puis repond a une
    requete HTTP a travers le tunnel ;
  * un client qui imite exactement le client SSLv23 d'OpenSSL 0.9.8
    (ClientHello au format SSLv2, remplissage RSA_SSLV23, numeros de
    sequence identiques).

Usage : python3 tools/ssl2_selftest.py [cert] [cle]
"""
import hashlib
import os
import socket
import struct
import sys
import threading
import time

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RACINE, "store"))

from ssl2 import RC4, SSL2Socket, _mac, CIPHER_WIRE  # noqa: E402

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

CERT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    RACINE, "store", "ospserver.crt")
KEY = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
    RACINE, "store", "ospserver.key")
PORT = 8443


# --------------------------------------------------------------------------
def envoyer(sock, body):
    sock.sendall(bytes([0x80 | (len(body) >> 8), len(body) & 0xFF]) + body)


def recevoir(sock):
    hdr = _exact(sock, 2)
    if hdr[0] & 0x80:
        length = ((hdr[0] & 0x7F) << 8) | hdr[1]
    else:
        length = ((hdr[0] & 0x3F) << 8) | hdr[1]
        _exact(sock, 1)
    return _exact(sock, length)


def _exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("connexion fermee (%d/%d)" % (len(buf), n))
        buf += chunk
    return buf


def serveur(resultats):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(1)
    srv.settimeout(20)
    try:
        raw, _ = srv.accept()
        raw.settimeout(20)
        conn = SSL2Socket(raw, CERT, KEY, log=lambda m: print("  [srv] " + m))
        conn.handshake()
        resultats["serveur"] = "handshake OK"
        flux = conn.makefile("rb")
        requete = b""
        while b"\r\n\r\n" not in requete:
            morceau = flux.read(1)
            if not morceau:
                break
            requete += morceau
        resultats["requete"] = requete.split(b"\r\n")[0].decode("latin-1")
        corps = b"<response><currentServerTime>1</currentServerTime></response>"
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n"
                     b"Content-Length: " + str(len(corps)).encode()
                     + b"\r\nConnection: close\r\n\r\n" + corps)
        conn.close()
    except Exception as exc:
        resultats["serveur"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        srv.close()


def client(resultats):
    with open(CERT, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    with open(KEY, "rb") as f:
        cle = serialization.load_pem_private_key(f.read(), None)
    nums = cle.private_numbers()
    n = nums.public_numbers.n
    e = nums.public_numbers.e
    k = (n.bit_length() + 7) // 8

    ciphers = bytes.fromhex(
        "000039 000038 000035 000016 000013 00000a 0700c0 000033 "
        "000032 00002f 030080 000005 000004 010080 000015 000012 "
        "000009 060040 040080 020080 000003 000002 000001 00000b 00000c")
    challenge = os.urandom(16)
    hello = (bytes([1, 3, 1])
             + len(ciphers).to_bytes(2, "big")
             + b"\x00\x00"
             + len(challenge).to_bytes(2, "big")
             + ciphers + challenge)
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=20)
    sock.settimeout(20)
    envoyer(sock, hello)

    # Le client SSLv23 ecrit son hello hors de ssl2_write : la sequence
    # suivante est donc 1.
    write_seq = 1
    read_seq = 0

    # --- SERVER-HELLO ---
    body = recevoir(sock)
    read_seq += 1
    if body[0] != 4:
        raise RuntimeError("message %d au lieu de SERVER-HELLO" % body[0])
    version = body[3:5]
    cert_len = int.from_bytes(body[5:7], "big")
    csl = int.from_bytes(body[7:9], "big")
    cid_len = int.from_bytes(body[9:11], "big")
    pos = 11
    cert_recu = body[pos:pos + cert_len]
    pos += cert_len
    cipher_liste = body[pos:pos + csl]
    pos += csl
    conn_id = body[pos:pos + cid_len]
    if version != b"\x00\x02":
        raise RuntimeError("version serveur %s" % version.hex())
    if CIPHER_WIRE not in [cipher_liste[i:i + 3]
                           for i in range(0, len(cipher_liste), 3)]:
        raise RuntimeError("cipher absent du SERVER-HELLO")
    if cert_recu != cert.public_bytes(serialization.Encoding.DER):
        raise RuntimeError("certificat different")
    print("  [cli] SERVER-HELLO : version=%s conn_id=%s cert=%d octets"
          % (version.hex(), conn_id.hex(), cert_len))

    # --- CLIENT-MASTER-KEY ---
    master = os.urandom(16)
    rembourrage = b"\x03" * 8
    alea = os.urandom(k - 3 - len(rembourrage) - 16).replace(b"\x00", b"\x01")
    bloc = b"\x00\x02" + alea + rembourrage + b"\x00" + master
    assert len(bloc) == k, (len(bloc), k)
    chiffre = pow(int.from_bytes(bloc, "big"), e, n).to_bytes(k, "big")
    cmk = (bytes([2]) + CIPHER_WIRE + b"\x00\x00"
           + len(chiffre).to_bytes(2, "big") + b"\x00\x00" + chiffre)
    envoyer(sock, cmk)
    write_seq += 1

    # --- derivation des cles (client=1 : write=bloc 1, read=bloc 0) ---
    materiau = (hashlib.md5(master + b"0" + challenge + conn_id).digest()
                + hashlib.md5(master + b"1" + challenge + conn_id).digest())
    write_key = materiau[16:]
    read_key = materiau[:16]
    rc4_write = RC4(write_key)
    rc4_read = RC4(read_key)

    # --- CLIENT-FINISHED (chiffre, sequence 2) ---
    corps = bytes([3]) + conn_id
    envoyer(sock, rc4_write.update(_mac(write_key, write_seq, corps) + corps))
    write_seq += 1

    # --- SERVER-VERIFY + SERVER-FINISHED ---
    sv = rc4_read.update(recevoir(sock))[16:]
    read_seq += 1
    sf = rc4_read.update(recevoir(sock))[16:]
    read_seq += 1
    if sv[0] != 5 or sv[1:] != challenge:
        raise RuntimeError("SERVER-VERIFY invalide")
    if sf[0] != 6 or len(sf) != 1 + 16:
        raise RuntimeError("SERVER-FINISHED invalide (%d octets)" % len(sf))
    print("  [cli] SERVER-VERIFY + SERVER-FINISHED OK")

    # --- requete HTTP dans le tunnel ---
    requete = (b"GET /security/sso/initialize/time HTTP/1.1\r\n"
               b"Host: www.ospserver.net\r\nConnection: close\r\n\r\n")
    envoyer(sock, rc4_write.update(_mac(write_key, write_seq, requete)
                                   + requete))
    reponse = b""
    while True:
        try:
            corps = recevoir(sock)
        except RuntimeError:
            break
        clair = rc4_read.update(corps)
        if _mac(read_key, read_seq, clair[16:]) != clair[:16]:
            raise RuntimeError("MAC invalide dans la reponse HTTP")
        read_seq += 1
        reponse += clair[16:]
        if b"</response>" in reponse:
            break
    sock.close()
    resultats["reponse"] = reponse.split(b"\r\n\r\n")[-1].decode("latin-1")


# --------------------------------------------------------------------------
resultats = {}
t = threading.Thread(target=serveur, args=(resultats,), daemon=True)
t.start()
time.sleep(0.3)
try:
    client(resultats)
except Exception as exc:
    resultats["client"] = "%s: %s" % (type(exc).__name__, exc)
t.join(25)

print()
print("serveur :", resultats.get("serveur", "aucun"))
print("requete :", resultats.get("requete", "-"))
print("reponse :", resultats.get("reponse", "-"))
if resultats.get("client"):
    print("client  :", resultats["client"])
ok = (resultats.get("serveur") == "handshake OK"
      and "<currentServerTime>" in resultats.get("reponse", ""))
print("RESULTAT :", "OK" if ok else "ECHEC")
sys.exit(0 if ok else 1)
