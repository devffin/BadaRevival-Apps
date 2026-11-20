"""Terminateur SSLv2 minimal pour le banc bada (port 443).

Pourquoi ce module existe
-------------------------
Le Wave Y (bada 2.0) embarque OpenSSL 0.9.8, qui negocie encore SSLv2. Le
telephone ouvre donc ses connexions HTTPS par un ClientHello au format
SSLv2 (102 octets commencant par ``80 64 01 03 01``). Python 3 et OpenSSL 3
refusent ce format : la poignee de main n'aboutit jamais et Samsung Apps
affiche "Reseau non disponible".

Ce module termine SSLv2 a la main, avec le seul cipher que le telephone
annonce et qui nous suffit : RC4-128-MD5 (octets ``01 00 80``). Il ne gere
que la sequence utile au client (ServerHello, CLIENT-MASTER-KEY,
SERVER-VERIFY, CLIENT-FINISHED, SERVER-FINISHED). Une fois le handshake
termine, la socket se comporte comme une socket ordinaire (makefile,
sendall) : le Handler HTTP de mock.py sert les reponses sans modification.

Reference : OpenSSL 0.9.8zh, ssl/s2_srvr.c, ssl/s2_clnt.c, ssl/s2_lib.c,
ssl/s2_enc.c, ssl/s2_pkt.c, ssl/s23_clnt.c. Les numero de sequence suivent
le code de reference : *chaque* enregistrement consomme un numero, y
compris ceux envoyes en clair (ServerHello, CLIENT-MASTER-KEY).
"""
import hashlib
import io
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509


MT_ERROR = 0
MT_CLIENT_HELLO = 1
MT_CLIENT_MASTER_KEY = 2
MT_CLIENT_FINISHED = 3
MT_SERVER_HELLO = 4
MT_SERVER_VERIFY = 5
MT_SERVER_FINISHED = 6

# Cipher tel qu'il apparait sur le fil (l'identifiant interne OpenSSL est
# 0x02010080 ; ssl_put_cipher_by_char n'ecrit que les 3 octets de poids
# faible).
CIPHER_WIRE = b"\x01\x00\x80"
CIPHER_NAME = "RC4-128-MD5"

MAC_SIZE = 16
KEY_SIZE = 16
CONN_ID_LEN = 16        # SSL2_CONNECTION_ID_LENGTH
SESSION_ID_LEN = 16     # SSL2_SSL_SESSION_ID_LENGTH
SERVER_VERSION = 0x0002  # SSL2_VERSION : exige par ssl23_get_server_hello

SSL2_PE_ERRORS = {
    0x0000: "erreur non definie",
    0x0001: "aucun cipher commun",
    0x0002: "aucun certificat",
    0x0003: "mauvais certificat",
    0x0004: "certificat refuse",
    0x0006: "type de certificat non supporte",
}


class SSL2Error(Exception):
    """Echec de la poignee de main SSLv2 (message deja lisible)."""


class RC4:
    """RC4 minimal ; les volumes echanges ici tiennent en quelques Ko."""

    def __init__(self, key):
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xFF
            s[i], s[j] = s[j], s[i]
        self.s = s
        self.i = 0
        self.j = 0

    def update(self, data):
        s = self.s
        i = self.i
        j = self.j
        out = bytearray(len(data))
        for k, byte in enumerate(data):
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            out[k] = byte ^ s[(s[i] + s[j]) & 0xFF]
        self.i = i
        self.j = j
        return bytes(out)


def _mac(key, seq, data):
    """MAC SSLv2 : MD5(cle || donnees || numero de sequence big-endian)."""
    return hashlib.md5(key + data + seq.to_bytes(4, "big")).digest()


class SSL2Socket:
    """Socket TCP dont les octets sont (de)chiffres en SSLv2.

    Utilisation : ``s = SSL2Socket(sock, cert, key, log)`` puis
    ``s.handshake()`` ; la socket est ensuite utilisable comme une socket
    normale.
    """

    def __init__(self, sock, cert_path, key_path, log=None):
        self.sock = sock
        self.log = log or (lambda *a, **k: None)
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        self.cert_der = cert.public_bytes(serialization.Encoding.DER)
        with open(key_path, "rb") as f:
            self.key = serialization.load_pem_private_key(f.read(), None)
        nums = self.key.private_numbers()
        self._n = nums.public_numbers.n
        self._d = nums.d
        self._k = (self._n.bit_length() + 7) // 8

        self.read_seq = 0
        self.write_seq = 0
        self.rc4_read = None
        self.rc4_write = None
        self._rfile = None
        self._closed = False
        self._peer = "%s:%s" % sock.getpeername()[:2]

    # -- lecture ---------------------------------------------------------
    def _recv_exact(self, n):
        parts = []
        got = 0
        while got < n:
            chunk = self.sock.recv(n - got)
            if not chunk:
                raise SSL2Error("connexion fermee par le client apres "
                                "%d/%d octets" % (got, n))
            parts.append(chunk)
            got += len(chunk)
        return b"".join(parts)

    def _read_record(self):
        """Lit un enregistrement SSLv2, sans le dechiffrer.

        Les messages chiffres en RC4 utilisent l'en-tete court (2 octets,
        bit de poids fort a 1). L'en-tete long (3 octets, octet de bourrage)
        est accepte par prudence.
        """
        hdr = self._recv_exact(2)
        if hdr[0] & 0x80:
            three_byte = False
            length = ((hdr[0] & 0x7F) << 8) | hdr[1]
        else:
            three_byte = True
            length = ((hdr[0] & 0x3F) << 8) | hdr[1]
        body = self._recv_exact(length)
        padding = 0
        if three_byte:
            if not body:
                raise SSL2Error("enregistrement a en-tete long vide")
            padding = body[0]
            body = body[1:]
        return body, padding

    def _read_plain(self):
        body, _pad = self._read_record()
        self.read_seq = (self.read_seq + 1) & 0xFFFFFFFF
        return body

    def _read_encrypted(self):
        body, padding = self._read_record()
        plain = self.rc4_read.update(body)
        mac = plain[:MAC_SIZE]
        data = plain[MAC_SIZE:]
        seq = self.read_seq
        attendu = _mac(self.read_key, seq, data)
        if mac != attendu:
            # Filet de securite : si la numerotation different d'un cran,
            # on le signale et on accepte, pour ne pas bloquer tout le banc
            # sur une subtilite de sequence.
            trouve = None
            for cand in (seq - 1, seq + 1, seq + 2):
                if cand < 0:
                    continue
                if _mac(self.read_key, cand, data) == mac:
                    trouve = cand
                    break
            if trouve is None:
                self.log("# SSLv2 MAC invalide (seq=%d, %d octets) : recu %s "
                         "attendu %s" % (seq, len(data), mac.hex(),
                                         attendu.hex()))
                raise SSL2Error("MAC invalide a la sequence %d" % seq)
            self.log("# SSLv2 MAC valide avec la sequence %d au lieu de %d"
                     % (trouve, seq))
            seq = trouve
        self.read_seq = (seq + 1) & 0xFFFFFFFF
        if padding:
            if padding > len(data):
                raise SSL2Error("bourrage invalide (%d octets)" % padding)
            data = data[:len(data) - padding]
        return data

    # -- ecriture --------------------------------------------------------
    def _send_record(self, body):
        if len(body) >= 0x8000:
            raise SSL2Error("enregistrement trop long (%d octets)" % len(body))
        self.sock.sendall(bytes([0x80 | (len(body) >> 8), len(body) & 0xFF])
                          + body)

    def _write_plain(self, data):
        self._send_record(data)
        self.write_seq = (self.write_seq + 1) & 0xFFFFFFFF

    def _write_encrypted(self, data):
        seq = self.write_seq
        mac = _mac(self.write_key, seq, data)
        self._send_record(self.rc4_write.update(mac + data))
        self.write_seq = (seq + 1) & 0xFFFFFFFF

    # -- dechiffrement RSA ----------------------------------------------
    def _rsa_decrypt(self, blob):
        """Dechiffre le bloc RSA et retire le remplissage PKCS#1 v1.5.

        Le client SSLv23 de bada utilise le remplissage special
        RSA_SSLV23_PADDING (00 02 PS 00 cle, PS finissant par huit 0x03),
        qui a la meme structure que PKCS#1 type 2. On decoupe donc nous-meme
        apres ``pow()`` pour accepter les deux variantes.
        """
        if len(blob) != self._k:
            raise SSL2Error("bloc RSA de %d octets au lieu de %d"
                            % (len(blob), self._k))
        clair = pow(int.from_bytes(blob, "big"), self._d, self._n)
        bloc = clair.to_bytes(self._k, "big")
        if bloc[0] != 0x00 or bloc[1] != 0x02:
            self.log("# RSA: remplissage inattendu %s" % bloc[:8].hex())
            raise SSL2Error("remplissage RSA invalide (pas 00 02)")
        sep = bloc.find(b"\x00", 2)
        if sep < 0:
            raise SSL2Error("remplissage RSA sans separateur")
        return bloc[sep + 1:]

    # -- poignee de main -------------------------------------------------
    def handshake(self):
        hello = self._read_plain()          # sequence 0
        if not hello:
            raise SSL2Error("ClientHello vide")
        if hello[0] == MT_ERROR:
            self._raise_client_error(hello)
        if hello[0] != MT_CLIENT_HELLO:
            raise SSL2Error("message %d au lieu d'un ClientHello" % hello[0])
        if len(hello) < 9:
            raise SSL2Error("ClientHello tronque (%d octets)" % len(hello))

        version = hello[1:3]
        csl = int.from_bytes(hello[3:5], "big")
        sid_len = int.from_bytes(hello[5:7], "big")
        ch_len = int.from_bytes(hello[7:9], "big")
        debut = 9
        ciphers = hello[debut:debut + csl]
        challenge = hello[debut + csl + sid_len:
                          debut + csl + sid_len + ch_len]
        offered = {int.from_bytes(ciphers[i:i + 3], "big")
                   for i in range(0, len(ciphers) - 2, 3)}
        self.log("# SSLv2 ClientHello depuis %s : version=%s, %d ciphers, "
                 "challenge=%d, session=%d"
                 % (self._peer, version.hex(), len(offered), len(challenge),
                    sid_len))
        if int.from_bytes(CIPHER_WIRE, "big") not in offered:
            raise SSL2Error("le client n'annonce pas %s" % CIPHER_NAME)

        conn_id = os.urandom(CONN_ID_LEN)
        session_id = os.urandom(SESSION_ID_LEN)

        # SERVER-HELLO (clair, sequence 0)
        entete = (bytes([MT_SERVER_HELLO, 0, 1])
                  + SERVER_VERSION.to_bytes(2, "big")
                  + len(self.cert_der).to_bytes(2, "big")
                  + len(CIPHER_WIRE).to_bytes(2, "big")
                  + len(conn_id).to_bytes(2, "big"))
        self._write_plain(entete + self.cert_der + CIPHER_WIRE + conn_id)

        cmk = self._read_plain()            # sequence 1
        if cmk and cmk[0] == MT_ERROR:
            self._raise_client_error(cmk)
        if not cmk or cmk[0] != MT_CLIENT_MASTER_KEY:
            raise SSL2Error("message %s au lieu d'un CLIENT-MASTER-KEY"
                            % (cmk[0] if cmk else "vide"))
        if len(cmk) < 10:
            raise SSL2Error("CLIENT-MASTER-KEY tronque")
        cipher = cmk[1:4]
        clear_len = int.from_bytes(cmk[4:6], "big")
        enc_len = int.from_bytes(cmk[6:8], "big")
        karg_len = int.from_bytes(cmk[8:10], "big")
        self.log("# SSLv2 CLIENT-MASTER-KEY : cipher=%s, clair=%d, chiffre=%d, "
                 "keyarg=%d" % (cipher.hex(), clear_len, enc_len, karg_len))
        if cipher != CIPHER_WIRE:
            raise SSL2Error("cipher %s inattendu" % cipher.hex())
        if clear_len != 0:
            raise SSL2Error("cle secrete partiellement en clair (%d octets)"
                            % clear_len)
        debut = 10 + clear_len
        clear = cmk[10:debut]
        blob = cmk[debut:debut + enc_len]
        master = clear + self._rsa_decrypt(blob)
        if len(master) != KEY_SIZE:
            raise SSL2Error("cle maitre de %d octets au lieu de %d"
                            % (len(master), KEY_SIZE))

        material = (hashlib.md5(master + b"0" + challenge + conn_id).digest()
                    + hashlib.md5(master + b"1" + challenge + conn_id).digest())
        self.read_key = material[KEY_SIZE:]
        self.write_key = material[:KEY_SIZE]
        self.rc4_read = RC4(self.read_key)
        self.rc4_write = RC4(self.write_key)

        cf = self._read_encrypted()         # sequence 2
        if not cf or cf[0] != MT_CLIENT_FINISHED:
            raise SSL2Error("message %s au lieu d'un CLIENT-FINISHED"
                            % (cf[0] if cf else "vide"))
        if cf[1:] != conn_id:
            self.log("# SSLv2 CLIENT-FINISHED : connection id different "
                     "(%s au lieu de %s)" % (cf[1:].hex(), conn_id.hex()))
            raise SSL2Error("connection id du CLIENT-FINISHED different")

        # SERVER-VERIFY (sequence 1) puis SERVER-FINISHED (sequence 2)
        self._write_encrypted(bytes([MT_SERVER_VERIFY]) + challenge)
        self._write_encrypted(bytes([MT_SERVER_FINISHED]) + session_id)
        self.log("# SSLv2 handshake termine avec %s (%s)"
                 % (self._peer, CIPHER_NAME))

    def _raise_client_error(self, msg):
        code = int.from_bytes(msg[1:3], "big") if len(msg) >= 3 else 0
        texte = SSL2_PE_ERRORS.get(code, "code inconnu")
        self.log("# SSLv2 ERREUR envoyee par le client : 0x%04x (%s)"
                 % (code, texte))
        raise SSL2Error("le client a renvoye une erreur SSLv2 0x%04x (%s)"
                        % (code, texte))

    # -- interface socket ------------------------------------------------
    def makefile(self, mode="rb", bufsize=-1):
        # StreamRequestHandler demande 'rb' pour rfile et eventuellement 'wb'.
        if "r" in mode:
            if self._rfile is None:
                self._rfile = io.BufferedReader(_Reader(self), 8192)
            return self._rfile
        return io.BufferedWriter(_Writer(self), 8192)

    def sendall(self, data, flags=0):
        data = bytes(data)
        for i in range(0, len(data), 16384):
            self._write_encrypted(data[i:i + 16384])

    def send(self, data, flags=0):
        self.sendall(data, flags)
        return len(data)

    def recv(self, n, flags=0):
        return self._reader().read(n)

    def _reader(self):
        stream = self.makefile("rb")
        return stream

    def settimeout(self, value):
        self.sock.settimeout(value)

    def gettimeout(self):
        return self.sock.gettimeout()

    def setsockopt(self, *args):
        return self.sock.setsockopt(*args)

    def fileno(self):
        return self.sock.fileno()

    def shutdown(self, how):
        return self.sock.shutdown(how)

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.sock.close()
        except OSError:
            pass

    @property
    def closed(self):
        return self._closed


class _Reader(io.RawIOBase):
    def __init__(self, conn):
        super().__init__()
        self.conn = conn
        self._buf = b""

    def readable(self):
        return True

    def readinto(self, b):
        while not self._buf:
            try:
                self._buf = self.conn._read_encrypted()
            except SSL2Error as exc:
                self.conn.log("# SSLv2 lecture : %s" % exc)
                return 0
            except OSError as exc:
                self.conn.log("# SSLv2 lecture interrompue : %s" % exc)
                return 0
        n = min(len(b), len(self._buf))
        b[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        return n


class _Writer(io.RawIOBase):
    def __init__(self, conn):
        super().__init__()
        self.conn = conn

    def writable(self):
        return True

    def write(self, b):
        if b:
            self.conn.sendall(b)
        return len(b)
