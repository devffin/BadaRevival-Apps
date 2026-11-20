#!/usr/bin/env python3
"""Bada Revival - capture passive des paquets du telephone (root).

But      : savoir, sans aucun doute possible, si le telephone emet encore
           quelque chose apres la 4e reponse de la boutique -- et vers ou.
Methode  : socket AF_PACKET (promiscuite inutile, on ne lit que le trafic qui
           passe par la machine), filtrage IPv4/TCP sur l'adresse du telephone.
Impact   : aucun. Aucun port ouvert, aucun paquet envoye, rien n'est modifie
           sur le telephone.
Journal  : /home/user/badarevival/logs/packets.log
Arret    : sudo pkill -f packets.py
"""
import socket
import struct
import sys
import time

PHONE = "192.168.1.68"
LOG = "/home/user/badarevival/logs/packets.log"

TCP_FLAGS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
             (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]


def flags(tcp_off):
    names = [n for bit, n in TCP_FLAGS if tcp_off & bit]
    return ",".join(names) if names else "-"


def hexdump(data, maxlen=96):
    """Debut de charge utile en hexa + ASCII, pour identifier un protocole."""
    data = data[:maxlen]
    hexa = " ".join("%02x" % b for b in data)
    texte = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return "%d octets | %s | %s" % (len(data), hexa, texte)


def log(line):
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as exc:
        sys.stderr.write("log: %s\n" % exc)


def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    log("# capture demarree %s (telephone %s)" % (time.strftime("%Y-%m-%dT%H:%M:%S"), PHONE))
    while True:
        try:
            pkt = s.recv(65535)
        except OSError as exc:
            log("# erreur lecture: %s" % exc)
            continue
        if len(pkt) < 34:
            continue
        if pkt[12:14] != b"\x08\x00":      # IPv4 seulement
            continue
        ip = pkt[14:]
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6:                      # TCP seulement
            continue
        src = socket.inet_ntoa(ip[12:16])
        dst = socket.inet_ntoa(ip[16:20])
        if PHONE not in (src, dst):
            continue
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        sport, dport = struct.unpack("!HH", tcp[0:4])
        seq, ack = struct.unpack("!II", tcp[4:12])
        off = tcp[12] >> 4
        data_len = max(0, len(tcp) - off * 4)
        ligne = ("%s\t%d\t%s:%d -> %s:%d\t%s\tseq=%u ack=%u data=%d"
                 % (time.strftime("%H:%M:%S"), len(pkt), src, sport, dst,
                    dport, flags(tcp[13]), seq, ack, data_len))
        # On ne dump que les petites charges utiles : les requetes de
        # protocole (SSO, ODC) tiennent en un segment, alors qu'un
        # telechargement .app arrive en segments pleins de 1460 octets.
        if 0 < data_len <= 600:
            ligne += "\t" + hexdump(tcp[off * 4:off * 4 + data_len])
        log(ligne)


if __name__ == "__main__":
    main()
