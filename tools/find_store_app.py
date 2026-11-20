#!/usr/bin/env python3
"""Bada Revival - inventaire des paquets bada de la collection archive.org.

Role       : pour chaque archive de badaappsandgamescollection, lire
             Info/manifest.xml a l'interieur (archive.org sert les fichiers
             internes des zip) et afficher le nom et l'identifiant de l'appli.
Dependances: Python 3.7+, stdlib.
Sortie     : une ligne par paquet : fichier | nom | appid | binaires
"""
import html
import re
import sys
import urllib.parse
import urllib.request

ITEM = "badaappsandgamescollection"
BASE = "https://archive.org/download/%s" % ITEM
UA = {"User-Agent": "BadaRevival/0.1 (inventaire)"}


def get(url, timeout=40):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def listing():
    page = get(BASE + "/").decode("utf-8", "replace")
    names = re.findall(r'href="([^"]+)"', page)
    out = []
    for n in names:
        n = urllib.parse.unquote(n)
        if re.search(r"\.(zip|rar|7z)$", n, re.I):
            out.append(n)
    return sorted(set(out))


def manifest(name):
    url = "%s/%s/Info/manifest.xml" % (BASE, urllib.parse.quote(name))
    try:
        xml = get(url).decode("utf-8", "replace")
    except Exception as exc:
        return None, "illisible (%s)" % exc
    if "<" not in xml or "unzip" in xml[:200]:
        return None, "non extrait par archive.org"
    def tag(t):
        m = re.search(r"<%s[^>]*>(.*?)</%s>" % (t, t), xml, re.S | re.I)
        return html.unescape(m.group(1)).strip() if m else ""
    return (tag("Name"), tag("AppId")), tag("Description")[:60]


def binaries(name):
    url = "%s/%s/" % (BASE, urllib.parse.quote(name))
    try:
        page = get(url).decode("utf-8", "replace")
    except Exception:
        return []
    return [urllib.parse.unquote(b) for b in re.findall(r'href="[^"]*?/(Bin%2F[^"]+)"', page)]


if __name__ == "__main__":
    files = listing()
    print("# %d archives" % len(files), flush=True)
    for f in files:
        info, desc = manifest(f)
        if info:
            print("%s\t%s\t%s\t%s" % (f, info[0], info[1], desc), flush=True)
        else:
            print("%s\t-\t-\t%s" % (f, desc), flush=True)
