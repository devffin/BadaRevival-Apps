#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bada Revival - serveur de boutique (prototype, v14).

Role       : repondre au protocole SamsungProtocol utilise par l'application
             Samsung Apps de bada 2.0 (POST /ods.as, XML, HTTP clair).

v14        : endpoints RI (normalAppRIRequest.as / rightIssueRequest.as /
             ri.as) : journalisation complete + enveloppe RI configurable.
Dependances: Python 3.7+, stdlib uniquement.
Lancement  : sudo python3 mock.py    (port 80)
Arret      : Ctrl+C

Format de reponse (etabli par desassemblage de Kona.exe, bada 2.0) :

  <response id="2309" name="getDownloadList" returnCode="0"
            transactionId="3" startNum="1" endNum="3" totalCount="3">
    <list numValue="4">
      <value name="GUID">1000000001</value>
      <value name="version">1.0.0</value>
      ...
    </list>
    <list numValue="4"> ... deuxieme element ... </list>
  </response>

  - CKonaXmlParser ne connait que six elements : SamsungProtocol, request,
    response, errorString, list, value. Tout autre nom est ignore.
  - les attributs de <response> alimentent CKonaRespSpecBase :
    id -> fonction, name, returnCode, startNum, endNum, totalCount,
    transactionId.
  - <list> = UN element de liste. A sa fermeture le decodeur empile la table
    des <value> courants (s'il y en a au moins une) et repart a zero.
  - <value name="X">texte</value> : le seul attribut reconnu est "name", qui
    donne le nom du parametre ; le texte est la valeur.
  - le nom des parametres attendus pour chaque fonction vient de la table
    CKonaXmlAttrPicker::GetXmlParamTable (voir store/params.py, genere depuis
    le binaire). C'est ce nom qui determine, via GetXmlParamType, l'indice
    utilise par CKonaRespSpec*::Visit pour ranger la valeur.

Fichiers de controle (relus a chaque requete, aucun redemarrage necessaire),
tous dans store/ :
  responses/<operation>.xml  remplace l'interieur de <response> ;
  error_on                   operations a forcer en erreur 1004 ;
  skip                       operations auxquelles on repond une enveloppe
                             <response/> vide ;
  hang                       operations sans reponse pendant HANG_TIMEOUT s ;
  close_on                   operations apres lesquelles on ferme la socket.
"""
import os
import socket
import ssl
import struct
import sys
import threading
import time
import traceback
import zlib
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape

BASE = os.path.dirname(os.path.abspath(__file__))
if BASE not in sys.path:
    sys.path.insert(0, BASE)

import params as PROTO  # noqa: E402  (table generee depuis Kona.exe)

# Terminateur SSLv2 (bada 2.0 / OpenSSL 0.9.8). Le module importe
# `cryptography` ; s'il manque, le port 443 reste en TLS moderne et le HTTP
# clair continue de fonctionner.
try:
    import ssl2
except Exception as _exc:  # pragma: no cover - depend de l'installation
    ssl2 = None
    _SSL2_IMPORT_ERROR = _exc
else:
    _SSL2_IMPORT_ERROR = None

LOGDIR = os.path.join(os.path.dirname(BASE), "logs")
LOG = os.path.join(LOGDIR, "store.log")
RESPDIR = os.path.join(BASE, "responses")
PORT = int(os.environ.get("PORT", "80"))
SELF = "http://192.168.1.21"

# Ecoute TLS sur 443, pour www.ospserver.net (le client bada y accede en HTTPS).
# TLS_PORT=0 desactive l'ecoute. Le certificat est auto-signe : s'il est refuse
# par le telephone, l'alerte TLS est journalisee dans logs/store.log et
# logs/mock.out, ce qui evite de deviner.
TLS_PORT = int(os.environ.get("TLS_PORT", "443"))
TLS_CERT = os.environ.get("TLS_CERT", os.path.join(BASE, "ospserver.crt"))
TLS_KEY = os.environ.get("TLS_KEY", os.path.join(BASE, "ospserver.key"))

# Version de disclaimer annoncee a la fois par 2306 (checkAppUpgrade) et par
# 5060 (termInformation).
#
# 2306 est le seul levier cote serveur pour effacer la version memorisee par
# le telephone (registre, config+0x2cc) : KonaViewManager::FillCheckAppUpgradeForm
# compare la version stockee a celle de la reponse avec
# KonaViewUtil::CompareVersionString et, si la reponse est SUPERIEURE, appelle
# SetDisclaimerVersion("", true) -> popup 0x7d3. Au lancement suivant, la
# version etant vide, FillCountrySearchForm empile l'ecran 0x408 et envoie
# 5060. Il faut donc une valeur plus grande que tout ce que le vrai serveur a
# pu stocker, et la MEME valeur dans les deux reponses pour ne pas boucler
# (accepter -> effacer -> reaccepter). DISCLAIMER_VERSION permet de changer la
# valeur sans editer le code (ex. DISCLAIMER_VERSION=2147483647).
DISCLAIMER_VERSION = os.environ.get("DISCLAIMER_VERSION", "9999")

# freeStoreClsf de la reponse 2300 (countrySearchEx).
#
# KonaSplashForm::FillCountrySearchForm fait SetFreeStore(resp[0x74] ^ 1) :
# la valeur est donc INVERSEE avant d'etre stockee dans config+0x375.
#   freeStoreClsf="Y" -> freeStore=0
#   freeStoreClsf="N" -> freeStore=1
# On annonce "Y" (freeStore=0). La valeur est aussi memorisee dans le registre
# (param 0x11) par SetLastCountryFree : si elle a deja ete enregistree a 1, le
# chemin rapide du splash la reprend telle quelle et la 2300 n'est pas renvoyee ;
# dans ce cas vider les donnees de l'application (ou effacer le parametre 0x11)
# avant de relancer.
#
# Choix de l'hote dans CKonaNetHttpParamDoc (0x27e760) :
#   config[0x1c]  (staging)  == 0 -> GetHostAddr     (config+0x348)  <- notre cas
#   config[0x281] (mini mode)      -> GetStgUdcDocAddr (config+0x2b0)
#   config[0x375] (freeStore)      -> GetStgFreeDocAddr (config+0x29c)
#   sinon                          -> GetDocHostAddr   (config+0x48)
# Staging vaut 0 : la 2300 part vers GetHubUrl() (hub-odc) par le biais de
# HostAddr, ce qui ne peut arriver que par la premiere branche. La 5060 utilise
# donc elle aussi HostAddr, que FillCountrySearchForm vient de fixer a
# countryURL : c'est cette valeur, et elle seule, qui decide de l'URL de 5060.
#
# IMPORTANT : countryURL doit contenir le CHEMIN "/ods.as".
# CKonaNetHttpParamDoc ne rajoute aucun chemin : il fait
# SetServerUrl(host) puis CKonaNetHttpConnection::SendHttpRequest passe cette
# chaine telle quelle a HttpSession::Construct et HttpRequest::SetUri. Le chemin
# fait donc partie de la valeur stockee dans HostAddr. Les 2350/2301/2309
# envoyees au lancement (avec le HostAddr par defaut) arrivent bien sur
# "/ods.as" : c'est la preuve que le format attendu est "http://hote/ods.as".
# Sans le chemin, la 5060 est refusee localement, avant tout socket et toute
# resolution DNS (rien dans packets.log), d'ou "Reseau non disponible".
FREE_STORE_CLSF = os.environ.get("FREE_STORE_CLSF", "Y")

# Diagnostic : FORCE_ERROR="getDownloadList,autre" force returnCode=1.
FORCE_ERROR = [n.strip() for n in os.environ.get("FORCE_ERROR", "").split(",") if n.strip()]

# Diagnostic : un fichier "hang" contenant un nom d'operation fait attendre le
# serveur HANG_TIMEOUT secondes sans rien envoyer.
HANG_TIMEOUT = int(os.environ.get("HANG_TIMEOUT", "180"))

ENVELOPE = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<SamsungProtocol version="0.9" lang="EN" networkType="0" '
            'deviceModel="GT-S5380" supportWebp="false" systemId="0">%s</SamsungProtocol>')


_LOGDIR_READY = False
_FILE_CACHE = {}  # chemin -> (mtime, texte ou None), pour les fichiers de controle


def log(line):
    """Ecrit une ligne dans store.log (le dossier n'est cree qu'une fois)."""
    global _LOGDIR_READY
    try:
        if not _LOGDIR_READY:
            os.makedirs(LOGDIR, exist_ok=True)
            _LOGDIR_READY = True
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as exc:
        sys.stderr.write("log: %s\n" % exc)


def read_text(path):
    """Lit un fichier de controle, reopenant uniquement s'il a change.

    Les fichiers de diagnostic (skip, error_on, hang, close_on, responses/*.xml)
    restent modifiables a chaud : on compare leur mtime a chaque appel, comme
    dnsprobe.py le fait pour dns-map.txt, mais on evite de rouvrir le disque a
    chaque requete quand rien n'a change.
    """
    try:
        st = os.stat(path)
    except OSError:
        _FILE_CACHE.pop(path, None)
        return None
    cached = _FILE_CACHE.get(path)
    if cached is not None and cached[0] == st.st_mtime:
        return cached[1]
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read().strip()
    except OSError:
        text = None
    _FILE_CACHE[path] = (st.st_mtime, text)
    return text


def _hexdump(data, maxlen=96):
    """Resume lisible d'un debut de flux, pour identifier un protocole inconnu.

    Le telephone envoie sur 443 un bloc dont le premier octet n'est pas 0x16 :
    sans les octets eux-memes impossible de trancher entre SSLv2, HTTP precede
    d'un octet parasite, ou autre chose. On affiche hexa + ASCII imprimable sur
    une seule ligne pour garder store.log compact.
    """
    data = data[:maxlen]
    hexa = " ".join("%02x" % b for b in data)
    texte = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return "%d octets | %s | %s" % (len(data), hexa, texte)


# --------------------------------------------------------------------------
# images : PNG 48x48
# --------------------------------------------------------------------------
def make_png(w=48, h=48, rgb=(200, 120, 40)):
    raw = b"".join(b"\x00" + bytes(list(rgb) * w) for _ in range(h))

    def chunk(tag, data):
        return (struct.pack("!I", len(data)) + tag + data +
                struct.pack("!I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    ihdr = struct.pack("!IIBBBBB", w, h, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) +
            chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


PNG = make_png()


# --------------------------------------------------------------------------
# pages ouvertes par les 3 boutons de l'ecran "Conditions generales"
#
# Le TEXTE de l'ecran vient de la reponse 5060 (champ "value"), pas du web :
# KonaDisclaimerForm::FillForm le pose dans un TextBox natif.
# En revanche, les 3 boutons de detail appellent OpenUrlInBrowser avec :
#   http://www.samsungapps.com/common/term.as?mcc=<MCC>
#   http://www.samsungapps.com/common/privacy.as?mcc=<MCC>
#   http://static.bada.com/contents/deviceterms/<MCC>.txt
# Ces deux hotes doivent donc etre rediriges vers ce serveur (voir
# tools/dns-map.txt), sinon c'est le NAVIGATEUR qui affiche une page vide.
# Texte volontairement en ASCII : l'encodage attendu par le navigateur
# n'est pas connu, et un accent mal decode suffirait a masquer le reste.
# --------------------------------------------------------------------------
TERMS_TXT = """BADAREVIVAL - CONDITIONS GENERALES (texte local)

Le service Samsung Apps d'origine n'est plus operationnel.
Ce texte est fourni par le serveur local BadaRevival (192.168.1.21)
uniquement pour permettre au client de bada 2.0 d'afficher cet ecran.

1. Ce serveur est un banc de test prive, sans aucun lien avec Samsung.
2. Aucun compte, aucun paiement et aucune donnee personnelle ne sont traites.
3. Les applications proposees proviennent d'archives publiques et ne sont
   pas modifiees.
4. Vous pouvez refuser : l'application se fermera sans rien modifier sur le
   telephone.

Appuyez sur Accepter pour continuer.
"""

TERMS_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Conditions generales</title></head>
<body>
<h3>BADAREVIVAL - Conditions generales</h3>
<p>Le service Samsung Apps d'origine n'est plus operationnel. Cette page est
servie par le serveur local BadaRevival (192.168.1.21), uniquement pour
permettre au client bada 2.0 d'afficher cet ecran.</p>
<ul>
<li>Banc de test prive, sans lien avec Samsung.</li>
<li>Aucun compte, aucun paiement, aucune donnee personnelle.</li>
<li>Applications issues d'archives publiques, non modifiees.</li>
</ul>
<p>Vous pouvez refuser : l'application se fermera sans rien modifier sur le
telephone.</p>
</body></html>
"""


# --------------------------------------------------------------------------
# requete
# --------------------------------------------------------------------------
def parse(body):
    """Retourne (id, nom, transactionId, {param: valeur}) ou None."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None
    req = root.find("request")
    if req is None:
        return None
    params = {}
    for p in req.findall("param"):
        params[p.get("name", "")] = (p.text or "")
    return req.get("id", ""), req.get("name", ""), req.get("transactionId", ""), params


# --------------------------------------------------------------------------
# fabrique de reponse (format reel du client)
# --------------------------------------------------------------------------
def response_open(rid, name, tid, total=0, start=1, end=0):
    return ('<response id="%s" name="%s" returnCode="0" startNum="%d" endNum="%d" '
            'totalCount="%d" transactionId="%s">'
            % (escape(rid), escape(name), start, end, total, escape(tid)))


def item(fields):
    """Un element de liste : <list numValue="n"> puis un <value> par champ.

    Aucun blanc entre les balises : le texte situe entre <list> et le premier
    <value> serait ajoute a la valeur du premier parametre.
    """
    body = "".join('<value name="%s">%s</value>' % (escape(k), escape(str(v)))
                   for k, v in fields)
    return '<list numValue="%d">%s</list>' % (len(fields), body)


def list_response(rid, name, tid, items):
    """Reponse complete : compteurs en attributs + un <list> par element."""
    body = "".join(item(f) for f in items)
    if items:
        out = response_open(rid, name, tid, total=len(items),
                            start=1, end=len(items)) + body + "</response>"
    else:
        out = response_open(rid, name, tid, total=0, start=0, end=0) + "</response>"
    return out


# Valeurs fixes par nom de parametre (noms exacts de la table du client).
VALUES = {
    # 2300 countrySearchEx
    # Le chemin /ods.as est obligatoire : il n'est jamais rajoute par le client
    # (voir le commentaire detaille au-dessus de FREE_STORE_CLSF).
    "countryURL": "http://fr-bou.samsungapps.com/ods.as",
    "countryCode": "208",
    "freeStoreClsf": FREE_STORE_CLSF,
    "description": "BadaRevival",
    "currencyUnitPrecedes": "N",
    "currencyUnitHasPenny": "Y",
    "snsVal": "N",
    "currencyUnitDivision": "1",
    # 2301 getUpgradeNKillCount
    "UpgradeCount": "0",
    "KillCount": "0",
    "Timer": "0",
    # 2306 checkAppUpgrade
    "upgrade": "N",
    "contentSizeLimitation": "0",
    "clientType": "0",
    "odcUrl": "%s/ods.as" % SELF,
    "bdUrl": "%s/bd" % SELF,
    "licenseUrl": "",
    "disclaimerVer": DISCLAIMER_VERSION,
    "notificationType": "0",
    # Vide : FillCheckAppUpgradeForm ne lance CKonaConfigReplacement que si cet
    # identifiant est non vide (0xe4564). Une valeur differente de celle
    # memorisee declencherait 5094 getConfiguration et un remplacement de
    # configuration, sans rapport avec la renaissance de la boutique.
    "odcConfigurationId": "",
    "secureTime": "0",
    "flexibleTabClsf": "N",
    "addMobClsf": "N",
    "minPrice": "0",
    # 2303 downloadEx / 3040 download
    "downLoadURI": "%s/dl/zzz.app" % SELF,
    "successYn": "Y",
    "paymentID": "0",
    "paymentStatusCD": "0",
    "paymentRequestCompleteDate": "20260101",
    # elements produit
    "currencyUnit": "EUR",
    "categoryID": "100",
    "categoryName": "Applications",
    "categoryPath": "Applications",
    "shopID": "1",
    "sellerID": "bada",
    "sellerName": "BadaRevival",
    "sellerMedal": "0",
    "sellerReputation": "0",
    "sellerUrl": "",
    "productStatus": "1",
    "updateClsf": "0",
    "purchasedMethod": "0",
    "contentLanguage": "EN",
    "date": "20260101",
    "createDate": "20260101",
    "lastUpdateDate": "20260101",
    "purchaseDate": "20260101",
    "validDate": "20260101",
    "downloadPeriod": "0",
    "averageRating": "4.5",
    "productCommentCnt": "0",
    "screenShotCount": "1",
    "restrictedAge": "0",
    "settlementRate": "0",
    "platformVersion": "2.0",
    "compatibleOS": "2.0",
    "price": "0",
    "normalPrice": "0",
    "sellingPrice": "0",
    "reducePrice": "0",
    "discountPrice": "0",
    "paymentAmount": "0",
    "purchasedPrice": "0",
    "discountPhoneBillPrice": "0",
    "phonebillPrice": "0",
    "cyberCash": "0",
    "contentsSize": "1048576",
    "realContentsSize": "1048576",
    "installSize": "1048576",
    "version": "1.0.0",
    "contentType": "application",
    "loadType": "0",
    "settlementType": "0",
    "orderItemSeq": "0",
    "ordItemSeq": "0",
    "wishListID": "0",
    "recommendReasonType": "0",
    "bundle": "N",
    "bundleYN": "N",
    "trialYN": "N",
    "alreadyPurchased": "N",
    "discountFlag": "N",
    "nameAuthYN": "N",
    "tnbYn": "N",
    "rentalYn": "N",
    "optBillYn": "N",
    "pSmsPurchaseYN": "N",
    "testPSMSPurchaseYn": "N",
    "creditcardYN": "N",
    "phonebillYN": "N",
    "discountPhoneBillYn": "N",
    "couponName": "",
    "discountInfo": "",
    "prepaidCardList": "",
    "optBillList": "",
    "rentalTermArray": "",
    "rentalPriceArray": "",
    "rentalPhonebillPriceArray": "",
}

# --------------------------------------------------------------------------
# catalogue : une seule application reelle (Exploration, bada 2.0)
#
# Le paquet signe est servi tel quel depuis store/apps/. Toutes les reponses
# de liste et la fiche produit decrivent le MEME produit (meme productID et
# GUID, meme version, prix 0) : c'est ce qui permet au client d'ouvrir la
# fiche 2080 puis de lancer le telechargement sans passer par un achat.
# Le zip d'origine de l'application se trouve dans tmp/apps/559t46hurs.zip.
# --------------------------------------------------------------------------
APP_ID = "559t46hurs"
APP_FILE = APP_ID + ".app"
APP_DIR = os.path.join(BASE, "apps")
APP_PATH = os.path.join(APP_DIR, APP_FILE)
APP_SIZE = "543802"

PRODUCT = {
    "productID": "1000000001",
    "GUID": "1000000001",
    "productName": "Exploration",
    "productImgUrl": "%s/i/exploration.png" % SELF,
    "screenShotImgURL": "%s/i/exploration_1.png" % SELF,
    "categoryID": "100",
    "categoryName": "Applications",
    "categoryPath": "Applications",
    "productDescription": "Exploration - jeu de plateforme pour bada 2.0.",
    "currencyUnit": "EUR",
    "price": "0",
    "sellingPrice": "0",
    "normalPrice": "0",
    "reducePrice": "0",
    "discountPrice": "0",
    "paymentAmount": "0",
    "purchasedPrice": "0",
    "discountFlag": "N",
    "averageRating": "4.5",
    "version": "1.3.1",
    "contentsSize": APP_SIZE,
    "realContentsSize": APP_SIZE,
    "installSize": APP_SIZE,
    "contentType": "application",
    "contentURL": "%s/dl/%s" % (SELF, APP_FILE),
    "platformVersion": "2.0",
    "compatibleOS": "2.0",
    "screenShotCount": "1",
    "contentLanguage": "EN",
    "restrictedAge": "0",
    "productStatus": "1",
    "updateClsf": "0",
    "loadType": "0",
    "alreadyPurchased": "N",
    "purchasedMethod": "0",
    "sellerID": "badarevival",
    "sellerName": "BadaRevival",
    "shopID": "1",
    "createDate": "20261101",
    "lastUpdateDate": "20261101",
    "date": "20261101",
    "purchaseDate": "20261101",
    "validDate": "20261101",
    "discountPhoneBillPrice": "0",
    "phonebillPrice": "0",
    "cyberCash": "0",
    "orderID": "",
    "orderItemSeq": "0",
    "ordItemSeq": "0",
    "wishListID": "0",
    "bundle": "N",
    "bundleYN": "N",
    "trialYN": "N",
    "nameAuthYN": "N",
    "tnbYn": "N",
    "rentalYn": "N",
    "optBillYn": "N",
    "pSmsPurchaseYN": "N",
    "testPSMSPurchaseYn": "N",
    "creditcardYN": "N",
    "phonebillYN": "N",
    "discountPhoneBillYn": "N",
    "couponName": "",
    "discountInfo": "",
    "settlementType": "0",
    "settlementRate": "0",
    "prepaidCardList": "",
    "optBillList": "",
    "rentalTermArray": "",
    "rentalPriceArray": "",
    "rentalPhonebillPriceArray": "",
    "recommendReasonType": "0",
    "youtubeRtspUrl": "",
    "youtubeScreenShoutUrl": "",
    "contentGradeImgUrl": "",
    "sellerMedal": "0",
    "sellerReputation": "0",
    "sellerUrl": "",
    "downloadPeriod": "0",
    "productCommentCnt": "0",
    "bannerTitle": "Exploration",
    "bannerImgURL": "%s/i/exploration.png" % SELF,
    "bannerType": "0",
    "updatedCount": "0",
    "bannerPos": "1",
    "bannerProductID": "1000000001",
}

# Compte local : n'importe quel identifiant est accepte, le mot de passe
# n'est jamais verifie. Les reponses renvoient l'identifiant recu pour que
# l'interface affiche le compte que l'utilisateur vient de saisir.
DEFAULT_USER = "bada@badarevival.local"


def product_fields(fid):
    """Champs du catalogue dans l'ordre exact de la table du client."""
    out = []
    for n in PROTO.PARAMS.get(fid, []):
        if n in PRODUCT:
            v = PRODUCT[n]
        else:
            low = n.lower()
            if low.endswith("url") or low.endswith("imgurl"):
                v = PRODUCT["productImgUrl"]
            elif low.endswith(("size", "cnt", "count")):
                v = "0"
            elif low.endswith(("id", "type", "seq", "pos", "level", "rating",
                               "flag", "clsf", "yn")):
                v = "0"
            else:
                v = ""
        out.append((n, v))
    return out


def account_fields(fid, overrides):
    """Champs d'une reponse de compte, dans l'ordre de PARAMS."""
    return [(n, overrides.get(n, "")) for n in PROTO.PARAMS.get(fid, [])]


def fields_for(fid, index=1, prefix="ZZZ"):
    """Valeurs plausibles pour les parametres attendus d'une fonction.

    Les noms viennent de store/params.py (table du client). Les valeurs sont
    des marqueurs impossibles a confondre avec du contenu local : si l'ecran
    affiche "ZZZ-1", c'est bien notre serveur qui l'a fourni.
    """
    names = PROTO.PARAMS.get(fid, [])
    pid = "%010d" % (1000000000 + index)
    pname = "%s-%d" % (prefix, index)
    img = "%s/i/%s-%d.png" % (SELF, prefix.lower(), index)
    out = []
    for n in names:
        low = n.lower()
        if n == "productID" or n == "GUID":
            v = pid
        elif n == "productName":
            v = pname
        elif n == "bannerProductID":
            v = pid
        elif n in ("productImgUrl", "screenShotImgURL", "contentGradeImgUrl",
                   "systemCheckImgUrl", "promotionImgUrl", "bannerImgURL",
                   "categoryImgUrl", "youtubeScreenShoutUrl"):
            v = img
        elif n == "productDescription":
            v = "Element de test %s" % pname
        elif n == "keyword":
            v = "zzz"
        elif n == "bannerTitle":
            v = pname
        elif n in VALUES:
            v = VALUES[n]
        elif low.endswith("url"):
            v = img
        elif low.endswith(("size", "cnt", "count")):
            v = "0"
        elif low.endswith(("id", "type", "seq", "pos", "level", "rating")):
            v = "0"
        else:
            v = ""
        out.append((n, v))
    return out


# --------------------------------------------------------------------------
# reponses particulieres
# --------------------------------------------------------------------------
def r_country(rid, name, tid, params):
    return list_response(rid, name, tid, [fields_for(rid)])


def r_upgrade_nkill(rid, name, tid, params):
    return list_response(rid, name, tid, [fields_for(rid)])


def r_push_message(rid, name, tid, params):
    items = [[("notificationMsg", ""), ("notificationParam", "")]]
    return list_response(rid, name, tid, items)


def r_download_list(rid, name, tid, params):
    """2309 getDownloadList : applications deja installees via la boutique.

    C'est un controle de mise a jour, pas le catalogue. Une liste vide est la
    bonne reponse : sinon le client croit que des applications sont installees
    et propose des mises a jour fantomes.
    """
    return list_response(rid, name, tid, [])


# --------------------------------------------------------------------------
# Auto-mise a jour Samsung Apps (2306 upgrade != 0)
#
# Pourquoi ce detour : une installation normale passe par ProcessDrmProtect
# puis GetDRMContentsInfo, qui exige une licence signee Samsung (l'octet
# BDAgentC6 vaut 1 sur l'appareil et n'est pas modifiable par le reseau).
# UpgradeKona(), lui, installe /Home/Share/Upgrade/Kona.oap via
# PackageManager SANS aucun controle DRM.
#
# Deroulement verifie dans BDAgent.exe :
#   BDAgentSelfUpdateMgr::RequestComplete (0x68300)
#     1. premier paquet (appId 36cbr89p8t = BDAgent.oap) termine
#        -> envoie tout seul la requete du second paquet (8d7uw8z551)
#     2. second paquet termine -> deplace /Home/App/{BDAgent,Kona}.oap vers
#        /Home/Share/Upgrade/, SetUpgradeMode(true), termine BDAgent
#     3. au redemarrage : UpgradeKona (0x66800) -> InstallApplication(ct=0)
#        sur /Home/Share/Upgrade/Kona.oap
#
# UpgradeKona abandonne SANS RIEN INSTALLER si IsRunning("8d7uw8z551") est
# vrai (0x66898). C'est l'explication la plus probable de l'echec du 13/11
# (Samsung Apps etait ouvert pendant tout le telechargement) : le telephone
# a affiche la boite 0xff10 et l'appli est restee en "pause".
# D'ou le ralentissement volontaire de /dl/ ci-dessous : il laisse le temps
# de revenir a l'ecran d'accueil pour que Samsung Apps ne tourne plus.
#
# Remarque : InstallApplication ne prend PAS d'appId, il lit le manifeste du
# paquet. Servir Exploration comme "Kona.oap" installe donc Exploration sous
# son propre appId (559t46hurs), pas sous celui de Samsung Apps.
#
# La taille annoncee doit etre exacte : elle est verifiee par le telephone.
# --------------------------------------------------------------------------
UPGRADE_ENABLED = False

# Debit maximal de /dl/ en Ko/s (0 = pas de limite). La voie UpgradeKona est
# abandonnee (elle bloque le telephone jusqu'au reboot) : plus de goutte a
# goutte, le telechargement normal n'est plus utilise.
DL_RATE_KBPS = 0


def r_check_upgrade(rid, name, tid, params):
    # Si cette version est superieure a celle memorisee sur le telephone, le
    # client efface la version stockee (voir DISCLAIMER_VERSION).
    fields = dict(fields_for(rid))
    fields["clientType"] = "0"
    fields["disclaimerVer"] = DISCLAIMER_VERSION
    if UPGRADE_ENABLED:
        # upgrade=1 : Kona ouvre la popup 0x7d3 (action 0x1b65) et envoie la
        # demande d'auto-mise a jour a BDAgent avec ces deux URL.
        fields["upgrade"] = "1"
        fields["odcUrl"] = PRODUCT["contentURL"]
        fields["odcSize"] = APP_SIZE
        fields["bdUrl"] = PRODUCT["contentURL"]
        fields["bdSize"] = APP_SIZE
        log("\t\t2306 upgrade=1 odcUrl=%s (%s o) bdUrl=idem"
            % (PRODUCT["contentURL"], APP_SIZE))
    else:
        fields["upgrade"] = "N"
    log("\t\t2306 disclaimerVer=%s (si > version stockee : effacement + popup 0x7d3)"
        % DISCLAIMER_VERSION)
    return list_response(rid, name, tid, [list(fields.items())])


def r_term_info(rid, name, tid, params):
    """5060 termInformation : texte de l'ecran Conditions generales.

    Le client remplit l'ecran uniquement si la reponse porte la fonction 0x46.
    Le texte vient du champ "value", la version acceptee de "disclaimerVer"
    (elle est memorisee par le telephone quand on appuie sur Accepter).
    """
    text = "ZZZ-CONDITIONS-5060\n" + TERMS_TXT
    log("\t\t5060 disclaimerVer=%s (version memorisee a l'acceptation)"
        % DISCLAIMER_VERSION)
    return list_response(rid, name, tid,
                         [[("value", text), ("disclaimerVer", DISCLAIMER_VERSION)]])


# --------------------------------------------------------------------------
# catalogue (listes, fiche, telechargement)
# --------------------------------------------------------------------------
def r_product_list(rid, name, tid, params):
    """Toute liste de produits renvoie l'unique application du catalogue."""
    return list_response(rid, name, tid, [product_fields(rid)])


def r_category_list(rid, name, tid, params):
    """2010 categoryList : une seule categorie, celle du produit."""
    values = {
        "categoryID": "100",
        "categoryName": "Applications",
        "categoryShopID": "1",
        "upLevelCategoryID": "0",
        "subLevelCategory": "0",
        "categoryLevel": "1",
        "categorySortString": "1",
        "subProductCount": "1",
        "categoryImgUrl": PRODUCT["productImgUrl"],
        "categoryDescription": "Applications bada 2.0",
    }
    fields = [(n, values.get(n, "")) for n in PROTO.PARAMS.get(rid, [])]
    return list_response(rid, name, tid, [fields])


def r_banner_list(rid, name, tid, params):
    """2320 promotionBannerList : une banniere qui mene a Exploration."""
    return list_response(rid, name, tid, [product_fields(rid)])


def r_product_detail(rid, name, tid, params):
    """2080 productDetail : fiche complete du produit telechargeable."""
    return list_response(rid, name, tid, [product_fields(rid)])


def r_download(rid, name, tid, params):
    """2303 downloadEx / 3040 download : URI du paquet signe local."""
    values = {
        "downLoadURI": PRODUCT["contentURL"],
        "contentsSize": APP_SIZE,
        "productID": PRODUCT["productID"],
        "productName": PRODUCT["productName"],
        "orderID": "",
        "successYn": "Y",
        "installSize": APP_SIZE,
        "paymentID": "0",
        "paymentStatusCD": "0",
        "paymentRequestCompleteDate": "20261101",
    }
    fields = [(n, values.get(n, "")) for n in PROTO.PARAMS.get(rid, [])]
    log("\t\t%s : URI de telechargement %s"
        % (name, values["downLoadURI"]))
    return list_response(rid, name, tid, [fields])


def r_empty(rid, name, tid, params):
    """Reponse vide volontaire (aucun element de liste)."""
    return list_response(rid, name, tid, [])


# --------------------------------------------------------------------------
# compte Samsung (mock local)
#
# La boutique possede son propre parcours d'inscription, sans passer par
# l'application Bori/SSO :
#   5100 checkDuplication -> formulaire des conditions (0x40b)
#   5050 joinRegister     -> KonaTermsForm::FillPaymentSaveForm, qui appelle
#                            SetLoggedIn(true), SetUserId et SetAutoLogin
#   5010 login            -> connexion si une identite est deja memorisee
# Aucun mot de passe n'est verifie : tout identifiant est accepte.
# --------------------------------------------------------------------------
def account_user(params):
    return (params.get("userID") or params.get("emailId")
            or params.get("emailID") or params.get("userId")
            or DEFAULT_USER)


def r_check_duplication(rid, name, tid, params):
    user = account_user(params)
    log("\t\t5100 checkDuplication : %s accepte" % user)
    return list_response(rid, name, tid, [account_fields(rid, {
        "userID": user,
        "emialID": user,
        "birthYear": "1990",
        "birthMonth": "1",
        "birthDay": "1",
        "realAge": "30",
        "nameAuthYn": "N",
        "smartClsf": "0",
        "gender": "0",
    })])


def r_join_register(rid, name, tid, params):
    user = account_user(params)
    log("\t\t5050 joinRegister : compte %s cree, client connecte" % user)
    return list_response(rid, name, tid,
                         [account_fields(rid, {"userID": user})])


def r_login(rid, name, tid, params):
    user = account_user(params)
    log("\t\t5010 login : %s accepte" % user)
    return list_response(rid, name, tid, [account_fields(rid, {
        "userID": user,
        "emialID": user,
        "birthYear": "1990",
        "birthMonth": "1",
        "birthDay": "1",
        "realAge": "30",
        "nameAuthYn": "N",
        "smartClsf": "0",
        "gender": "0",
    })])


def r_logout(rid, name, tid, params):
    log("\t\t5020 logout : session locale fermee")
    return list_response(rid, name, tid, [])


def r_name_auth(rid, name, tid, params):
    log("\t\t5093 nameAuthSetting : realAge=30 (majeur)")
    return list_response(rid, name, tid,
                         [account_fields(rid, {"realAge": "30"})])


def r_odc_config(rid, name, tid, params):
    # URL vide : le client garde sa configuration actuelle, aucun 5094
    # supplementaire n'est declenche.
    return list_response(rid, name, tid,
                         [account_fields(rid, {"configurationUrl": ""})])


def default_items(rid, name):
    """Nombre d'elements : 3 pour une liste (nom en ...List), 1 sinon."""
    n = 3 if "list" in name.lower() or rid in ("2235", "2302", "2304") else 1
    return [fields_for(rid, i) for i in range(1, n + 1)]


BUILDERS = {
    # catalogue
    "2010": r_category_list,
    "2030": r_product_list,
    "2033": r_product_list,
    "2034": r_product_list,
    "2035": r_product_list,
    "2036": r_product_list,
    "2037": r_product_list,
    "2038": r_product_list,
    "2039": r_product_list,
    "2235": r_product_list,
    "2236": r_product_list,
    "2310": r_product_list,
    "2320": r_banner_list,
    "2080": r_product_detail,
    "2302": r_empty,
    "2304": r_empty,
    "2303": r_download,
    "3040": r_download,
    # demarrage / conditions
    "2300": r_country,
    "2301": r_upgrade_nkill,
    "2350": r_push_message,
    "2309": r_download_list,
    "2306": r_check_upgrade,
    "5060": r_term_info,
    # compte
    "5010": r_login,
    "5020": r_logout,
    "5050": r_join_register,
    "5090": r_empty,
    "5093": r_name_auth,
    "5094": r_odc_config,
    "5095": r_empty,
    "5100": r_check_duplication,
}


def override_file(name):
    return read_text(os.path.join(RESPDIR, name + ".xml"))


# --------------------------------------------------------------------------
# Droit d'installation (RI : Right Issuer) demande par BDAgent
#
# Apres un telechargement, BDAgent construit une requete XML (<DRMType>, <sid>,
# <cid>) et la poste a l'URL de BDAgentC4, c'est-a-dire
# http://zirconia.samsungapps.com/normalAppRIRequest.as. La reponse est lue par
# PackageManager::GenerateDrmLicenseRequest, dont l'implementation reelle
# (DrmSdcGenerateLicenseRequest) est un module ECOM absent du firmware extrait.
#
# Le format exact de la reponse est donc inconnu : on renvoie par defaut une
# enveloppe qui reprend les seules balises attestees dans BDAgent.exe
# (<SID length>, <CID length>, <RIURL length>, voir .rodata 0xea88e) en
# recopiant le sid/cid de la requete. Le fichier store/responses/appri.xml
# remplace cette reponse a chaud (aucun redemarrage) pour essayer un autre
# format ; store/responses/ri.xml fait de meme pour l'URL de licence.
# --------------------------------------------------------------------------
def xml_tag(body, tag):
    """Valeur d'un <tag>texte</tag> simple (premier occurrence)."""
    start = body.find("<%s>" % tag)
    if start < 0:
        return ""
    start += len(tag) + 2
    end = body.find("</%s>" % tag, start)
    return body[start:end].strip() if end >= 0 else ""


def is_ri_path(path):
    base = path.split("?", 1)[0].lower()
    return (base.endswith("/normalapprirequest.as")
            or base.endswith("/rightissuerequest.as")
            or base.endswith("/ri.as"))


def ri_document(body=""):
    """Reponse RI par defaut, construite a partir de la requete.

    returnCode vaut 0 (succes dans SamsungProtocol) : c'est le seul code que
    l'on puisse supposer compris par DrmSdcGenerateLicenseRequest.
    """
    sid = xml_tag(body, "sid") or "SN100"
    cid = xml_tag(body, "cid") or "1000000001-1.3.1"
    url = "%s/ri.as" % SELF
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<response returnCode="0">'
            '<SID length="%d">%s</SID>'
            '<CID length="%d">%s</CID>'
            '<RIURL length="%d">%s</RIURL>'
            '</response>' % (len(sid), sid, len(cid), cid, len(url), url))


def ri_expand(text, body=""):
    """Remplace {{sid}}/{{cid}}/{{url}}/{{drmtype}} dans responses/appri.xml.

    Permet d'essayer un autre habillage sans figer les valeurs de la requete.
    """
    values = {
        "sid": xml_tag(body, "sid") or "SN100",
        "cid": xml_tag(body, "cid") or "1000000001-1.3.1",
        "url": "%s/ri.as" % SELF,
        "drmtype": xml_tag(body, "DRMType") or "0",
    }
    for key, val in values.items():
        text = text.replace("{{%s}}" % key, val)
    return text


def read_list(fname):
    raw = read_text(os.path.join(BASE, fname))
    if raw is None:
        return []
    return [n.strip() for n in raw.replace("\n", ",").split(",") if n.strip()]


def error_on():
    return read_list("error_on")


def skip_on():
    return read_list("skip")


def build_response(rid, name, tid, params):
    if name in skip_on():
        log("\t\tREPONSE vide volontairement (diagnostic skip)")
        return ENVELOPE % ('<response id="%s" name="%s" returnCode="0" '
                           'transactionId="%s"></response>'
                           % (escape(rid), escape(name), escape(tid)))
    if name in FORCE_ERROR or name in error_on():
        log("\t\tREPONSE forcee en erreur (diagnostic)")
        return ENVELOPE % ('<response id="%s" name="%s" returnCode="1" '
                           'transactionId="%s"><errorString returnCode="1" '
                           'errorCode="1004">TEST-%s</errorString></response>'
                           % (escape(rid), escape(name), escape(tid), escape(name)))
    override = override_file(name)
    if override is not None:
        override = (override.replace("{{id}}", rid)
                    .replace("{{name}}", name)
                    .replace("{{tid}}", tid))
        log("\t\tREPONSE surchargee depuis responses/%s.xml" % name)
        return ENVELOPE % override
    builder = BUILDERS.get(rid)
    if builder is not None:
        log("\t\tREPONSE conforme (%s, fonction %s)" % (name, rid))
        return ENVELOPE % builder(rid, name, tid, params)
    items = default_items(rid, name)
    log("\t\tREPONSE par defaut : fonction %s (%s), %d element(s)"
        % (rid, name, len(items)))
    return ENVELOPE % list_response(rid, name, tid, items)


# --------------------------------------------------------------------------
# endpoints /security/* (SSO et IDM du compte Samsung)
#
# Le protocole exact de ces endpoints n'est pas documente. Plutot que de
# deviner une reponse, le serveur journalise la methode, les entetes et le
# corps de chaque requete, puis sert un fichier modifiable a chaud :
#
#   store/responses/security_sso_initialize_time.txt
#
# (nom = chemin sans "/" initial, "/" remplace par "_", query ignoree).
# Si le fichier n'existe pas, une reponse neutre est renvoyee : le journal
# indique alors precisement quelle requete reste a couvrir.
# --------------------------------------------------------------------------
def security_file(path):
    clean = path.split("?", 1)[0].strip("/").replace("/", "_")
    return os.path.join(RESPDIR, "security_%s.txt" % (clean or "root"))


def _between(text, tag):
    """Valeur d'un element XML simple : <tag>valeur</tag>."""
    if not text:
        return ""
    start = text.find("<%s>" % tag)
    if start < 0:
        return ""
    start += len(tag) + 2
    end = text.find("</%s>" % tag, start)
    if end < 0:
        return ""
    value = text[start:end]
    return (value.replace("&lt;", "<").replace("&gt;", ">")
            .replace("&quot;", '"').replace("&amp;", "&"))


def security_body(path, body=""):
    """Reponse aux endpoints /security/* (SSO et IDM du compte Samsung).

    Protocole deduit du desassemblage de mosp (bada 1.2, meme famille que le
    mosp 2.0 du telephone) :

      GET  /security/sso/initialize/time
           -> element racine contenant <currentServerTime> (horodatage Unix).
              Le client n'utilise que cet element (msecIdentityManagerImpl.c,
              __IdentityManagerImpl_saveServerTime).

      POST /security/sso/userprofiles/authentication/emailid
           corps <userAuthRequest> avec <loginID>, <password> et <duid>.
           -> element racine contenant <userID>, <plainID>, <emailID>,
              <deviceID>, <authToken>, <authTokenSecret> (et <birthDate>
              facultatif), lus comme enfants directs de la racine par
              __IdentityManagerSpi_getValueFromXmlRoot.
    """
    base = path.split("?", 1)[0]
    if base.endswith("/initialize/time") or base.endswith("/time"):
        return ('<?xml version="1.0" encoding="UTF-8"?>'
                '<response><currentServerTime>%d</currentServerTime></response>'
                % int(time.time()))
    if "/userprofiles/authentication/" in base:
        login = _between(body, "loginID") or "test@test.com"
        duid = _between(body, "duid") or "0000000000000000"
        # Authentification applicative : le client ne lit que accessToken et
        # accessTokenSecret (__IdentityManagerImpl_saveCredentialResult).
        if ("/application" in base or "/accesstoken/" in base
                or "/authtoken/" in base):
            return ('<?xml version="1.0" encoding="UTF-8"?>'
                    '<credentialResponse>'
                    '<accessToken>badaReviveAccessToken</accessToken>'
                    '<accessTokenSecret>badaReviveAccessSecret</accessTokenSecret>'
                    '</credentialResponse>')
        return ('<?xml version="1.0" encoding="UTF-8"?>'
                '<userAuthResponse>'
                '<userID>1000000001</userID>'
                '<plainID>%s</plainID>'
                '<emailID>%s</emailID>'
                '<deviceID>%s</deviceID>'
                '<authToken>badaReviveAuthToken</authToken>'
                '<authTokenSecret>badaReviveAuthSecret</authTokenSecret>'
                '<birthDate>19900101</birthDate>'
                '</userAuthResponse>' % (escape(login), escape(login),
                                         escape(duid)))
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<response><returnCode>0</returnCode></response>')


# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "BadaRevival/0.9"

    def log_message(self, fmt, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        """Journalise la ligne brute quand le parseur HTTP refuse la requete.

        BaseHTTPRequestHandler abandonne la connexion des que la ligne de
        requete est invalide : sans ce crochet on ne saurait jamais ce que le
        telephone a reellement envoye (cas du bloc de 102 octets sur 443).
        """
        raw = getattr(self, "raw_requestline", b"") or b""
        if code in (400, 414, 431) and raw:
            log("\t\tERREUR HTTP %d sur ligne brute : %s"
                % (code, _hexdump(raw, 200)))
        super().send_error(code, message, explain)

    def setup(self):
        super().setup()
        log("%s\tCONNEXION\t%s:%s" % (time.strftime("%Y-%m-%dT%H:%M:%S"),
                                      self.client_address[0], self.client_address[1]))

    def finish(self):
        log("%s\tDECONNEXION\t%s:%s" % (time.strftime("%Y-%m-%dT%H:%M:%S"),
                                        self.client_address[0], self.client_address[1]))
        super().finish()

    def _log_headers(self, limit=None):
        """Journalise les en-tetes recus (diagnostic des endpoints inconnus)."""
        try:
            hdrs = " | ".join("%s: %s" % (k, v) for k, v in self.headers.items())
            log("\t\tENTETES %s" % (hdrs if limit is None else hdrs[:limit]))
        except Exception:
            pass

    def _emit(self, data, ctype="text/xml; charset=UTF-8", keepalive=True):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive" if keepalive else "close")
        if not keepalive:
            self.close_connection = True
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()

    def do_GET(self):
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        log("%s\tGET\t%s\t%s\t%s" % (stamp, self.headers.get("Host", "-"),
                                     self.path, self.headers.get("User-Agent", "-")[:60]))
        if self.path.startswith("/i/") or self.path.lower().endswith(".png"):
            self._emit(PNG, "image/png")
            return
        if self.path.startswith("/dl/"):
            self._serve_app()
            return
        # Endpoints du compte Samsung (SSO/IDM) : on journalise tout et on
        # sert une reponse modifiable (voir security_file).
        if self.path.startswith("/security/"):
            self._security("GET", "")
            return
        if self.path.startswith("/social/"):
            self._social("GET", "")
            return
        if is_ri_path(self.path):
            self._ri("GET", b"", "")
            return
        # Ecran "Conditions generales" : texte et page HTML.
        if self.path.startswith("/contents/deviceterms/"):
            log("\t\tTEXTE des conditions generales demande")
            self._emit(TERMS_TXT.encode("utf-8"), "text/plain; charset=UTF-8")
            return
        if self.path.startswith("/common/") or self.path.startswith("/t.as"):
            log("\t\tPAGE des conditions generales demandee")
            self._emit(TERMS_HTML.encode("utf-8"), "text/html; charset=UTF-8")
            return
        log("\t\tCHEMIN INCONNU (404)")
        self.send_error(404)

    def _serve_app(self):
        """Sert un paquet .app de store/apps/, avec support de Range.

        Le gestionnaire de telechargement de bada reprend parfois un fichier
        en plusieurs morceaux : sans l'entete Content-Range il recommencerait
        depuis zero (ou refuserait la reprise).
        """
        fname = os.path.basename(self.path.split("?", 1)[0])
        local = os.path.join(APP_DIR, fname)
        if not os.path.isfile(local):
            log("\t\tFICHIER ABSENT : %s" % fname)
            self._emit(b"BADAREVIVAL-DL\n", "application/octet-stream")
            return
        with open(local, "rb") as f:
            payload = f.read()
        size = len(payload)
        rng = (self.headers.get("Range") or "").strip()
        start, end = 0, size - 1
        partial = False
        if rng.lower().startswith("bytes="):
            part = rng[6:].split(",", 1)[0].strip()
            a, _, b = part.partition("-")
            try:
                if a:
                    start = int(a)
                if b:
                    end = min(int(b), size - 1)
                else:
                    end = size - 1
                if not a:
                    start = max(0, size - int(b))
                    end = size - 1
                partial = True
            except ValueError:
                start, end = 0, size - 1
                partial = False
        if start > end or start >= size:
            self.send_response(416)
            self.send_header("Content-Range", "bytes */%d" % size)
            self.send_header("Content-Length", "0")
            self.end_headers()
            log("\t\tRANGE INVALIDE %s (taille %d)" % (rng, size))
            return
        chunk = payload[start:end + 1]
        log("\t\tTELECHARGEMENT %s : %d octets%s"
            % (fname, len(chunk),
               " (morceau %d-%d/%d)" % (start, end, size) if partial else ""))
        if DL_RATE_KBPS:
            log("\t\t  debit limite a %d Ko/s (~%d s)"
                % (DL_RATE_KBPS, len(chunk) // (DL_RATE_KBPS * 1024) + 1))
        self.send_response(206 if partial else 200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(chunk)))
        self.send_header("Accept-Ranges", "bytes")
        if partial:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        if DL_RATE_KBPS and len(chunk) > 16384:
            # Envoi au goutte a goutte (voir DL_RATE_KBPS) : le debit vaut
            # 4 tranches par seconde, donc DL_RATE_KBPS*1024 octets/s.
            tranche = max(4096, DL_RATE_KBPS * 1024 // 4)
            for i in range(0, len(chunk), tranche):
                self.wfile.write(chunk[i:i + tranche])
                self.wfile.flush()
                time.sleep(0.25)
        else:
            self.wfile.write(chunk)
            self.wfile.flush()

    def _social(self, method, body):
        """Endpoints /social/* du compte Samsung (creation de compte appli,
        enregistrement de l'appareil).

        Formats deduits du desassemblage de mosp (bada 1.2, meme famille) :

          POST /social/member/appusers
               corps <appAccountCreate>...  Cree le compte applicatif.
               __MemberServiceAsyncListener_onHttpResponseReceived compare le
               corps a "true" (String_equals) : tout autre corps leve
               [ServerException] "Response result is not [true]".

          POST /social/user/<id>/devices
               enregistre l'appareil ; la reponse est lue par atol()
               (__MDeviceManager_onHttpResponseReceived type 0) : un nombre.

          POST /social/user/<id>/devices/<n>
               supprime l'appareil ; corps compare a "true".

          GET  /social/user/<id>/devices[/list]
               liste d'appareils : racine <userDeviceList> contenant des
               <UserDevice> (__GetDeviceListFromXmlDocument).

          GET  /social/user/<id>/devices/<n>
               un appareil : racine <UserDevice> (__GetUserDeviceVoFromXmlDocument).
        """
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        host = self.headers.get("Host", "-")
        base = self.path.split("?", 1)[0].rstrip("/") or "/"
        log("%s\t%s\t%s\t%s\tSOCIAL (%d octets)"
            % (stamp, method, host, self.path, len(body)))
        if body:
            log("\t\t" + body.replace("\n", " ")[:400])

        device = ("<userID>1000000001</userID>"
                  "<deviceID>1</deviceID>"
                  "<deviceTypeCode>MOBILE</deviceTypeCode>"
                  "<deviceModelID>GT-S5380</deviceModelID>"
                  "<deviceUniqueID>%s</deviceUniqueID>"
                  "<devicePhysicalAddressText></devicePhysicalAddressText>"
                  "<deviceName>GT-S5380</deviceName>"
                  "<deviceStatusCode>IN USE</deviceStatusCode>")

        if base.endswith("/appusers"):
            log("\t\tREPONSE SOCIAL createAppAccount = true")
            self._emit(b"true", "text/plain; charset=UTF-8")
            return
        if base.endswith("/devices/list") or (
                base.endswith("/devices") and method == "GET"):
            xml = ('<?xml version="1.0" encoding="UTF-8"?>'
                   "<userDeviceList><UserDevice>%s</UserDevice></userDeviceList>"
                   % device)
            log("\t\tREPONSE SOCIAL liste d'appareils (%d octets)" % len(xml))
            self._emit(xml.encode("utf-8"), "text/xml; charset=UTF-8")
            return
        if "/devices/" in base:
            if method == "GET":
                xml = ('<?xml version="1.0" encoding="UTF-8"?>'
                       "<UserDevice>%s</UserDevice>" % device)
                log("\t\tREPONSE SOCIAL appareil (%d octets)" % len(xml))
                self._emit(xml.encode("utf-8"), "text/xml; charset=UTF-8")
            else:
                log("\t\tREPONSE SOCIAL appareil supprime = true")
                self._emit(b"true", "text/plain; charset=UTF-8")
            return
        if base.endswith("/devices") and method == "POST":
            log("\t\tREPONSE SOCIAL enregistrement appareil = 1")
            self._emit(b"1", "text/plain; charset=UTF-8")
            return
        # Chemin social inconnu : reponse neutre, le journal precise lequel.
        log("\t\tREPONSE SOCIAL neutre pour %s" % base)
        self._emit(b"true", "text/plain; charset=UTF-8")

    def _security(self, method, body):
        """Journalise et repond a un endpoint /security/* (SSO/IDM)."""
        host = self.headers.get("Host", "-")
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        log("%s\t%s\t%s\t%s\tSECURITE" % (stamp, method, host, self.path))
        self._log_headers()
        if body:
            log("\t\tCORPS %s" % body)
        local = security_file(self.path)
        if os.path.isfile(local):
            with open(local, "rb") as f:
                data = f.read()
            log("\t\tREPONSE SECURITE depuis %s (%d octets)"
                % (os.path.basename(local), len(data)))
        else:
            data = security_body(self.path, body).encode("utf-8")
            log("\t\tREPONSE SECURITE par defaut (%d octets)" % len(data))
        self._emit(data, "text/xml; charset=UTF-8")

    def _dump_body(self, raw):
        """Journalise un corps binaire : hexa + chaines lisibles."""
        if not raw:
            return
        try:
            log("\t\tHEXA %s" % raw[:160].hex())
        except Exception:
            pass
        # Chaines ASCII de 4 caracteres ou plus, utiles pour un protocole
        # binaire (identifiants, URI, noms de fichiers).
        out, cur = [], []
        for b in raw[:2048]:
            if 0x20 <= b < 0x7f:
                cur.append(chr(b))
            else:
                if len(cur) >= 4:
                    out.append("".join(cur))
                cur = []
        if len(cur) >= 4:
            out.append("".join(cur))
        if out:
            log("\t\tCHAINE %s" % " | ".join(out[:20]))
        # Certains champs sont en UTF-16LE (chaines bada).
        try:
            wide = raw.decode("utf-16-le", "ignore")
            keep = "".join(c if 0x20 <= ord(c) < 0x7f else " " for c in wide)
            keep = " ".join(keep.split())
            if len(keep) >= 4:
                log("\t\tUTF16 %s" % keep[:200])
        except Exception:
            pass

    def _bd(self, raw):
        """Requete du gestionnaire de telechargement (protocole inconnu)."""
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        host = self.headers.get("Host", "-")
        log("%s\tPOST\t%s\t%s\tBD (%d octets)" % (stamp, host, self.path, len(raw)))
        self._log_headers(400)
        self._dump_body(raw)
        # Reponse neutre : 200, corps vide. A ajuster quand le format des
        # commandes sera connu (voir OnBDCommRespCallbackDownload dans Kona.exe).
        self._emit(b"", "application/octet-stream")

    def _ri(self, method, raw, body):
        """Requete RI (Right Issuer) de BDAgent : on journalise tout.

        Le corps est le XML construit par BDAgentDrmDownMgr (DRMType, sid,
        cid). La reponse provient de store/responses/appri.xml si present,
        sinon d'une enveloppe construite localement (voir ri_document).
        """
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        host = self.headers.get("Host", "-")
        log("%s\t%s\t%s\t%s\tDRM-RI (%d octets)"
            % (stamp, method, host, self.path, len(raw)))
        self._log_headers(400)
        if method == "POST":
            log("\t\tCORPS %s" % body.replace("\n", " ")[:600])
            self._dump_body(raw)

        base = self.path.split("?", 1)[0].lower()
        if base.endswith("/ri.as"):
            over = override_file("ri")
            data = (over.encode("utf-8") if over
                    else b'<response returnCode="1"/>')
            log("\t\tREPONSE RI-LICENCE %s (%d octets)"
                % ("depuis ri.xml" if over else "par defaut", len(data)))
        else:
            over = override_file("appri")
            if over:
                over = ri_expand(over, body)
            data = (over.encode("utf-8") if over
                    else ri_document(body).encode("utf-8"))
            log("\t\tREPONSE RI-DEMANDE %s (%d octets)"
                % ("depuis appri.xml" if over else "par defaut", len(data)))
            log("\t\t%s" % data.decode("utf-8", "replace").replace("\n", " ")[:600])
        self._emit(data, "text/xml; charset=UTF-8")

    def do_POST(self):
        try:
            self._post()
        except Exception as exc:
            log("ERREUR: %s" % exc)
            log(traceback.format_exc().replace("\n", " | "))

    def _post(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        body = raw.decode("utf-8", "replace") if raw else ""
        host = self.headers.get("Host", "-")
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")

        if self.path.startswith("/security/"):
            self._security("POST", body)
            return

        if self.path.startswith("/bd"):
            # Protocole binaire du gestionnaire de telechargement de bada.
            # On ne le connait pas encore : on journalise tout et on repond
            # une enveloppe neutre. Le journal dira si le telephone passe par
            # ici ou s'il telecharge directement l'URI de la reponse 3040.
            self._bd(raw)
            return

        if self.path.startswith("/social/"):
            self._social("POST", body)
            return

        if is_ri_path(self.path):
            self._ri("POST", raw, body)
            return

        parsed = parse(body)

        if not parsed:
            log("%s\tPOST\t%s\t%s\tILLISIBLE (%d octets)" % (stamp, host, self.path, len(body)))
            log("\t\t" + body.replace("\n", " ")[:400])
            self._dump_body(raw)
            self._emit((ENVELOPE % ('<response returnCode="1">'
                                    '<errorString returnCode="1" errorCode="1">'
                                    "bad request</errorString></response>")).encode("utf-8"))
            return

        rid, name, tid, params = parsed
        self._n = getattr(self, "_n", 0) + 1
        log("%s\tPOST\t%s\t%s\tid=%s name=%s tid=%s (requete %d sur cette connexion)"
            % (stamp, host, self.path, rid, name, tid, self._n))
        log("\t\t%s %s" % (self.command, self.request_version))
        self._log_headers(400)
        for k, v in params.items():
            if k == "imei":
                log("\t\t%s = (masque)" % k)
            else:
                log("\t\t%s = %s" % (k, v[:200]))

        xml = build_response(rid, name, tid, params)

        if name in read_list("hang"):
            log("\t\tPAS DE REPONSE (diagnostic hang) : attente %d s" % HANG_TIMEOUT)
            time.sleep(HANG_TIMEOUT)
            log("\t\tFIN du hang, envoi tardif de %d octets" % len(xml))

        log("\t\tENVOI %d octets" % len(xml))
        try:
            with open(os.path.join(LOGDIR, "responses.log"), "a", encoding="utf-8") as f:
                f.write("%s %s tid=%s\n%s\n\n"
                        % (time.strftime("%Y-%m-%dT%H:%M:%S"), name, tid, xml[:3000]))
        except OSError:
            pass
        try:
            self._emit(xml.encode("utf-8"), keepalive=(name not in read_list("close_on")))
        except OSError as exc:
            log("\t\tCLIENT PARTI avant la reponse (%s)" % exc)
            raise


def serve_tls():
    """Ecoute sur 443, TLS ou HTTP en clair selon le premier octet recu.

    Pourquoi un detection : on ne sait pas encore si le telephone parle HTTPS
    ou HTTP simple sur ce port. Un premier octet 0x16 = enregistrement TLS
    (ClientHello), sinon on traite la connexion comme du HTTP ordinaire. Le
    meme Handler repond dans les deux cas, donc aucun comportement metier ne
    depend du transport.

    bada 2.0 est ancien : niveau de securite abaisse (ALL:@SECLEVEL=0) et TLS
    1.0 autorise. Les echecs de handshake et le SNI sont journalises pour
    savoir si le certificat auto-signe est refuse (alerte TLS) ou si le
    telephone ne parle pas TLS du tout.
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        ctx.load_cert_chain(TLS_CERT, TLS_KEY)

        def _sni(sslsock, servername, _ctx):
            log("# TLS SNI = %r" % (servername,))
            return None

        ctx.set_servername_callback(_sni)
    except Exception as exc:
        log("# TLS indisponible : %s" % exc)
        return

    class HybridServer(ThreadingHTTPServer):
        daemon_threads = True

        def get_request(self):
            raw, addr = self.socket.accept()
            tls = False
            try:
                raw.settimeout(20)
                # On lit large (64 octets) et pas seulement le premier : le
                # journal doit montrer le debut du flux pour identifier un
                # protocole inconnu (SSLv2, HTTP precede de CRLF, autre).
                probe = raw.recv(64, socket.MSG_PEEK)
                # Un ClientHello SSLv2 peut arriver en plusieurs morceaux :
                # il faut au moins 3 octets pour lire le type de message.
                while 0 < len(probe) < 3:
                    time.sleep(0.01)
                    probe = raw.recv(64, socket.MSG_PEEK)
                first = probe[:1]
                tls = first == b"\x16"
                raw.settimeout(None)
                if probe:
                    log("# 443 premiere donnee depuis %s : %s"
                        % (addr[0], _hexdump(probe)))
                if first == b"\x80" and len(probe) >= 3 and probe[2] == 1:
                    # bada 2.0 (OpenSSL 0.9.8) ouvre HTTPS par un ClientHello
                    # au format SSLv2, que Python/OpenSSL 3 refuse. On termine
                    # la poignee de main nous-memes puis on rend la socket au
                    # Handler HTTP : la suite est du HTTP ordinaire, chiffre.
                    if ssl2 is None:
                        log("# 443 ClientHello SSLv2 mais module ssl2 "
                            "indisponible : %s" % _SSL2_IMPORT_ERROR)
                        raise OSError("module ssl2 indisponible")
                    log("# 443 ClientHello SSLv2 depuis %s : handshake maison"
                        % addr[0])
                    conn = ssl2.SSL2Socket(raw, TLS_CERT, TLS_KEY, log=log)
                    conn.handshake()
                    conn.settimeout(None)
                    return conn, addr
                if first == b"\x80":
                    log("# 443 format SSLv2 (0x80) non exploitable : %s"
                        % _hexdump(probe))
                if not tls:
                    # Certains clients bada prefixent leur requete par CRLF.
                    # On les consomme avant de rendre la socket au parseur,
                    # sinon la ligne de requete est invalide (400).
                    n = len(probe) - len(probe.lstrip(b"\r\n"))
                    if n:
                        raw.recv(n)
                        log("# 443 %d octet(s) CRLF ignore(s)" % n)
                    log("# 443 en clair (HTTP) depuis %s%s"
                        % (addr[0], "" if probe else ", ferme aussitot"))
                    return raw, addr
                sock = self.ctx.wrap_socket(raw, server_side=True)
            except Exception as exc:
                log("# 443 echec de %s depuis %s : %s"
                    % ("handshake TLS" if tls else "lecture", addr[0], exc))
                try:
                    raw.close()
                except OSError:
                    pass
                raise OSError(str(exc))
            try:
                log("# 443 TLS OK depuis %s : %s %s"
                    % (addr[0], sock.version(), sock.cipher()[0]))
            except Exception:
                pass
            return sock, addr

    try:
        httpd = HybridServer(("0.0.0.0", TLS_PORT), Handler)
        httpd.ctx = ctx
        log("# TLS/HTTP en ecoute sur le port %d" % TLS_PORT)
        httpd.serve_forever()
    except Exception as exc:
        log("# TLS: impossible d'ecouter sur %d : %s" % (TLS_PORT, exc))


if __name__ == "__main__":
    if PORT < 1024 and os.geteuid() != 0:
        sys.exit("erreur: le port %d exige root (sudo python3 mock.py)" % PORT)
    os.makedirs(LOGDIR, exist_ok=True)
    os.makedirs(RESPDIR, exist_ok=True)

    if TLS_PORT:
        if os.path.exists(TLS_CERT) and os.path.exists(TLS_KEY):
            threading.Thread(target=serve_tls, name="tls", daemon=True).start()
            log("# TLS demande sur le port %d (cert %s)" % (TLS_PORT, TLS_CERT))
        else:
            log("# TLS desactive : %s / %s absent(s)" % (TLS_CERT, TLS_KEY))

    log("# SSLv2 : %s" % ("terminateur maison disponible" if ssl2
                           else "indisponible (%s)" % _SSL2_IMPORT_ERROR))
    log("# serveur v14 demarre %s port=%d" % (time.strftime("%Y-%m-%dT%H:%M:%S"), PORT))
    print("boutique prototype v14 sur le port %d - Ctrl+C pour arreter" % PORT)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
