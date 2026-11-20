#!/bin/bash
# Bada Revival - demarrage du banc de test (a lancer avec sudo).
# Les processus sont detaches du terminal : fermer la console ne les tue plus.
# Arret : sudo pkill -f mock.py ; sudo pkill -f dnsprobe.py

set -u
TOOLS=/home/user/badarevival/tools
STORE=/home/user/badarevival/store
LOGS=/home/user/badarevival/logs

# Hotes a rediriger vers le banc (la liste de reference est tools/dns-map.txt).
# - protocole /ods.as : fr-bou, hub-odc
# - pages et images HTTP : www.samsungapps.com, static.bada.com, img, zirconia
# - documents OSP 2306/5060 : www.ospserver.net (port 443, TLS ou HTTP clair,
#   servi par mock.py). Les autres services sans banc derriere (push 5223,
#   vlingo, adhub) restent NON rediriges : un RST serait traduit en
#   "Reseau non disponible".
MAP="fr-bou.samsungapps.com=192.168.1.21,hub-odc.samsungapps.com=192.168.1.21"
MAP="$MAP,www.samsungapps.com=192.168.1.21,samsungapps.com=192.168.1.21"
MAP="$MAP,static.bada.com=192.168.1.21,img.samsungapps.com=192.168.1.21"
MAP="$MAP,zirconia.samsungapps.com=192.168.1.21"
MAP="$MAP,www.ospserver.net=192.168.1.21"
# La carte effective est tools/dns-map.txt (relue a chaud). MAP n'est qu'un
# repli si ce fichier disparait. Ne pas y ajouter push/vlingo : un hote
# redirige sans service derriere = "Reseau non disponible".
export MAPFILE=/home/user/badarevival/tools/dns-map.txt
export TLS_PORT="${TLS_PORT:-443}"

mkdir -p "$LOGS"

# Un fichier de journal par lancement : les tests ne se melangent plus.
if [ -s "$LOGS/store.log" ]; then
  mv "$LOGS/store.log" "$LOGS/store-$(date +%Y%m%d-%H%M%S).log"
fi
if [ -s "$LOGS/packets.log" ]; then
  mv "$LOGS/packets.log" "$LOGS/packets-$(date +%Y%m%d-%H%M%S).log"
fi

pkill -f dnsprobe.py 2>/dev/null
pkill -f capture.py 2>/dev/null
pkill -f mock.py 2>/dev/null
pkill -f packets.py 2>/dev/null
sleep 1

MAP="$MAP" setsid nohup python3 "$TOOLS/dnsprobe.py" >> "$LOGS/dnsprobe.out" 2>&1 < /dev/null &
sleep 1
setsid nohup python3 "$TOOLS/packets.py" >> "$LOGS/packets.out" 2>&1 < /dev/null &
setsid nohup python3 "$STORE/mock.py" >> "$LOGS/mock.out" 2>&1 < /dev/null &
sleep 2

echo "--- test local du serveur (doit repondre returnCode=\"0\") ---"
curl -s --max-time 5 -H "Host: fr-bou.samsungapps.com" --data-binary \
  '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><SamsungProtocol version="0.9" lang="EN"><request id="2300" name="countrySearchEx" transactionId="1"><param name="whoAmI">odc</param></request></SamsungProtocol>' \
  http://127.0.0.1/ods.as | head -c 300
echo
echo "--- test local 443 (5060 termInformation, TLS negocie) ---"
curl -sk --max-time 5 -H "Host: www.ospserver.net" --data-binary \
  '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><SamsungProtocol version="0.9" lang="EN"><request id="5060" name="termInformation" transactionId="1"><param name="disclaimerVer">0</param></request></SamsungProtocol>' \
  https://127.0.0.1/ods.as | head -c 200
echo
echo "--- ports en ecoute (TCP 80/443 + UDP 53) ---"
ss -lntu | grep -E ":(53|80|443)\b" || echo "AUCUN port 53/80/443 en ecoute"
echo "--- processus ---"
pgrep -af "dnsprobe.py|mock.py|packets.py" | grep -v pgrep
echo
echo "Banc de test actif. Arret : sudo pkill -f mock.py ; sudo pkill -f dnsprobe.py"
