#!/bin/bash
# Bada Revival - session d'observation
# Lance la sonde DNS avec redirection des noms Samsung vers ce serveur,
# puis la capture des connexions sur 80 et 443.
# Arret : Ctrl+C (les deux processus s'arretent).
# Retour arriere : remettre le DNS du telephone en DHCP.

set -u
cd /home/user/badarevival/tools || exit 1

MAP="fr-bou.samsungapps.com=192.168.1.21,hub-odc.samsungapps.com=192.168.1.21,opt.samsungadhub.com=192.168.1.21"

pkill -f dnsprobe.py 2>/dev/null
pkill -f capture.py 2>/dev/null
sleep 1

MAP="$MAP" python3 dnsprobe.py &
DNS_PID=$!
sleep 1

python3 capture.py
kill "$DNS_PID" 2>/dev/null
