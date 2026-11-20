#!/bin/bash
# Bada Revival - superviseur du banc de test (prevu pour runit).
# Lance dnsprobe, packets et mock en arriere-plan puis reste en avant-plan.
# Si l'un des trois meurt, les autres sont arretes et le script sort en
# erreur : runit relance alors l'ensemble. Aucun port n'est ouvert vers
# l'exterieur : seuls 53 (DNS du banc) et 80 (boutique) ecoutent sur le LAN.

set -u
TOOLS=/home/user/badarevival/tools
STORE=/home/user/badarevival/store
LOGS=/home/user/badarevival/logs

MAP="fr-bou.samsungapps.com=192.168.1.21,hub-odc.samsungapps.com=192.168.1.21"
MAP="$MAP,www.samsungapps.com=192.168.1.21,samsungapps.com=192.168.1.21"
MAP="$MAP,static.bada.com=192.168.1.21,img.samsungapps.com=192.168.1.21"
MAP="$MAP,zirconia.samsungapps.com=192.168.1.21"
# Ne PAS rediriger les hotes sans service sur le banc (ospserver 443,
# push 5223, vlingo) : un RST les transforme en "Reseau non disponible".
# La carte reelle est lue dans tools/dns-map.txt (modifiable a chaud).
export MAPFILE=/home/user/badarevival/tools/dns-map.txt

mkdir -p "$LOGS"

# Un journal par lancement : les tests ne se melangent pas.
STAMP=$(date +%Y%m%d-%H%M%S)
if [ -s "$LOGS/store.log" ]; then
  mv "$LOGS/store.log" "$LOGS/store-$STAMP.log"
fi
if [ -s "$LOGS/packets.log" ]; then
  mv "$LOGS/packets.log" "$LOGS/packets-$STAMP.log"
fi

# Journaux secondaires (sorties d'erreur) : rotation simple au-dela de 2 Mo,
# pour qu'une relance en boucle par runit ne remplisse pas le disque.
for f in dnsprobe.out packets.out mock.out; do
  if [ -f "$LOGS/$f" ] && [ "$(wc -c < "$LOGS/$f")" -gt 2097152 ]; then
    mv "$LOGS/$f" "$LOGS/$f.$STAMP"
  fi
done

echo "=== banc demarre $(date -Is) (pid $$) ===" >> "$LOGS/dnsprobe.out"

cleanup() {
  kill $(jobs -p) 2>/dev/null
  wait 2>/dev/null
}
trap 'cleanup; exit 0' INT TERM

python3 "$TOOLS/dnsprobe.py"  >> "$LOGS/dnsprobe.out" 2>&1 &
python3 "$TOOLS/packets.py"   >> "$LOGS/packets.out"  2>&1 &
python3 "$STORE/mock.py"      >> "$LOGS/mock.out"     2>&1 &

# Attend la fin du premier processus qui s'arrete.
wait -n
cleanup
exit 1
