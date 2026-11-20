#!/bin/bash
# Bada Revival - mouchard reseau passif.
# Enregistre toutes les connexions du telephone (tous etats : SYN-SENT,
# ESTAB, TIME-WAIT...) ainsi que les ports en ecoute qui les recoivent.
# Ne modifie rien, ne necessite pas root. Arret : pkill -f netwatch.sh
# le dossier logs/ appartient a root (ecrit par le mock) : on ecrit ici, ou
# l'utilisateur a le droit d'ecrire, sans avoir besoin de sudo.
OUT=/home/user/badarevival/net.log
PHONE=192.168.1.68
PREV=""
echo "# netwatch demarre $(date -Is) (telephone $PHONE)" >> "$OUT"
while true; do
    CUR=$(ss -tan 2>/dev/null | awk -v p="$PHONE" 'NR>1 && ($5 ~ p || $4 ~ p) {print $1"\t"$4"\t"$5}')
    if [ "$CUR" != "$PREV" ]; then
        {
            echo "--- $(date -Is) ---"
            if [ -n "$CUR" ]; then echo "$CUR"; else echo "(aucune)"; fi
        } >> "$OUT"
        PREV="$CUR"
    fi
    sleep 1
done
