#!/bin/sh
# Bada Revival - installe le banc de test comme service runit.
# A lancer UNE fois avec sudo :  sudo /home/user/badarevival/tools/install-autostart.sh
# Effet : au prochain demarrage de la machine, le banc (DNS 53 + boutique 80)
#         est relance automatiquement. Retour arriere :
#           sudo rm /etc/service/badarevival
#           sudo sv stop badarevival 2>/dev/null
#           sudo rm -rf /etc/sv/badarevival

set -e
SVDIR=/etc/sv/badarevival

# 1. Arrete une eventuelle instance lancee a la main (test-store.sh).
pkill -f dnsprobe.py 2>/dev/null || true
pkill -f packets.py  2>/dev/null || true
pkill -f mock.py     2>/dev/null || true
sleep 1

# 2. Cree le service.
mkdir -p "$SVDIR"
cat > "$SVDIR/run" <<'EOF'
#!/bin/sh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root
exec 2>&1
cd /home/user/badarevival
exec /home/user/badarevival/tools/bank-run.sh
EOF
chmod +x "$SVDIR/run" /home/user/badarevival/tools/bank-run.sh

ln -sfn "$SVDIR" /etc/service/badarevival

# 3. Demarre et verifie.
sleep 2
sv up badarevival 2>/dev/null || true
sleep 3
if pgrep -f 'dnsprobe.py' >/dev/null && pgrep -f 'mock.py' >/dev/null; then
  echo "OK : service badarevival actif (demarrage automatique au boot)."
  pgrep -af 'dnsprobe.py|packets.py|mock.py'
else
  echo "ECHEC : le banc n'est pas actif. Voir : sudo sv status badarevival" >&2
  exit 1
fi
