#!/usr/bin/env bash
# Remet l'app démo en état VULNÉRABLE (pour rejouer la boucle devant le jury).
# Copie la version vulnérable sur le manifest suivi par Argo, commit + push sur main.
# Argo CD redéploie ensuite l'app vulnérable -> Trivy/Kyverno la re-signalent.
set -euo pipefail
cd "$(dirname "$0")"

SRC="demo/vulnerable-deployment.yaml"
DST="apps/vulnerable-app/deployment.yaml"

echo "⚠  Ce script va remettre l'app démo en état VULNÉRABLE sur main (commit + push)."
read -r -p "Continuer ? [o/N] " ok
[[ "$ok" == "o" || "$ok" == "O" ]] || { echo "Annulé."; exit 0; }

# On garde l'en-tête de commentaire hors du manifest suivi par Argo
grep -v '^#' "$SRC" > "$DST"

git add "$DST"
git commit -m "demo: remettre l'app en etat vulnerable (reset de demonstration)"
git push origin HEAD

cat <<EOF

✅ Reset poussé sur main. Argo CD va redéployer l'app vulnérable (~1-2 min).
   Ensuite, lance la boucle :  cd apps/remediator && python3 remediator.py
EOF
