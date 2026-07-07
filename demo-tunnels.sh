#!/usr/bin/env bash
# Lance les 3 tunnels (Argo CD, Grafana, Prometheus) et les RELANCE
# automatiquement s'ils tombent. Laisse ce terminal ouvert pendant la démo.
# Ctrl+C pour tout arrêter proprement.
set -u

# Kubeconfig du bundle (surchargeable : KUBECONFIG=... ./demo-tunnels.sh)
export KUBECONFIG="${KUBECONFIG:-$(cd "$(dirname "$0")" && pwd)/archive (1)/kubeconfig-equipe-2.yaml}"

# Un superviseur par service : boucle infinie qui relance le port-forward s'il meurt.
supervise() {
  local name="$1" ns="$2" svc="$3" ports="$4"
  while true; do
    echo "[$(date +%H:%M:%S)] ▶ $name : (re)connexion..."
    kubectl -n "$ns" port-forward "svc/$svc" "$ports" --address 127.0.0.1 >/dev/null 2>&1
    echo "[$(date +%H:%M:%S)] ⚠ $name est tombé — relance dans 1s"
    sleep 1
  done
}

# Arrêt propre : on tue tous les enfants quand on fait Ctrl+C
trap 'echo; echo "Arrêt des tunnels..."; kill 0; exit 0' INT TERM

supervise "Argo CD"    argocd     argocd-server                    8080:443  &
supervise "Grafana"    monitoring kube-prometheus-stack-grafana    3000:80   &
supervise "Prometheus" monitoring kube-prometheus-stack-prometheus 9090:9090 &

cat <<EOF

  Tunnels actifs (auto-réparants) :
    • Argo CD    -> https://localhost:8080   (user: admin)
    • Grafana    -> http://localhost:3000     (user: admin)
    • Prometheus -> http://localhost:9090

  Mot de passe Argo CD :
    kubectl -n argocd get secret argocd-initial-admin-secret \\
      -o jsonpath='{.data.password}' | base64 -d
  Mot de passe Grafana : voir la valeur grafana.adminPassword du chart.

  Laisse ce terminal ouvert. Ctrl+C pour tout arrêter.

EOF

wait
