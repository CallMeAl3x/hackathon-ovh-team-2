# Hackathon OVH — Team 2

## Structure

```
apps/
  vulnerable-app/   # Application volontairement vulnérable (démo)
  remediator/       # Service de remédiation automatique
infra/
  trivy/            # Scan de vulnérabilités
  kyverno/          # Policies d'admission Kubernetes
  prometheus/       # Monitoring & alerting
  falco/            # Détection runtime
policies/           # Policies de sécurité
docs/               # Documentation
```
