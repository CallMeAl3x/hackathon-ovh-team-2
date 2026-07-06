# Remédiateur IA

Le cœur de la boucle : lit les `VulnerabilityReports` de Trivy dans le cluster,
demande un correctif à l'IA (AI Endpoints OVHcloud), et ouvre une Pull Request
avec le manifest corrigé + l'explication.

## Lancer

```bash
pip install -r requirements.txt
cp .env.example .env   # remplir les valeurs, puis :
source .env
python3 remediator.py
```

## Variables d'environnement

| Variable | Rôle |
|---|---|
| `OVH_AI_TOKEN` | Clé d'API AI Endpoints (manager OVHcloud → Public Cloud → AI Endpoints) |
| `OVH_AI_BASE_URL` | URL de base du modèle (sur la fiche du modèle, se termine par `/v1`) |
| `OVH_AI_MODEL` | Nom exact du modèle (ex. un Mistral ou Llama récent) |
| `GITHUB_TOKEN` | Fine-grained token avec `Contents: RW` + `Pull requests: RW` sur ce repo |
| `GITHUB_REPO` | `CallMeAl3x/hackathon-ovh-team-2` |

⚠️ Aucun secret en clair dans Git — tout passe par les variables d'environnement.

## Ce que fait le script (5 temps)

1. **Lit** les `VulnerabilityReports` du namespace `demo` (CRD trivy-operator)
2. **Lit** le manifest YAML concerné dans le dépôt Git (Git = source de vérité, pas le cluster)
3. **Demande à l'IA** : rapport + manifest → manifest corrigé + explication
4. **Crée une branche** `fix/ai-remediation` + un commit avec le YAML corrigé
5. **Ouvre une Pull Request** → revue humaine → merge → Argo CD applique

## Pistes d'amélioration (par ordre de valeur)

- [ ] Boucler sur tous les rapports (+ `ConfigAuditReports` Trivy + `PolicyReports` Kyverno)
- [ ] CronJob Kubernetes (déployé via Argo CD) avec `config.load_incluster_config()` + ServiceAccount RBAC lecture seule
- [x] Éviter les PR en double
- [ ] Valider le correctif avant la PR : `kubectl apply --dry-run=server -f -` (boucle de retry avec le message d'erreur)
- [ ] Enrichir avec Falco : sur alerte critique, analyse IA + issue GitHub
