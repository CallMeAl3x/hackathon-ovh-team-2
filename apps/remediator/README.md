# Remédiateur IA

Le cœur de la boucle : lit les `VulnerabilityReports` de Trivy dans le cluster,
demande un correctif à l'IA (AI Endpoints OVHcloud), et ouvre une Pull Request
avec le manifest corrigé + l'explication.

## Lancer

```bash
pip install -r requirements.txt
cp .env.example .env   # remplir les valeurs, puis :
source .env
python3 remediator.py --dry-run
```

Le mode `--dry-run` valide toute la chaîne et affiche le diff proposé, mais ne
crée pas de branche, ne commit pas, ne push pas et n'ouvre pas de PR.

Quand le dry-run est validé :

```bash
python3 remediator.py
```

## Variables d'environnement

| Variable | Rôle |
|---|---|
| `OVH_AI_TOKEN` | Clé d'API AI Endpoints (manager OVHcloud → Public Cloud → AI Endpoints) |
| `OVH_AI_BASE_URL` | URL de base du modèle (sur la fiche du modèle, se termine par `/v1`) |
| `OVH_AI_MODEL` | Nom exact du modèle (ex. un Mistral ou Llama récent) |
| `GITHUB_TOKEN` | Requis hors dry-run : fine-grained token avec `Contents: RW` + `Pull requests: RW` sur ce repo |
| `GITHUB_REPO` | Requis hors dry-run : `CallMeAl3x/hackathon-ovh-team-2` |

⚠️ Aucun secret en clair dans Git — tout passe par les variables d'environnement.

## Ce que fait le script

1. **Lit** les `VulnerabilityReports` du namespace `demo` (CRD trivy-operator).
2. **Lit** le manifest YAML depuis `origin/main` (Git = source de vérité).
3. **Demande à l'IA** : rapport + manifest → manifest corrigé + explication.
4. **Valide** la réponse IA et le YAML Kubernetes avant toute modification.
5. **Affiche le diff** pour contrôler le correctif proposé.
6. **Crée une branche** `fix/ai-remediation-YYYYMMDD-HHMMSS`.
7. **Commit uniquement le manifest concerné** (`git add` ciblé, jamais `git add .`).
8. **Push la branche** et **ouvre une Pull Request** vers `main`.
9. **S'arrête** : le merge reste manuel, puis Argo CD synchronise le cluster.

## Scripts

- `config.py` : lit les variables d'environnement et refuse de démarrer si un secret manque.
- `trivy_client.py` : récupère et résume les rapports Trivy.
- `ai_client.py` : appelle OVHcloud AI Endpoints et extrait l'explication + le YAML.
- `validators.py` : refuse un YAML dangereux ou incohérent.
- `git_workflow.py` : gère branche, diff, `git add` ciblé, commit et push.
- `remediator.py` : orchestre toutes les étapes.

## Pistes d'amélioration (par ordre de valeur)

- [ ] Boucler sur tous les rapports (+ `ConfigAuditReports` Trivy + `PolicyReports` Kyverno)
- [ ] CronJob Kubernetes (déployé via Argo CD) avec `config.load_incluster_config()` + ServiceAccount RBAC lecture seule
- [x] Éviter les PR en double
- [ ] Valider le correctif avant la PR : `kubectl apply --dry-run=server -f -` (boucle de retry avec le message d'erreur)
- [ ] Enrichir avec Falco : sur alerte critique, analyse IA + issue GitHub
