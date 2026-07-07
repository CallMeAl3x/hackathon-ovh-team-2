# Rapport d'architecture — Chaîne d'audit et de remédiation GitOps sécurisée

**Hackathon Lille Ynov Campus × OVHcloud — 6 & 7 juillet 2026 — Team 2**

## Situation & problématique

**Situation.** Une équipe plateforme peu nombreuse gère plusieurs clusters et croule
sous les findings Trivy/Kyverno. Elle veut automatiser la remédiation par IA générative
pour tenir la charge — mais ne peut pas risquer qu'une IA casse la production.

**Problématique.**
> Peut-on automatiser la remédiation des vulnérabilités par IA tout en se méfiant de
> l'IA elle-même — c'est-à-dire en corrigeant automatiquement son correctif s'il casse la prod ?

Le sujet impose une IA qui *propose* un correctif. Notre angle va au-delà : nous traitons
l'IA comme **faillible**. La question n'est pas « l'IA sait-elle corriger ? » mais
« que se passe-t-il **quand elle se trompe**, et comment la chaîne l'encaisse ? »

## Notre angle : une boucle qui se méfie de son IA

Lors de la démonstration, l'IA a produit un correctif **sécurisé mais non fonctionnel**
(image non-root sur un port privilégié → pod en CrashLoopBackOff). Trois garde-fous
ont empêché tout dégât, et un quatrième est prévu :

1. **Revue humaine** — aucun correctif n'est mergé sans validation d'un humain.
2. **Rolling update + readiness (Kubernetes)** — le nouveau pod doit être *Ready* avant
   que l'ancien soit supprimé : le pod cassé n'a jamais coupé le service.
3. **Auto-correction** — le remédiateur détecte le pod en échec, capture l'erreur runtime
   et la **renvoie à l'IA**, qui corrige son propre correctif (PR suivante).
4. **(Évolution)** — un environnement de **pré-prod** où le correctif est validé avant
   d'être promu, pour couvrir aussi un correctif qui *démarre mais est cassé*.

## La boucle

> Détection d'une faille → analyse & correctif par l'IA → Pull Request automatique
> → revue humaine → merge → resynchronisation Argo CD → cluster corrigé

```
┌──────────────────────── Cluster Kubernetes OVHcloud ────────────────────────┐
│                                                                             │
│  ┌─────────┐   ┌────────────────┐   ┌─────────┐  ┌───────┐                  │
│  │ Argo CD │   │ Trivy-operator │   │ Kyverno │  │ Falco │                  │
│  │ (GitOps)│   │ (scan vulnéra.)│   │(policies)│ │(runtime)│                │
│  └────┬────┘   └───────┬────────┘   └────┬────┘  └───┬───┘                  │
│       │                │                 └─────┬─────┘                      │
│       │                ▼                 ┌─────┴──────┐                     │
│       │        ┌───────────────┐         │ Prometheus │                     │
│       │        │  Remédiateur  │────────▶│ (métriques)│                     │
│       │        │  (notre code) │         └────────────┘                     │
│       │        └───────┬───────┘                                            │
│       │                │            ┌──────────────────┐                    │
│       │                └───────────▶│ AI Endpoints OVH │                    │
│       │                             │  (IA générative) │                    │
│       │                ouvre une PR └──────────────────┘                    │
└───────┼────────────────┬────────────────────────────────────────────────────┘
        │                ▼
        │         ┌─────────────┐
        └─────────│  Dépôt Git  │◀── revue humaine + merge
       synchronise│   (GitHub)  │
                  └─────────────┘
```

## Rôle de chaque brique

- **Argo CD** — source de vérité unique : le cluster est en permanence l'image du
  dépôt Git (pattern *app-of-apps* : `root-app.yaml` → `infra/argocd-apps/`).
  `prune` + `selfHeal` garantissent qu'un drift manuel est réparé automatiquement.
- **Trivy-operator** — scanne en continu images (CVE) et configurations, publie
  des CRD `VulnerabilityReport` / `ConfigAuditReport` : la matière première du remédiateur.
- **Kyverno** — policy-as-code à l'admission, 3 policies en mode `Audit`
  (privileged, limits, tag latest). Les `PolicyReports` sont une deuxième source de données.
- **Prometheus + Grafana** — la métrique `trivy_image_vulnerabilities` permet de
  tracer « CVE critiques au fil du temps » : la courbe chute au merge de la PR.
- **Falco** — détection runtime (eBPF `modern_ebpf`) : complète l'analyse statique
  par le comportemental (shell dans un conteneur, lecture de /etc/shadow…).
- **AI Endpoints OVHcloud** — API compatible OpenAI ; analyse rapport + manifest
  et produit le YAML corrigé avec explication.
- **Remédiateur** (`apps/remediator/`) — notre code : il ferme la boucle en
  ouvrant une PR GitHub que valide un humain avant merge.

## Nos choix (et pourquoi)

- **Trivy plutôt que Kubescape** : rapports en CRD simples à consommer par script.
- **Kyverno en `Audit` et pas `Enforce`** : en Enforce, l'app vulnérable serait
  bloquée à l'admission et il n'y aurait plus rien à démontrer.
- **Revue humaine obligatoire avant merge** : garde-fou pour empêcher une IA de
  pousser un correctif cassé en production ; c'est un choix d'architecture, pas une limite.
- **Aucun secret dans Git** : tokens IA/GitHub en variables d'environnement,
  kubeconfig hors dépôt.

## Tableau récapitulatif du statut CNCF

| Composant | Rôle dans la chaîne | Statut CNCF |
|---|---|---|
| Argo CD | GitOps — synchronisation Git → cluster | Graduated |
| Trivy-operator | Audit de sécurité (CVE + config) | Projet Aqua Security, scanner validé CNCF |
| Kyverno | Policy-as-code | Graduated |
| Falco | Détection de menaces runtime | Graduated |
| Prometheus | Observabilité & métriques | Graduated |
| AI Endpoints | Couche d'IA générative | OVHcloud (hors CNCF) |

## Limites & améliorations possibles

- Le remédiateur traite le premier `VulnerabilityReport` : boucler sur tous les
  rapports (+ ConfigAudit + PolicyReports Kyverno).
- Déclenchement manuel : en faire un CronJob in-cluster (ServiceAccount RBAC
  lecture seule, `load_incluster_config`), déployé via Argo CD.
- Valider le YAML de l'IA par `kubectl apply --dry-run=server` avant d'ouvrir la PR.
- Secrets : passer à External Secrets Operator (CNCF Incubating).
- Enrichir avec Falco : alerte critique → analyse IA → issue GitHub.
