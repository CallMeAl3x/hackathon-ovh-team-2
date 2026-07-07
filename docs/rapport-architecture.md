# Rapport d'architecture — Chaîne d'audit et de remédiation GitOps sécurisée

**Hackathon Lille Ynov Campus × OVHcloud — 6 & 7 juillet 2026 — Team 2**

## Problématique

Une petite équipe qui gère plusieurs clusters doit traiter beaucoup de vulnérabilités
remontées par Trivy et Kyverno. Automatiser la correction avec une IA aide à suivre le
rythme, mais une IA ne doit pas pouvoir modifier la production sans contrôle.

Notre question n'est pas de savoir si l'IA sait corriger une faille (le sujet le demande),
mais si on peut lui faire confiance, et ce qui se passe quand elle se trompe. On part du
principe que l'IA peut proposer un mauvais correctif, et on construit la chaîne pour gérer
ce cas.

C'est ce qui est arrivé pendant nos tests : l'IA a proposé un correctif correct pour la
sécurité mais qui empêchait le conteneur de démarrer. La production n'a pas été coupée pour
autant, pour trois raisons :

- le merge est manuel, donc quelqu'un relit avant que ce soit appliqué ;
- Kubernetes ne supprime l'ancien pod que si le nouveau démarre correctement, donc le pod
  cassé n'a pas remplacé celui qui marchait ;
- le remédiateur voit que le pod ne démarre pas, récupère l'erreur et la renvoie à l'IA,
  qui corrige son correctif dans une nouvelle Pull Request.

Avec plus de temps, l'étape suivante serait un environnement de test où l'on vérifie le
correctif avant de le mettre en production.

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
