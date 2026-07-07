"""
Remédiateur IA — Hackathon OVHcloud x Ynov
Boucle : rapports Trivy -> analyse IA -> Pull Request GitHub
"""
import os
import re
import yaml
from kubernetes import client, config
from openai import OpenAI
from github import Github

# ---------- 1. Lire les rapports Trivy dans le cluster ----------

def get_vulnerability_reports(namespace: str = "demo") -> list[dict]:
    """Récupère les VulnerabilityReports (CRD de trivy-operator)."""
    config.load_kube_config()  # utilise ~/.kube/config
    api = client.CustomObjectsApi()
    reports = api.list_namespaced_custom_object(
        group="aquasecurity.github.io",
        version="v1alpha1",
        namespace=namespace,
        plural="vulnerabilityreports",
    )
    return reports["items"]


def summarize_report(report: dict, max_cves: int = 15) -> str:
    """Résume un rapport en texte compact pour le prompt (on ne garde que l'essentiel)."""
    vulns = report["report"]["vulnerabilities"]
    # Tri : les plus graves d'abord
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    vulns.sort(key=lambda v: order.get(v["severity"], 9))
    lines = [
        f"Workload: {report['metadata']['labels'].get('trivy-operator.resource.name', '?')}",
        f"Image scannee: {report['report']['artifact']['repository']}:"
        f"{report['report']['artifact'].get('tag', '?')}",
        f"Total: {len(vulns)} vulnerabilites.",
        "Principales CVE (severite, paquet, version installee -> version corrigee):",
    ]
    for v in vulns[:max_cves]:
        lines.append(
            f"- {v['vulnerabilityID']} [{v['severity']}] {v['resource']} "
            f"{v.get('installedVersion', '?')} -> fix: {v.get('fixedVersion', 'n/a')}"
        )
    return "\n".join(lines)


# ---------- 1bis. Détecter un correctif précédent qui casse le workload ----------

def get_runtime_failure(namespace: str = "demo") -> str | None:
    """Si un pod est en échec (CrashLoopBackOff/Error), renvoie un extrait de logs
    à donner à l'IA : elle pourra corriger un correctif précédent non fonctionnel.
    C'est ce qui rend la boucle *auto-corrective* (feedback runtime -> IA)."""
    core = client.CoreV1Api()
    for p in core.list_namespaced_pod(namespace).items:
        for cs in (p.status.container_statuses or []):
            w = cs.state.waiting
            if w and w.reason in ("CrashLoopBackOff", "Error",
                                  "RunContainerError", "CreateContainerError"):
                name = p.metadata.name
                try:  # 'previous=True' : logs de l'instance qui a crashé
                    logs = core.read_namespaced_pod_log(name, namespace, tail_lines=15, previous=True)
                except Exception:
                    try:
                        logs = core.read_namespaced_pod_log(name, namespace, tail_lines=15)
                    except Exception:
                        logs = "(logs indisponibles)"
                return f"Pod {name} en {w.reason}.\nLogs:\n{logs.strip()}"
    return None


# ---------- 2. Lire le manifest actuel depuis GitHub ----------

MANIFEST_PATH = "apps/vulnerable-app/deployment.yaml"


def get_manifest_from_github(gh_repo) -> tuple[str, str]:
    f = gh_repo.get_contents(MANIFEST_PATH, ref="main")
    return f.decoded_content.decode(), f.sha


# ---------- 3. Demander le correctif à l'IA ----------

SYSTEM_PROMPT = """Tu es un expert en securite Kubernetes.
On te donne : (1) un resume de vulnerabilites detectees par Trivy,
(2) le manifest YAML actuel du workload concerne,
(3) OPTIONNEL : l'erreur d'execution d'un correctif precedent (pod en echec).
Ta mission :
- Proposer le manifest YAML CORRIGE : mets a jour l'image vers une version
  recente corrigeant les CVE, supprime privileged, fais tourner le conteneur
  en utilisateur non-root, ajoute des requests/limits CPU et memoire raisonnables.
- IMPERATIF : le correctif doit REELLEMENT DEMARRER. Une image non-root ne peut
  ni ecrire dans les repertoires systeme (ex. /var/cache/nginx) ni binder un port
  < 1024. Si tu passes le conteneur en non-root, choisis une image concue pour cela
  (ex. nginxinc/nginx-unprivileged) et un containerPort > 1024 (ex. 8080).
  Si une erreur d'execution t'est fournie, corrige-la explicitement.
- Le YAML doit rester un Deployment valide et minimal (memes noms, memes labels).
Reponds STRICTEMENT dans ce format :
EXPLICATION:
<3 a 6 lignes en francais expliquant chaque correction>
YAML:
```yaml
<le manifest complet corrige>
```"""


def ask_ai_for_fix(ai: OpenAI, report_summary: str, current_manifest: str,
                   runtime_failure: str | None = None, max_tries: int = 3) -> tuple[str, str]:
    user_content = f"RAPPORT TRIVY:\n{report_summary}\n\nMANIFEST ACTUEL:\n{current_manifest}"
    if runtime_failure:
        user_content += ("\n\nERREUR D'EXECUTION DU CORRECTIF PRECEDENT "
                         f"(a corriger imperativement):\n{runtime_failure}")

    # Retry : si l'IA renvoie un YAML invalide, on lui renvoie l'erreur et on redemande.
    # Le cas normal (YAML valide) sort au 1er tour, comportement identique a avant.
    last_error = None
    for tentative in range(1, max_tries + 1):
        content = user_content
        if last_error:
            content += ("\n\nTON YAML PRECEDENT ETAIT INVALIDE. Corrige-le et renvoie "
                        f"un YAML valide. Erreur rencontree :\n{last_error}")
        resp = ai.chat.completions.create(
            model=os.environ["OVH_AI_MODEL"],
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": content},
            ],
            temperature=0.2,   # peu de creativite : on veut du YAML fiable
            max_tokens=2000,
        )
        text = resp.choices[0].message.content
        try:
            explanation = text.split("EXPLICATION:")[1].split("YAML:")[0].strip()
            match = re.search(r"```yaml\n(.*?)```", text, re.DOTALL)
            if not match:
                raise ValueError("aucun bloc YAML dans la reponse")
            fixed_yaml = match.group(1).strip() + "\n"
            yaml.safe_load(fixed_yaml)  # garde-fou : le YAML doit etre parsable
            return explanation, fixed_yaml
        except Exception as e:
            last_error = str(e)
            print(f"  ⚠ tentative {tentative}/{max_tries} : YAML invalide "
                  f"({last_error}) — on redemande a l'IA")

    raise ValueError(f"L'IA n'a pas produit de YAML valide apres {max_tries} tentatives. "
                     f"Derniere erreur : {last_error}")


# ---------- 4 & 5. Brancher, committer, ouvrir la PR ----------

def open_pull_request(gh_repo, file_sha: str, fixed_yaml: str,
                      explanation: str, report_summary: str) -> str:
    main = gh_repo.get_branch("main")
    branch = "fix/ai-remediation"

    # Évite les PR en double : si une PR de remédiation est déjà ouverte, on s'arrête
    for pr in gh_repo.get_pulls(state="open", head=f"{gh_repo.owner.login}:{branch}"):
        print(f"Une PR de remédiation est déjà ouverte : {pr.html_url}")
        return pr.html_url

    # (Re)cree la branche depuis main
    try:
        gh_repo.get_git_ref(f"heads/{branch}").delete()
    except Exception:
        pass
    gh_repo.create_git_ref(ref=f"refs/heads/{branch}", sha=main.commit.sha)

    gh_repo.update_file(
        path=MANIFEST_PATH,
        message="fix(security): remediation automatique proposee par l'IA",
        content=fixed_yaml,
        sha=file_sha,
        branch=branch,
    )
    pr = gh_repo.create_pull(
        title="[IA] Remediation automatique des vulnerabilites detectees",
        body=(f"## Correctif propose par l'IA\n\n{explanation}\n\n"
              f"## Rapport Trivy ayant declenche l'analyse\n```\n{report_summary}\n```\n\n"
              f"*PR generee automatiquement — relecture humaine requise avant merge.*"),
        head=branch,
        base="main",
    )
    return pr.html_url


# ---------- Orchestration ----------

def main():
    ai = OpenAI(base_url=os.environ["OVH_AI_BASE_URL"],
                api_key=os.environ["OVH_AI_TOKEN"])
    gh_repo = Github(os.environ["GITHUB_TOKEN"]).get_repo(os.environ["GITHUB_REPO"])

    reports = get_vulnerability_reports("demo")
    if not reports:
        print("Aucun VulnerabilityReport dans le namespace demo. Trivy a-t-il fini de scanner ?")
        return

    summary = summarize_report(reports[0])
    print("=== Rapport resume ===\n" + summary)

    manifest, sha = get_manifest_from_github(gh_repo)

    # Boucle auto-corrective : si un correctif precedent a casse le workload,
    # on renvoie l'erreur d'execution a l'IA pour qu'elle la corrige.
    runtime_failure = get_runtime_failure("demo")
    if runtime_failure:
        print("\n=== Echec d'execution detecte (feedback pour l'IA) ===\n" + runtime_failure)

    print("\n=== Appel a l'IA (AI Endpoints OVHcloud)... ===")
    explanation, fixed_yaml = ask_ai_for_fix(ai, summary, manifest, runtime_failure)
    print("\n=== Explication de l'IA ===\n" + explanation)

    url = open_pull_request(gh_repo, sha, fixed_yaml, explanation, summary)
    print(f"\n✅ Pull Request ouverte : {url}")


if __name__ == "__main__":
    main()
