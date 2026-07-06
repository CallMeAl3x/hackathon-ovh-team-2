"""
Remédiateur IA — Hackathon OVHcloud x Ynov
Boucle : rapports Trivy -> analyse IA -> Pull Request GitHub
"""
import argparse
import logging

from ai_client import AIResponseError, ask_ai_for_fix
from config import ConfigurationError, RemediatorConfig, read_config
from git_workflow import (
    GitWorkflowError,
    build_remediation_branch_name,
    build_virtual_diff,
    commit_manifest,
    create_branch_from_ref,
    diff_manifest,
    ensure_clean_worktree,
    ensure_only_expected_changes,
    fetch_base_branch,
    push_branch,
    read_file_from_ref,
    stage_manifest,
    target_ref,
    write_manifest,
)
from trivy_client import TrivyReportError, get_vulnerability_reports, summarize_report
from validators import ManifestValidationError, validate_fixed_manifest


LOG = logging.getLogger("remediator")


def setup_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Remediate a Trivy finding with OVHcloud AI Endpoints and a GitHub PR."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate the AI remediation and show the diff without branch, commit, push or PR",
    )
    return parser.parse_args()


# ---------- Pull Request GitHub ----------

def create_pull_request(gh_repo, cfg: RemediatorConfig, branch_name: str,
                        explanation: str, report_summary: str) -> str:
    for pr in gh_repo.get_pulls(
        state="open",
        head=f"{gh_repo.owner.login}:{branch_name}",
        base=cfg.target_branch,
    ):
        LOG.info("Une PR de remédiation est déjà ouverte : %s", pr.html_url)
        return pr.html_url

    pr = gh_repo.create_pull(
        title="[IA] Remediation automatique des vulnerabilites detectees",
        body=(f"## Correctif propose par l'IA\n\n{explanation}\n\n"
              f"## Rapport Trivy ayant declenche l'analyse\n```\n{report_summary}\n```\n\n"
              "## Validations automatiques\n"
              "- Reponse IA extraite et controlee\n"
              "- Manifest YAML valide avant commit\n"
              "- Diff Git controle avant push\n\n"
              "*PR generee automatiquement — relecture humaine requise avant merge.*"),
        head=branch_name,
        base=cfg.target_branch,
    )
    return pr.html_url


# ---------- Orchestration ----------

def main():
    setup_logging()
    args = parse_args()
    cfg = read_config(require_github=not args.dry_run)
    LOG.info("Configuration chargee:\n%s", cfg.public_summary())

    if args.dry_run:
        LOG.info("Mode dry-run actif: aucun fichier de travail, commit, push ou PR.")
    else:
        ensure_clean_worktree(cfg.repo_root)

    LOG.info("Synchronisation de la branche cible %s depuis origin", cfg.target_branch)
    fetch_base_branch(cfg.repo_root, cfg.target_branch)

    reports = get_vulnerability_reports(cfg.trivy_namespace)
    if not reports:
        LOG.info("Aucun VulnerabilityReport dans le namespace %s. Trivy a-t-il fini de scanner ?",
                 cfg.trivy_namespace)
        return

    summary = summarize_report(reports[0])
    LOG.info("Rapport resume:\n%s", summary)

    base_ref = target_ref(cfg)
    manifest = read_file_from_ref(
        cfg.repo_root,
        base_ref,
        cfg.manifest_path,
    )
    LOG.info("Manifest source lu depuis %s:%s", base_ref, cfg.manifest_path)

    LOG.info("Appel a l'IA (AI Endpoints OVHcloud)...")
    explanation, fixed_yaml = ask_ai_for_fix(cfg, summary, manifest)
    validated_manifest = validate_fixed_manifest(fixed_yaml, manifest)
    LOG.info("Explication de l'IA:\n%s", explanation)
    LOG.info(
        "Manifest corrige valide: %s/%s",
        validated_manifest["kind"],
        validated_manifest["metadata"]["name"],
    )

    if args.dry_run:
        diff = build_virtual_diff(cfg.manifest_path, manifest, fixed_yaml)
        LOG.info("Diff virtuel controle avant commit:\n%s", diff)
        LOG.info("Dry-run termine: aucun fichier modifie, aucun commit, aucun push, aucune PR.")
        return

    branch_name = build_remediation_branch_name(cfg.remediation_branch_prefix)
    LOG.info("Creation de la branche de remediation: %s", branch_name)
    create_branch_from_ref(cfg.repo_root, branch_name, base_ref)

    write_manifest(cfg.repo_root, cfg.manifest_path, fixed_yaml)
    diff = diff_manifest(cfg.repo_root, cfg.manifest_path)
    LOG.info("Diff Git controle avant commit:\n%s", diff)

    ensure_only_expected_changes(cfg.repo_root, cfg.manifest_path)
    stage_manifest(cfg.repo_root, cfg.manifest_path)
    ensure_only_expected_changes(cfg.repo_root, cfg.manifest_path)
    commit_manifest(
        cfg.repo_root,
        "fix(security): remediation automatique proposee par l'IA",
    )
    push_branch(cfg.repo_root, branch_name)

    from github import Github

    gh_repo = Github(cfg.github_token).get_repo(cfg.github_repo)
    url = create_pull_request(gh_repo, cfg, branch_name, explanation, summary)
    LOG.info("Pull Request ouverte : %s", url)


if __name__ == "__main__":
    try:
        main()
    except ConfigurationError as exc:
        setup_logging()
        LOG.error("%s", exc)
        raise SystemExit(2) from exc
    except ManifestValidationError as exc:
        setup_logging()
        LOG.error("Manifest IA refuse: %s", exc)
        raise SystemExit(3) from exc
    except AIResponseError as exc:
        setup_logging()
        LOG.error("Reponse IA invalide: %s", exc)
        raise SystemExit(4) from exc
    except TrivyReportError as exc:
        setup_logging()
        LOG.error("Rapport Trivy invalide: %s", exc)
        raise SystemExit(5) from exc
    except GitWorkflowError as exc:
        setup_logging()
        LOG.error("Workflow Git interrompu: %s", exc)
        raise SystemExit(6) from exc
