from dataclasses import dataclass
from pathlib import Path
import os


class ConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class RemediatorConfig:
    repo_root: Path
    manifest_path: str
    target_branch: str
    trivy_namespace: str
    remediation_branch_prefix: str

    ovh_ai_token: str
    ovh_ai_base_url: str
    ovh_ai_model: str

    github_token: str
    github_repo: str

    @property
    def manifest_abspath(self) -> Path:
        path = (self.repo_root / self.manifest_path).resolve()
        try:
            path.relative_to(self.repo_root)
        except ValueError as exc:
            raise ConfigurationError(
                f"Manifest path is outside the repository: {self.manifest_path}"
            ) from exc
        return path

    def public_summary(self) -> str:
        return (
            f"repo_root={self.repo_root}\n"
            f"manifest_path={self.manifest_path}\n"
            f"target_branch={self.target_branch}\n"
            f"trivy_namespace={self.trivy_namespace}\n"
            f"remediation_branch_prefix={self.remediation_branch_prefix}\n"
            f"ovh_ai_base_url={self.ovh_ai_base_url}\n"
            f"ovh_ai_model={self.ovh_ai_model}\n"
            f"github_repo={self.github_repo}"
        )


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"Missing required environment variable: {name}")
    return value


def read_config(require_github: bool = True) -> RemediatorConfig:
    repo_root = Path(__file__).resolve().parents[2]

    return RemediatorConfig(
        repo_root=repo_root,
        manifest_path=os.environ.get(
            "MANIFEST_PATH",
            "apps/vulnerable-app/deployment.yaml",
        ),
        target_branch=os.environ.get("TARGET_BRANCH", "main"),
        trivy_namespace=os.environ.get("TRIVY_NAMESPACE", "demo"),
        remediation_branch_prefix=os.environ.get(
            "REMEDIATION_BRANCH_PREFIX",
            "fix/ai-remediation",
        ),
        ovh_ai_token=_required_env("OVH_AI_TOKEN"),
        ovh_ai_base_url=_required_env("OVH_AI_BASE_URL"),
        ovh_ai_model=_required_env("OVH_AI_MODEL"),
        github_token=_github_env("GITHUB_TOKEN", require_github),
        github_repo=_github_env("GITHUB_REPO", require_github),
    )


def _github_env(name: str, required: bool) -> str:
    if required:
        return _required_env(name)
    return os.environ.get(name, "").strip()
