"""
Controlled local Git workflow for remediation branches.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import difflib
import subprocess

from config import RemediatorConfig


class GitWorkflowError(RuntimeError):
    pass


@dataclass(frozen=True)
class GitCommandResult:
    returncode: int
    stdout: str
    stderr: str


def build_remediation_branch_name(prefix: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{timestamp}"


def target_ref(cfg: RemediatorConfig) -> str:
    return f"origin/{cfg.target_branch}"


def fetch_base_branch(repo_root: Path, target_branch: str) -> None:
    _git(repo_root, "fetch", "origin", target_branch)


def ensure_clean_worktree(repo_root: Path) -> None:
    status = _git(repo_root, "status", "--porcelain").stdout.strip()
    if status:
        raise GitWorkflowError(
            "Working tree is not clean. Commit or stash local changes before remediation.\n"
            + status
        )


def read_file_from_ref(repo_root: Path, ref: str, relative_path: str) -> str:
    _validate_relative_path(repo_root, relative_path)
    return _git(repo_root, "show", f"{ref}:{relative_path}").stdout


def create_branch_from_ref(repo_root: Path, branch_name: str, ref: str) -> None:
    result = _git(
        repo_root,
        "show-ref",
        "--verify",
        "--quiet",
        f"refs/heads/{branch_name}",
        check=False,
    )
    if result.returncode == 0:
        raise GitWorkflowError(f"Local branch already exists: {branch_name}")
    if result.returncode not in (0, 1):
        raise GitWorkflowError(result.stderr.strip())
    _git(repo_root, "switch", "--create", branch_name, ref)


def write_manifest(repo_root: Path, relative_path: str, content: str) -> None:
    path = _validate_relative_path(repo_root, relative_path)
    path.write_text(content, encoding="utf-8")


def diff_manifest(repo_root: Path, relative_path: str) -> str:
    _validate_relative_path(repo_root, relative_path)
    diff = _git(repo_root, "diff", "--", relative_path).stdout
    if not diff.strip():
        raise GitWorkflowError("No manifest change detected after AI remediation")
    return diff


def build_virtual_diff(relative_path: str, original_content: str, fixed_content: str) -> str:
    diff = "".join(
        difflib.unified_diff(
            original_content.splitlines(keepends=True),
            fixed_content.splitlines(keepends=True),
            fromfile=f"a/{relative_path}",
            tofile=f"b/{relative_path}",
        )
    )
    if not diff.strip():
        raise GitWorkflowError("No manifest change detected after AI remediation")
    return diff


def ensure_only_expected_changes(repo_root: Path, expected_path: str) -> None:
    expected = expected_path.replace("\\", "/")
    status = _git(repo_root, "status", "--porcelain").stdout.splitlines()
    unexpected: list[str] = []

    for line in status:
        if not line:
            continue
        path = line[3:].strip().replace("\\", "/")
        if path != expected:
            unexpected.append(line)

    if unexpected:
        raise GitWorkflowError(
            "Unexpected files changed during remediation:\n" + "\n".join(unexpected)
        )


def stage_manifest(repo_root: Path, relative_path: str) -> None:
    _validate_relative_path(repo_root, relative_path)
    _git(repo_root, "add", "--", relative_path)


def commit_manifest(repo_root: Path, message: str) -> None:
    _git(repo_root, "commit", "-m", message)


def push_branch(repo_root: Path, branch_name: str) -> None:
    _git(repo_root, "push", "--set-upstream", "origin", branch_name)


def _validate_relative_path(repo_root: Path, relative_path: str) -> Path:
    path = (repo_root / relative_path).resolve()
    try:
        path.relative_to(repo_root)
    except ValueError as exc:
        raise GitWorkflowError(f"Path is outside repository: {relative_path}") from exc
    return path


def _git(repo_root: Path, *args: str, check: bool = True) -> GitCommandResult:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if check and completed.returncode != 0:
        command = "git " + " ".join(args)
        details = completed.stderr.strip() or completed.stdout.strip()
        raise GitWorkflowError(f"{command} failed: {details}")
    return GitCommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
