"""
Trivy Operator report retrieval and summarization.
"""
from __future__ import annotations

from typing import Any


class TrivyReportError(ValueError):
    pass


def get_vulnerability_reports(namespace: str) -> list[dict[str, Any]]:
    """Read Trivy Operator VulnerabilityReport CRDs from the target namespace."""
    from kubernetes import client, config as kube_config

    kube_config.load_kube_config()
    api = client.CustomObjectsApi()
    reports = api.list_namespaced_custom_object(
        group="aquasecurity.github.io",
        version="v1alpha1",
        namespace=namespace,
        plural="vulnerabilityreports",
    )
    items = reports.get("items", [])
    if not isinstance(items, list):
        raise TrivyReportError("Trivy API returned an invalid VulnerabilityReport list")
    return items


def summarize_report(report: dict[str, Any], max_cves: int = 15) -> str:
    """Summarize one Trivy VulnerabilityReport for the AI prompt."""
    report_body = _required_mapping(report, ("report",))
    vulnerabilities = report_body.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise TrivyReportError("VulnerabilityReport report.vulnerabilities must be a list")

    sorted_vulnerabilities = sorted(
        vulnerabilities,
        key=lambda vulnerability: _severity_order(vulnerability.get("severity")),
    )

    artifact = report_body.get("artifact", {})
    if not isinstance(artifact, dict):
        artifact = {}

    lines = [
        f"Workload: {_workload_name(report)}",
        f"Image scannee: {artifact.get('repository', '?')}:{artifact.get('tag', '?')}",
        f"Total: {len(vulnerabilities)} vulnerabilites.",
        "Principales CVE (severite, paquet, version installee -> version corrigee):",
    ]

    for vulnerability in sorted_vulnerabilities[:max_cves]:
        if not isinstance(vulnerability, dict):
            continue
        lines.append(
            f"- {vulnerability.get('vulnerabilityID', '?')} "
            f"[{vulnerability.get('severity', '?')}] "
            f"{vulnerability.get('resource', '?')} "
            f"{vulnerability.get('installedVersion', '?')} -> "
            f"fix: {vulnerability.get('fixedVersion', 'n/a')}"
        )

    return "\n".join(lines)


def _workload_name(report: dict[str, Any]) -> str:
    metadata = report.get("metadata", {})
    if not isinstance(metadata, dict):
        return "?"
    labels = metadata.get("labels", {})
    if not isinstance(labels, dict):
        return "?"
    return labels.get("trivy-operator.resource.name", "?")


def _severity_order(severity: Any) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    if not isinstance(severity, str):
        return 9
    return order.get(severity.upper(), 9)


def _required_mapping(document: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    current: Any = document
    for part in path:
        if not isinstance(current, dict) or part not in current:
            raise TrivyReportError(f"VulnerabilityReport missing {'.'.join(path)}")
        current = current[part]
    if not isinstance(current, dict):
        raise TrivyReportError(f"VulnerabilityReport {'.'.join(path)} must be a mapping")
    return current
