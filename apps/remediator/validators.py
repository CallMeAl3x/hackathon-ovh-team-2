"""
Validation helpers for AI-generated Kubernetes manifests.
"""
from __future__ import annotations

from typing import Any

import yaml


class ManifestValidationError(ValueError):
    pass


def validate_fixed_manifest(fixed_yaml: str, original_yaml: str) -> dict[str, Any]:
    """Validate that the AI output is still the expected Kubernetes Deployment."""
    original = _load_single_document(original_yaml, "original manifest")
    fixed = _load_single_document(fixed_yaml, "fixed manifest")

    _validate_identity(original, fixed)
    _validate_pod_template(fixed)

    return fixed


def _load_single_document(yaml_text: str, label: str) -> dict[str, Any]:
    try:
        docs = list(yaml.safe_load_all(yaml_text))
    except yaml.YAMLError as exc:
        raise ManifestValidationError(f"{label}: invalid YAML: {exc}") from exc

    if len(docs) != 1:
        raise ManifestValidationError(f"{label}: expected exactly one YAML document")

    document = docs[0]
    if not isinstance(document, dict):
        raise ManifestValidationError(f"{label}: expected a YAML mapping")

    return document


def _validate_identity(original: dict[str, Any], fixed: dict[str, Any]) -> None:
    if fixed.get("apiVersion") != "apps/v1":
        raise ManifestValidationError("fixed manifest: apiVersion must be apps/v1")
    if fixed.get("kind") != "Deployment":
        raise ManifestValidationError("fixed manifest: kind must be Deployment")

    _require_equal(original, fixed, ("apiVersion",))
    _require_equal(original, fixed, ("kind",))
    _require_equal(original, fixed, ("metadata", "name"))
    _require_equal(original, fixed, ("metadata", "namespace"))
    _require_equal(original, fixed, ("spec", "selector", "matchLabels"))
    _require_equal(original, fixed, ("spec", "template", "metadata", "labels"))

    original_names = _container_names(original, "original manifest")
    fixed_names = _container_names(fixed, "fixed manifest")
    if fixed_names != original_names:
        raise ManifestValidationError(
            f"fixed manifest: container names changed from {original_names} to {fixed_names}"
        )


def _validate_pod_template(document: dict[str, Any]) -> None:
    pod_spec = _required_mapping(document, ("spec", "template", "spec"))

    for field in ("hostNetwork", "hostPID", "hostIPC"):
        if pod_spec.get(field) is True:
            raise ManifestValidationError(f"fixed manifest: {field} must not be true")

    for volume in pod_spec.get("volumes", []) or []:
        if isinstance(volume, dict) and "hostPath" in volume:
            raise ManifestValidationError("fixed manifest: hostPath volumes are not allowed")

    pod_security_context = pod_spec.get("securityContext") or {}
    if not isinstance(pod_security_context, dict):
        raise ManifestValidationError("fixed manifest: pod securityContext must be a mapping")
    if pod_security_context.get("runAsUser") == 0:
        raise ManifestValidationError("fixed manifest: pod must not run as root")

    containers = _required_list(document, ("spec", "template", "spec", "containers"))
    if not containers:
        raise ManifestValidationError("fixed manifest: at least one container is required")

    for container in containers:
        if not isinstance(container, dict):
            raise ManifestValidationError("fixed manifest: each container must be a mapping")
        _validate_container(container, pod_security_context)


def _validate_container(container: dict[str, Any], pod_security_context: dict[str, Any]) -> None:
    name = container.get("name", "<unknown>")
    image = container.get("image")
    if not isinstance(image, str) or not image:
        raise ManifestValidationError(f"container {name}: image is required")
    if image.endswith(":latest"):
        raise ManifestValidationError(f"container {name}: image tag :latest is not allowed")

    security_context = container.get("securityContext") or {}
    if not isinstance(security_context, dict):
        raise ManifestValidationError(f"container {name}: securityContext must be a mapping")
    if security_context.get("privileged") is True:
        raise ManifestValidationError(f"container {name}: privileged must not be true")
    if security_context.get("runAsUser") == 0:
        raise ManifestValidationError(f"container {name}: runAsUser must not be 0")

    run_as_non_root = security_context.get(
        "runAsNonRoot",
        pod_security_context.get("runAsNonRoot"),
    )
    run_as_user = security_context.get(
        "runAsUser",
        pod_security_context.get("runAsUser"),
    )
    if run_as_non_root is not True and not _is_non_root_user(run_as_user):
        raise ManifestValidationError(
            f"container {name}: runAsNonRoot true or a non-root runAsUser is required"
        )

    resources = container.get("resources")
    if not isinstance(resources, dict):
        raise ManifestValidationError(f"container {name}: resources are required")
    for section in ("requests", "limits"):
        values = resources.get(section)
        if not isinstance(values, dict):
            raise ManifestValidationError(f"container {name}: resources.{section} is required")
        for key in ("cpu", "memory"):
            if not values.get(key):
                raise ManifestValidationError(
                    f"container {name}: resources.{section}.{key} is required"
                )


def _is_non_root_user(value: Any) -> bool:
    if isinstance(value, int):
        return value > 0
    if isinstance(value, str) and value.isdigit():
        return int(value) > 0
    return False


def _container_names(document: dict[str, Any], label: str) -> list[str]:
    containers = _required_list(document, ("spec", "template", "spec", "containers"))
    names: list[str] = []
    for container in containers:
        if not isinstance(container, dict) or not isinstance(container.get("name"), str):
            raise ManifestValidationError(f"{label}: every container must have a name")
        names.append(container["name"])
    return names


def _require_equal(
    original: dict[str, Any],
    fixed: dict[str, Any],
    path: tuple[str, ...],
) -> None:
    original_value = _required_value(original, path, "original manifest")
    fixed_value = _required_value(fixed, path, "fixed manifest")
    if fixed_value != original_value:
        dotted_path = ".".join(path)
        raise ManifestValidationError(
            f"fixed manifest: {dotted_path} changed from {original_value!r} to {fixed_value!r}"
        )


def _required_mapping(document: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    value = _required_value(document, path, "fixed manifest")
    if not isinstance(value, dict):
        raise ManifestValidationError(f"fixed manifest: {'.'.join(path)} must be a mapping")
    return value


def _required_list(document: dict[str, Any], path: tuple[str, ...]) -> list[Any]:
    value = _required_value(document, path, "fixed manifest")
    if not isinstance(value, list):
        raise ManifestValidationError(f"fixed manifest: {'.'.join(path)} must be a list")
    return value


def _required_value(document: dict[str, Any], path: tuple[str, ...], label: str) -> Any:
    current: Any = document
    for part in path:
        if not isinstance(current, dict) or part not in current:
            raise ManifestValidationError(f"{label}: missing {'.'.join(path)}")
        current = current[part]
    return current
