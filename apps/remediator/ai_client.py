"""
OVHcloud AI Endpoints integration.
"""
from __future__ import annotations

import re

from config import RemediatorConfig


class AIResponseError(ValueError):
    pass


SYSTEM_PROMPT = """Tu es un expert en securite Kubernetes.
On te donne : (1) un resume de vulnerabilites detectees par Trivy,
(2) le manifest YAML actuel du workload concerne.
Ta mission :
- Proposer le manifest YAML CORRIGE : mets a jour l'image vers une version
  recente corrigeant les CVE, supprime privileged, fais tourner le conteneur
  en utilisateur non-root, ajoute des requests/limits CPU et memoire raisonnables.
- Le YAML doit rester un Deployment valide et minimal (memes noms, memes labels).
Reponds STRICTEMENT dans ce format :
EXPLICATION:
<3 a 6 lignes en francais expliquant chaque correction>
YAML:
```yaml
<le manifest complet corrige>
```"""


def ask_ai_for_fix(
    cfg: RemediatorConfig,
    report_summary: str,
    current_manifest: str,
) -> tuple[str, str]:
    from openai import OpenAI

    client = OpenAI(base_url=cfg.ovh_ai_base_url, api_key=cfg.ovh_ai_token)
    response = client.chat.completions.create(
        model=cfg.ovh_ai_model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"RAPPORT TRIVY:\n{report_summary}\n\n"
                    f"MANIFEST ACTUEL:\n{current_manifest}"
                ),
            },
        ],
        temperature=0.2,
        max_tokens=2000,
    )

    content = response.choices[0].message.content
    if not content:
        raise AIResponseError("AI response is empty")

    return extract_ai_response(content)


def extract_ai_response(text: str) -> tuple[str, str]:
    explanation = _extract_explanation(text)
    fixed_yaml = _extract_yaml_block(text)
    return explanation, fixed_yaml


def _extract_explanation(text: str) -> str:
    match = re.search(r"EXPLICATION:\s*(.*?)\s*YAML:", text, re.DOTALL | re.IGNORECASE)
    if not match:
        raise AIResponseError("AI response must contain EXPLICATION followed by YAML")

    explanation = match.group(1).strip()
    if not explanation:
        raise AIResponseError("AI explanation is empty")
    return explanation


def _extract_yaml_block(text: str) -> str:
    match = re.search(r"```(?:yaml|yml)?\s*\n(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if not match:
        raise AIResponseError("AI response must contain a fenced YAML block")

    fixed_yaml = match.group(1).strip()
    if not fixed_yaml:
        raise AIResponseError("AI YAML block is empty")
    return fixed_yaml + "\n"
