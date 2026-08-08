from __future__ import annotations

import json
from pathlib import Path

from .models import ReleasePolicy
from .policy_generator import generate_policy


def generate_policy_from_release_health_html(html: str) -> ReleasePolicy:
    return generate_policy(release_health_html=html)


def generate_policy_json_from_release_health_html(html: str) -> str:
    policy = generate_policy_from_release_health_html(html)
    return json.dumps(policy.to_dict(), indent=2, sort_keys=True) + "\n"


def write_policy_json_from_release_health_html(html: str, path: str | Path) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(generate_policy_json_from_release_health_html(html), encoding="utf-8")
    return output_path


__all__ = [
    "generate_policy_from_release_health_html",
    "generate_policy_json_from_release_health_html",
    "write_policy_json_from_release_health_html",
]
