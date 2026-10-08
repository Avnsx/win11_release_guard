from __future__ import annotations

from typing import Any, Mapping
from .exceptions import PolicyError
from .models import ReleaseHistoryEntry, ReleasePolicy, ReleasePolicyEntry
from .policy_http import fetch_policy_bytes, fetch_release_policy
from .policy_json import load_policy_bytes, load_policy_text
from .release_health import parse_windows11_release_health_html
from .release_health_tables import _build_key  # ponytail: re-exported for tests until Task 12


def policy_from_dict(data: Mapping[str, Any]) -> ReleasePolicy:
    return ReleasePolicy.from_dict(data)


def policy_to_dict(policy: ReleasePolicy) -> dict[str, Any]:
    return policy.to_dict()


def require_broad_target(policy: ReleasePolicy) -> ReleasePolicyEntry:
    if policy.broad_target_existing_devices is None:
        raise PolicyError("Release policy does not define broad_target_existing_devices.")
    return policy.broad_target_existing_devices


__all__ = [
    "ReleaseHistoryEntry",
    "ReleasePolicy",
    "ReleasePolicyEntry",
    "fetch_release_policy",
    "fetch_policy_bytes",
    "load_policy_bytes",
    "load_policy_text",
    "parse_windows11_release_health_html",
    "policy_from_dict",
    "policy_to_dict",
    "require_broad_target",
]
