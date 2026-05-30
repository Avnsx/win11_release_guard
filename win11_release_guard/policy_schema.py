from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .exceptions import PolicyParseError


POLICY_SCHEMA_VERSION = 1
GENERATOR_VERSION = "win-release-guard/0.2"

REQUIRED_POLICY_FIELDS = (
    "schema_version",
    "generated_at_utc",
    "generator_version",
    "source_urls",
    "source_fetch_status",
    "current_versions",
    "release_history",
    "supported_build_families",
    "broad_target_existing_devices",
    "excluded_for_existing_devices",
    "special_releases",
    "quality_baselines",
    "preview_builds",
    "out_of_band_builds",
    "known_notes",
    "validation_warnings",
)

_RELEASE_PATTERN = re.compile(r"^\d{2}H[12]$", re.IGNORECASE)
_BUILD_PATTERN = re.compile(r"^\d{5}\.\d+$")


def _require_mapping(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key)
    if not isinstance(value, Mapping):
        raise PolicyParseError(f"Generated policy field '{key}' must be an object.")
    return value


def _require_sequence(data: Mapping[str, Any], key: str) -> Sequence[Any]:
    value = data.get(key)
    if not isinstance(value, list):
        raise PolicyParseError(f"Generated policy field '{key}' must be a list.")
    return value


def _release(value: Any, field: str) -> str:
    text = str(value or "").upper()
    if not _RELEASE_PATTERN.fullmatch(text):
        raise PolicyParseError(f"{field} must be a Windows release string like 25H2.")
    return text


def _build_family(value: Any, field: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise PolicyParseError(f"{field} must be a build family integer.") from exc
    if parsed < 10000:
        raise PolicyParseError(f"{field} must be a Windows build family.")
    return parsed


def _build(value: Any, field: str) -> str:
    text = str(value or "")
    if not _BUILD_PATTERN.fullmatch(text):
        raise PolicyParseError(f"{field} must be a full build string like 26200.8457.")
    return text


def validate_policy_document(data: Mapping[str, Any]) -> tuple[str, ...]:
    missing = [field for field in REQUIRED_POLICY_FIELDS if field not in data]
    if missing:
        raise PolicyParseError(f"Generated policy is missing required fields: {', '.join(missing)}.")

    try:
        schema_version = int(data["schema_version"])
    except (TypeError, ValueError) as exc:
        raise PolicyParseError("schema_version must be an integer.") from exc
    if schema_version != POLICY_SCHEMA_VERSION:
        raise PolicyParseError(
            f"Unsupported generated policy schema_version {schema_version}; "
            f"supported version is {POLICY_SCHEMA_VERSION}."
        )

    source_urls = _require_sequence(data, "source_urls")
    if not source_urls or not all(isinstance(url, str) and url for url in source_urls):
        raise PolicyParseError("source_urls must contain at least one URL.")

    _require_mapping(data, "source_fetch_status")
    current_versions = _require_sequence(data, "current_versions")
    if not current_versions:
        raise PolicyParseError("current_versions must not be empty.")
    release_history = _require_sequence(data, "release_history")
    if not release_history:
        raise PolicyParseError("release_history must not be empty.")

    supported = _require_mapping(data, "supported_build_families")
    normalized_supported: dict[int, str] = {}
    for key, value in supported.items():
        normalized_supported[_build_family(key, f"supported_build_families[{key!r}]")] = _release(
            value,
            f"supported_build_families[{key!r}]",
        )

    seen_current: set[tuple[str, int]] = set()
    for index, entry in enumerate(current_versions):
        if not isinstance(entry, Mapping):
            raise PolicyParseError(f"current_versions[{index}] must be an object.")
        release = _release(entry.get("version"), f"current_versions[{index}].version")
        family = _build_family(entry.get("build_family"), f"current_versions[{index}].build_family")
        _build(entry.get("latest_build"), f"current_versions[{index}].latest_build")
        seen_current.add((release, family))

    target = _require_mapping(data, "broad_target_existing_devices")
    target_release = _release(target.get("version"), "broad_target_existing_devices.version")
    target_family = _build_family(target.get("build_family"), "broad_target_existing_devices.build_family")
    _build(target.get("latest_build"), "broad_target_existing_devices.latest_build")
    if (target_release, target_family) not in seen_current:
        raise PolicyParseError("broad_target_existing_devices must be present in current_versions.")
    if normalized_supported.get(target_family) != target_release:
        raise PolicyParseError("broad target build family must match supported_build_families.")

    for index, row in enumerate(release_history):
        if not isinstance(row, Mapping):
            raise PolicyParseError(f"release_history[{index}] must be an object.")
        _release(row.get("release"), f"release_history[{index}].release")
        _build_family(row.get("build_family"), f"release_history[{index}].build_family")
        _build(row.get("build"), f"release_history[{index}].build")

    quality_baselines = _require_mapping(data, "quality_baselines")
    target_baselines = quality_baselines.get(target_release)
    if not isinstance(target_baselines, Mapping) or "b_release_only" not in target_baselines:
        raise PolicyParseError("quality_baselines must contain b_release_only for the broad target.")
    baseline = target_baselines["b_release_only"]
    if not isinstance(baseline, Mapping):
        raise PolicyParseError("quality_baselines broad-target b_release_only must be an object.")
    if baseline.get("preview"):
        raise PolicyParseError("b_release_only quality baseline must not be a preview build.")

    for key in ("preview_builds", "out_of_band_builds", "known_notes", "validation_warnings"):
        _require_sequence(data, key)

    return tuple(str(warning) for warning in data.get("validation_warnings", []))


def policy_document_to_json(data: Mapping[str, Any]) -> str:
    validate_policy_document(data)
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


__all__ = [
    "GENERATOR_VERSION",
    "POLICY_SCHEMA_VERSION",
    "REQUIRED_POLICY_FIELDS",
    "policy_document_to_json",
    "validate_policy_document",
]
