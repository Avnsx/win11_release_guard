from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .exceptions import PolicyParseError


SUPPORTED_POLICY_SCHEMA_VERSION = 1
POLICY_SCHEMA_VERSION = SUPPORTED_POLICY_SCHEMA_VERSION
GENERATOR_VERSION = "win11_release_guard/0.2"

REQUIRED_POLICY_FIELDS = (
    "schema_version",
    "generated_at_utc",
    "generator_version",
    "source_urls",
    "published_urls",
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

OPTIONAL_COMPATIBILITY_FIELDS = (
    "min_reader_schema_version",
    "max_reader_schema_version",
    "api_version",
    "compatibility",
    "extensions",
)

ALLOWED_POLICY_FIELDS = frozenset(
    (
        *REQUIRED_POLICY_FIELDS,
        *OPTIONAL_COMPATIBILITY_FIELDS,
        "source",
        "source_diagnostics",
        "quality_policy",
        "supported_releases",
        "metadata",
    )
)

_RELEASE_PATTERN = re.compile(r"^\d{2}H[12]$", re.IGNORECASE)
_BUILD_PATTERN = re.compile(r"^\d{5}\.\d+$")
_URL_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
PUBLISHED_URL_KEYS = (
    "landing",
    "policy",
    "signature",
    "manifest",
    "api_policy",
    "api_signature",
    "api_manifest",
)


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


def _optional_build(value: Any, field: str) -> str | None:
    if value in (None, ""):
        return None
    return _build(value, field)


def _validate_source_diagnostics(data: Mapping[str, Any]) -> None:
    value = data.get("source_diagnostics")
    if value is None:
        return
    if not isinstance(value, Mapping):
        raise PolicyParseError("source_diagnostics must be an object.")
    for key in ("release_health_html", "atom_feed"):
        source = value.get(key)
        if source is None:
            continue
        if not isinstance(source, Mapping):
            raise PolicyParseError(f"source_diagnostics.{key} must be an object.")
        source_url = source.get("source_url")
        if source_url is not None and (not isinstance(source_url, str) or not _URL_PATTERN.match(source_url)):
            raise PolicyParseError(f"source_diagnostics.{key}.source_url must be an absolute URL.")
        fetched_at = source.get("fetched_at_utc")
        if fetched_at is not None and not isinstance(fetched_at, str):
            raise PolicyParseError(f"source_diagnostics.{key}.fetched_at_utc must be a string.")
        byte_count = source.get("bytes")
        if byte_count is not None and (not isinstance(byte_count, int) or byte_count < 0):
            raise PolicyParseError(f"source_diagnostics.{key}.bytes must be a non-negative integer.")
    drift = value.get("drift")
    if drift is not None and not isinstance(drift, Mapping):
        raise PolicyParseError("source_diagnostics.drift must be an object.")
    warnings = value.get("warnings")
    if warnings is not None and not isinstance(warnings, list):
        raise PolicyParseError("source_diagnostics.warnings must be a list.")


def _optional_int(data: Mapping[str, Any], key: str) -> int | None:
    value = data.get(key)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise PolicyParseError(f"{key} must be an integer.") from exc


def _validate_compatibility(data: Mapping[str, Any]) -> list[str]:
    warnings: list[str] = []
    min_reader = _optional_int(data, "min_reader_schema_version")
    max_reader = _optional_int(data, "max_reader_schema_version")
    if min_reader is not None and min_reader > SUPPORTED_POLICY_SCHEMA_VERSION:
        raise PolicyParseError(
            f"Policy requires reader schema_version {min_reader}; "
            f"this reader supports {SUPPORTED_POLICY_SCHEMA_VERSION}."
        )
    if max_reader is not None and max_reader < SUPPORTED_POLICY_SCHEMA_VERSION:
        raise PolicyParseError(
            f"Policy max_reader_schema_version {max_reader} excludes this reader "
            f"schema_version {SUPPORTED_POLICY_SCHEMA_VERSION}."
        )
    if min_reader is not None and max_reader is not None and min_reader > max_reader:
        raise PolicyParseError("min_reader_schema_version must not exceed max_reader_schema_version.")

    api_version = data.get("api_version")
    if api_version is not None and (not isinstance(api_version, str) or not api_version):
        raise PolicyParseError("api_version must be a non-empty string.")
    compatibility = data.get("compatibility")
    if compatibility is not None and not isinstance(compatibility, Mapping):
        raise PolicyParseError("compatibility must be an object.")
    extensions = data.get("extensions")
    if extensions is not None and not isinstance(extensions, Mapping):
        raise PolicyParseError("extensions must be an object.")

    unknown_keys = sorted(
        str(key)
        for key in data.keys()
        if key not in ALLOWED_POLICY_FIELDS and not str(key).startswith("x_")
    )
    for key in unknown_keys:
        warnings.append(f"Policy compatibility warning: unknown top-level key {key!r} ignored by this reader.")
    return warnings


def validate_policy_document(data: Mapping[str, Any]) -> tuple[str, ...]:
    compatibility_warnings = _validate_compatibility(data)
    missing = [field for field in REQUIRED_POLICY_FIELDS if field not in data]
    if missing:
        raise PolicyParseError(f"Generated policy is missing required fields: {', '.join(missing)}.")

    try:
        schema_version = int(data["schema_version"])
    except (TypeError, ValueError) as exc:
        raise PolicyParseError("schema_version must be an integer.") from exc
    if schema_version != SUPPORTED_POLICY_SCHEMA_VERSION:
        raise PolicyParseError(
            f"Unsupported generated policy schema_version {schema_version}; "
            f"supported version is {SUPPORTED_POLICY_SCHEMA_VERSION}."
        )

    source_urls = _require_sequence(data, "source_urls")
    if not source_urls or not all(isinstance(url, str) and url for url in source_urls):
        raise PolicyParseError("source_urls must contain at least one URL.")

    published_urls = _require_mapping(data, "published_urls")
    missing_published_urls = [key for key in PUBLISHED_URL_KEYS if key not in published_urls]
    if missing_published_urls:
        raise PolicyParseError(
            "published_urls is missing required field(s): "
            f"{', '.join(missing_published_urls)}."
        )
    for key in PUBLISHED_URL_KEYS:
        value = published_urls[key]
        if not isinstance(value, str) or not value:
            raise PolicyParseError(f"published_urls.{key} must be a non-empty URL string.")
        if not _URL_PATTERN.match(value):
            raise PolicyParseError(f"published_urls.{key} must be an absolute URL.")

    _require_mapping(data, "source_fetch_status")
    _validate_source_diagnostics(data)
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
        latest = _build(entry.get("latest_build"), f"current_versions[{index}].latest_build")
        latest_observed = _optional_build(
            entry.get("latest_observed_build"),
            f"current_versions[{index}].latest_observed_build",
        )
        if latest_observed is not None and latest_observed != latest:
            raise PolicyParseError(
                f"current_versions[{index}].latest_observed_build must match latest_build."
            )
        baseline_build = _optional_build(entry.get("baseline_build"), f"current_versions[{index}].baseline_build")
        required_baseline = _optional_build(
            entry.get("required_baseline_build"),
            f"current_versions[{index}].required_baseline_build",
        )
        if baseline_build is not None and required_baseline is not None and required_baseline != baseline_build:
            raise PolicyParseError(
                f"current_versions[{index}].required_baseline_build must match baseline_build."
            )
        seen_current.add((release, family))

    target = _require_mapping(data, "broad_target_existing_devices")
    target_release = _release(target.get("version"), "broad_target_existing_devices.version")
    target_family = _build_family(target.get("build_family"), "broad_target_existing_devices.build_family")
    target_latest = _build(target.get("latest_build"), "broad_target_existing_devices.latest_build")
    target_latest_observed = _optional_build(
        target.get("latest_observed_build"),
        "broad_target_existing_devices.latest_observed_build",
    )
    if target_latest_observed is not None and target_latest_observed != target_latest:
        raise PolicyParseError("broad_target_existing_devices.latest_observed_build must match latest_build.")
    target_baseline_build = _optional_build(
        target.get("baseline_build"),
        "broad_target_existing_devices.baseline_build",
    )
    target_required_baseline = _optional_build(
        target.get("required_baseline_build"),
        "broad_target_existing_devices.required_baseline_build",
    )
    if (
        target_baseline_build is not None
        and target_required_baseline is not None
        and target_required_baseline != target_baseline_build
    ):
        raise PolicyParseError("broad_target_existing_devices.required_baseline_build must match baseline_build.")
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

    return tuple(dict.fromkeys([*(str(warning) for warning in data.get("validation_warnings", [])), *compatibility_warnings]))


def policy_document_to_json(data: Mapping[str, Any]) -> str:
    validate_policy_document(data)
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


__all__ = [
    "GENERATOR_VERSION",
    "POLICY_SCHEMA_VERSION",
    "PUBLISHED_URL_KEYS",
    "REQUIRED_POLICY_FIELDS",
    "SUPPORTED_POLICY_SCHEMA_VERSION",
    "policy_document_to_json",
    "validate_policy_document",
]
