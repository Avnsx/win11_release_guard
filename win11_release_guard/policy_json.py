"""Validating and normalising signed policy JSON at the trust boundary."""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import datetime
from typing import Any, Mapping
from .config import DEFAULT_PUBLISHED_POLICY_URLS
from .exceptions import PolicyParseError
from .json_utils import DEFAULT_MAX_POLICY_BYTES, StrictJSONError, strict_json_object
from .models import ReleasePolicy
from .policy_schema import SUPPORTED_POLICY_SCHEMA_VERSION, is_source_diagnostic_id
from .release_health import _BUILD_PATTERN, parse_windows11_release_health_html


_RELEASE_PATTERN = re.compile(r"^\d{2}H[12]$", re.IGNORECASE)


def _looks_like_json(text: str) -> bool:
    stripped = text.lstrip("\ufeff\r\n\t ")
    return stripped.startswith("{") or stripped.startswith("[")


def _looks_like_html(text: str) -> bool:
    stripped = text.lstrip("\ufeff\r\n\t ").lower()
    return stripped.startswith("<!doctype html") or stripped.startswith("<html") or "<html" in stripped[:500]


def _parse_iso_datetime(value: str, field: str) -> None:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyParseError(f"{field} must be an ISO 8601 timestamp.") from exc


def _require_mapping(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key)
    if not isinstance(value, Mapping):
        raise PolicyParseError(f"JSON policy is missing required object '{key}'.")
    return value


def _require_sequence(data: Mapping[str, Any], key: str) -> list[Any]:
    value = data.get(key)
    if not isinstance(value, list) or not value:
        raise PolicyParseError(f"JSON policy is missing required non-empty list '{key}'.")
    return value


def _normalize_published_urls(value: Any) -> dict[str, str]:
    if value in (None, {}):
        return dict(DEFAULT_PUBLISHED_POLICY_URLS)
    if not isinstance(value, Mapping):
        raise PolicyParseError("JSON policy field 'published_urls' must be an object.")
    normalized: dict[str, str] = {}
    for key, url in value.items():
        if not isinstance(url, str) or not url:
            raise PolicyParseError(f"published_urls.{key} must be a non-empty URL string.")
        normalized[str(key)] = url
    return normalized


def _source_url_is_listed(
    source_url: str | None,
    *,
    source_urls: list[Any],
    published_urls: Mapping[str, str],
) -> bool:
    if not source_url or not _is_url(source_url):
        return True
    upstream_urls = {str(url) for url in source_urls if isinstance(url, str)}
    public_urls = {str(url) for url in published_urls.values()}
    return source_url in upstream_urls or source_url in public_urls


def _validate_release(value: Any, field: str) -> str:
    release = str(value or "").upper()
    if not _RELEASE_PATTERN.fullmatch(release):
        raise PolicyParseError(f"{field} must be a release string like 25H2.")
    return release


def _validate_build_family(value: Any, field: str) -> int:
    try:
        build_family = int(value)
    except (TypeError, ValueError) as exc:
        raise PolicyParseError(f"{field} must be a build family integer.") from exc
    if build_family < 10000:
        raise PolicyParseError(f"{field} must be a Windows build family.")
    return build_family


def _validate_build(value: Any, field: str, *, required: bool = False) -> str | None:
    if value in (None, ""):
        if required:
            raise PolicyParseError(f"{field} is required.")
        return None
    build = str(value)
    if not _BUILD_PATTERN.fullmatch(build):
        raise PolicyParseError(f"{field} must be a full build string like 26200.8457.")
    return build


def _validated_build_key(value: str) -> tuple[int, int]:
    major, minor = value.split(".", 1)
    return int(major), int(minor)


def _validate_latest_observed_build(
    latest_build: str | None,
    latest_observed_build: str | None,
    field: str,
) -> None:
    if latest_build is None or latest_observed_build is None:
        return
    if _validated_build_key(latest_observed_build) < _validated_build_key(latest_build):
        raise PolicyParseError(f"{field} must not be older than latest_build.")


def _entry_has_explicit_baseline(data: Mapping[str, Any], target: Mapping[str, Any]) -> bool:
    if _validate_build(target.get("baseline_build"), "broad_target_existing_devices.baseline_build"):
        return True
    if _validate_build(target.get("required_baseline_build"), "broad_target_existing_devices.required_baseline_build"):
        return True
    if _validate_build(data.get("baseline_build"), "baseline_build"):
        return True
    quality_baseline = data.get("quality_baseline")
    if isinstance(quality_baseline, Mapping):
        if _validate_build(quality_baseline.get("build"), "quality_baseline.build"):
            return True
    return bool(_validate_build(target.get("latest_build"), "broad_target_existing_devices.latest_build"))


def _optional_int(data: Mapping[str, Any], key: str) -> int | None:
    value = data.get(key)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise PolicyParseError(f"{key} must be an integer.") from exc


def _compatibility_warnings(data: Mapping[str, Any], allowed_keys: set[str]) -> list[str]:
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
        if key not in allowed_keys and not str(key).startswith("x_")
    )
    warnings.extend(
        f"Policy compatibility warning: unknown top-level key {key!r} ignored by this reader."
        for key in unknown_keys
    )
    return warnings


def _validate_source_diagnostic_ids(data: Mapping[str, Any]) -> None:
    source_diagnostics = data.get("source_diagnostics")
    if source_diagnostics is None:
        return
    if not isinstance(source_diagnostics, Mapping):
        raise PolicyParseError("source_diagnostics must be an object.")

    events = source_diagnostics.get("events")
    if events is not None:
        if not isinstance(events, list):
            raise PolicyParseError("source_diagnostics.events must be a list.")
        seen_event_ids: set[str] = set()
        for index, event in enumerate(events):
            if not isinstance(event, Mapping):
                raise PolicyParseError(f"source_diagnostics.events[{index}] must be an object.")
            diagnostic_id = event.get("id")
            if diagnostic_id is not None and not is_source_diagnostic_id(diagnostic_id):
                raise PolicyParseError(
                    f"source_diagnostics.events[{index}].id must be a source diagnostic id."
                )
            if isinstance(diagnostic_id, str):
                if diagnostic_id in seen_event_ids:
                    raise PolicyParseError("source_diagnostics.events ids must be unique.")
                seen_event_ids.add(diagnostic_id)

    issue_status = source_diagnostics.get("issue_status")
    if issue_status is not None:
        if not isinstance(issue_status, Mapping):
            raise PolicyParseError("source_diagnostics.issue_status must be an object.")
        for diagnostic_id in issue_status:
            if not is_source_diagnostic_id(diagnostic_id):
                raise PolicyParseError("source_diagnostics.issue_status keys must be source diagnostic ids.")


def _normalize_json_policy_data(
    data: Mapping[str, Any],
    *,
    source_url: str | None = None,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    warnings = [str(warning) for warning in data.get("validation_warnings", [])]
    allowed_keys = {
        "schema_version",
        "generated_at_utc",
        "source",
        "source_urls",
        "published_urls",
        "generator_version",
        "source_fetch_status",
        "source_diagnostics",
        "quality_policy",
        "current_versions",
        "release_history",
        "supported_build_families",
        "broad_target_existing_devices",
        "excluded_for_existing_devices",
        "special_releases",
        "supported_releases",
        "quality_baselines",
        "quality_baseline",
        "baseline_build",
        "preview_builds",
        "out_of_band_builds",
        "known_notes",
        "validation_warnings",
        "metadata",
        "min_reader_schema_version",
        "max_reader_schema_version",
        "api_version",
        "compatibility",
        "extensions",
    }
    warnings.extend(_compatibility_warnings(data, allowed_keys))

    schema_version = data.get("schema_version")
    if schema_version is None:
        raise PolicyParseError("JSON policy is missing required field 'schema_version'.")
    try:
        schema_version_int = int(schema_version)
    except (TypeError, ValueError) as exc:
        raise PolicyParseError("schema_version must be an integer.") from exc
    if schema_version_int != SUPPORTED_POLICY_SCHEMA_VERSION:
        raise PolicyParseError(
            f"Unsupported policy schema_version {schema_version_int}; "
            f"supported version is {SUPPORTED_POLICY_SCHEMA_VERSION}."
        )

    generated_at = data.get("generated_at_utc")
    if not isinstance(generated_at, str) or not generated_at:
        raise PolicyParseError("JSON policy is missing required field 'generated_at_utc'.")
    _parse_iso_datetime(generated_at, "generated_at_utc")

    source_urls = data.get("source_urls")
    if not isinstance(source_urls, list) or not source_urls or not all(isinstance(url, str) and url for url in source_urls):
        raise PolicyParseError("JSON policy is missing required non-empty list 'source_urls'.")
    published_urls = _normalize_published_urls(data.get("published_urls"))
    if not _source_url_is_listed(
        source_url,
        source_urls=source_urls,
        published_urls=published_urls,
    ):
        warnings.append("Loaded policy URL is not listed in published_urls or source_urls.")
    _validate_source_diagnostic_ids(data)

    current_versions = _require_sequence(data, "current_versions")
    normalized_current_versions: list[Mapping[str, Any]] = []
    target_version_counts: dict[str, set[int]] = {}
    for index, item in enumerate(current_versions):
        if not isinstance(item, Mapping):
            raise PolicyParseError(f"current_versions[{index}] must be an object.")
        release = _validate_release(item.get("version"), f"current_versions[{index}].version")
        build_family = _validate_build_family(item.get("build_family"), f"current_versions[{index}].build_family")
        latest_build = _validate_build(item.get("latest_build"), f"current_versions[{index}].latest_build")
        latest_observed = _validate_build(
            item.get("latest_observed_build"),
            f"current_versions[{index}].latest_observed_build",
        )
        _validate_latest_observed_build(
            latest_build,
            latest_observed,
            f"current_versions[{index}].latest_observed_build",
        )
        baseline_build = _validate_build(item.get("baseline_build"), f"current_versions[{index}].baseline_build")
        required_baseline = _validate_build(
            item.get("required_baseline_build"),
            f"current_versions[{index}].required_baseline_build",
        )
        if baseline_build and required_baseline and required_baseline != baseline_build:
            raise PolicyParseError(f"current_versions[{index}].required_baseline_build must match baseline_build.")
        target_version_counts.setdefault(release, set()).add(build_family)
        normalized_current_versions.append(item)

    supported_build_families = data.get("supported_build_families")
    if not isinstance(supported_build_families, Mapping) or not supported_build_families:
        raise PolicyParseError("JSON policy is missing required object 'supported_build_families'.")
    normalized_supported: dict[str, str] = {}
    for raw_build_family, raw_release in supported_build_families.items():
        build_family = _validate_build_family(raw_build_family, "supported_build_families key")
        normalized_supported[str(build_family)] = _validate_release(
            raw_release,
            f"supported_build_families[{raw_build_family!r}]",
        )

    broad_target = _require_mapping(data, "broad_target_existing_devices")
    target_release = _validate_release(
        broad_target.get("version"),
        "broad_target_existing_devices.version",
    )
    target_build_family = _validate_build_family(
        broad_target.get("build_family"),
        "broad_target_existing_devices.build_family",
    )
    target_latest_build = _validate_build(broad_target.get("latest_build"), "broad_target_existing_devices.latest_build")
    target_latest_observed = _validate_build(
        broad_target.get("latest_observed_build"),
        "broad_target_existing_devices.latest_observed_build",
    )
    _validate_latest_observed_build(
        target_latest_build,
        target_latest_observed,
        "broad_target_existing_devices.latest_observed_build",
    )
    target_baseline_build = _validate_build(
        broad_target.get("baseline_build"),
        "broad_target_existing_devices.baseline_build",
    )
    target_required_baseline = _validate_build(
        broad_target.get("required_baseline_build"),
        "broad_target_existing_devices.required_baseline_build",
    )
    if target_baseline_build and target_required_baseline and target_required_baseline != target_baseline_build:
        raise PolicyParseError("broad_target_existing_devices.required_baseline_build must match baseline_build.")

    if str(target_build_family) not in normalized_supported:
        raise PolicyParseError("broad_target_existing_devices build family is missing from supported_build_families.")
    if not any(
        item.get("version", "").upper() == target_release
        and int(item.get("build_family")) == target_build_family
        for item in normalized_current_versions
    ):
        raise PolicyParseError("broad_target_existing_devices is missing from current_versions.")

    matching_families = target_version_counts.get(target_release, set())
    if len(matching_families) > 1 and not any("ambiguous" in warning.lower() for warning in warnings):
        raise PolicyParseError("Ambiguous target selection without explicit warning.")

    release_history = data.get("release_history")
    if isinstance(release_history, list) and release_history:
        for index, item in enumerate(release_history):
            if not isinstance(item, Mapping):
                raise PolicyParseError(f"release_history[{index}] must be an object.")
            _validate_release(item.get("release"), f"release_history[{index}].release")
            _validate_build_family(item.get("build_family"), f"release_history[{index}].build_family")
            _validate_build(item.get("build"), f"release_history[{index}].build", required=True)
    elif _entry_has_explicit_baseline(data, broad_target):
        warnings.append("release_history is missing; using explicit quality baseline fields.")
    else:
        raise PolicyParseError("JSON policy requires release_history or explicit quality baseline fields.")

    normalized = dict(data)
    normalized["schema_version"] = schema_version_int
    normalized["supported_build_families"] = normalized_supported
    normalized["source_urls"] = list(source_urls)
    normalized["published_urls"] = dict(published_urls)
    if source_url:
        source = dict(normalized.get("source") or {})
        source["policy_url"] = source_url
        normalized["source"] = source
    normalized["validation_warnings"] = list(dict.fromkeys(warnings))
    return normalized, tuple(normalized["validation_warnings"])


def _load_json_policy(
    text: str,
    *,
    source_url: str | None = None,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> ReleasePolicy:
    try:
        data = strict_json_object(text, label="JSON policy", max_bytes=max_bytes)
    except StrictJSONError as exc:
        raise PolicyParseError(f"Malformed JSON policy: {exc}") from exc

    normalized, warnings = _normalize_json_policy_data(data, source_url=source_url)
    try:
        policy = ReleasePolicy.from_dict(normalized)
    except (TypeError, ValueError, KeyError) as exc:
        raise PolicyParseError(f"JSON policy schema is invalid: {exc}") from exc

    return replace(policy, validation_warnings=warnings)


def _load_policy_text(
    text: str,
    *,
    content_type: str | None = None,
    source_url: str | None = None,
    allow_html_fallback: bool = False,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> ReleasePolicy:
    content_type_l = (content_type or "").lower()

    if "application/json" in content_type_l or _looks_like_json(text):
        return _load_json_policy(text, source_url=source_url, max_bytes=max_bytes)

    if "text/html" in content_type_l or _looks_like_html(text):
        if not allow_html_fallback:
            raise PolicyParseError("HTML policy source is not allowed in runtime mode.")
        policy = parse_windows11_release_health_html(text)
        if source_url:
            source = dict(policy.source)
            source["release_health_url"] = source_url
            source["policy_url"] = source_url
            policy = replace(policy, source=source)
        return policy

    raise PolicyParseError("Policy source is neither JSON nor HTML.")


def load_policy_text(
    text: str,
    *,
    source_url: str | None = None,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> ReleasePolicy:
    return _load_policy_text(text, source_url=source_url, max_bytes=max_bytes)


def load_policy_bytes(
    data: bytes,
    *,
    content_type: str | None = None,
    source_url: str | None = None,
    allow_html_fallback: bool = False,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> ReleasePolicy:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PolicyParseError("Policy bytes are not valid UTF-8.") from exc
    return _load_policy_text(
        text,
        content_type=content_type,
        source_url=source_url,
        allow_html_fallback=allow_html_fallback,
        max_bytes=max_bytes,
    )


def _is_url(value: str) -> bool:
    return bool(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value))
