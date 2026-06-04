from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import platform
import sys
import traceback
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from importlib import metadata, resources
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives import serialization

from .api import _load_runtime_policy, check_current_system
from .bundled_policy import (
    BUNDLED_POLICY_FILE,
    BUNDLED_POLICY_PACKAGE,
    BUNDLED_POLICY_SIGNATURE_FILE,
    load_bundled_policy,
)
from .cache import default_cache_path
from .config import (
    DEFAULT_CACHE_MAX_AGE_HOURS,
    DEFAULT_EVENT_LOG_MAX_EVENTS,
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    DEFAULT_POLICY_URL,
    DEFAULT_PUBLISHED_POLICY_URLS,
    DEFAULT_QUALITY_POLICY,
    DEFAULT_STALE_CACHE_MAX_AGE_HOURS,
    DEFAULT_USER_AGENT,
    DEFAULT_WUA_MAX_HISTORY,
    DEFAULT_WUA_MAX_RELEVANT_UPDATES,
    DEFAULT_WUA_TIMEOUT_SECONDS,
    POLICY_URL_ENV_VAR,
    ReleaseCheckerConfig,
    STRICT_PRODUCTION_ENV_VAR,
    normalize_policy_url,
    policy_url_from_env,
    strict_production_from_env,
)
from .exceptions import PolicyFetchError, PolicyParseError, PolicyTrustError, WindowsReleaseCheckerError
from .json_utils import DEFAULT_MAX_JSON_BYTES, StrictJSONError, strict_json_object
from .models import (
    EvaluationResult,
    EvaluationStatus,
    InstalledBuildClassification,
    InstalledBuildOrigin,
    SourceStatus,
)
from .policy_schema import validate_policy_document
from .remote_policy import fetch_policy_bytes
from .signing import load_public_key, load_trusted_policy, verify_policy_signature


EXIT_COMPLIANT = 0
EXIT_UPDATE_REQUIRED = 1
EXIT_UNKNOWN_OR_POLICY_ERROR = 2
EXIT_ABOVE_BROAD_TARGET = 3
EXIT_ARGUMENT_ERROR = 10


@dataclass(frozen=True)
class PublicFetchResult:
    url: str
    status_code: int
    content: bytes
    content_type: str | None = None
    headers: Mapping[str, str] | None = None

    @property
    def auth_challenge(self) -> bool:
        headers = {str(key).lower(): str(value) for key, value in dict(self.headers or {}).items()}
        return self.status_code == 401 or "www-authenticate" in headers


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="win11_release_guard",
        description="Evaluate Windows 11 release compliance against broad-fleet policy.",
        epilog="Source-tree entry point: python -m win11_release_guard",
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    output.add_argument("--json-pretty", action="store_true", help="Print pretty machine-readable JSON.")
    output.add_argument("--pretty", action="store_true", help="Print concise admin-readable output.")
    parser.add_argument("--output", type=Path, default=None, help="Write JSON output to this UTF-8 file.")
    parser.add_argument("--unicode", action="store_true", help="Emit readable UTF-8 JSON instead of ASCII-escaped JSON.")
    parser.add_argument(
        "--include-raw-wua-history",
        action="store_true",
        help="Include full bounded WUA history in JSON output.",
    )
    parser.add_argument("--policy-url", default=None, help="Generated JSON policy URL or file path.")
    parser.add_argument(
        "--diagnose-config",
        action="store_true",
        help="Print effective configuration, including policy URL source, without running probes.",
    )
    parser.add_argument(
        "--check-source",
        action="store_true",
        help="With --diagnose-config, perform the configured policy source check.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Validate local package integrity and the bundled signed policy without probes or network.",
    )
    parser.add_argument(
        "--check-policy-source",
        action="store_true",
        help="Fetch and verify the configured signed policy source without local Windows probes.",
    )
    parser.add_argument(
        "--check-public-pages",
        action="store_true",
        help="Validate the public GitHub Pages landing page and API aliases after policy source checks.",
    )
    parser.add_argument(
        "--allow-missing-manifest",
        action="store_true",
        help="Allow --check-policy-source to pass when a remote policy manifest cannot be fetched.",
    )
    parser.add_argument("--cache-file", type=Path, default=None, help="Optional policy cache path.")
    parser.add_argument(
        "--cache-max-age-hours",
        type=float,
        default=DEFAULT_CACHE_MAX_AGE_HOURS,
        help="Fresh cache maximum age.",
    )
    parser.add_argument(
        "--stale-cache-max-age-hours",
        type=float,
        default=DEFAULT_STALE_CACHE_MAX_AGE_HOURS,
        help="Stale cache maximum age.",
    )
    parser.add_argument("--explicit-target-release", default=None, help="Force a target release, for example 25H2.")
    parser.add_argument(
        "--quality-policy",
        default=DEFAULT_QUALITY_POLICY,
        choices=[
            "b_release_only",
            "latest_non_preview",
            "latest_anything",
        ],
    )
    wua = parser.add_mutually_exclusive_group()
    wua.add_argument(
        "--wua",
        "--with-wua",
        action="store_true",
        help="Enable the read-only Windows Update Agent secondary probe.",
    )
    wua.add_argument(
        "--no-wua",
        action="store_true",
        help="Keep the Windows Update Agent secondary probe disabled.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=DEFAULT_HTTP_TIMEOUT_SECONDS,
        help="HTTP policy fetch timeout.",
    )
    parser.add_argument(
        "--wua-timeout-seconds",
        type=float,
        default=DEFAULT_WUA_TIMEOUT_SECONDS,
        help="Overall WUA subprocess timeout.",
    )
    parser.add_argument(
        "--wua-max-history",
        type=int,
        default=DEFAULT_WUA_MAX_HISTORY,
        help="Maximum WUA history entries to query.",
    )
    parser.add_argument(
        "--wua-max-relevant-updates",
        type=int,
        default=DEFAULT_WUA_MAX_RELEVANT_UPDATES,
        help="Maximum relevant WUA OS updates to include in output.",
    )
    parser.add_argument(
        "--event-log-max-events",
        type=int,
        default=DEFAULT_EVENT_LOG_MAX_EVENTS,
        help="Maximum Setup/Servicing event-log entries to read during WUA diagnostics.",
    )
    parser.add_argument(
        "--allow-runtime-release-health-html",
        action="store_true",
        help="Allow direct Microsoft Release Health HTML parsing at runtime.",
    )
    parser.add_argument(
        "--allow-unsigned-policy",
        action="store_true",
        help="Accept unsigned generated JSON policies.",
    )
    parser.add_argument(
        "--trusted-policy-public-key",
        default=None,
        help="Override the trusted Ed25519 policy public key.",
    )
    parser.add_argument(
        "--no-bundled-policy-fallback",
        action="store_true",
        help="Disable the bundled last-known-good policy fallback.",
    )
    parser.add_argument(
        "--source-check-required-for-green",
        action="store_true",
        help="Return CHECK_INCOMPLETE instead of COMPLIANT when live source check failed.",
    )
    parser.add_argument(
        "--strict-production",
        action="store_true",
        help="Require a complete signed live remote JSON policy source before returning COMPLIANT.",
    )
    parser.add_argument(
        "--allow-major-upgrade-recommendation",
        action="store_true",
        help="Allow Windows 10 client to Windows 11 recommendation instead of OUT_OF_SCOPE.",
    )
    parser.add_argument(
        "--allow-server-evaluation",
        action="store_true",
        help="Evaluate Windows Server builds against policy instead of OUT_OF_SCOPE.",
    )
    parser.add_argument(
        "--no-preview-installed-warning",
        action="store_true",
        help="Suppress the diagnostic warning when the installed build is a preview build.",
    )
    parser.add_argument(
        "--disallow-preview-installed",
        action="store_true",
        help="Return PREVIEW_BUILD_INSTALLED when the local build is identified as a preview.",
    )
    parser.add_argument("--debug", action="store_true", help="Show tracebacks for unexpected failures.")
    return parser


def _exit_code(status: EvaluationStatus) -> int:
    if status is EvaluationStatus.COMPLIANT:
        return EXIT_COMPLIANT
    if status in {
        EvaluationStatus.FEATURE_UPDATE_REQUIRED,
        EvaluationStatus.QUALITY_UPDATE_REQUIRED,
        EvaluationStatus.PREVIEW_BUILD_INSTALLED,
    }:
        return EXIT_UPDATE_REQUIRED
    if status is EvaluationStatus.ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE:
        return EXIT_ABOVE_BROAD_TARGET
    return EXIT_UNKNOWN_OR_POLICY_ERROR


RELEVANT_WUA_CLASSIFICATIONS = {
    "feature_update",
    "quality_update",
    "quality_preview",
    "out_of_band",
}


def _compact_wua_output(wua: dict[str, object], *, target_offer_expected: bool) -> dict[str, object]:
    available_updates = [
        item for item in wua.get("available_updates", []) if isinstance(item, dict)
    ]
    history = [item for item in wua.get("history", []) if isinstance(item, dict)]
    relevant_os_updates = [
        item for item in wua.get("relevant_os_updates", []) if isinstance(item, dict)
    ]
    latest_relevant_history = [
        item
        for item in history
        if item.get("classification") in RELEVANT_WUA_CLASSIFICATIONS
    ][:3]
    available_counts = Counter(str(item.get("classification") or "unknown") for item in available_updates)
    history_counts = Counter(str(item.get("classification") or "unknown") for item in history)
    raw_truncated = bool(
        history
        or len(available_updates) != len(relevant_os_updates)
        or len(latest_relevant_history) < len(
            [item for item in history if item.get("classification") in RELEVANT_WUA_CLASSIFICATIONS]
        )
    )
    return {
        "available": wua.get("available"),
        "service_enabled": wua.get("service_enabled"),
        "target_feature_update_offered": wua.get("target_feature_update_offered"),
        "target_feature_update_offer_expected": target_offer_expected,
        "target_release_in_history": wua.get("target_release_in_history"),
        "timed_out": wua.get("timed_out", False),
        "counts_by_category": {
            "available_updates_total": len(available_updates),
            "history_total": len(history),
            "relevant_os_updates_total": len(relevant_os_updates),
            "available_update_classifications": dict(available_counts),
            "history_classifications": dict(history_counts),
            "noise_counts": dict(wua.get("noise_counts") or {}),
        },
        "relevant_os_updates": relevant_os_updates,
        "latest_relevant_history": latest_relevant_history,
        "warnings": list(wua.get("warnings") or []),
        "errors": list(wua.get("errors") or []),
        "raw_output_truncated": raw_truncated,
    }


def _output_payload(result: EvaluationResult, *, include_raw_wua_history: bool) -> dict[str, object]:
    payload = result.to_dict()
    wua = payload.get("wua_secondary")
    if isinstance(wua, dict):
        if include_raw_wua_history:
            wua["target_feature_update_offer_expected"] = result.target_feature_update_offer_expected
            wua["raw_output_truncated"] = False
        else:
            payload["wua_secondary"] = _compact_wua_output(
                wua,
                target_offer_expected=result.target_feature_update_offer_expected,
            )
    return payload


def _json_text(
    result: EvaluationResult,
    *,
    pretty: bool,
    unicode_output: bool,
    include_raw_wua_history: bool,
) -> str:
    return json.dumps(
        _output_payload(result, include_raw_wua_history=include_raw_wua_history),
        indent=2 if pretty else None,
        sort_keys=True,
        ensure_ascii=not unicode_output,
        separators=None if pretty else (",", ":"),
    )


def _print_json(
    result: EvaluationResult,
    *,
    pretty: bool,
    unicode_output: bool,
    include_raw_wua_history: bool,
) -> None:
    print(
        _json_text(
            result,
            pretty=pretty,
            unicode_output=unicode_output,
            include_raw_wua_history=include_raw_wua_history,
        )
    )


def _write_json_output(
    path: Path,
    result: EvaluationResult,
    *,
    pretty: bool,
    unicode_output: bool,
    include_raw_wua_history: bool,
) -> None:
    json_text = _json_text(
        result,
        pretty=pretty,
        unicode_output=unicode_output,
        include_raw_wua_history=include_raw_wua_history,
    )
    path.write_text(json_text + "\n", encoding="utf-8", newline="\n")


def _source_degradation_warning(result: EvaluationResult) -> str | None:
    source_status = result.source_status
    source_kind = result.policy_source_kind or "unknown"
    if source_status is SourceStatus.REMOTE_POLICY_OK and source_kind == "remote_json" and result.is_source_check_complete:
        return None
    if source_status is SourceStatus.USING_FRESH_CACHE:
        return "using fresh cache; live remote policy was not used for this result."
    if source_status is SourceStatus.USING_STALE_CACHE:
        return "using stale cache; treat this as degraded evidence, not production green."
    if source_status is SourceStatus.USING_BUNDLED_POLICY:
        return "using bundled last-known-good policy; live policy source is unavailable."
    if source_status is SourceStatus.POLICY_UNAVAILABLE:
        return "policy unavailable; release compliance check is incomplete."
    if source_kind != "remote_json" or not result.is_source_check_complete:
        return "live signed remote JSON policy was not fully verified."
    return None


def _source_drift_warnings(result: EvaluationResult) -> list[str]:
    warnings: list[str] = []
    for warning in result.warnings:
        if "source freshness warning" in warning.lower() or "source drift" in warning.lower():
            warnings.append(warning)
    metadata = result.metadata if isinstance(result.metadata, Mapping) else {}
    source_diagnostics = metadata.get("source_diagnostics")
    if isinstance(source_diagnostics, Mapping):
        warnings.extend(str(item) for item in source_diagnostics.get("warnings", []) if item)
    return list(dict.fromkeys(warnings))


def _print_pretty(result: EvaluationResult) -> None:
    target_version = result.target.version if result.target else "unknown"
    target_build = result.baseline_build or (result.target.effective_baseline_build if result.target else None)
    latest_observed = result.target.latest_observed_build if result.target else None
    source_status = result.source_status.value if result.source_status else "unknown"
    print(f"Status: {result.status.value}")
    print(f"Local: {result.installed_release or 'unknown'} / {result.installed_build or 'unknown'}")
    if result.local_consensus:
        print(f"Display OS: {result.local_consensus.display_os_name}")
        if result.local_consensus.raw_product_name:
            print(f"Raw ProductName: {result.local_consensus.raw_product_name}")
    print(f"Target: {target_version} / {target_build or 'unknown'}")
    if result.target:
        print(f"Required baseline: {target_build or 'unknown'}")
        print(f"Latest observed: {latest_observed or 'unknown'}")
    print(f"Source: {source_status} / {result.policy_source_kind or 'unknown'}")
    source_warning = _source_degradation_warning(result)
    if source_warning:
        print(
            "Source warning: live signed remote JSON policy was not fully verified; "
            f"{source_warning}"
        )
    if result.installed_build_origin:
        print(f"Build origin: {_format_build_origin(result.installed_build_origin, result)}")
        if (
            result.status is EvaluationStatus.COMPLIANT
            and result.installed_build_origin.classification is InstalledBuildClassification.PREVIEW
        ):
            print(
                "Preview warning: COMPLIANT means the installed build is at or above the required B-release "
                "baseline, but a preview build is installed."
            )
    drift_warnings = _source_drift_warnings(result)
    if drift_warnings:
        print("Source drift warnings:")
        for warning in drift_warnings:
            print(f"- {warning}")
    print(f"Action: {result.action or 'Manual inspection required.'}")
    if result.notes:
        print("Notes:")
        for note in result.notes:
            print(f"- {note}")
    if result.errors:
        print("Errors:")
        for error in result.errors:
            print(f"- {error}")
    if result.source_problems:
        print("Source problems:")
        for problem in result.source_problems:
            print(f"- {problem}")


def _format_build_origin(origin: InstalledBuildOrigin, result: EvaluationResult) -> str:
    classification = origin.classification
    if classification is InstalledBuildClassification.UNKNOWN_NEWER_THAN_BASELINE:
        if result.policy_source_kind == "bundled":
            return "newer than bundled baseline; exact KB/origin unknown because live policy/WUA evidence was not used."
        return "newer than policy baseline; exact KB/origin unknown."
    if classification is InstalledBuildClassification.UNKNOWN_OLDER_THAN_BASELINE:
        return "older than policy baseline; exact KB/origin unknown."

    labels = {
        InstalledBuildClassification.B_RELEASE: "B release",
        InstalledBuildClassification.PREVIEW: "preview",
        InstalledBuildClassification.OUT_OF_BAND: "out-of-band",
    }
    label = labels.get(classification, classification.value if classification else "unknown")
    parts = [label, origin.evidence_source.value]
    if origin.kb_article:
        parts.append(origin.kb_article)
    return " / ".join(parts)


def _error_payload(message: str, status: str = "POLICY_ERROR") -> dict[str, object]:
    return {
        "status": status,
        "error": message,
    }


def _print_error(message: str, *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(_error_payload(message), indent=2, sort_keys=True, ensure_ascii=True), file=sys.stderr)
    else:
        print(f"Error: {message}", file=sys.stderr)


def _config_from_args(args: argparse.Namespace) -> ReleaseCheckerConfig:
    policy_url, _policy_url_source = _policy_url_from_args(args)
    strict_production = bool(args.strict_production or strict_production_from_env())
    return ReleaseCheckerConfig(
        policy_url=policy_url,
        cache_file=str(args.cache_file) if args.cache_file is not None else None,
        cache_max_age_hours=args.cache_max_age_hours,
        stale_cache_max_age_hours=args.stale_cache_max_age_hours,
        quality_policy=args.quality_policy,
        explicit_target_release=args.explicit_target_release,
        enable_wua_probe=bool(args.wua and not args.no_wua),
        timeout_seconds=args.timeout_seconds,
        wua_timeout_seconds=args.wua_timeout_seconds,
        wua_max_history=args.wua_max_history,
        wua_max_relevant_updates=args.wua_max_relevant_updates,
        event_log_max_events=args.event_log_max_events,
        allow_runtime_release_health_html=args.allow_runtime_release_health_html,
        allow_unsigned_policy=args.allow_unsigned_policy,
        trusted_policy_public_key=args.trusted_policy_public_key,
        use_bundled_policy_fallback=not args.no_bundled_policy_fallback,
        source_check_required_for_green=args.source_check_required_for_green,
        strict_production=strict_production,
        allow_major_upgrade_recommendation=args.allow_major_upgrade_recommendation,
        allow_server_evaluation=args.allow_server_evaluation,
        warn_on_preview_installed=not args.no_preview_installed_warning,
        disallow_preview_installed=args.disallow_preview_installed,
    )


def _policy_url_from_args(args: argparse.Namespace) -> tuple[str | None, str]:
    cli_policy_url = normalize_policy_url(args.policy_url)
    if cli_policy_url:
        return cli_policy_url, "cli"
    env_policy_url = policy_url_from_env()
    if env_policy_url:
        return env_policy_url, "env"
    default_policy_url = normalize_policy_url(DEFAULT_POLICY_URL)
    if default_policy_url:
        return default_policy_url, "default"
    return None, "none"


def _package_version() -> str:
    try:
        return metadata.version("win11_release_guard")
    except metadata.PackageNotFoundError:
        pass

    pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    try:
        for line in pyproject_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("version = "):
                return stripped.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "unknown"


def _trusted_public_key_fingerprint(public_key: str | None) -> str:
    try:
        key = load_public_key(public_key)
        raw_key = key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return f"sha256:{hashlib.sha256(raw_key).hexdigest()}"
    except Exception as exc:
        return f"invalid: {exc}"


def _platform_summary() -> dict[str, object]:
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
    }


def _bundled_policy_file_status() -> tuple[bool, bool]:
    try:
        package_files = resources.files(BUNDLED_POLICY_PACKAGE)
        return (
            package_files.joinpath(BUNDLED_POLICY_FILE).is_file(),
            package_files.joinpath(BUNDLED_POLICY_SIGNATURE_FILE).is_file(),
        )
    except Exception:
        return False, False


def _bundled_policy_diagnostics(config: ReleaseCheckerConfig) -> dict[str, object]:
    policy_present, signature_present = _bundled_policy_file_status()
    payload: dict[str, object] = {
        "bundled_policy_present": policy_present,
        "bundled_policy_signature_present": signature_present,
        "bundled_policy_generated_at_utc": None,
        "bundled_policy_signature_status": "unavailable",
    }
    if not policy_present:
        return payload

    try:
        trusted = load_bundled_policy(
            public_key=config.trusted_policy_public_key,
            allow_unsigned=config.allow_unsigned_policy,
        )
    except Exception as exc:
        payload["bundled_policy_signature_status"] = f"invalid: {exc}"
        return payload

    payload["bundled_policy_generated_at_utc"] = trusted.policy.generated_at_utc
    payload["bundled_policy_signature_status"] = trusted.signature_status
    return payload


def _source_check_payload(config: ReleaseCheckerConfig) -> dict[str, object]:
    try:
        source = _load_runtime_policy(config)
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "exception_type": type(exc).__name__,
        }

    return {
        "ok": source.policy is not None,
        "source_status": source.source_status.value,
        "is_source_check_complete": source.is_source_check_complete,
        "policy_source_url": source.policy_source_url,
        "policy_source_kind": source.policy_source_kind,
        "policy_signature_status": source.policy_signature_status,
        "policy_age_hours": source.policy_age_hours,
        "warnings": list(source.warnings),
        "errors": list(source.errors),
        "source_problems": [problem.to_dict() for problem in source.source_problems],
    }


def _diagnose_config_payload(args: argparse.Namespace) -> dict[str, object]:
    policy_url, source = _policy_url_from_args(args)
    config = _config_from_args(args)
    payload = {
        "package_version": _package_version(),
        "effective_policy_url": policy_url,
        "policy_url": policy_url,
        "policy_url_source": source,
        "policy_url_env_var": POLICY_URL_ENV_VAR,
        "strict_production_env_var": STRICT_PRODUCTION_ENV_VAR,
        "cache_file": str(Path(config.cache_file)) if config.cache_file else str(default_cache_path()),
        "trusted_public_key_fingerprint": _trusted_public_key_fingerprint(config.trusted_policy_public_key),
        "wua_default_enabled": ReleaseCheckerConfig().enable_wua_probe,
        "wua_effective_enabled": config.enable_wua_probe,
        "runtime_html_fallback_enabled": config.allow_runtime_release_health_html,
        "source_check_required_for_green": config.source_check_required_for_green,
        "strict_production": config.strict_production,
        "platform_summary": _platform_summary(),
        "remote_fetch_enabled": policy_url is not None,
        "live_remote_fetch_performed": bool(args.check_source),
        "cache_max_age_hours": config.cache_max_age_hours,
        "stale_cache_max_age_hours": config.stale_cache_max_age_hours,
        "use_bundled_policy_fallback": config.use_bundled_policy_fallback,
        "allow_unsigned_policy": config.allow_unsigned_policy,
        "allow_runtime_release_health_html": config.allow_runtime_release_health_html,
    }
    payload.update(_bundled_policy_diagnostics(config))
    if args.check_source:
        payload["source_check"] = _source_check_payload(config)
    return payload


def _self_test_payload() -> tuple[dict[str, object], bool]:
    payload: dict[str, object] = {
        "ok": False,
        "package_version": _package_version(),
        "remote_fetch_performed": False,
        "wua_probe_performed": False,
        "checks": {
            "package_import": "not_run",
            "bundled_policy_loaded": "not_run",
            "bundled_policy_signature": "not_run",
            "policy_schema": "not_run",
        },
        "bundled_policy_generated_at_utc": None,
        "errors": [],
    }
    checks = payload["checks"]
    errors = payload["errors"]
    assert isinstance(checks, dict)
    assert isinstance(errors, list)

    try:
        importlib.import_module("win11_release_guard")
        checks["package_import"] = "ok"
    except Exception as exc:
        checks["package_import"] = "failed"
        errors.append(f"Package import failed: {exc}")
        return payload, False

    try:
        trusted = load_bundled_policy()
        checks["bundled_policy_loaded"] = "ok"
        checks["bundled_policy_signature"] = trusted.signature_status
        payload["bundled_policy_generated_at_utc"] = trusted.policy.generated_at_utc
        if trusted.policy.schema_version != 1:
            checks["policy_schema"] = "failed"
            errors.append(f"Unsupported bundled policy schema_version {trusted.policy.schema_version}.")
            return payload, False
        checks["policy_schema"] = "ok"
    except Exception as exc:
        checks["bundled_policy_loaded"] = "failed"
        if "signature" in str(exc).lower():
            checks["bundled_policy_signature"] = "failed"
        errors.append(f"Bundled policy validation failed: {exc}")
        return payload, False

    payload["ok"] = True
    return payload, True


def _policy_signature_source(policy_url: str) -> str:
    if policy_url.endswith("/api/v1/policy.json"):
        return f"{policy_url.rsplit('/', 1)[0]}/policy.sig"
    return f"{policy_url}.sig"


def _is_http_url(value: str | None) -> bool:
    return bool(value and str(value).lower().startswith(("http://", "https://")))


def _fetch_public_url(url: str, *, timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS) -> PublicFetchResult:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "*/*",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            headers = {str(key): str(value) for key, value in response.headers.items()}
            content_type = response.headers.get("Content-Type")
            return PublicFetchResult(
                url=url,
                status_code=int(getattr(response, "status", 200)),
                content=response.read(DEFAULT_MAX_JSON_BYTES + 1),
                content_type=content_type,
                headers=headers,
            )
    except urllib.error.HTTPError as exc:
        headers = {str(key): str(value) for key, value in exc.headers.items()} if exc.headers else {}
        return PublicFetchResult(
            url=url,
            status_code=int(exc.code),
            content=exc.read(DEFAULT_MAX_JSON_BYTES + 1),
            content_type=headers.get("Content-Type"),
            headers=headers,
        )
    except Exception as exc:
        raise PolicyFetchError(f"Failed to fetch public Pages URL {url}: {exc}") from exc


def _decode_json_bytes(data: bytes, *, label: str) -> Mapping[str, Any]:
    try:
        return strict_json_object(data, label=label)
    except StrictJSONError as exc:
        raise PolicyParseError(str(exc)) from exc


def _sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest_url_for_policy(policy_url: str, policy) -> str | None:
    if not _is_http_url(policy_url):
        return None
    published_urls = dict(policy.published_urls or {})
    if policy_url == published_urls.get("api_policy"):
        return published_urls.get("api_manifest") or DEFAULT_PUBLISHED_POLICY_URLS["api_manifest"]
    return published_urls.get("manifest") or DEFAULT_PUBLISHED_POLICY_URLS["manifest"]


def _manifest_check_payload(
    *,
    policy_url: str,
    policy,
    policy_bytes: bytes,
    timeout_seconds: float,
    allow_missing_manifest: bool = False,
) -> tuple[dict[str, object], bool]:
    manifest_url = _manifest_url_for_policy(policy_url, policy)
    if manifest_url is None:
        return (
            {
                "manifest_url": None,
                "manifest_status": "not_checked",
                "manifest_warning": None,
                "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
            },
            True,
        )

    try:
        manifest_bytes, _manifest_content_type = fetch_policy_bytes(manifest_url, timeout=timeout_seconds)
    except Exception as exc:
        policy_sha256 = hashlib.sha256(policy_bytes).hexdigest()
        return (
            {
                "manifest_url": manifest_url,
                "manifest_status": "unavailable",
                "manifest_warning": f"Manifest unavailable: {exc}",
                "manifest_missing_allowed": bool(allow_missing_manifest),
                "policy_sha256": policy_sha256,
            },
            bool(allow_missing_manifest),
        )

    try:
        manifest = _decode_json_bytes(manifest_bytes, label="Policy manifest")
    except PolicyParseError as exc:
        return (
            {
                "manifest_url": manifest_url,
                "manifest_status": "invalid",
                "manifest_warning": str(exc),
                "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
            },
            False,
        )

    actual_policy_sha256 = hashlib.sha256(policy_bytes).hexdigest()
    expected_policy_sha256 = str(manifest.get("policy_sha256") or "")
    if not expected_policy_sha256:
        return (
            {
                "manifest_url": manifest_url,
                "manifest_status": "invalid",
                "manifest_warning": "Policy manifest is missing policy_sha256.",
                "policy_sha256": actual_policy_sha256,
            },
            False,
        )
    if expected_policy_sha256 != actual_policy_sha256:
        return (
            {
                "manifest_url": manifest_url,
                "manifest_status": "sha256_mismatch",
                "manifest_warning": "Policy manifest policy_sha256 does not match fetched policy bytes.",
                "policy_sha256": actual_policy_sha256,
                "manifest_policy_sha256": expected_policy_sha256,
            },
            False,
        )

    return (
        {
            "manifest_url": manifest_url,
            "manifest_status": "ok",
            "manifest_warning": None,
            "policy_sha256": actual_policy_sha256,
            "manifest_policy_sha256": expected_policy_sha256,
        },
        True,
    )


def _public_pages_urls(policy) -> dict[str, str]:
    published_urls = dict(DEFAULT_PUBLISHED_POLICY_URLS)
    policy_published_urls = getattr(policy, "published_urls", None)
    if isinstance(policy_published_urls, Mapping):
        for key in DEFAULT_PUBLISHED_POLICY_URLS:
            value = policy_published_urls.get(key)
            if isinstance(value, str) and value:
                published_urls[key] = value
    landing = published_urls["landing"].rstrip("/")
    return {
        "landing": published_urls["landing"],
        "policy": published_urls["policy"],
        "signature": published_urls["signature"],
        "manifest": published_urls["manifest"],
        "api_policy": published_urls["api_policy"],
        "api_signature": published_urls["api_signature"],
        "api_manifest": published_urls["api_manifest"],
        "robots": f"{landing}/robots.txt",
        "sitemap": f"{landing}/sitemap.xml",
    }


def _public_page_fetch_check(
    *,
    name: str,
    url: str,
    timeout_seconds: float,
    expect_json: bool = False,
    expect_signature: bool = False,
    expect_robots: bool = False,
) -> tuple[dict[str, object], PublicFetchResult | None, Mapping[str, Any] | None]:
    try:
        response = _fetch_public_url(url, timeout=timeout_seconds)
    except Exception as exc:
        return (
            {
                "name": name,
                "url": url,
                "ok": False,
                "status_code": None,
                "error": str(exc),
            },
            None,
            None,
        )

    errors: list[str] = []
    decoded_json: Mapping[str, Any] | None = None
    if response.status_code != 200:
        errors.append(f"HTTP {response.status_code}")
    if len(response.content) > DEFAULT_MAX_JSON_BYTES:
        errors.append(f"response is too large: exceeds {DEFAULT_MAX_JSON_BYTES} bytes")
    if response.auth_challenge:
        errors.append("auth challenge present")

    if (expect_json or expect_signature) and not errors:
        try:
            decoded_json = _decode_json_bytes(response.content, label=f"{name} endpoint")
        except PolicyParseError as exc:
            errors.append(str(exc))

    if expect_signature and not errors and decoded_json is not None and not decoded_json.get("signature"):
        errors.append("signature field is missing")

    if expect_robots and not errors:
        text = response.content.decode("utf-8", errors="replace")
        if "User-agent: *" not in text or "Allow: /" not in text:
            errors.append("robots.txt does not allow all")

    check = {
        "name": name,
        "url": url,
        "ok": not errors,
        "status_code": response.status_code,
        "errors": errors,
    }
    if response.status_code == 200:
        check["sha256"] = _sha256_hex_bytes(response.content)
    return check, response, decoded_json


def _check_public_page_url(
    *,
    name: str,
    url: str,
    timeout_seconds: float,
    expect_json: bool = False,
    expect_signature: bool = False,
    expect_robots: bool = False,
) -> dict[str, object]:
    check, _response, _decoded_json = _public_page_fetch_check(
        name=name,
        url=url,
        timeout_seconds=timeout_seconds,
        expect_json=expect_json,
        expect_signature=expect_signature,
        expect_robots=expect_robots,
    )
    return check


def _public_consistency_check(
    name: str,
    errors: Sequence[str],
    **metadata: object,
) -> dict[str, object]:
    check: dict[str, object] = {
        "name": name,
        "ok": not errors,
        "errors": list(errors),
    }
    check.update({key: value for key, value in metadata.items() if value is not None})
    return check


def _manifest_policy_sha256_errors(
    manifest: Mapping[str, Any] | None,
    expected_policy_sha256: str | None,
    *,
    label: str,
) -> list[str]:
    if expected_policy_sha256 is None:
        return [f"{label} policy bytes unavailable"]
    if manifest is None:
        return [f"{label} manifest unavailable"]
    manifest_policy_sha256 = str(manifest.get("policy_sha256") or "")
    if not manifest_policy_sha256:
        return [f"{label} manifest missing policy_sha256"]
    if manifest_policy_sha256 != expected_policy_sha256:
        return [
            f"{label} manifest policy_sha256 {manifest_policy_sha256} does not match policy SHA-256 {expected_policy_sha256}"
        ]
    return []


def _manifest_documents_different_api_policy(
    manifest: Mapping[str, Any] | None,
    api_policy_sha256: str | None,
) -> bool:
    if manifest is None or api_policy_sha256 is None:
        return False
    marker = bool(
        manifest.get("api_policy_differs_from_canonical")
        or manifest.get("allow_different_api_policy_bytes")
    )
    return marker and str(manifest.get("api_policy_sha256") or "") == api_policy_sha256


def _manifest_documents_different_api_signature(
    manifest: Mapping[str, Any] | None,
    api_signature_sha256: str | None,
) -> bool:
    if manifest is None or api_signature_sha256 is None:
        return False
    marker = bool(
        manifest.get("api_policy_differs_from_canonical")
        or manifest.get("allow_different_api_policy_bytes")
    )
    return marker and str(manifest.get("api_signature_sha256") or "") == api_signature_sha256


def _published_url_errors(
    policy_document: Mapping[str, Any] | None,
    expected_urls: Mapping[str, str],
    *,
    label: str,
) -> list[str]:
    if policy_document is None:
        return [f"{label} policy JSON unavailable"]
    published_urls = policy_document.get("published_urls")
    if not isinstance(published_urls, Mapping):
        return [f"{label} policy JSON missing published_urls object"]

    errors: list[str] = []
    for key in DEFAULT_PUBLISHED_POLICY_URLS:
        expected_url = expected_urls[key]
        actual_url = published_urls.get(key)
        if actual_url != expected_url:
            errors.append(
                f"{label} published_urls.{key} expected {expected_url!r}, got {actual_url!r}"
            )
    return errors


def _check_public_pages_payload(
    policy,
    *,
    timeout_seconds: float,
    trusted_policy_public_key: str | bytes | None = None,
) -> tuple[dict[str, object], bool]:
    urls = _public_pages_urls(policy)
    endpoint_specs = [
        ("landing", urls["landing"], False, False, False),
        ("policy", urls["policy"], True, False, False),
        ("signature", urls["signature"], False, True, False),
        ("manifest", urls["manifest"], True, False, False),
        ("api_policy", urls["api_policy"], True, False, False),
        ("api_signature", urls["api_signature"], False, True, False),
        ("api_manifest", urls["api_manifest"], True, False, False),
        ("robots", urls["robots"], False, False, True),
        ("sitemap", urls["sitemap"], False, False, False),
    ]
    checks: list[dict[str, object]] = []
    responses: dict[str, PublicFetchResult] = {}
    decoded_documents: dict[str, Mapping[str, Any]] = {}
    for name, url, expect_json, expect_signature, expect_robots in endpoint_specs:
        check, response, decoded_json = _public_page_fetch_check(
            name=name,
            url=url,
            timeout_seconds=timeout_seconds,
            expect_json=expect_json,
            expect_signature=expect_signature,
            expect_robots=expect_robots,
        )
        checks.append(check)
        if response is not None:
            responses[name] = response
        if decoded_json is not None:
            decoded_documents[name] = decoded_json

    policy_bytes = responses.get("policy").content if responses.get("policy") else None
    signature_bytes = responses.get("signature").content if responses.get("signature") else None
    api_policy_bytes = responses.get("api_policy").content if responses.get("api_policy") else None
    api_signature_bytes = responses.get("api_signature").content if responses.get("api_signature") else None

    policy_sha256 = _sha256_hex_bytes(policy_bytes) if policy_bytes is not None else None
    api_policy_sha256 = _sha256_hex_bytes(api_policy_bytes) if api_policy_bytes is not None else None
    signature_sha256 = _sha256_hex_bytes(signature_bytes) if signature_bytes is not None else None
    api_signature_sha256 = _sha256_hex_bytes(api_signature_bytes) if api_signature_bytes is not None else None

    canonical_signature_ok = False
    canonical_signature_errors: list[str] = []
    if policy_bytes is None:
        canonical_signature_errors.append("canonical policy bytes unavailable")
    if signature_bytes is None:
        canonical_signature_errors.append("canonical signature bytes unavailable")
    if policy_bytes is not None and signature_bytes is not None:
        canonical_signature_ok = verify_policy_signature(
            policy_bytes,
            signature_bytes,
            trusted_policy_public_key,
        )
        if not canonical_signature_ok:
            canonical_signature_errors.append("canonical policy signature verification failed")
    checks.append(
        _public_consistency_check(
            "canonical_signature",
            canonical_signature_errors,
            policy_sha256=policy_sha256,
            signature_sha256=signature_sha256,
        )
    )

    api_signature_ok = False
    api_signature_errors: list[str] = []
    if api_policy_bytes is None:
        api_signature_errors.append("API policy bytes unavailable")
    if api_signature_bytes is None:
        api_signature_errors.append("API signature bytes unavailable")
    if api_policy_bytes is not None and api_signature_bytes is not None:
        api_signature_ok = verify_policy_signature(
            api_policy_bytes,
            api_signature_bytes,
            trusted_policy_public_key,
        )
        if not api_signature_ok:
            api_signature_errors.append("API policy signature verification failed")
    checks.append(
        _public_consistency_check(
            "api_signature_integrity",
            api_signature_errors,
            policy_sha256=api_policy_sha256,
            signature_sha256=api_signature_sha256,
        )
    )

    manifest = decoded_documents.get("manifest")
    api_manifest = decoded_documents.get("api_manifest")
    documented_api_difference = _manifest_documents_different_api_policy(manifest, api_policy_sha256)

    policy_alias_errors: list[str] = []
    if policy_bytes is None or api_policy_bytes is None:
        policy_alias_errors.append("canonical or API policy bytes unavailable")
    elif policy_bytes != api_policy_bytes and not documented_api_difference:
        policy_alias_errors.append(
            "canonical policy bytes differ from API policy bytes without manifest api_policy_sha256 "
            "and api_policy_differs_from_canonical=true"
        )
    checks.append(_public_consistency_check("policy_api_alias", policy_alias_errors))

    signature_alias_errors: list[str] = []
    if signature_bytes is None or api_signature_bytes is None:
        signature_alias_errors.append("canonical or API signature bytes unavailable")
    elif signature_bytes != api_signature_bytes:
        same_policy_hash = policy_sha256 == api_policy_sha256
        documented_signature_difference = _manifest_documents_different_api_signature(
            manifest,
            api_signature_sha256,
        )
        if same_policy_hash and canonical_signature_ok and api_signature_ok:
            pass
        elif documented_api_difference and documented_signature_difference and canonical_signature_ok and api_signature_ok:
            pass
        else:
            signature_alias_errors.append(
                "canonical signature bytes differ from API signature bytes and do not verify the same policy hash"
            )
    checks.append(_public_consistency_check("signature_api_alias", signature_alias_errors))

    checks.append(
        _public_consistency_check(
            "manifest_policy_sha256",
            _manifest_policy_sha256_errors(manifest, policy_sha256, label="canonical"),
        )
    )
    checks.append(
        _public_consistency_check(
            "api_manifest_policy_sha256",
            _manifest_policy_sha256_errors(api_manifest, api_policy_sha256, label="API"),
        )
    )

    published_url_errors = [
        *_published_url_errors(decoded_documents.get("policy"), urls, label="canonical"),
        *_published_url_errors(decoded_documents.get("api_policy"), urls, label="API"),
    ]
    checks.append(_public_consistency_check("published_urls", published_url_errors))

    ok = all(bool(check.get("ok")) for check in checks)
    return (
        {
            "status": "OK" if ok else "FAILED",
            "checks": checks,
        },
        ok,
    )


def _policy_source_failure_payload(
    *,
    status: str,
    policy_url: str | None,
    signature_url: str | None,
    message: str,
    exc: BaseException | None = None,
) -> dict[str, object]:
    return {
        "ok": False,
        "status": status,
        "policy_url": policy_url,
        "signature_url": signature_url,
        "error": message,
        "exception_type": type(exc).__name__ if exc is not None else None,
    }


def _policy_source_success_payload(
    policy_url: str,
    signature_url: str,
    trusted_signature_status: str,
    policy,
    *,
    manifest_payload: Mapping[str, object],
    public_pages_payload: Mapping[str, object] | None = None,
) -> dict[str, object]:
    target = policy.broad_target_existing_devices
    broad_target = None
    baseline = None
    if target is not None:
        broad_target = {
            "version": target.version,
            "build_family": target.build_family,
            "latest_build": target.latest_build,
            "latest_observed_build": target.latest_observed_build,
            "baseline_build": target.baseline_build,
            "required_baseline_build": target.required_baseline_build,
            "servicing_channel": target.servicing_channel.value,
        }
        baseline = target.required_baseline_build

    excluded_releases = [
        {
            "version": entry.version,
            "build_family": entry.build_family,
            "reason": entry.reason or entry.metadata.get("reason"),
            "latest_build": entry.latest_build,
            "latest_observed_build": entry.latest_observed_build,
            "baseline_build": entry.baseline_build,
            "required_baseline_build": entry.required_baseline_build,
        }
        for entry in policy.excluded_for_existing_devices
    ]
    status = "OK"
    if manifest_payload.get("manifest_status") in {"invalid", "sha256_mismatch"}:
        status = "INVALID"
    if (
        manifest_payload.get("manifest_status") == "unavailable"
        and not manifest_payload.get("manifest_missing_allowed")
    ):
        status = "INVALID"
    if public_pages_payload and public_pages_payload.get("status") != "OK":
        status = "PUBLIC_PAGES_FAILED"

    return {
        "ok": True,
        "status": status,
        "policy_url": policy_url,
        "signature_url": signature_url,
        "signature_status": trusted_signature_status,
        "generated_at_utc": policy.generated_at_utc,
        "source_urls": list(policy.source_urls),
        "source_diagnostics": dict(policy.source_diagnostics),
        "published_urls": dict(policy.published_urls),
        "manifest_url": manifest_payload.get("manifest_url"),
        "manifest_status": manifest_payload.get("manifest_status"),
        "manifest_warning": manifest_payload.get("manifest_warning"),
        "policy_sha256": manifest_payload.get("policy_sha256"),
        "manifest_policy_sha256": manifest_payload.get("manifest_policy_sha256"),
        "public_pages": dict(public_pages_payload) if public_pages_payload else None,
        "broad_target": broad_target,
        "baseline": baseline,
        "excluded_releases": excluded_releases,
        "validation_warnings": list(policy.validation_warnings),
    }


def _print_public_policy_source_line(text: str) -> None:
    # This CLI mode prints public policy feed diagnostics; it does not print secrets.
    # codeql[py/clear-text-logging-sensitive-data]
    print(text)


def _check_policy_source_payload(args: argparse.Namespace) -> tuple[dict[str, object], bool]:
    policy_url, _source = _policy_url_from_args(args)
    if policy_url is None:
        return (
            _policy_source_failure_payload(
                status="UNAVAILABLE",
                policy_url=None,
                signature_url=None,
                message="Policy source unavailable: no policy URL configured.",
            ),
            False,
        )

    signature_url = _policy_signature_source(policy_url)
    try:
        policy_bytes, content_type = fetch_policy_bytes(policy_url, timeout=args.timeout_seconds)
    except PolicyFetchError as exc:
        return (
            _policy_source_failure_payload(
                status="UNAVAILABLE",
                policy_url=policy_url,
                signature_url=signature_url,
                message=f"Policy source unavailable: {exc}",
                exc=exc,
            ),
            False,
        )
    except Exception as exc:
        return (
            _policy_source_failure_payload(
                status="UNAVAILABLE",
                policy_url=policy_url,
                signature_url=signature_url,
                message=f"Policy source unavailable: {exc}",
                exc=exc,
            ),
            False,
        )

    try:
        signature_bytes, _signature_content_type = fetch_policy_bytes(signature_url, timeout=args.timeout_seconds)
    except PolicyFetchError as exc:
        return (
            _policy_source_failure_payload(
                status="UNAVAILABLE",
                policy_url=policy_url,
                signature_url=signature_url,
                message=f"Policy signature unavailable: {exc}",
                exc=exc,
            ),
            False,
        )
    except Exception as exc:
        return (
            _policy_source_failure_payload(
                status="UNAVAILABLE",
                policy_url=policy_url,
                signature_url=signature_url,
                message=f"Policy signature unavailable: {exc}",
                exc=exc,
            ),
            False,
        )

    try:
        trusted = load_trusted_policy(
            policy_bytes,
            signature_bytes=signature_bytes,
            public_key=args.trusted_policy_public_key,
            require_signature=True,
            allow_unsigned=False,
            content_type=content_type,
            source_url=policy_url,
            allow_html_fallback=False,
        )
    except PolicyTrustError as exc:
        return (
            _policy_source_failure_payload(
                status="SIGNATURE_FAILED",
                policy_url=policy_url,
                signature_url=signature_url,
                message=f"Policy signature invalid: {exc}",
                exc=exc,
            ),
            False,
        )
    except PolicyParseError as exc:
        return (
            _policy_source_failure_payload(
                status="INVALID",
                policy_url=policy_url,
                signature_url=signature_url,
                message=f"Policy source invalid: {exc}",
                exc=exc,
            ),
            False,
        )
    except WindowsReleaseCheckerError as exc:
        return (
            _policy_source_failure_payload(
                status="INVALID",
                policy_url=policy_url,
                signature_url=signature_url,
                message=f"Policy source invalid: {exc}",
                exc=exc,
            ),
            False,
        )
    except Exception as exc:
        return (
            _policy_source_failure_payload(
                status="INVALID",
                policy_url=policy_url,
                signature_url=signature_url,
                message=f"Policy source invalid: {exc}",
                exc=exc,
            ),
            False,
        )

    try:
        validate_policy_document(trusted.policy.to_dict())
    except PolicyParseError as exc:
        return (
            _policy_source_failure_payload(
                status="INVALID",
                policy_url=policy_url,
                signature_url=signature_url,
                message=f"Policy schema invalid: {exc}",
                exc=exc,
            ),
            False,
        )

    manifest_payload, manifest_ok = _manifest_check_payload(
        policy_url=policy_url,
        policy=trusted.policy,
        policy_bytes=policy_bytes,
        timeout_seconds=args.timeout_seconds,
        allow_missing_manifest=bool(args.allow_missing_manifest),
    )

    public_pages_payload = None
    public_pages_ok = True
    if args.check_public_pages:
        public_pages_payload, public_pages_ok = _check_public_pages_payload(
            trusted.policy,
            timeout_seconds=args.timeout_seconds,
            trusted_policy_public_key=args.trusted_policy_public_key,
        )

    return (
        _policy_source_success_payload(
            policy_url,
            signature_url,
            trusted.signature_status,
            trusted.policy,
            manifest_payload=manifest_payload,
            public_pages_payload=public_pages_payload,
        ),
        manifest_ok and public_pages_ok,
    )


def _print_policy_source_payload(payload: dict[str, object]) -> None:
    emit = _print_public_policy_source_line
    emit(f"Policy source: {payload['status']}")
    if payload.get("policy_url"):
        emit(f"Policy URL: {payload['policy_url']}")
    if payload.get("signature_url"):
        emit(f"Signature URL: {payload['signature_url']}")
    if not payload.get("ok"):
        emit(f"Error: {payload['error']}")
        if payload.get("exception_type"):
            emit(f"Exception type: {payload['exception_type']}")
        return

    emit(f"Signature: {payload['signature_status']}")
    emit(f"Generated at UTC: {payload['generated_at_utc'] or 'unknown'}")
    if payload.get("manifest_url"):
        emit(f"Manifest URL: {payload['manifest_url']}")
        emit(f"Manifest: {payload.get('manifest_status') or 'unknown'}")
        if payload.get("manifest_policy_sha256"):
            emit(f"Manifest policy SHA-256: {payload['manifest_policy_sha256']}")
    elif payload.get("manifest_status"):
        emit(f"Manifest: {payload['manifest_status']}")
    if payload.get("policy_sha256"):
        emit(f"Policy SHA-256: {payload['policy_sha256']}")
    emit("Source URLs:")
    for source_url in payload.get("source_urls") or []:
        emit(f"- {source_url}")
    source_diagnostics = payload.get("source_diagnostics") or {}
    if isinstance(source_diagnostics, dict) and source_diagnostics:
        emit("Source freshness:")
        release_health = source_diagnostics.get("release_health_html")
        if isinstance(release_health, dict):
            emit(
                "- release_health_html: "
                f"fetched_at={release_health.get('fetched_at_utc') or 'unknown'}, "
                f"bytes={release_health.get('bytes') if release_health.get('bytes') is not None else 'unknown'}, "
                f"newest_current_revision={release_health.get('newest_current_version_revision_date') or 'unknown'}, "
                f"newest_history_availability={release_health.get('newest_release_history_availability_date') or 'unknown'}"
            )
        atom_feed = source_diagnostics.get("atom_feed")
        if isinstance(atom_feed, dict):
            emit(
                "- atom_feed: "
                f"fetched_at={atom_feed.get('fetched_at_utc') or 'unknown'}, "
                f"bytes={atom_feed.get('bytes') if atom_feed.get('bytes') is not None else 'unknown'}, "
                f"newest_atom_updated={atom_feed.get('newest_atom_updated') or 'unknown'}, "
                f"newest_atom_published={atom_feed.get('newest_atom_published') or 'unknown'}"
            )
    published_urls = payload.get("published_urls") or {}
    if isinstance(published_urls, dict) and published_urls:
        emit("Published URLs:")
        for key, url in published_urls.items():
            emit(f"- {key}: {url}")

    broad_target = payload.get("broad_target")
    if isinstance(broad_target, dict):
        emit(
            "Broad target: "
            f"{broad_target.get('version')} / "
            f"{broad_target.get('build_family')}"
        )
        emit(f"Latest observed build: {broad_target.get('latest_observed_build') or broad_target.get('latest_build') or 'unknown'}")
        emit(f"Required baseline build: {broad_target.get('required_baseline_build') or 'unknown'}")
    else:
        emit("Broad target: unknown")
    emit(f"Required baseline: {payload.get('baseline') or 'unknown'}")

    emit("Excluded releases:")
    excluded_releases = payload.get("excluded_releases") or []
    if excluded_releases:
        for entry in excluded_releases:
            if isinstance(entry, dict):
                reason = f" / {entry['reason']}" if entry.get("reason") else ""
                emit(f"- {entry.get('version')} / {entry.get('build_family')}{reason}")
    else:
        emit("- none")

    warnings = payload.get("validation_warnings") or []
    if isinstance(source_diagnostics, dict):
        warnings = list(dict.fromkeys([*warnings, *(source_diagnostics.get("warnings") or [])]))
    manifest_warning = payload.get("manifest_warning")
    if manifest_warning:
        warnings = [*warnings, manifest_warning]
    if warnings:
        emit("Warnings:")
        for warning in warnings:
            emit(f"- {warning}")

    public_pages = payload.get("public_pages")
    if isinstance(public_pages, dict):
        emit(f"Public Pages: {public_pages.get('status') or 'unknown'}")
        for check in public_pages.get("checks") or []:
            if not isinstance(check, dict):
                continue
            status = "OK" if check.get("ok") else "FAILED"
            status_code = check.get("status_code")
            suffix = f" HTTP {status_code}" if status_code is not None else ""
            line = f"- {check.get('name')}: {status}{suffix}"
            if check.get("url"):
                line = f"{line} {check['url']}"
            emit(line)
            for error in check.get("errors") or []:
                emit(f"  - {error}")
            if check.get("error"):
                emit(f"  - {check['error']}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        if exc.code == 0:
            return 0
        return EXIT_ARGUMENT_ERROR

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if args.self_test:
        payload, ok = _self_test_payload()
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True))
        return 0 if ok else EXIT_UNKNOWN_OR_POLICY_ERROR

    if args.check_policy_source or args.check_public_pages:
        payload, ok = _check_policy_source_payload(args)
        _print_policy_source_payload(payload)
        return 0 if ok else EXIT_UNKNOWN_OR_POLICY_ERROR

    if args.diagnose_config:
        diagnose_payload = _diagnose_config_payload(args)
        # codeql[py/clear-text-logging-sensitive-data]
        print(json.dumps(diagnose_payload, indent=2, sort_keys=True, ensure_ascii=True))
        return 0

    json_output = bool(args.json or args.json_pretty or args.output is not None)

    try:
        result = check_current_system(_config_from_args(args))
        if args.output is not None:
            _write_json_output(
                args.output,
                result,
                pretty=bool(args.json_pretty),
                unicode_output=bool(args.unicode),
                include_raw_wua_history=bool(args.include_raw_wua_history),
            )
        if args.json or args.json_pretty:
            _print_json(
                result,
                pretty=bool(args.json_pretty),
                unicode_output=bool(args.unicode),
                include_raw_wua_history=bool(args.include_raw_wua_history),
            )
        elif args.output is None or args.pretty:
            _print_pretty(result)
        return _exit_code(result.status)
    except WindowsReleaseCheckerError as exc:
        _print_error(str(exc), json_output=json_output)
        if args.debug:
            traceback.print_exc()
        return EXIT_UNKNOWN_OR_POLICY_ERROR
    except Exception as exc:
        _print_error(str(exc), json_output=json_output)
        if args.debug:
            traceback.print_exc()
        return EXIT_UNKNOWN_OR_POLICY_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
