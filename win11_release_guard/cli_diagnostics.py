"""Self-test, configuration diagnosis, and state inspection payloads."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import platform
import sys
from importlib import resources
from cryptography.hazmat.primitives import serialization
from .api import _load_runtime_policy
from .bundled_policy import BUNDLED_POLICY_FILE, BUNDLED_POLICY_PACKAGE, BUNDLED_POLICY_SIGNATURE_FILE, load_bundled_policy
from . import state_store
from .config import CACHE_FILE_ENV_VAR, MAX_POLICY_BYTES_ENV_VAR, POLICY_URL_ENV_VAR, ReleaseCheckerConfig, STATE_DIR_ENV_VAR, STATELESS_ENV_VAR, STRICT_PRODUCTION_ENV_VAR
from .signing import load_public_key
from .version import package_version
from .cli_args import (
    _cache_file_from_args,
    _config_from_args,
    _policy_url_from_args,
    _state_dir_from_args,
    _stateless_from_args,
)


def _package_version() -> str:
    return package_version()


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
    _state_dir_value, state_dir_source = _state_dir_from_args(args)
    _stateless_value, stateless_source = _stateless_from_args(args)
    _cache_file_value, cache_file_source = _cache_file_from_args(args)
    config = _config_from_args(args)
    scope = state_store.resolve_state_scope(config)
    if config.cache_file:
        effective_cache_file: str | None = str(config.cache_file)
    elif scope.path is not None:
        effective_cache_file = str(scope.path)
    else:
        effective_cache_file = None
    payload = {
        "package_version": _package_version(),
        "effective_policy_url": policy_url,
        "policy_url": policy_url,
        "policy_url_source": source,
        "policy_url_env_var": POLICY_URL_ENV_VAR,
        "strict_production_env_var": STRICT_PRODUCTION_ENV_VAR,
        "max_policy_bytes_env_var": MAX_POLICY_BYTES_ENV_VAR,
        "cache_file": effective_cache_file,
        "state_layout": scope.layout,
        "state_path": str(scope.path) if scope.path is not None else None,
        "state_dir": config.state_dir,
        "state_dir_source": state_dir_source,
        "state_dir_env_var": STATE_DIR_ENV_VAR,
        "stateless": config.stateless,
        "stateless_source": stateless_source,
        "stateless_env_var": STATELESS_ENV_VAR,
        "cache_file_source": cache_file_source,
        "cache_file_env_var": CACHE_FILE_ENV_VAR,
        "state_format_version": state_store.STATE_FORMAT_VERSION,
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
        "max_policy_bytes": config.max_policy_bytes,
        "use_bundled_policy_fallback": config.use_bundled_policy_fallback,
        "allow_unsigned_policy": config.allow_unsigned_policy,
        "allow_runtime_release_health_html": config.allow_runtime_release_health_html,
    }
    payload.update(_bundled_policy_diagnostics(config))
    if args.check_source:
        payload["source_check"] = _source_check_payload(config)
    return payload


def _purge_state_payload(config: ReleaseCheckerConfig) -> dict[str, object]:
    events = state_store.purge_state(config)
    return {"events": [event.to_dict() for event in events]}


def _show_state_payload(config: ReleaseCheckerConfig) -> dict[str, object]:
    return state_store.describe_state(config)


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
