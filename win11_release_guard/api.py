from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .bundled_policy import load_bundled_policy
from .cache import default_cache_path
from .config import ReleaseCheckerConfig, resolve_policy_url
from .evaluator import evaluate_windows_update_state, select_broad_fleet_target
from .exceptions import PolicyError, PolicyFetchError, PolicyParseError, PolicyTrustError, WindowsReleaseCheckerError
from .local_state import get_local_windows_state
from .models import EvaluationResult, EvaluationStatus, LocalWindowsState, ReleasePolicy, SourceProblem, SourceStatus
from .audit_probes import collect_audit_diagnostics
from .policy_diagnostics import apply_silent_feature_update_diagnostics
from .remote_policy import fetch_policy_bytes
from .signing import TrustedPolicy, load_trusted_policy
from .wua_probe import query_wua_secondary


@dataclass(frozen=True)
class PolicySourceResult:
    policy: ReleasePolicy | None
    source_status: SourceStatus
    is_source_check_complete: bool
    policy_source_url: str | None = None
    policy_source_kind: str | None = None
    policy_signature_status: str | None = None
    policy_age_hours: float | None = None
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    source_problems: tuple[SourceProblem, ...] = ()


def _source_problem(
    kind: str,
    message: str,
    *,
    source_url: str | None = None,
    exc: BaseException | None = None,
    retryable: bool = False,
) -> SourceProblem:
    return SourceProblem(
        kind=kind,
        message=message,
        source_url=source_url,
        exception_type=type(exc).__name__ if exc is not None else None,
        retryable=retryable,
    )


def _has_http_status(message: str, status_code: int) -> bool:
    return bool(
        re.search(
            rf"\bhttp(?:\s+error|\s+status)?\s*:?\s*{status_code}\b",
            message,
        )
    )


def _is_dns_failure_message(message: str) -> bool:
    dns_fragments = (
        "getaddrinfo",
        "name resolution",
        "temporary failure in name resolution",
        "name or service not known",
        "nodename nor servname",
        "no address associated with hostname",
        "no such host is known",
        "errno 11001",
        "errno -3",
        "dns",
    )
    return any(fragment in message for fragment in dns_fragments)


def _is_tls_failure_retryable(message: str) -> bool:
    non_retryable_fragments = (
        "certificate verify failed",
        "self-signed",
        "self signed",
        "hostname mismatch",
        "certificate has expired",
        "certificate expired",
        "unable to get local issuer",
    )
    return not any(fragment in message for fragment in non_retryable_fragments)


def _problem_kind_for_exception(exc: BaseException, *, context: str) -> tuple[str, bool]:
    message = str(exc).lower()
    if isinstance(exc, PolicyTrustError):
        if "signature" in message and ("required" in message or "is missing" in message):
            return "missing_signature", False
        if "signature" in message or "invalid" in message or "verification failed" in message:
            return SourceStatus.REMOTE_POLICY_SIGNATURE_FAILED.value.lower(), False
        if "html" in message:
            return "runtime_html_rejected", False
        return SourceStatus.REMOTE_POLICY_SIGNATURE_FAILED.value.lower(), False
    if isinstance(exc, PolicyParseError):
        return SourceStatus.REMOTE_POLICY_PARSE_FAILED.value.lower(), False
    if isinstance(exc, TimeoutError) or "timed out" in message or "timeout" in message:
        return "timeout", True
    if _is_dns_failure_message(message):
        return "dns_failure", True
    if "connection refused" in message or "actively refused" in message:
        return "connection_refused", True
    if "tls" in message or "ssl" in message or "certificate" in message:
        return "tls_failure", _is_tls_failure_retryable(message)
    if "proxy" in message:
        return "proxy_failure", True
    if _has_http_status(message, 403):
        return "http_403", False
    if _has_http_status(message, 404):
        return "http_404", False
    if _has_http_status(message, 500):
        return "http_500", True
    if "http " in message:
        return "http_error", True
    if "signature" in message:
        return SourceStatus.REMOTE_POLICY_SIGNATURE_FAILED.value.lower(), False
    if "json" in message or "html" in message or "current-version table" in message or "target" in message or "baseline" in message:
        return SourceStatus.REMOTE_POLICY_PARSE_FAILED.value.lower(), False
    return context or SourceStatus.REMOTE_POLICY_UNREACHABLE.value.lower(), isinstance(exc, PolicyFetchError)


def _policy_age_hours(policy: ReleasePolicy, now: datetime | None = None) -> float | None:
    if not policy.generated_at_utc:
        return None
    try:
        generated = datetime.fromisoformat(policy.generated_at_utc.replace("Z", "+00:00"))
    except ValueError:
        return None
    if generated.tzinfo is None:
        generated = generated.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    return max(0.0, (reference - generated.astimezone(timezone.utc)).total_seconds() / 3600)


def _policy_is_fresh(policy: ReleasePolicy, cache_path: Path, *, max_age_hours: float) -> bool:
    if policy.generated_at_utc:
        age = _policy_age_hours(policy)
        return age is not None and age <= max_age_hours
    modified = datetime.fromtimestamp(cache_path.stat().st_mtime, tz=timezone.utc)
    return datetime.now(timezone.utc) - modified <= timedelta(hours=max_age_hours)


def _cache_path(config: ReleaseCheckerConfig) -> Path:
    return Path(config.cache_file) if config.cache_file else default_cache_path()


def _signature_path(path: str | Path) -> Path:
    return Path(f"{path}.sig")


def _signature_url(policy_url: str) -> str:
    return f"{policy_url}.sig"


def _is_url(value: str) -> bool:
    return bool(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value))


def _looks_like_html(data: bytes, content_type: str | None) -> bool:
    content_type_l = (content_type or "").lower()
    if "text/html" in content_type_l:
        return True
    prefix = data.lstrip(b"\xef\xbb\xbf\r\n\t ").lower()[:500]
    return prefix.startswith(b"<!doctype html") or prefix.startswith(b"<html") or b"<html" in prefix


def _source_kind_from_bytes(
    data: bytes,
    content_type: str | None,
    *,
    source_url: str,
    config: ReleaseCheckerConfig,
) -> str:
    is_url = _is_url(source_url)
    if _looks_like_html(data, content_type):
        if config.allow_runtime_release_health_html:
            return "remote_html"
        raise PolicyTrustError("HTML policy source is not allowed in runtime mode.")
    return "remote_json" if is_url else "local_json"


def _accept_trusted_policy(
    trusted: TrustedPolicy,
    *,
    source_kind: str,
    source_url: str,
    source_status: SourceStatus,
    is_source_check_complete: bool,
    warnings: list[str],
    errors: list[str],
    source_problems: list[SourceProblem],
) -> PolicySourceResult:
    warnings.extend(trusted.policy.validation_warnings)
    signature_status = (
        "not_applicable_html"
        if source_kind == "remote_html"
        else trusted.signature_status
    )
    return PolicySourceResult(
        policy=trusted.policy,
        source_status=source_status,
        is_source_check_complete=is_source_check_complete,
        policy_source_url=source_url,
        policy_source_kind=source_kind,
        policy_signature_status=signature_status,
        policy_age_hours=_policy_age_hours(trusted.policy),
        warnings=tuple(dict.fromkeys(warnings)),
        errors=tuple(dict.fromkeys(errors)),
        source_problems=tuple(dict.fromkeys(source_problems)),
    )


def _load_trusted_from_bytes(
    policy_bytes: bytes,
    *,
    signature_bytes: bytes | None,
    content_type: str | None,
    source_url: str,
    source_kind: str,
    config: ReleaseCheckerConfig,
) -> TrustedPolicy:
    html_source = source_kind == "remote_html"
    return load_trusted_policy(
        policy_bytes,
        signature_bytes=signature_bytes,
        public_key=config.trusted_policy_public_key,
        require_signature=(not config.allow_unsigned_policy and not html_source),
        allow_unsigned=(config.allow_unsigned_policy or html_source),
        content_type=content_type,
        source_url=source_url,
        allow_html_fallback=html_source,
    )


def _fetch_signature_bytes(policy_url: str, config: ReleaseCheckerConfig) -> bytes | None:
    try:
        data, _content_type = fetch_policy_bytes(
            _signature_url(policy_url),
            timeout=config.timeout_seconds,
        )
        return data
    except WindowsReleaseCheckerError:
        return None
    except Exception:
        return None


def _save_trusted_cache(trusted: TrustedPolicy, cache_path: Path) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(trusted.policy_bytes)
    if trusted.signature_bytes is not None:
        _signature_path(cache_path).write_bytes(trusted.signature_bytes)


def _load_remote_policy(
    config: ReleaseCheckerConfig,
    *,
    policy_url: str,
    warnings: list[str],
    errors: list[str],
    source_problems: list[SourceProblem],
) -> PolicySourceResult | None:
    policy_bytes, content_type = fetch_policy_bytes(
        policy_url,
        timeout=config.timeout_seconds,
    )
    source_kind = _source_kind_from_bytes(
        policy_bytes,
        content_type,
        source_url=policy_url,
        config=config,
    )
    signature_bytes = None if source_kind == "remote_html" else _fetch_signature_bytes(policy_url, config)
    if signature_bytes is None and source_kind != "remote_html" and not config.allow_unsigned_policy:
        source_problems.append(
            _source_problem(
                "missing_signature",
                "Remote policy signature fetch failed or signature is missing.",
                source_url=_signature_url(policy_url),
                retryable=True,
            )
        )
    trusted = _load_trusted_from_bytes(
        policy_bytes,
        signature_bytes=signature_bytes,
        content_type=content_type,
        source_url=policy_url,
        source_kind=source_kind,
        config=config,
    )
    accepted = _accept_trusted_policy(
        trusted,
        source_kind=source_kind,
        source_url=policy_url,
        source_status=(
            SourceStatus.RUNTIME_HTML_FALLBACK_USED
            if source_kind == "remote_html"
            else SourceStatus.REMOTE_POLICY_OK
        ),
        is_source_check_complete=True,
        warnings=warnings,
        errors=errors,
        source_problems=source_problems,
    )
    if source_kind == "remote_json":
        _save_trusted_cache(trusted, _cache_path(config))
    return accepted


def _load_cache_policy(
    cache_path: Path,
    config: ReleaseCheckerConfig,
    *,
    max_age_hours: float,
    source_kind: str,
    source_status: SourceStatus,
    warning: str,
    warnings: list[str],
    errors: list[str],
    source_problems: list[SourceProblem],
) -> PolicySourceResult | None:
    if not cache_path.exists():
        return None
    signature_path = _signature_path(cache_path)
    signature_bytes = signature_path.read_bytes() if signature_path.exists() else None
    trusted = load_trusted_policy(
        cache_path.read_bytes(),
        signature_bytes=signature_bytes,
        public_key=config.trusted_policy_public_key,
        require_signature=not config.allow_unsigned_policy,
        allow_unsigned=config.allow_unsigned_policy,
        content_type="application/json",
        source_url=str(cache_path),
    )
    if not _policy_is_fresh(trusted.policy, cache_path, max_age_hours=max_age_hours):
        source_problems.append(
            _source_problem(
                "stale_cache",
                f"Cached policy at {cache_path} is older than {max_age_hours:g} hours.",
                source_url=str(cache_path),
                retryable=False,
            )
        )
        return None
    return _accept_trusted_policy(
        trusted,
        source_kind=source_kind,
        source_url=str(cache_path),
        source_status=source_status,
        is_source_check_complete=False,
        warnings=warnings + [warning],
        errors=errors,
        source_problems=source_problems,
    )


def _load_runtime_policy(config: ReleaseCheckerConfig) -> PolicySourceResult:
    warnings: list[str] = []
    errors: list[str] = []
    source_problems: list[SourceProblem] = []
    policy_url = resolve_policy_url(config.policy_url)

    if policy_url:
        try:
            remote = _load_remote_policy(
                config,
                policy_url=policy_url,
                warnings=warnings,
                errors=errors,
                source_problems=source_problems,
            )
            if remote is not None:
                return remote
        except WindowsReleaseCheckerError as exc:
            kind, retryable = _problem_kind_for_exception(exc, context="remote_policy_failed")
            source_problems.append(
                _source_problem(kind, f"Remote policy failed: {exc}", source_url=policy_url, exc=exc, retryable=retryable)
            )
        except Exception as exc:
            kind, retryable = _problem_kind_for_exception(exc, context="remote_policy_failed")
            source_problems.append(
                _source_problem(kind, f"Remote policy failed: {exc}", source_url=policy_url, exc=exc, retryable=retryable)
            )
    else:
        warnings.append("No remote policy URL configured; using bundled last-known-good policy.")

    if policy_url:
        cache_path = _cache_path(config)
        try:
            fresh_cache = _load_cache_policy(
                cache_path,
                config,
                max_age_hours=config.cache_max_age_hours,
                source_kind="fresh_cache",
                source_status=SourceStatus.USING_FRESH_CACHE,
                warning="Remote policy unavailable; using fresh cached policy.",
                warnings=warnings,
                errors=errors,
                source_problems=source_problems,
            )
            if fresh_cache is not None:
                return fresh_cache
        except WindowsReleaseCheckerError as exc:
            source_problems.append(
                _source_problem("corrupt_cache", f"Fresh cache failed: {exc}", source_url=str(cache_path), exc=exc, retryable=False)
            )
        except Exception as exc:
            source_problems.append(
                _source_problem("corrupt_cache", f"Fresh cache failed: {exc}", source_url=str(cache_path), exc=exc, retryable=False)
            )

        try:
            stale_cache = _load_cache_policy(
                cache_path,
                config,
                max_age_hours=config.stale_cache_max_age_hours,
                source_kind="stale_cache",
                source_status=SourceStatus.USING_STALE_CACHE,
                warning="Remote policy unavailable; using stale cached policy. Source check is incomplete.",
                warnings=warnings,
                errors=errors,
                source_problems=source_problems,
            )
            if stale_cache is not None:
                return stale_cache
        except WindowsReleaseCheckerError as exc:
            source_problems.append(
                _source_problem("corrupt_cache", f"Stale cache failed: {exc}", source_url=str(cache_path), exc=exc, retryable=False)
            )
        except Exception as exc:
            source_problems.append(
                _source_problem("corrupt_cache", f"Stale cache failed: {exc}", source_url=str(cache_path), exc=exc, retryable=False)
            )

    if config.use_bundled_policy_fallback:
        try:
            bundled = load_bundled_policy(
                public_key=config.trusted_policy_public_key,
                allow_unsigned=config.allow_unsigned_policy,
            )
            warning = (
                "Remote policy and cache unavailable; using bundled last-known-good policy."
                if policy_url
                else "No remote policy URL configured; using bundled last-known-good policy."
            )
            return _accept_trusted_policy(
                bundled,
                source_kind="bundled",
                source_url="bundled:windows-release-policy.json",
                source_status=SourceStatus.USING_BUNDLED_POLICY,
                is_source_check_complete=False,
                warnings=warnings + [warning],
                errors=errors,
                source_problems=source_problems,
            )
        except WindowsReleaseCheckerError as exc:
            kind, retryable = _problem_kind_for_exception(exc, context="bundled_policy_failed")
            source_problems.append(
                _source_problem(kind, f"Bundled policy failed: {exc}", source_url="bundled:windows-release-policy.json", exc=exc, retryable=retryable)
            )
        except Exception as exc:
            kind, retryable = _problem_kind_for_exception(exc, context="bundled_policy_failed")
            source_problems.append(
                _source_problem(kind, f"Bundled policy failed: {exc}", source_url="bundled:windows-release-policy.json", exc=exc, retryable=retryable)
            )

    return PolicySourceResult(
        policy=None,
        source_status=SourceStatus.POLICY_UNAVAILABLE,
        is_source_check_complete=False,
        policy_signature_status="unavailable",
        warnings=tuple(dict.fromkeys(warnings)),
        errors=tuple(dict.fromkeys(errors or ["No valid release policy is available."])),
        source_problems=tuple(dict.fromkeys(source_problems)),
    )


def _with_source(result: EvaluationResult, source: PolicySourceResult) -> EvaluationResult:
    warnings = tuple(dict.fromkeys(source.warnings + result.warnings + result.notes))
    errors = tuple(dict.fromkeys(source.errors + result.errors))
    return replace(
        result,
        notes=warnings,
        warnings=warnings,
        errors=errors,
        source_problems=source.source_problems,
        source_status=source.source_status,
        is_source_check_complete=source.is_source_check_complete,
        policy_age_hours=source.policy_age_hours,
        policy_source_url=source.policy_source_url,
        policy_source_kind=source.policy_source_kind,
        policy_signature_status=source.policy_signature_status,
    )


def _incomplete_result(local_state: LocalWindowsState, source: PolicySourceResult) -> EvaluationResult:
    return EvaluationResult(
        status=EvaluationStatus.CHECK_INCOMPLETE,
        local=local_state,
        action="Policy unavailable; release compliance check is incomplete.",
        is_warning=True,
        is_error=True,
        summary="Check incomplete: no valid release policy is available.",
        source_status=source.source_status,
        is_source_check_complete=False,
        policy_signature_status=source.policy_signature_status,
        warnings=source.warnings,
        errors=source.errors,
        source_problems=source.source_problems,
    )


def _get_local_state(config: ReleaseCheckerConfig) -> LocalWindowsState:
    try:
        return get_local_windows_state(
            dism_timeout_seconds=config.dism_timeout_seconds,
            powershell_timeout_seconds=config.powershell_timeout_seconds,
            panther_tail_max_bytes=config.panther_tail_max_bytes,
        )
    except TypeError as exc:
        if "unexpected keyword" not in str(exc):
            raise
        return get_local_windows_state()


def _with_audit_diagnostics(result: EvaluationResult, config: ReleaseCheckerConfig) -> EvaluationResult:
    if not result.silent_feature_update_missing:
        return result
    try:
        audit = collect_audit_diagnostics(
            dism_timeout_seconds=config.dism_timeout_seconds,
            panther_tail_max_bytes=config.panther_tail_max_bytes,
        )
    except Exception as exc:
        audit = {"errors": [f"Audit diagnostics failed: {exc}"]}
    return apply_silent_feature_update_diagnostics(result, audit)


def check_current_system(config: ReleaseCheckerConfig | None = None) -> EvaluationResult:
    active_config = config or ReleaseCheckerConfig()

    local_state = _get_local_state(active_config)
    source = _load_runtime_policy(active_config)
    if source.policy is None:
        return _incomplete_result(local_state, source)
    policy = source.policy

    wua_secondary = None
    if active_config.enable_wua_probe:
        target_release = None
        try:
            target_release = select_broad_fleet_target(
                policy,
                prefer_h2_releases=active_config.prefer_h2_releases,
                excluded_releases=set(active_config.excluded_releases),
                explicit_target_release=active_config.explicit_target_release,
            ).version
        except PolicyError:
            target_release = None
        try:
            wua_secondary = query_wua_secondary(
                target_release,
                max_history=active_config.wua_max_history,
                timeout_seconds=active_config.wua_timeout_seconds,
                max_relevant_updates=active_config.wua_max_relevant_updates,
                event_log_max_events=active_config.event_log_max_events,
            )
        except Exception as exc:
            wua_secondary = {
                "available": False,
                "warnings": [f"WUA probe failed: {exc}"],
                "errors": [],
                "timed_out": False,
            }

    result = evaluate_windows_update_state(
        local_state,
        policy,
        quality_policy=active_config.quality_policy,
        prefer_h2_releases=active_config.prefer_h2_releases,
        excluded_releases=set(active_config.excluded_releases),
        explicit_target_release=active_config.explicit_target_release,
        wua_secondary=wua_secondary,
        allow_major_upgrade_recommendation=active_config.allow_major_upgrade_recommendation,
        allow_server_evaluation=active_config.allow_server_evaluation,
        warn_on_preview_installed=active_config.warn_on_preview_installed,
        disallow_preview_installed=active_config.disallow_preview_installed,
    )
    result = _with_audit_diagnostics(result, active_config)
    if (
        active_config.source_check_required_for_green
        and result.status is EvaluationStatus.COMPLIANT
        and not source.is_source_check_complete
    ):
        result = replace(
            result,
            status=EvaluationStatus.CHECK_INCOMPLETE,
            is_warning=False,
            is_error=True,
            action="Source check incomplete; cannot return green result.",
            summary="Check incomplete: source check did not complete.",
        )
    return _with_source(result, source)


__all__ = ["PolicySourceResult", "check_current_system"]
