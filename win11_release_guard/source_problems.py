"""Classifying policy source problems, policy age, and source degradation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable
from .config import LIVE_POLICY_FRESHNESS_WARNING_AGE_HOURS, STRICT_PRODUCTION_MAX_LIVE_POLICY_AGE_HOURS, ReleaseCheckerConfig
from .exceptions import PolicyFetchError, PolicyParseError, PolicyTrustError
from .models import EvaluationStatus, ReleasePolicy, SourceProblem, SourceStatus


@dataclass(frozen=True)
class PolicySourceResult:
    policy: ReleasePolicy | None
    source_status: SourceStatus
    is_source_check_complete: bool
    policy_source_url: str | None = None
    policy_source_kind: str | None = None
    policy_signature_status: str | None = None
    policy_age_hours: float | None = None
    feed_age_days: float | None = None
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    source_problems: tuple[SourceProblem, ...] = ()


@dataclass(frozen=True)
class SourceDegradationDecision:
    source_status: SourceStatus
    source_class: str
    candidate_status: EvaluationStatus
    allow_compliant_green: bool
    force_check_incomplete: bool
    must_exit_code_2: bool
    mode: str
    reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "source_status": self.source_status.value,
            "source_class": self.source_class,
            "candidate_status": self.candidate_status.value,
            "allow_compliant_green": self.allow_compliant_green,
            "force_check_incomplete": self.force_check_incomplete,
            "must_exit_code_2": self.must_exit_code_2,
            "mode": self.mode,
            "reason": self.reason,
        }


SOURCE_STATUS_CLASSES = {
    SourceStatus.REMOTE_POLICY_OK: "remote",
    SourceStatus.USING_FRESH_CACHE: "fresh_cache",
    SourceStatus.USING_STALE_CACHE: "stale_cache",
    SourceStatus.USING_BUNDLED_POLICY: "bundled",
    SourceStatus.POLICY_UNAVAILABLE: "unavailable",
    SourceStatus.RUNTIME_HTML_FALLBACK_USED: "runtime_html",
    SourceStatus.REMOTE_POLICY_UNREACHABLE: "unavailable",
    SourceStatus.REMOTE_POLICY_PARSE_FAILED: "unavailable",
    SourceStatus.REMOTE_POLICY_SIGNATURE_FAILED: "unavailable",
    SourceStatus.CHECK_INCOMPLETE: "unavailable",
}


def _dedupe_text(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(value) for value in values if str(value)))


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


def _feed_age_days(policy_age_hours: float | None) -> float | None:
    if policy_age_hours is None:
        return None
    return round(policy_age_hours / 24, 2)


def _live_policy_age_warning(policy_age_hours: float | None) -> str | None:
    if policy_age_hours is None or policy_age_hours <= LIVE_POLICY_FRESHNESS_WARNING_AGE_HOURS:
        return None
    days = _feed_age_days(policy_age_hours)
    return (
        f"Live signed policy feed is {days:g} days old; generated_at_utc is older than 14 days. "
        "Treat this as a feed maintenance warning."
    )


def _is_live_remote_json_source(source: PolicySourceResult) -> bool:
    return (
        source.source_status is SourceStatus.REMOTE_POLICY_OK
        and source.policy_source_kind == "remote_json"
        and source.is_source_check_complete
    )


def _policy_is_fresh_at(policy: ReleasePolicy, modified_epoch: float | None, *, max_age_hours: float) -> bool:
    if policy.generated_at_utc:
        age = _policy_age_hours(policy)
        return age is not None and age <= max_age_hours
    if modified_epoch is None:
        return False
    try:
        modified = datetime.fromtimestamp(modified_epoch, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        # read_state fills modified_epoch straight from st.st_mtime, so a container file
        # carrying a timestamp outside the platform time_t range reaches this conversion.
        # CPython raises OverflowError there -- an ArithmeticError, NOT a ValueError -- and
        # it would surface as a corrupt_cache the record never earned. An unusable
        # timestamp is simply no age available, which is the branch just above.
        return False
    return datetime.now(timezone.utc) - modified <= timedelta(hours=max_age_hours)


def _policy_is_fresh(policy: ReleasePolicy, cache_path: Path, *, max_age_hours: float) -> bool:
    return _policy_is_fresh_at(
        policy,
        None if policy.generated_at_utc else cache_path.stat().st_mtime,
        max_age_hours=max_age_hours,
    )


def _source_status_class(source_status: SourceStatus) -> str:
    return SOURCE_STATUS_CLASSES.get(source_status, "unavailable")


def decide_source_degradation(
    config: ReleaseCheckerConfig,
    source: PolicySourceResult,
    *,
    candidate_status: EvaluationStatus,
) -> SourceDegradationDecision:
    source_status = source.source_status
    source_class = _source_status_class(source_status)
    live_remote_json = _is_live_remote_json_source(source)
    live_remote_json_too_old = (
        live_remote_json
        and source.policy_age_hours is not None
        and source.policy_age_hours > STRICT_PRODUCTION_MAX_LIVE_POLICY_AGE_HOURS
    )

    if config.strict_production:
        force_check_incomplete = not live_remote_json or live_remote_json_too_old
        reason = None
        if live_remote_json_too_old:
            days = _feed_age_days(source.policy_age_hours)
            reason = (
                "Strict production requires a live signed remote JSON policy generated within 45 days before "
                f"returning a production result. Current live policy age is {days:g} days."
            )
        elif force_check_incomplete:
            source_kind = source.policy_source_kind or "unknown"
            reason = (
                "Strict production requires a complete live signed remote JSON policy source before returning a production result. "
                f"Current source is {source_status.value} / {source_kind}."
            )
        return SourceDegradationDecision(
            source_status=source_status,
            source_class=source_class,
            candidate_status=candidate_status,
            allow_compliant_green=candidate_status is EvaluationStatus.COMPLIANT and not force_check_incomplete,
            force_check_incomplete=force_check_incomplete,
            must_exit_code_2=force_check_incomplete,
            mode="strict_production",
            reason=reason,
        )

    force_for_green = (
        config.source_check_required_for_green
        and candidate_status is EvaluationStatus.COMPLIANT
        and not source.is_source_check_complete
    )
    return SourceDegradationDecision(
        source_status=source_status,
        source_class=source_class,
        candidate_status=candidate_status,
        allow_compliant_green=candidate_status is EvaluationStatus.COMPLIANT and not force_for_green,
        force_check_incomplete=force_for_green,
        must_exit_code_2=force_for_green,
        mode="source_check_required" if config.source_check_required_for_green else "normal",
        reason="Source check incomplete; cannot return green result." if force_for_green else None,
    )


def _local_scope_status(candidate_status: EvaluationStatus) -> EvaluationStatus | None:
    if candidate_status is EvaluationStatus.OUT_OF_SCOPE:
        return EvaluationStatus.OUT_OF_SCOPE
    return None
