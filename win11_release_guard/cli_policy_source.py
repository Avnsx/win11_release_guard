"""Checking the configured policy source end to end."""

from __future__ import annotations

import argparse
from typing import Mapping
from .exceptions import PolicyFetchError, PolicyParseError, PolicyTrustError, WindowsReleaseCheckerError
from .json_utils import DEFAULT_MAX_SIGNATURE_BYTES
from .policy_schema import validate_policy_document
from .remote_policy import fetch_policy_bytes
from .signing import load_trusted_policy
from .cli_args import _max_policy_bytes_from_args, _policy_url_from_args
from .cli_public_pages import _check_public_pages_payload, _manifest_check_payload, _policy_signature_source


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
        policy_bytes, content_type = fetch_policy_bytes(
            policy_url,
            timeout=args.timeout_seconds,
            max_bytes=_max_policy_bytes_from_args(args),
        )
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
        signature_bytes, _signature_content_type = fetch_policy_bytes(
            signature_url,
            timeout=args.timeout_seconds,
            max_bytes=DEFAULT_MAX_SIGNATURE_BYTES,
        )
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
            max_policy_bytes=_max_policy_bytes_from_args(args),
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
        servicing_toc = source_diagnostics.get("servicing_toc")
        if isinstance(servicing_toc, dict):
            emit(
                "- servicing_toc: "
                f"fetched_at={servicing_toc.get('fetched_at_utc') or 'unknown'}, "
                f"bytes={servicing_toc.get('bytes') if servicing_toc.get('bytes') is not None else 'unknown'}, "
                f"newest_servicing_build={servicing_toc.get('newest_servicing_build') or 'unknown'}, "
                f"entries={servicing_toc.get('entry_count') if servicing_toc.get('entry_count') is not None else 'unknown'}"
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
