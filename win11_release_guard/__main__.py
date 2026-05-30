from __future__ import annotations

import argparse
import json
import sys
import traceback
from collections import Counter
from pathlib import Path
from typing import Sequence

from .api import check_current_system
from .config import (
    DEFAULT_CACHE_MAX_AGE_HOURS,
    DEFAULT_EVENT_LOG_MAX_EVENTS,
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    DEFAULT_POLICY_URL,
    DEFAULT_QUALITY_POLICY,
    DEFAULT_STALE_CACHE_MAX_AGE_HOURS,
    DEFAULT_WUA_MAX_HISTORY,
    DEFAULT_WUA_MAX_RELEVANT_UPDATES,
    DEFAULT_WUA_TIMEOUT_SECONDS,
    POLICY_URL_ENV_VAR,
    ReleaseCheckerConfig,
    normalize_policy_url,
    policy_url_from_env,
)
from .exceptions import WindowsReleaseCheckerError
from .models import EvaluationResult, EvaluationStatus


EXIT_COMPLIANT = 0
EXIT_UPDATE_REQUIRED = 1
EXIT_UNKNOWN_OR_POLICY_ERROR = 2
EXIT_ABOVE_BROAD_TARGET = 3
EXIT_ARGUMENT_ERROR = 10


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="win-release-guard",
        description="Evaluate Windows 11 release compliance against broad-fleet policy.",
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


def _print_pretty(result: EvaluationResult) -> None:
    target_version = result.target.version if result.target else "unknown"
    target_build = result.baseline_build or (result.target.effective_baseline_build if result.target else None)
    source_status = result.source_status.value if result.source_status else "unknown"
    print(f"Status: {result.status.value}")
    print(f"Local: {result.installed_release or 'unknown'} / {result.installed_build or 'unknown'}")
    if result.local_consensus:
        print(f"Display OS: {result.local_consensus.display_os_name}")
        if result.local_consensus.raw_product_name:
            print(f"Raw ProductName: {result.local_consensus.raw_product_name}")
    print(f"Target: {target_version} / {target_build or 'unknown'}")
    print(f"Source: {source_status} / {result.policy_source_kind or 'unknown'}")
    if result.installed_build_origin:
        origin = result.installed_build_origin
        print(
            "Build origin: "
            f"{origin.classification.value if origin.classification else 'unknown'} / "
            f"{origin.evidence_source.value}"
            f"{' / ' + origin.kb_article if origin.kb_article else ''}"
        )
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
    return None, "default/bundled-only"


def _diagnose_config_payload(args: argparse.Namespace) -> dict[str, object]:
    policy_url, source = _policy_url_from_args(args)
    config = _config_from_args(args)
    return {
        "policy_url": policy_url,
        "policy_url_source": source,
        "policy_url_env_var": POLICY_URL_ENV_VAR,
        "remote_fetch_enabled": policy_url is not None,
        "cache_file": config.cache_file,
        "cache_max_age_hours": config.cache_max_age_hours,
        "stale_cache_max_age_hours": config.stale_cache_max_age_hours,
        "use_bundled_policy_fallback": config.use_bundled_policy_fallback,
        "allow_unsigned_policy": config.allow_unsigned_policy,
        "allow_runtime_release_health_html": config.allow_runtime_release_health_html,
    }


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

    if args.diagnose_config:
        print(json.dumps(_diagnose_config_payload(args), indent=2, sort_keys=True, ensure_ascii=True))
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
