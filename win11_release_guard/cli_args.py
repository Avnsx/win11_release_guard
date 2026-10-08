"""Command-line arguments and the runtime configuration derived from them."""

from __future__ import annotations

import argparse
from pathlib import Path
from .config import DEFAULT_CACHE_MAX_AGE_HOURS, DEFAULT_EVENT_LOG_MAX_EVENTS, DEFAULT_HTTP_TIMEOUT_SECONDS, DEFAULT_POLICY_URL, DEFAULT_QUALITY_POLICY, DEFAULT_STALE_CACHE_MAX_AGE_HOURS, DEFAULT_WUA_MAX_HISTORY, DEFAULT_WUA_MAX_RELEVANT_UPDATES, DEFAULT_WUA_TIMEOUT_SECONDS, ReleaseCheckerConfig, cache_file_from_env, max_policy_bytes_from_env, normalize_policy_url, normalize_state_dir, policy_url_from_env, state_dir_from_env, stateless_from_env, strict_production_from_env
from .json_utils import DEFAULT_MAX_POLICY_BYTES


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
    parser.add_argument(
        "--include-raw-local-diagnostics",
        action="store_true",
        help="Include full bounded local diagnostic log tails such as Panther setup logs in JSON output.",
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
        "--state-dir",
        type=Path,
        default=None,
        help="Store the on-disk state record in this directory instead of the OS temp directory.",
    )
    parser.add_argument(
        "--stateless",
        action="store_true",
        help="Read and write no on-disk state for this run.",
    )
    parser.add_argument(
        "--purge-state",
        action="store_true",
        help="Remove every on-disk state artifact this configuration may have written and report it.",
    )
    parser.add_argument(
        "--show-state",
        action="store_true",
        help="Print the decoded on-disk state for this configuration without running probes.",
    )
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
        "--max-policy-bytes",
        type=int,
        default=None,
        help=(
            "Last-resort safety cap for policy and Microsoft source payloads. "
            f"Defaults to {DEFAULT_MAX_POLICY_BYTES} bytes."
        ),
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


def _config_from_args(args: argparse.Namespace) -> ReleaseCheckerConfig:
    policy_url, _policy_url_source = _policy_url_from_args(args)
    strict_production = bool(args.strict_production or strict_production_from_env())
    return ReleaseCheckerConfig(
        policy_url=policy_url,
        cache_file=_cache_file_from_args(args)[0],
        state_dir=_state_dir_from_args(args)[0],
        stateless=_stateless_from_args(args)[0],
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
        max_policy_bytes=_max_policy_bytes_from_args(args),
    )


def _max_policy_bytes_from_args(args: argparse.Namespace) -> int:
    value = getattr(args, "max_policy_bytes", None)
    if value is None:
        return max_policy_bytes_from_env()
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return max_policy_bytes_from_env()
    return parsed if parsed > 0 else max_policy_bytes_from_env()


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


def _state_dir_from_args(args: argparse.Namespace) -> tuple[str | None, str]:
    cli_state_dir = normalize_state_dir(getattr(args, "state_dir", None))
    if cli_state_dir:
        return cli_state_dir, "cli"
    env_state_dir = state_dir_from_env()
    if env_state_dir:
        return env_state_dir, "env"
    return None, "none"


def _stateless_from_args(args: argparse.Namespace) -> tuple[bool, str]:
    if getattr(args, "stateless", False):
        return True, "cli"
    if stateless_from_env():
        return True, "env"
    return False, "default"


def _cache_file_from_args(args: argparse.Namespace) -> tuple[str | None, str]:
    cli_cache_file = getattr(args, "cache_file", None)
    if cli_cache_file is not None:
        return str(cli_cache_file), "cli"
    env_cache_file = cache_file_from_env()
    if env_cache_file:
        return env_cache_file, "env"
    return None, "none"
