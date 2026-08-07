from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from win11_release_guard.config import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    DEFAULT_RELEASE_HEALTH_URL,
    DEFAULT_TRUSTED_POLICY_KEY_ID,
)
from win11_release_guard.exceptions import WindowsReleaseCheckerError
from win11_release_guard.policy_generator import (
    DEFAULT_SERVICING_TOC_URL,
    build_policy_from_sources,
    write_policy_outputs,
)
from win11_release_guard.policy_schema import is_source_diagnostic_id


SOURCE_DIAGNOSTIC_ISSUE_URL_RE = re.compile(
    r"^https://github\.com/Avnsx/win11_release_guard/issues/([1-9][0-9]*)$"
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python tools/generate_policy.py",
        description="Generate site/windows-release-policy.json from Microsoft Release Health and servicing index sources.",
    )
    parser.add_argument("--release-health-url", default=DEFAULT_RELEASE_HEALTH_URL)
    parser.add_argument("--servicing-toc-url", default=DEFAULT_SERVICING_TOC_URL)
    parser.add_argument("--release-health-html", type=Path, default=None, help="Local Release Health HTML fixture.")
    parser.add_argument(
        "--servicing-toc", type=Path, default=None, help="Local servicing index JSON fixture."
    )
    parser.add_argument("--output-dir", type=Path, default=Path("site"))
    parser.add_argument("--timeout", type=float, default=DEFAULT_HTTP_TIMEOUT_SECONDS)
    parser.add_argument("--write-index", action="store_true", help="Write site/index.html summary.")
    parser.add_argument("--write-robots", action="store_true", help="Write site/robots.txt.")
    parser.add_argument("--write-sitemap", action="store_true", help="Write site/sitemap.xml.")
    parser.add_argument("--write-manifest", action="store_true", help="Write site/policy-manifest.json and API aliases.")
    parser.add_argument(
        "--source-diagnostic-issue-status-file",
        type=Path,
        default=None,
        help="Merge static source-diagnostic issue metadata before rendering Pages artifacts.",
    )
    parser.add_argument(
        "--signing-key-env",
        default=None,
        help="Environment variable containing an Ed25519 private key PEM or base64 raw seed.",
    )
    parser.add_argument(
        "--signing-key-file",
        type=Path,
        default=None,
        help="File containing an Ed25519 private key PEM or base64 raw seed.",
    )
    parser.add_argument(
        "--key-id",
        default=DEFAULT_TRUSTED_POLICY_KEY_ID,
        help="Trusted policy key id to write into windows-release-policy.json.sig.",
    )
    return parser


def _signing_key(args: argparse.Namespace) -> str | None:
    if args.signing_key_file is not None:
        return args.signing_key_file.read_text(encoding="utf-8").strip()
    if args.signing_key_env:
        return os.environ.get(args.signing_key_env)
    return None


def _issue_status_mapping(value: Any) -> dict[str, Mapping[str, Any]]:
    if isinstance(value, Mapping) and isinstance(value.get("issue_status"), Mapping):
        value = value.get("issue_status")
    if not isinstance(value, Mapping):
        raise ValueError("source diagnostic issue status must be an object.")
    records: dict[str, Mapping[str, Any]] = {}
    for diagnostic_id, record in value.items():
        if not is_source_diagnostic_id(diagnostic_id):
            raise ValueError("source diagnostic issue status keys must be deterministic diagnostic IDs.")
        if not isinstance(record, Mapping):
            raise ValueError("source diagnostic issue status records must be objects.")
        try:
            number = int(record.get("number"))
        except (TypeError, ValueError) as exc:
            raise ValueError("source diagnostic issue status number must be a positive integer.") from exc
        if number <= 0:
            raise ValueError("source diagnostic issue status number must be a positive integer.")
        state = str(record.get("state") or "open").strip().lower()
        if state not in {"open", "closed"}:
            raise ValueError("source diagnostic issue status state must be open or closed.")
        canonical_url = f"https://github.com/Avnsx/win11_release_guard/issues/{number}"
        supplied_url = str(record.get("url") or canonical_url).strip()
        match = SOURCE_DIAGNOSTIC_ISSUE_URL_RE.fullmatch(supplied_url)
        if match is None or int(match.group(1)) != number:
            raise ValueError("source diagnostic issue status URL must be canonical and match the issue number.")
        records[diagnostic_id] = {
            "number": number,
            "state": state,
            "url": canonical_url,
        }
    return records


def _issue_sync_metadata(value: Any) -> dict[str, str]:
    if value in (None, ""):
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("source diagnostic issue sync metadata must be an object.")
    status = str(value.get("status") or "").strip().lower()
    if status not in {"available", "degraded", "unavailable"}:
        raise ValueError("source diagnostic issue sync status must be available, degraded, or unavailable.")
    metadata = {"status": status}
    for key in ("reason", "message"):
        text = str(value.get(key) or "").strip()
        if text:
            metadata[key] = text
    return metadata


def _load_issue_status(path: Path | None) -> tuple[dict[str, Mapping[str, Any]], dict[str, str]]:
    if path is None:
        return {}, {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    issue_status = _issue_status_mapping(raw)
    issue_sync = _issue_sync_metadata(raw.get("issue_sync") if isinstance(raw, Mapping) else None)
    return issue_status, issue_sync


def _policy_with_issue_status(
    policy: object,
    issue_status: Mapping[str, Mapping[str, Any]],
    issue_sync: Mapping[str, str],
) -> object:
    if not issue_status and not issue_sync:
        return policy
    data = policy.to_dict()
    source_diagnostics = dict(data.get("source_diagnostics") or {})
    if issue_status:
        source_diagnostics["issue_status"] = dict(issue_status)
    if issue_sync:
        source_diagnostics["issue_sync"] = dict(issue_sync)
    data["source_diagnostics"] = source_diagnostics
    return type(policy).from_dict(data)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        signing_key = _signing_key(args)
        policy = build_policy_from_sources(
            release_health_url=args.release_health_url,
            servicing_toc_url=args.servicing_toc_url,
            release_health_html_path=args.release_health_html,
            servicing_toc_path=args.servicing_toc,
            timeout=args.timeout,
            signature_status="valid" if signing_key else "unsigned",
        )
        issue_status, issue_sync = _load_issue_status(args.source_diagnostic_issue_status_file)
        policy = _policy_with_issue_status(policy, issue_status, issue_sync)
        written = write_policy_outputs(
            policy,
            output_dir=args.output_dir,
            signing_key=signing_key,
            key_id=args.key_id,
            write_index=args.write_index,
            write_robots=args.write_robots,
            write_sitemap=args.write_sitemap,
            write_manifest=args.write_manifest,
        )
    except (OSError, ValueError, WindowsReleaseCheckerError) as exc:
        print(f"Policy generation failed: {exc}", file=sys.stderr)
        return 1

    for label, path in written.items():
        print(f"{label}: {path}")
    if policy.validation_warnings:
        print("warnings:")
        for warning in policy.validation_warnings:
            print(f"- {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
