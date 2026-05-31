from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from win11_release_guard.config import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    DEFAULT_RELEASE_HEALTH_URL,
    DEFAULT_TRUSTED_POLICY_KEY_ID,
)
from win11_release_guard.exceptions import WindowsReleaseCheckerError
from win11_release_guard.policy_generator import (
    DEFAULT_WINDOWS11_ATOM_FEED_URL,
    build_policy_from_sources,
    write_policy_outputs,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python tools/generate_policy.py",
        description="Generate site/windows-release-policy.json from Microsoft Release Health and Atom sources.",
    )
    parser.add_argument("--release-health-url", default=DEFAULT_RELEASE_HEALTH_URL)
    parser.add_argument("--atom-feed-url", default=DEFAULT_WINDOWS11_ATOM_FEED_URL)
    parser.add_argument("--release-health-html", type=Path, default=None, help="Local Release Health HTML fixture.")
    parser.add_argument("--atom-feed", type=Path, default=None, help="Local Atom XML fixture.")
    parser.add_argument("--output-dir", type=Path, default=Path("site"))
    parser.add_argument("--timeout", type=float, default=DEFAULT_HTTP_TIMEOUT_SECONDS)
    parser.add_argument("--write-index", action="store_true", help="Write site/index.html summary.")
    parser.add_argument("--write-robots", action="store_true", help="Write site/robots.txt.")
    parser.add_argument("--write-sitemap", action="store_true", help="Write site/sitemap.xml.")
    parser.add_argument("--write-manifest", action="store_true", help="Write site/manifest.json.")
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        signing_key = _signing_key(args)
        policy = build_policy_from_sources(
            release_health_url=args.release_health_url,
            atom_feed_url=args.atom_feed_url,
            release_health_html_path=args.release_health_html,
            atom_feed_path=args.atom_feed,
            timeout=args.timeout,
            signature_status="valid" if signing_key else "unsigned",
        )
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
    except (OSError, WindowsReleaseCheckerError) as exc:
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
