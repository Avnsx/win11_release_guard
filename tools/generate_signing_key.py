from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from win11_release_guard.config import DEFAULT_TRUSTED_POLICY_KEY_ID


PRIVATE_KEY_SECRET_NAME = "WIN11_RELEASE_GUARD_POLICY_SIGNING_KEY_B64"
PRIVATE_KEY_FILE_NAME = "private-" + "key.b64"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _default_key_id() -> str:
    return f"win11_release_guard-policy-{datetime.now(timezone.utc):%Y-%m}"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python tools/generate_signing_key.py",
        description="Generate an Ed25519 policy signing key pair and trusted public-key file.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(".tmp/signing-key"),
        help="Output directory. Private keys are restricted to .tmp/ unless --allow-outside-tmp is set.",
    )
    parser.add_argument(
        "--key-id",
        default=_default_key_id(),
        help=f"Policy signing key id. Current committed key id is {DEFAULT_TRUSTED_POLICY_KEY_ID}.",
    )
    parser.add_argument("--status", default="active", choices=["active", "retiring", "retired"])
    parser.add_argument("--created-at-utc", default=None, help="Override created_at_utc for reproducible metadata.")
    parser.add_argument("--valid-from-utc", default=None, help="Override valid_from_utc; defaults to created_at_utc.")
    parser.add_argument(
        "--verify-not-after-utc",
        default=None,
        help="Required for retiring/retired key skeletons; omitted for active keys unless provided.",
    )
    parser.add_argument(
        "--allow-outside-tmp",
        action="store_true",
        help=f"Explicitly allow writing {PRIVATE_KEY_FILE_NAME} under RUNNER_TEMP.",
    )
    return parser


def _is_under_repo_tmp(path: Path) -> bool:
    repo_tmp = (Path.cwd() / ".tmp").resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(repo_tmp)
    except ValueError:
        return False
    return True


def _is_under_runner_temp(path: Path) -> bool:
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        return False
    resolved = path.resolve()
    try:
        resolved.relative_to(Path(runner_temp).resolve())
    except ValueError:
        return False
    return True


def _trusted_keys_document(
    *,
    key_id: str,
    public_key_b64: str,
    created_at_utc: str,
    status: str,
    valid_from_utc: str,
    verify_not_after_utc: str | None,
) -> dict[str, object]:
    record = {
        "key_id": key_id,
        "algorithm": "ed25519",
        "public_key_b64": public_key_b64,
        "created_at_utc": created_at_utc,
        "valid_from_utc": valid_from_utc,
        "status": status,
    }
    if verify_not_after_utc:
        record["verify_not_after_utc"] = verify_not_after_utc
    return {
        "trusted_policy_keys": [record]
    }


def _generate_key_material() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    private_seed = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(private_seed).decode("ascii"),
        base64.b64encode(public_key).decode("ascii"),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    out_dir = args.out_dir
    if not _is_under_repo_tmp(out_dir):
        runner_temp_allowed = bool(args.allow_outside_tmp and _is_under_runner_temp(out_dir))
    else:
        runner_temp_allowed = True
    if not runner_temp_allowed:
        print(
            f"Refusing to write {PRIVATE_KEY_FILE_NAME} outside .tmp/ or RUNNER_TEMP. "
            "Pass --allow-outside-tmp only for an explicitly controlled runner temp path.",
            file=sys.stderr,
        )
        return 2

    created_at_utc = args.created_at_utc or _utc_now()
    valid_from_utc = args.valid_from_utc or created_at_utc
    if args.status in {"retiring", "retired"} and not args.verify_not_after_utc:
        print(
            f"--verify-not-after-utc is required for {args.status} trusted key skeletons.",
            file=sys.stderr,
        )
        return 2
    private_key_b64, public_key_b64 = _generate_key_material()
    trusted_keys = _trusted_keys_document(
        key_id=args.key_id,
        public_key_b64=public_key_b64,
        created_at_utc=created_at_utc,
        status=args.status,
        valid_from_utc=valid_from_utc,
        verify_not_after_utc=args.verify_not_after_utc,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    private_key_file = out_dir / PRIVATE_KEY_FILE_NAME
    public_key_file = out_dir / "public-key.b64"
    trusted_keys_file = out_dir / "trusted_policy_keys.json"

    private_key_file.write_text(private_key_b64 + "\n", encoding="utf-8", newline="\n")
    public_key_file.write_text(public_key_b64 + "\n", encoding="utf-8", newline="\n")
    trusted_keys_file.write_text(
        json.dumps(trusted_keys, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"private_key: {private_key_file}")
    print(f"public_key: {public_key_file}")
    print(f"trusted_policy_keys: {trusted_keys_file}")
    print()
    instruction = (
        "Copy the generated private key file contents into GitHub Actions Secret "
        f"{PRIVATE_KEY_SECRET_NAME}."
    )
    # codeql[py/clear-text-logging-sensitive-data]
    print(instruction)
    print(f"Do not commit {PRIVATE_KEY_FILE_NAME} or any private signing key material.")
    print("Commit only the public trusted_policy_keys.json after reviewing key_id and status.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
