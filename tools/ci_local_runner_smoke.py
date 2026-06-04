from __future__ import annotations

import json
import subprocess
import sys
from typing import Any, Mapping


CLIENT_SMOKE_STATUSES = {
    "COMPLIANT",
    "FEATURE_UPDATE_REQUIRED",
    "QUALITY_UPDATE_REQUIRED",
    "PREVIEW_BUILD_INSTALLED",
    "ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE",
}
RUNNER_SCOPE_STATUSES = {"OUT_OF_SCOPE", "CHECK_INCOMPLETE", "UNKNOWN_LOCAL_RELEASE"}


def _load_payload(stdout: str) -> dict[str, Any]:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"CLI did not emit valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("CLI JSON payload must be an object.")
    if not payload.get("status"):
        raise RuntimeError("CLI JSON payload must include status.")
    return payload


def _is_windows_client(local: Mapping[str, Any]) -> bool:
    return bool(local.get("is_windows_client")) and not bool(local.get("is_server"))


def main() -> int:
    command = [
        sys.executable,
        "-m",
        "win11_release_guard",
        "--json",
        "--no-wua",
        "--policy-url",
        "win11_release_guard/data/windows-release-policy.json",
    ]
    proc = subprocess.run(command, capture_output=True, text=True, check=False)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr, end="" if proc.stderr.endswith("\n") else "\n")

    try:
        payload = _load_payload(proc.stdout)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        if proc.stdout:
            print(proc.stdout, file=sys.stderr)
        return 1

    status = str(payload["status"])
    local = payload.get("local") if isinstance(payload.get("local"), dict) else {}
    summary = {
        "ci_smoke": "local runner JSON only; not a client fleet target validation",
        "cli_exit_code": proc.returncode,
        "status": status,
        "product_family": local.get("product_family"),
        "is_windows_client": local.get("is_windows_client"),
        "is_server": local.get("is_server"),
    }
    print(json.dumps(summary, sort_keys=True))

    if status in RUNNER_SCOPE_STATUSES:
        return 0
    if status in CLIENT_SMOKE_STATUSES and _is_windows_client(local):
        return 0

    print(
        "Unexpected local runner smoke result. Server/non-client runners must be out_of_scope; "
        "client statuses are accepted only when local.is_windows_client is true.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
