"""Helpers shared by the test_runtime_policy_sources test modules."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
import win11_release_guard.api as api
from win11_release_guard.exceptions import PolicyFetchError
from win11_release_guard.models import LocalWindowsState, ReleaseHistoryEntry, ReleasePolicy, ReleasePolicyEntry
from win11_release_guard.signing import sign_policy_bytes


TEST_PRIVATE_KEY = "krtF2muLgucP7JDVNKk2g+YQfz92c7xM49dzszxHxjs="


TEST_PUBLIC_KEY = "45dOpVuYqoPkldNrzORHM5ZZUxs6ILVcvpKxRFxsu3s="


BAD_POLICY_URL = ("https://bad.example" + ".invalid/windows-release-policy.json")


def _generated_at(hours_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).replace(microsecond=0).isoformat()


def _policy(*, generated_at_utc: str | None = None, signature_status: str = "valid") -> ReleasePolicy:
    return ReleasePolicy(
        generated_at_utc=generated_at_utc or _generated_at(),
        source_urls=(("https://example" + ".invalid/windows-release-policy.json"),),
        broad_target_existing_devices=ReleasePolicyEntry(
            version="25H2",
            build_family=26200,
            latest_build="26200.8457",
            baseline_build="26200.8457",
            servicing_option="General Availability Channel",
        ),
        current_versions=(
            ReleasePolicyEntry(
                version="25H2",
                build_family=26200,
                latest_build="26200.8457",
                baseline_build="26200.8457",
                servicing_option="General Availability Channel",
            ),
            ReleasePolicyEntry(
                version="24H2",
                build_family=26100,
                latest_build="26100.8457",
                baseline_build="26100.8457",
                servicing_option="General Availability Channel",
            ),
        ),
        release_history=(
            ReleaseHistoryEntry(
                release="25H2",
                build_family=26200,
                build="26200.8457",
                update_type_letter="B",
                servicing_option="General Availability Channel",
                availability_date="2026-05-12",
            ),
        ),
        supported_build_families={26100: "24H2", 26200: "25H2"},
        metadata={"signature_status": signature_status},
    )


def _json_policy() -> dict:
    return _policy().to_dict()


def _write_signed_policy(path, policy: ReleasePolicy) -> bytes:
    return _write_signed_json(path, policy.to_dict())


def _write_signed_json(path, data: dict) -> bytes:
    policy_bytes = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    signature = sign_policy_bytes(policy_bytes, TEST_PRIVATE_KEY)
    signature_bytes = (json.dumps(signature, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(policy_bytes)
    path.with_name(path.name + ".sig").write_bytes(signature_bytes)
    return policy_bytes


def _patch_local(monkeypatch, *, build: int = 26200, full_build: str = "26200.8457") -> None:
    monkeypatch.setattr(
        api,
        "get_local_windows_state",
        lambda: LocalWindowsState(current_build=build, full_build=full_build),
    )
    monkeypatch.setattr(api, "query_wua_secondary", lambda target_release: None)


def _fail_remote(monkeypatch, message: str = "network unavailable") -> None:
    def fail_fetch(*args, **kwargs):
        raise PolicyFetchError(message)

    monkeypatch.setattr(api, "fetch_policy_bytes", fail_fetch)
