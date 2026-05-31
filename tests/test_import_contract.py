import importlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from win11_release_guard.config import ReleaseCheckerConfig
from win11_release_guard.exceptions import PolicyFetchError
from win11_release_guard.models import (
    EvaluationStatus,
    LocalWindowsState,
    ReleaseHistoryEntry,
    ReleasePolicy,
    ReleasePolicyEntry,
    SourceStatus,
)
from win11_release_guard.signing import sign_policy_bytes


TEST_PRIVATE_KEY = "krtF2muLgucP7JDVNKk2g+YQfz92c7xM49dzszxHxjs="
TEST_PUBLIC_KEY = "45dOpVuYqoPkldNrzORHM5ZZUxs6ILVcvpKxRFxsu3s="


def _generated_at(*, hours_ago: int = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).replace(microsecond=0).isoformat()


def test_distribution_name_and_console_script_are_hyphenated():
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")

    assert 'name = "win-release-guard"' in pyproject
    assert 'win-release-guard = "win11_release_guard.__main__:main"' in pyproject
    assert 'include = ["win11_release_guard*"]' in pyproject


def test_import_has_no_side_effects(monkeypatch):
    calls = []

    monkeypatch.setattr(
        "win11_release_guard.local_state.get_local_windows_state",
        lambda: calls.append("local"),
    )
    monkeypatch.setattr(
        "win11_release_guard.remote_policy.fetch_release_policy",
        lambda *args, **kwargs: calls.append("fetch"),
    )

    module = importlib.reload(importlib.import_module("win11_release_guard"))

    assert calls == []
    assert hasattr(module, "LocalWindowsState")
    assert hasattr(module, "check_current_system")


def test_check_current_system_uses_cache_when_fetch_fails(monkeypatch, tmp_path):
    import win11_release_guard.api as api

    cache_file = tmp_path / "windows-release-policy.json"
    cached_policy = ReleasePolicy(
        generated_at_utc=_generated_at(),
        source_urls=("https://example.invalid/windows-release-policy.json",),
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
        supported_build_families={26200: "25H2"},
    )
    policy_bytes = (json.dumps(cached_policy.to_dict(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    cache_file.write_bytes(policy_bytes)
    cache_file.with_name(cache_file.name + ".sig").write_bytes(
        (json.dumps(sign_policy_bytes(policy_bytes, TEST_PRIVATE_KEY), indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    calls = []

    monkeypatch.setattr(api, "get_local_windows_state", lambda: LocalWindowsState(current_build=26200, full_build="26200.8457"))

    def fail_fetch(*args, **kwargs):
        calls.append(("fetch", args, kwargs))
        raise PolicyFetchError("network unavailable")

    monkeypatch.setattr(api, "fetch_policy_bytes", fail_fetch)
    monkeypatch.setattr(api, "query_wua_secondary", lambda target_release: None)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url="https://bad.example.invalid/windows-release-policy.json",
            cache_file=str(cache_file),
            enable_wua_probe=False,
            excluded_releases=frozenset({"26H1"}),
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.USING_FRESH_CACHE
    assert any("using fresh cached policy" in note for note in result.notes)
    assert calls and calls[0][0] == "fetch"
