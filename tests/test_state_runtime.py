from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import win11_release_guard.api as api
import win11_release_guard.state_store as state_store
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
REMOTE_URL = "https://policy.example" + ".invalid/windows-release-policy.json"


def _generated_at(hours_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).replace(microsecond=0).isoformat()


def _policy(*, generated_at_utc: str) -> ReleasePolicy:
    return ReleasePolicy(
        generated_at_utc=generated_at_utc,
        source_urls=("https://example" + ".invalid/windows-release-policy.json",),
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
        ),
        release_history=(
            ReleaseHistoryEntry(
                release="25H2",
                build_family=26200,
                build="26200.8457",
                update_type_letter="B",
                availability_date="2026-05-12",
            ),
        ),
        supported_build_families={26200: "25H2"},
    )


def test_policy_is_fresh_at_uses_generated_at():
    fresh = _policy(generated_at_utc=_generated_at(hours_ago=1))
    old = _policy(generated_at_utc=_generated_at(hours_ago=100))
    assert api._policy_is_fresh_at(fresh, None, max_age_hours=72) is True
    assert api._policy_is_fresh_at(old, None, max_age_hours=72) is False


def test_policy_is_fresh_at_uses_modified_epoch_when_no_generated_at():
    policy = _policy(generated_at_utc="")
    now = datetime.now(timezone.utc).timestamp()
    assert api._policy_is_fresh_at(policy, now, max_age_hours=72) is True
    assert api._policy_is_fresh_at(policy, now - 100 * 3600, max_age_hours=72) is False


def test_policy_is_fresh_at_false_when_no_age_available():
    policy = _policy(generated_at_utc="")
    assert api._policy_is_fresh_at(policy, None, max_age_hours=72) is False


def test_policy_is_fresh_preserves_mtime_laziness(tmp_path):
    # generated_at present -> the mtime branch must never be consulted, so a
    # nonexistent cache_path must not raise (today's laziness, A-6 rule 1).
    policy = _policy(generated_at_utc=_generated_at(hours_ago=1))
    missing = tmp_path / "does-not-exist.json"
    assert api._policy_is_fresh(policy, missing, max_age_hours=72) is True


def _signed_remote(policy: ReleasePolicy) -> tuple[bytes, bytes]:
    policy_bytes = (json.dumps(policy.to_dict(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    signature_bytes = (
        json.dumps(sign_policy_bytes(policy_bytes, TEST_PRIVATE_KEY), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    return policy_bytes, signature_bytes


def _patch_local(monkeypatch) -> None:
    monkeypatch.setattr(
        api,
        "get_local_windows_state",
        lambda: LocalWindowsState(current_build=26200, full_build="26200.8457"),
    )
    monkeypatch.setattr(api, "query_wua_secondary", lambda target_release: None)


def _patch_fetch(monkeypatch, policy_bytes: bytes, signature_bytes: bytes) -> None:
    def fake_fetch(url, *args, **kwargs):
        if str(url).endswith(".sig"):
            return signature_bytes, "application/json"
        return policy_bytes, "application/json"

    monkeypatch.setattr(api, "fetch_policy_bytes", fake_fetch)


def _fail_fetch(monkeypatch) -> None:
    def fail(*args, **kwargs):
        raise PolicyFetchError("network unavailable")

    monkeypatch.setattr(api, "fetch_policy_bytes", fail)


def _boom(*_args, **_kwargs):
    raise OSError(13, "forced")


def test_container_write_failure_keeps_verdict_and_emits_one_cache_write_failed(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_bytes, signature_bytes = _signed_remote(_policy(generated_at_utc=_generated_at(hours_ago=1)))
    _patch_fetch(monkeypatch, policy_bytes, signature_bytes)
    monkeypatch.setattr(state_store, "_replace", _boom)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=REMOTE_URL,
            state_dir=str(tmp_path),
            enable_wua_probe=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.source_status is SourceStatus.REMOTE_POLICY_OK
    assert result.is_source_check_complete is True
    assert result.status is EvaluationStatus.COMPLIANT
    failures = [p for p in result.source_problems if p.kind == "cache_write_failed"]
    assert len(failures) == 1
    assert failures[0].retryable is True


def test_unusable_container_self_heals_on_second_run(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    _fail_fetch(monkeypatch)
    config = ReleaseCheckerConfig(
        policy_url=REMOTE_URL,
        state_dir=str(tmp_path),
        enable_wua_probe=False,
        trusted_policy_public_key=TEST_PUBLIC_KEY,
    )
    scope = state_store.resolve_state_scope(config)
    # magic present, body too short -> "unusable"
    Path(scope.path).write_bytes(state_store.STATE_MAGIC + b"\x00\x00")

    first = api.check_current_system(config)
    corrupt = [p for p in first.source_problems if p.kind == "corrupt_cache"]
    assert len(corrupt) == 1
    assert corrupt[0].retryable is True
    assert not Path(scope.path).exists()  # magic-gated container delete

    second = api.check_current_system(config)
    assert [p for p in second.source_problems if p.kind == "corrupt_cache"] == []


def test_foreign_file_is_untouched_and_silent(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    _fail_fetch(monkeypatch)
    config = ReleaseCheckerConfig(
        policy_url=REMOTE_URL,
        state_dir=str(tmp_path),
        enable_wua_probe=False,
        trusted_policy_public_key=TEST_PUBLIC_KEY,
    )
    scope = state_store.resolve_state_scope(config)
    Path(scope.path).write_bytes(b"totally not our format")

    result = api.check_current_system(config)
    assert [p for p in result.source_problems if p.kind in ("corrupt_cache", "cache_write_failed")] == []
    assert Path(scope.path).read_bytes() == b"totally not our format"  # foreign content never destroyed


def test_fresh_and_stale_tiers_reachable_from_one_container(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_bytes, signature_bytes = _signed_remote(_policy(generated_at_utc=_generated_at(hours_ago=15 * 24)))  # 360h
    _patch_fetch(monkeypatch, policy_bytes, signature_bytes)
    seed = ReleaseCheckerConfig(
        policy_url=REMOTE_URL,
        state_dir=str(tmp_path),
        enable_wua_probe=False,
        trusted_policy_public_key=TEST_PUBLIC_KEY,
    )
    written = api.check_current_system(seed)
    assert written.source_status is SourceStatus.REMOTE_POLICY_OK  # container written

    _fail_fetch(monkeypatch)
    fresh = api.check_current_system(replace(seed, cache_max_age_hours=1000))
    assert fresh.source_status is SourceStatus.USING_FRESH_CACHE
    assert fresh.policy_source_kind == "fresh_cache"

    stale = api.check_current_system(replace(seed, cache_max_age_hours=1, stale_cache_max_age_hours=720))
    assert stale.source_status is SourceStatus.USING_STALE_CACHE
    assert stale.policy_source_kind == "stale_cache"


def test_container_older_than_stale_window_emits_stale_cache_and_is_kept(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_bytes, signature_bytes = _signed_remote(_policy(generated_at_utc=_generated_at(hours_ago=40 * 24)))  # 960h
    _patch_fetch(monkeypatch, policy_bytes, signature_bytes)
    seed = ReleaseCheckerConfig(
        policy_url=REMOTE_URL,
        state_dir=str(tmp_path),
        enable_wua_probe=False,
        trusted_policy_public_key=TEST_PUBLIC_KEY,
    )
    api.check_current_system(seed)
    scope = state_store.resolve_state_scope(seed)

    _fail_fetch(monkeypatch)
    result = api.check_current_system(seed)  # defaults: fresh 72h, stale 720h -> older than both
    assert any(p.kind == "stale_cache" for p in result.source_problems)
    assert result.policy_source_kind != "stale_cache"  # not served
    assert Path(scope.path).exists()  # age never authorises deletion


def test_cache_file_missing_parent_records_one_cache_write_failed(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_bytes, signature_bytes = _signed_remote(_policy(generated_at_utc=_generated_at(hours_ago=1)))
    _patch_fetch(monkeypatch, policy_bytes, signature_bytes)
    missing_parent = tmp_path / "no-such-dir"
    cache_file = missing_parent / "windows-release-policy.json"

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=REMOTE_URL,
            cache_file=str(cache_file),
            enable_wua_probe=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.source_status is SourceStatus.REMOTE_POLICY_OK
    failures = [p for p in result.source_problems if p.kind == "cache_write_failed"]
    assert len(failures) == 1
    assert not missing_parent.exists()  # A-1 rule 3: no parent.mkdir; O-4


def test_unremovable_unusable_container_reports_cache_write_failed_kind(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    _fail_fetch(monkeypatch)
    config = ReleaseCheckerConfig(
        policy_url=REMOTE_URL,
        state_dir=str(tmp_path),
        enable_wua_probe=False,
        trusted_policy_public_key=TEST_PUBLIC_KEY,
    )
    scope = state_store.resolve_state_scope(config)
    Path(scope.path).write_bytes(state_store.STATE_MAGIC + b"\x00\x00")
    monkeypatch.setattr(state_store, "_unlink", _boom)

    result = api.check_current_system(config)
    kinds = {p.kind for p in result.source_problems}
    assert "cache_write_failed" in kinds  # KIND, not corrupt_cache (§6.3)
    assert "corrupt_cache" not in kinds


def test_stateless_run_performs_no_state_io_or_probing(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_bytes, signature_bytes = _signed_remote(_policy(generated_at_utc=_generated_at(hours_ago=1)))
    _patch_fetch(monkeypatch, policy_bytes, signature_bytes)

    reads: list[int] = []
    writes: list[int] = []
    dirs: list[int] = []
    uids: list[int] = []

    real_read_state = state_store.read_state
    real_write_state = state_store.write_state

    def spy_read(scope):
        reads.append(1)
        return real_read_state(scope)

    def spy_write(scope, policy_bytes, signature_bytes):
        writes.append(1)
        return real_write_state(scope, policy_bytes, signature_bytes)

    def spy_dir(candidates):
        dirs.append(1)
        return None

    def spy_uid():
        uids.append(1)
        return None

    monkeypatch.setattr(state_store, "read_state", spy_read)
    monkeypatch.setattr(state_store, "write_state", spy_write)
    monkeypatch.setattr(state_store, "_first_existing_dir", spy_dir)
    monkeypatch.setattr(state_store, "_host_uid", spy_uid)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=REMOTE_URL,
            stateless=True,
            enable_wua_probe=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.source_status is SourceStatus.REMOTE_POLICY_OK  # run succeeded on the live fetch
    # observation-based (never raise-based; _persist_policy swallows exceptions, §16.7)
    assert reads == []
    assert writes == []
    assert dirs == []
    assert uids == []
