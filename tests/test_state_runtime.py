from __future__ import annotations

from datetime import datetime, timedelta, timezone

import win11_release_guard.api as api
from win11_release_guard.models import (
    ReleaseHistoryEntry,
    ReleasePolicy,
    ReleasePolicyEntry,
)


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
