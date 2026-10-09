from __future__ import annotations

import json
import pytest
from win11_release_guard.exceptions import PolicyParseError
from win11_release_guard.generator import generate_policy_from_release_health_html
from win11_release_guard.models import EditionScope, ReleasePolicy, ReleasePolicyEntry, ServicingChannel
from win11_release_guard.remote_policy import fetch_release_policy, parse_windows11_release_health_html, policy_from_dict, policy_to_dict
from tests.support.remote_policy_helpers import _fixture_html, _json_policy, _pending_26h2_html


class Response:
    def __init__(
        self,
        *,
        text: str | None = None,
        content: bytes | None = None,
        content_type: str | None = None,
        status_code: int = 200,
    ):
        self.text = text
        self.content = content
        self.headers = {"Content-Type": content_type} if content_type else {}
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def test_policy_round_trip_preserves_exclusions_and_build_map():
    data = {
        "generated_at_utc": "2026-05-28T00:00:00Z",
        "source": {"release_health_url": ("https://example" + ".invalid/windows11-release-information")},
        "broad_target_existing_devices": {
            "version": "25H2",
            "build_family": 26200,
            "latest_build": "26200.8457",
        },
        "excluded_for_existing_devices": [
            {
                "version": "26H1",
                "build_family": 28000,
                "reason": "new devices only",
            }
        ],
        "supported_build_families": {"26100": "24H2", "26200": "25H2", "28000": "26H1"},
    }

    policy = policy_from_dict(data)
    serialized = policy_to_dict(policy)
    restored = ReleasePolicy.from_dict(serialized)

    assert restored.broad_target_existing_devices is not None
    assert restored.broad_target_existing_devices.version == "25H2"
    assert restored.excluded_for_existing_devices[0].version == "26H1"
    assert restored.release_for_build_family(26100) == "24H2"


def test_release_policy_entry_from_dict_preserves_explicit_required_baseline():
    entry = ReleasePolicyEntry.from_dict(
        {
            "version": "25H2",
            "build_family": 26200,
            "latest_build": "26200.8524",
            "required_baseline_build": "26200.8457",
            "servicing_option": "General Availability Channel",
        }
    )
    serialized = entry.to_dict()
    restored = ReleasePolicyEntry.from_dict(serialized)

    assert entry.latest_build == "26200.8524"
    assert entry.latest_observed_build == "26200.8524"
    assert entry.baseline_build is None
    assert entry.required_baseline_build == "26200.8457"
    assert entry.effective_baseline_build == "26200.8457"
    assert serialized["required_baseline_build"] == "26200.8457"
    assert restored.required_baseline_build == "26200.8457"


def test_release_policy_entry_defaults_latest_observed_to_latest_build():
    entry = ReleasePolicyEntry.from_dict(
        {
            "version": "25H2",
            "build_family": 26200,
            "latest_build": "26200.8457",
            "baseline_build": "26200.8457",
        }
    )

    assert entry.latest_observed_build == "26200.8457"
    assert entry.to_dict()["latest_observed_build"] == "26200.8457"


def test_release_policy_entry_preserves_distinct_latest_observed_without_baseline_change():
    entry = ReleasePolicyEntry.from_dict(
        {
            "version": "25H2",
            "build_family": 26200,
            "latest_build": "26200.8457",
            "latest_observed_build": "26200.8655",
            "baseline_build": "26200.8457",
            "required_baseline_build": "26200.8457",
        }
    )

    assert entry.latest_build == "26200.8457"
    assert entry.latest_observed_build == "26200.8655"
    assert entry.required_baseline_build == "26200.8457"
    assert entry.effective_baseline_build == "26200.8457"
    assert ReleasePolicyEntry.from_dict(entry.to_dict()).latest_observed_build == "26200.8655"


def test_response_with_json_content_type_loads():
    calls = []

    def fake_get(url, timeout):
        calls.append((url, timeout))
        return Response(text=json.dumps(_json_policy()), content_type="application/json; charset=utf-8")

    policy = fetch_release_policy(
        ("https://example" + ".invalid/windows-release-policy.json"),
        timeout=1.5,
        http_get=fake_get,
    )

    assert calls == [(("https://example" + ".invalid/windows-release-policy.json"), 1.5)]
    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"


def test_html_fixture_loads_when_html_fallback_is_allowed_for_generator_mode():
    policy = generate_policy_from_release_health_html(_fixture_html())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"


def test_html_response_is_rejected_in_runtime_mode_unless_allowed():
    def fake_get(url, timeout):
        return Response(content=_fixture_html().encode("utf-8"), content_type="text/html")

    with pytest.raises(PolicyParseError, match="HTML policy source is not allowed"):
        fetch_release_policy(
            ("https://example" + ".invalid/windows11-release-information"),
            timeout=1,
            http_get=fake_get,
        )

    policy = fetch_release_policy(
        ("https://example" + ".invalid/windows11-release-information"),
        timeout=1,
        http_get=fake_get,
        allow_html_fallback=True,
    )

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"


@pytest.mark.parametrize(
    "edition_scope",
    [EditionScope.UNKNOWN, EditionScope.HOME_PRO, EditionScope.ENTERPRISE_EDUCATION],
)
def test_client_target_selection_agrees_with_held_broad_target_after_json_round_trip(edition_scope):
    from win11_release_guard.evaluator import select_broad_fleet_target

    policy = policy_from_dict(policy_to_dict(parse_windows11_release_health_html(_pending_26h2_html())))

    selected = select_broad_fleet_target(
        policy,
        edition_scope=edition_scope,
        servicing_channel=ServicingChannel.GENERAL_AVAILABILITY,
    )
    target = policy.broad_target_existing_devices
    assert (selected.version, selected.build_family) == (target.version, target.build_family) == ("25H2", 26200)
