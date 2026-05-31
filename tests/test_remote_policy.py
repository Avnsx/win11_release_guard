import json

import pytest

from win11_release_guard.exceptions import PolicyParseError
from win11_release_guard.generator import generate_policy_from_release_health_html
from win11_release_guard.models import EditionScope, ReleasePolicy, ServicingChannel
from win11_release_guard.remote_policy import (
    fetch_release_policy,
    load_policy_bytes,
    load_policy_text,
    parse_windows11_release_health_html,
    policy_from_dict,
    policy_to_dict,
)


def _fixture_html() -> str:
    with open("tests/fixtures/windows11-release-health.html", encoding="utf-8") as handle:
        return handle.read()


def _fixture_html_with_ltsc_table() -> str:
    ltsc_table = """
  <h2>Windows 11 Enterprise LTSC current versions</h2>
  <table>
    <thead>
      <tr>
        <th>Version</th>
        <th>Servicing option</th>
        <th>Availability date</th>
        <th>End of servicing: Enterprise LTSC and IoT Enterprise LTSC</th>
        <th>Latest revision date</th>
        <th>Latest build</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>24H2</td>
        <td>Long-Term Servicing Channel</td>
        <td>2024-10-01</td>
        <td>2034-10-10</td>
        <td>2026-05-12</td>
        <td>26100.8457</td>
      </tr>
    </tbody>
  </table>
"""
    return _fixture_html().replace("  <h2>Windows 11 release history</h2>", ltsc_table + "\n  <h2>Windows 11 release history</h2>", 1)


def _json_policy() -> dict:
    return {
        "schema_version": 1,
        "generated_at_utc": "2026-05-28T00:00:00Z",
        "source_urls": [
            "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information"
        ],
        "source": {"generator": "test"},
        "current_versions": [
            {
                "version": "24H2",
                "build_family": 26100,
                "latest_build": "26100.8457",
                "servicing_option": "General Availability Channel",
            },
            {
                "version": "25H2",
                "build_family": 26200,
                "latest_build": "26200.8457",
                "baseline_build": "26200.8457",
                "servicing_option": "General Availability Channel",
            },
        ],
        "supported_build_families": {
            "26100": "24H2",
            "26200": "25H2",
        },
        "broad_target_existing_devices": {
            "version": "25H2",
            "build_family": 26200,
            "latest_build": "26200.8457",
            "baseline_build": "26200.8457",
            "servicing_option": "General Availability Channel",
        },
        "release_history": [
            {
                "release": "25H2",
                "build_family": 26200,
                "build": "26200.8457",
                "availability_date": "2026-05-12",
                "servicing_option": "General Availability Channel",
                "update_type": "2026-05 B",
                "update_type_letter": "B",
                "kb_article": "KB5089549",
            }
        ],
    }


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
        "source": {"release_health_url": "https://example.invalid/windows11-release-information"},
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


def test_json_string_loads():
    policy = load_policy_text(
        json.dumps(_json_policy()),
        source_url="https://example.invalid/windows-release-policy.json",
    )

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert policy.source["policy_url"] == "https://example.invalid/windows-release-policy.json"
    assert "Loaded policy URL is not listed in source_urls." in policy.validation_warnings


def test_json_bytes_loads():
    policy = load_policy_bytes(json.dumps(_json_policy()).encode("utf-8"))

    assert policy.release_for_build_family(26200) == "25H2"
    assert policy.release_history[0].build == "26200.8457"


def test_response_with_json_content_type_loads():
    calls = []

    def fake_get(url, timeout):
        calls.append((url, timeout))
        return Response(text=json.dumps(_json_policy()), content_type="application/json; charset=utf-8")

    policy = fetch_release_policy(
        "https://example.invalid/windows-release-policy.json",
        timeout=1.5,
        http_get=fake_get,
    )

    assert calls == [("https://example.invalid/windows-release-policy.json", 1.5)]
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
            "https://example.invalid/windows11-release-information",
            timeout=1,
            http_get=fake_get,
        )

    policy = fetch_release_policy(
        "https://example.invalid/windows11-release-information",
        timeout=1,
        http_get=fake_get,
        allow_html_fallback=True,
    )

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"


def test_malformed_json_raises_policy_parse_error():
    with pytest.raises(PolicyParseError, match="Malformed JSON policy"):
        load_policy_text("{not-json")


def test_json_missing_broad_target_raises_policy_parse_error():
    data = _json_policy()
    data.pop("broad_target_existing_devices")

    with pytest.raises(PolicyParseError, match="broad_target_existing_devices"):
        load_policy_text(json.dumps(data))


def test_json_unknown_top_level_key_raises_policy_parse_error():
    data = _json_policy()
    data["unexpected_future_key"] = True

    with pytest.raises(PolicyParseError, match="unknown top-level key"):
        load_policy_text(json.dumps(data))


def test_json_malformed_release_and_build_raise_policy_parse_error():
    data = _json_policy()
    data["current_versions"][0]["version"] = "25Q9"

    with pytest.raises(PolicyParseError, match="release string"):
        load_policy_text(json.dumps(data))

    data = _json_policy()
    data["release_history"][0]["build"] = "26200"

    with pytest.raises(PolicyParseError, match="full build string"):
        load_policy_text(json.dumps(data))


def test_json_unsupported_schema_version_raises_policy_parse_error():
    data = _json_policy()
    data["schema_version"] = 999

    with pytest.raises(PolicyParseError, match="Unsupported policy schema_version"):
        load_policy_text(json.dumps(data))


def test_parse_release_health_builds_current_versions_and_history():
    policy = parse_windows11_release_health_html(_fixture_html())

    assert {entry.version for entry in policy.current_versions} == {
        "23H2",
        "24H2",
        "25H2",
        "26H1",
    }
    assert policy.release_for_build_family(26200) == "25H2"
    assert any(row.release == "25H2" and row.build == "26200.8457" for row in policy.release_history)


def test_parse_release_health_selects_h2_ga_broad_target_not_26h1():
    policy = parse_windows11_release_health_html(_fixture_html())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert policy.broad_target_existing_devices.build_family == 26200
    assert policy.broad_target_existing_devices.latest_build == "26200.8457"
    assert policy.broad_target_existing_devices.baseline_build == "26200.8457"


def test_parse_release_health_marks_26h1_special_new_devices_only():
    policy = parse_windows11_release_health_html(_fixture_html())

    special = {entry.version: entry for entry in policy.special_releases}

    assert "26H1" in special
    assert special["26H1"].metadata["special_release"] is True
    assert special["26H1"].metadata["new_devices_only"] is True
    assert special["26H1"].metadata["not_broad_target"] is True
    assert policy.excluded_for_existing_devices[0].version == "26H1"


def test_parse_release_health_keeps_ltsc_current_versions_separate_from_ga():
    policy = parse_windows11_release_health_html(_fixture_html_with_ltsc_table())
    entries = [
        entry
        for entry in policy.current_versions
        if entry.version == "24H2" and entry.build_family == 26100
    ]

    assert len(entries) == 2
    ga = next(entry for entry in entries if entry.servicing_channel is ServicingChannel.GENERAL_AVAILABILITY)
    ltsc = next(entry for entry in entries if entry.servicing_channel is ServicingChannel.LTSC)
    assert EditionScope.HOME_PRO in ga.edition_scopes
    assert EditionScope.ENTERPRISE_LTSC in ltsc.edition_scopes
    assert EditionScope.IOT_ENTERPRISE_LTSC in ltsc.edition_scopes


def test_non_json_non_html_source_raises_policy_parse_error():
    with pytest.raises(PolicyParseError, match="neither JSON nor HTML"):
        load_policy_bytes(b"plain text")
