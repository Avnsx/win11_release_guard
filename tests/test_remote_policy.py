import json

import pytest

from win11_release_guard.config import DEFAULT_POLICY_URL, DEFAULT_PUBLISHED_POLICY_URLS, DEFAULT_RELEASE_HEALTH_URL
from win11_release_guard.exceptions import PolicyParseError
from win11_release_guard.generator import generate_policy_from_release_health_html
from win11_release_guard.models import EditionScope, ReleasePolicy, ReleasePolicyEntry, ServicingChannel
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


def _fixture_html_file(name: str) -> str:
    with open(f"tests/fixtures/{name}", encoding="utf-8") as handle:
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


def _fixture_html_with_25h2_current_latest_build(build: str) -> str:
    return _fixture_html().replace("        <td>26200.8457</td>\n      </tr>", f"        <td>{build}</td>\n      </tr>", 1)


def _fixture_html_without_26h1_note() -> str:
    html = _fixture_html()
    start = html.index("  <p>\n    Windows 11, version 26H1")
    end = html.index("  </p>", start) + len("  </p>\n")
    return html[:start] + html[end:]


def _json_policy() -> dict:
    return {
        "schema_version": 1,
        "generated_at_utc": "2026-05-28T00:00:00Z",
        "source_urls": [
            DEFAULT_RELEASE_HEALTH_URL,
        ],
        "published_urls": dict(DEFAULT_PUBLISHED_POLICY_URLS),
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


def test_json_string_loads():
    policy = load_policy_text(
        json.dumps(_json_policy()),
        source_url=("https://policy.example" + ".invalid/windows-release-policy.json"),
    )

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert policy.source["policy_url"] == ("https://policy.example" + ".invalid/windows-release-policy.json")
    assert "Loaded policy URL is not listed in published_urls or source_urls." in policy.validation_warnings


def test_default_pages_policy_url_does_not_warn():
    policy = load_policy_text(json.dumps(_json_policy()), source_url=DEFAULT_POLICY_URL)

    assert "Loaded policy URL is not listed in published_urls or source_urls." not in policy.validation_warnings


def test_json_source_diagnostics_loads():
    data = _json_policy()
    data["source_diagnostics"] = {
        "release_health_html": {
            "source_url": DEFAULT_RELEASE_HEALTH_URL,
            "fetched_at_utc": "2026-05-31T00:00:00Z",
            "bytes": 1234,
            "status": "ok",
            "newest_current_version_revision_date": "2026-05-12",
            "newest_release_history_availability_date": "2026-05-12",
        },
        "atom_feed": {
            "source_url": DEFAULT_PUBLISHED_POLICY_URLS["policy"],
            "fetched_at_utc": "2026-05-31T00:00:01Z",
            "bytes": 5678,
            "status": "ok",
            "newest_atom_updated": "2026-05-16T18:00:00Z",
            "newest_atom_published": "2026-05-16T18:00:00Z",
        },
        "warnings": ["Source freshness warning: example"],
    }

    policy = load_policy_text(json.dumps(data), source_url=DEFAULT_POLICY_URL)

    assert policy.source_diagnostics["release_health_html"]["bytes"] == 1234
    assert policy.source_diagnostics["atom_feed"]["newest_atom_updated"] == "2026-05-16T18:00:00Z"
    assert not any("source_diagnostics" in warning for warning in policy.validation_warnings)


def test_api_policy_alias_does_not_warn():
    policy = load_policy_text(
        json.dumps(_json_policy()),
        source_url=DEFAULT_PUBLISHED_POLICY_URLS["api_policy"],
    )

    assert "Loaded policy URL is not listed in published_urls or source_urls." not in policy.validation_warnings


def test_local_policy_path_does_not_warn():
    policy = load_policy_text(
        json.dumps(_json_policy()),
        source_url=r"C:\tmp\windows-release-policy.json",
    )

    assert "Loaded policy URL is not listed in published_urls or source_urls." not in policy.validation_warnings


def test_upstream_source_url_does_not_warn():
    policy = load_policy_text(json.dumps(_json_policy()), source_url=DEFAULT_RELEASE_HEALTH_URL)

    assert DEFAULT_RELEASE_HEALTH_URL in policy.source_urls
    assert "Loaded policy URL is not listed in published_urls or source_urls." not in policy.validation_warnings


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


def test_malformed_json_raises_policy_parse_error():
    with pytest.raises(PolicyParseError, match="Malformed JSON policy"):
        load_policy_text("{not-json")


def test_json_missing_broad_target_raises_policy_parse_error():
    data = _json_policy()
    data.pop("broad_target_existing_devices")

    with pytest.raises(PolicyParseError, match="broad_target_existing_devices"):
        load_policy_text(json.dumps(data))


def test_json_unknown_top_level_key_is_forward_compatible_warning():
    data = _json_policy()
    data["unexpected_future_key"] = True

    policy = load_policy_text(json.dumps(data))

    assert any("unknown top-level key 'unexpected_future_key'" in warning for warning in policy.validation_warnings)


def test_json_extensions_and_x_keys_are_forward_compatible_without_warning():
    data = _json_policy()
    data["extensions"] = {"vendor": {"flag": True}}
    data["x_vendor_future_key"] = {"value": 1}

    policy = load_policy_text(json.dumps(data))

    assert not any("unknown top-level key" in warning for warning in policy.validation_warnings)


def test_json_malformed_release_and_build_raise_policy_parse_error():
    data = _json_policy()
    data["current_versions"][0]["version"] = "25Q9"

    with pytest.raises(PolicyParseError, match="release string"):
        load_policy_text(json.dumps(data))

    data = _json_policy()
    data["release_history"][0]["build"] = "26200"

    with pytest.raises(PolicyParseError, match="full build string"):
        load_policy_text(json.dumps(data))


def test_json_rejects_mismatched_current_required_baseline():
    data = _json_policy()
    data["current_versions"][1]["latest_build"] = "26200.8524"
    data["current_versions"][1]["latest_observed_build"] = "26200.8524"
    data["current_versions"][1]["baseline_build"] = "26200.8457"
    data["current_versions"][1]["required_baseline_build"] = "26200.8524"

    with pytest.raises(PolicyParseError, match=r"current_versions\[1\].required_baseline_build"):
        load_policy_text(json.dumps(data))


def test_json_unsupported_schema_version_raises_policy_parse_error():
    data = _json_policy()
    data["schema_version"] = 999

    with pytest.raises(PolicyParseError, match="Unsupported policy schema_version"):
        load_policy_text(json.dumps(data))


def test_json_incompatible_reader_schema_range_raises_policy_parse_error():
    data = _json_policy()
    data["schema_version"] = 1
    data["min_reader_schema_version"] = 2

    with pytest.raises(PolicyParseError, match="requires reader schema_version"):
        load_policy_text(json.dumps(data))

    data = _json_policy()
    data["schema_version"] = 1
    data["max_reader_schema_version"] = 0

    with pytest.raises(PolicyParseError, match="max_reader_schema_version"):
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


def test_parse_release_health_current_d_preview_fixture_keeps_latest_and_baseline_distinct():
    policy = parse_windows11_release_health_html(
        _fixture_html_file("windows11-release-health-current-d-26h1.html")
    )

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert policy.broad_target_existing_devices.latest_build == "26200.8524"
    assert policy.broad_target_existing_devices.latest_observed_build == "26200.8524"
    assert policy.broad_target_existing_devices.baseline_build == "26200.8457"
    assert policy.broad_target_existing_devices.required_baseline_build == "26200.8457"
    current_25h2 = next(entry for entry in policy.current_versions if entry.version == "25H2")
    assert current_25h2.latest_build == "26200.8524"
    assert current_25h2.latest_observed_build == "26200.8524"
    assert current_25h2.baseline_build == "26200.8457"
    assert current_25h2.required_baseline_build == "26200.8457"
    preview = next(row for row in policy.release_history if row.build == "26200.8524")
    assert preview.preview is True
    assert preview.update_type_letter == "D"
    assert preview.kb_article == "KB5089573"
    assert {entry.version for entry in policy.special_releases} == {"26H1"}


def test_parse_release_health_header_variants_accept_german_latest_and_update_type_headers():
    policy = parse_windows11_release_health_html(
        _fixture_html_file("windows11-release-health-header-variants.html")
    )

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert policy.broad_target_existing_devices.latest_build == "26200.8457"
    assert any(row.release == "25H2" and row.build == "26200.8524" and row.preview for row in policy.release_history)
    current_25h2 = next(entry for entry in policy.current_versions if entry.version == "25H2")
    assert current_25h2.servicing_option == "Allgemeiner Verfügbarkeitskanal"
    assert current_25h2.metadata["latest_revision_date"] == "2026-05-12"
    assert {entry.version for entry in policy.special_releases} == {"26H1"}


def test_parse_release_health_selects_h2_ga_broad_target_not_26h1():
    policy = parse_windows11_release_health_html(_fixture_html())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert policy.broad_target_existing_devices.build_family == 26200
    assert policy.broad_target_existing_devices.latest_build == "26200.8457"
    assert policy.broad_target_existing_devices.baseline_build == "26200.8457"


def test_parse_release_health_keeps_latest_observed_preview_distinct_from_baseline():
    policy = parse_windows11_release_health_html(_fixture_html_with_25h2_current_latest_build("26200.8524"))

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.latest_build == "26200.8524"
    assert policy.broad_target_existing_devices.latest_observed_build == "26200.8524"
    assert policy.broad_target_existing_devices.baseline_build == "26200.8457"
    assert policy.broad_target_existing_devices.required_baseline_build == "26200.8457"
    current_25h2 = next(entry for entry in policy.current_versions if entry.version == "25H2")
    assert current_25h2.latest_build == "26200.8524"
    assert current_25h2.latest_observed_build == "26200.8524"
    assert current_25h2.baseline_build == "26200.8457"
    assert current_25h2.required_baseline_build == "26200.8457"


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


def test_release_health_parser_reports_missing_current_version_latest_header():
    html = _fixture_html().replace("<th>Latest build</th>", "<th>Observed build</th>", 1)

    with pytest.raises(PolicyParseError, match=r"current_versions table.*Latest build.*table\[0\]"):
        parse_windows11_release_health_html(html)


def test_release_health_parser_reports_missing_release_history_update_type_header():
    html = _fixture_html().replace("<th>Update type</th>", "<th>Lifecycle marker</th>")

    with pytest.raises(PolicyParseError, match=r"release_history tables.*Update type.*Lifecycle marker"):
        parse_windows11_release_health_html(html)


def test_release_health_parser_requires_26h1_special_note_when_26h1_is_current():
    with pytest.raises(PolicyParseError, match="26H1 new-devices-only special release note"):
        parse_windows11_release_health_html(_fixture_html_without_26h1_note())


def test_non_json_non_html_source_raises_policy_parse_error():
    with pytest.raises(PolicyParseError, match="neither JSON nor HTML"):
        load_policy_bytes(b"plain text")
