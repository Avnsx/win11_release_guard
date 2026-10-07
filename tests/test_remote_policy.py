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


ATOM_SOURCE_DIAGNOSTIC_ID = "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480"
HASH_SOURCE_DIAGNOSTIC_ID = "wrg-source-diagnostic-v1:1111111111111111"
SIBLING_HASH_SOURCE_DIAGNOSTIC_ID = "wrg-source-diagnostic-v1:2222222222222222"


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


def _fixture_html_with_poison_current_table() -> str:
    poison = """
  <h2>Random dashboard</h2>
  <table>
    <thead>
      <tr>
        <th>Release</th>
        <th>Service option</th>
        <th>Latest OS build</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>25H2</td>
        <td>General Availability Channel</td>
        <td>26200.9999</td>
      </tr>
    </tbody>
  </table>
"""
    return _fixture_html().replace("  <h2>Windows 11 current versions by servicing option</h2>", poison + "\n  <h2>Windows 11 current versions by servicing option</h2>", 1)


def _fixture_html_with_minimal_current_versions() -> str:
    minimal = """
  <h2>Windows 11 current versions by servicing option</h2>
  <table>
    <thead>
      <tr>
        <th>Version</th>
        <th>Servicing option</th>
        <th>Latest build</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>26H1</td>
        <td>General Availability Channel</td>
        <td>28000.2113</td>
      </tr>
      <tr>
        <td>25H2</td>
        <td>General Availability Channel</td>
        <td>26200.8457</td>
      </tr>
      <tr>
        <td>24H2</td>
        <td>General Availability Channel</td>
        <td>26100.8457</td>
      </tr>
    </tbody>
  </table>
"""
    html = _fixture_html()
    start = html.index("  <h2>Windows 11 current versions by servicing option</h2>")
    end = html.index("  <h2>Windows 11 release history</h2>", start)
    return html[:start] + minimal + "\n" + html[end:]


def _fixture_html_without_release_history_kb_column() -> str:
    html = _fixture_html().replace("        <th>KB article</th>\n", "")
    for kb in ("KB5089549", "KB5083631", "KB5089548"):
        html = html.replace(f"        <td>{kb}</td>\n", "")
    return html


def _fixture_html_without_b_baseline_for_25h2() -> str:
    row_start = _fixture_html().index("      <tr>\n        <td>General Availability Channel</td>\n        <td>2026-05 B</td>")
    row_end = _fixture_html().index("      </tr>", row_start) + len("      </tr>\n")
    html = _fixture_html()
    return html[:row_start] + html[row_end:]


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


def test_json_source_diagnostics_accepts_supported_diagnostic_id_forms():
    data = _json_policy()
    data["source_diagnostics"] = {
        "events": [
            {
                "id": HASH_SOURCE_DIAGNOSTIC_ID,
                "severity": "warning",
                "kind": "legacy_hash_probe",
            },
            {
                "id": ATOM_SOURCE_DIAGNOSTIC_ID,
                "severity": "warning",
                "kind": "atom_probe",
            },
        ],
        "issue_status": {
            HASH_SOURCE_DIAGNOSTIC_ID: {
                "number": 41,
                "state": "open",
                "url": "https://github.com/Avnsx/win11_release_guard/issues/41",
            },
            ATOM_SOURCE_DIAGNOSTIC_ID: {
                "number": 42,
                "state": "open",
                "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
            },
        },
    }

    policy = load_policy_text(json.dumps(data), source_url=DEFAULT_POLICY_URL)

    assert [event["id"] for event in policy.source_diagnostics["events"]] == [
        HASH_SOURCE_DIAGNOSTIC_ID,
        ATOM_SOURCE_DIAGNOSTIC_ID,
    ]
    assert set(policy.source_diagnostics["issue_status"]) == {
        HASH_SOURCE_DIAGNOSTIC_ID,
        ATOM_SOURCE_DIAGNOSTIC_ID,
    }


def test_json_source_diagnostics_accepts_atom_canonical_and_sibling_hash_ids():
    data = _json_policy()
    data["source_diagnostics"] = {
        "events": [
            {
                "id": SIBLING_HASH_SOURCE_DIAGNOSTIC_ID,
                "severity": "notice",
                "kind": "atom_newer_than_release_history",
                "release": "24H2",
                "build_family": 26100,
                "build": "26100.8655",
                "kb_article": "KB5094126",
                "atom_entry_id": "uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480",
                "atom_support_article_id": "968480",
            },
            {
                "id": ATOM_SOURCE_DIAGNOSTIC_ID,
                "severity": "warning",
                "kind": "atom_newer_than_release_history",
                "release": "25H2",
                "build_family": 26200,
                "build": "26200.8655",
                "kb_article": "KB5094126",
                "atom_entry_id": "uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480",
                "atom_support_article_id": "968480",
            },
        ],
        "issue_status": {
            ATOM_SOURCE_DIAGNOSTIC_ID: {
                "number": 42,
                "state": "open",
                "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
            },
        },
    }

    policy = load_policy_text(json.dumps(data), source_url=DEFAULT_POLICY_URL)

    assert [event["id"] for event in policy.source_diagnostics["events"]] == [
        SIBLING_HASH_SOURCE_DIAGNOSTIC_ID,
        ATOM_SOURCE_DIAGNOSTIC_ID,
    ]
    assert policy.source_diagnostics["events"][0]["atom_support_article_id"] == "968480"


@pytest.mark.parametrize(
    "diagnostic_id",
    (
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af;id=968480",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=0",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=-1",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=notnumeric",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1C3E09919AF3;id=968480",
        "WRG-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3 ;id=968480",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480 extra",
        "wrg-source-diagnostic-v1:1111111111111111-suffix",
        "wrg-source-diagnostic-v1:AAAAAAAAAAAAAAAA",
        " wrg-source-diagnostic-v1:1111111111111111",
        "arbitrary-string-id",
    ),
)
def test_json_source_diagnostics_rejects_malformed_event_ids(diagnostic_id: str):
    data = _json_policy()
    data["source_diagnostics"] = {
        "events": [
            {
                "id": diagnostic_id,
                "severity": "warning",
                "kind": "probe",
            }
        ],
    }

    with pytest.raises(PolicyParseError, match=r"source_diagnostics\.events\[0\]\.id"):
        load_policy_text(json.dumps(data), source_url=DEFAULT_POLICY_URL)


def test_json_source_diagnostics_rejects_duplicate_event_ids():
    data = _json_policy()
    data["source_diagnostics"] = {
        "events": [
            {
                "id": HASH_SOURCE_DIAGNOSTIC_ID,
                "severity": "warning",
                "kind": "probe",
            },
            {
                "id": HASH_SOURCE_DIAGNOSTIC_ID,
                "severity": "notice",
                "kind": "probe_sibling",
            },
        ],
    }

    with pytest.raises(PolicyParseError, match="source_diagnostics.events ids must be unique"):
        load_policy_text(json.dumps(data), source_url=DEFAULT_POLICY_URL)


@pytest.mark.parametrize(
    "diagnostic_id",
    (
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af;id=968480",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=0",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=-1",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=notnumeric",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1C3E09919AF3;id=968480",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3 ;id=968480",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480-extra",
        "wrg-source-diagnostic-v1:1111111111111111-suffix",
        "arbitrary-string-id",
    ),
)
def test_json_source_diagnostics_rejects_malformed_issue_status_ids(diagnostic_id: str):
    data = _json_policy()
    data["source_diagnostics"] = {
        "issue_status": {
            diagnostic_id: {
                "number": 42,
                "state": "open",
                "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
            }
        }
    }

    with pytest.raises(PolicyParseError, match="source_diagnostics.issue_status keys"):
        load_policy_text(json.dumps(data), source_url=DEFAULT_POLICY_URL)


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


def test_json_accepts_newer_latest_observed_without_changing_required_baseline():
    data = _json_policy()
    data["current_versions"][1]["latest_observed_build"] = "26200.8655"
    data["current_versions"][1]["required_baseline_build"] = "26200.8457"
    data["broad_target_existing_devices"]["latest_observed_build"] = "26200.8655"
    data["broad_target_existing_devices"]["required_baseline_build"] = "26200.8457"

    policy = load_policy_text(json.dumps(data))

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.latest_build == "26200.8457"
    assert policy.broad_target_existing_devices.latest_observed_build == "26200.8655"
    assert policy.broad_target_existing_devices.required_baseline_build == "26200.8457"
    assert policy.broad_target_existing_devices.effective_baseline_build == "26200.8457"
    current_25h2 = next(entry for entry in policy.current_versions if entry.version == "25H2")
    assert current_25h2.latest_build == "26200.8457"
    assert current_25h2.latest_observed_build == "26200.8655"
    assert current_25h2.required_baseline_build == "26200.8457"


def test_json_rejects_malformed_latest_observed_build():
    data = _json_policy()
    data["current_versions"][1]["latest_observed_build"] = "26200"

    with pytest.raises(PolicyParseError, match=r"current_versions\[1\].latest_observed_build"):
        load_policy_text(json.dumps(data))


def test_json_rejects_older_latest_observed_build():
    data = _json_policy()
    data["broad_target_existing_devices"]["latest_observed_build"] = "26200.7000"

    with pytest.raises(PolicyParseError, match="latest_observed_build must not be older than latest_build"):
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


def test_parse_release_health_ignores_poison_current_versions_table_before_real_table():
    policy = parse_windows11_release_health_html(_fixture_html_with_poison_current_table())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert policy.broad_target_existing_devices.latest_build == "26200.8457"
    assert all(entry.latest_build != "26200.9999" for entry in policy.current_versions)
    events = policy.source_diagnostics["parser"]["events"]
    assert any(event["kind"] == "ignored_current_versions_subset_table" for event in events)


def test_parse_release_health_current_versions_missing_optional_lifecycle_revision_fields_still_loads():
    policy = parse_windows11_release_health_html(_fixture_html_with_minimal_current_versions())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert policy.broad_target_existing_devices.latest_build == "26200.8457"
    assert policy.broad_target_existing_devices.required_baseline_build == "26200.8457"


def test_parse_release_history_missing_kb_article_column_still_loads():
    policy = parse_windows11_release_health_html(_fixture_html_without_release_history_kb_column())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.required_baseline_build == "26200.8457"
    row = next(row for row in policy.release_history if row.release == "25H2" and row.build == "26200.8457")
    assert row.kb_article is None
    assert row.kb_url is None


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


def test_release_health_parser_requires_b_baseline_for_broad_target():
    with pytest.raises(PolicyParseError, match="B-release required baseline"):
        parse_windows11_release_health_html(_fixture_html_without_b_baseline_for_25h2())


PENDING_26H2_FIXTURE = "windows11-release-health-26h2-pending-b.html"


def _pending_26h2_html() -> str:
    return _fixture_html_file(PENDING_26H2_FIXTURE)


def _history_row(update_type: str, availability_date: str, build: str, kb_article: str) -> str:
    return (
        "      <tr>\n"
        "        <td>General Availability Channel</td>\n"
        f"        <td>{update_type}</td>\n"
        f"        <td>{availability_date}</td>\n"
        f"        <td>{build}</td>\n"
        f"        <td>{kb_article}</td>\n"
        "      </tr>\n"
    )


def _with_history_row(html: str, heading: str, row: str) -> str:
    section = html.index(f"<h3>{heading}</h3>")
    body = html.index("<tbody>\n", section) + len("<tbody>\n")
    return html[:body] + row + html[body:]


def _pending_26h2_html_after_october_patch_tuesday() -> str:
    html = _with_history_row(
        _pending_26h2_html(),
        "Version 26H2 (OS build 26300)",
        _history_row("2026-10 B", "2026-10-13", "26300.9700", "KB5130001"),
    )
    return _with_history_row(
        html,
        "Version 25H2 (OS build 26200)",
        _history_row("2026-10 B", "2026-10-13", "26200.9700", "KB5130001"),
    )


def _pending_26h2_html_with_patch_tuesday_missing_for_26h2() -> str:
    return _with_history_row(
        _pending_26h2_html(),
        "Version 25H2 (OS build 26200)",
        _history_row("2026-10 B", "2026-10-13", "26200.9700", "KB5130001"),
    )


def _current_entry(policy: ReleasePolicy, version: str) -> ReleasePolicyEntry:
    return next(entry for entry in policy.current_versions if entry.version == version)


def test_release_health_parser_holds_broad_target_while_new_h2_awaits_first_b_release():
    policy = parse_windows11_release_health_html(_pending_26h2_html())

    target = policy.broad_target_existing_devices
    assert target is not None
    assert (target.version, target.build_family) == ("25H2", 26200)
    assert target.baseline_build == "26200.9445"
    assert target.required_baseline_build == "26200.9445"
    assert target.latest_build == "26200.9550"


def test_release_health_parser_marks_pending_release_not_broad_target_without_special_flags():
    policy = parse_windows11_release_health_html(_pending_26h2_html())

    pending = _current_entry(policy, "26H2")
    assert pending.metadata["not_broad_target"] is True
    assert pending.metadata["not_broad_target_existing_devices"] is True
    assert pending.metadata["pending_first_b_release"] is True
    assert "25H2" in pending.metadata["broad_target_hold_reason"]
    assert "special_release" not in pending.metadata
    assert "new_devices_only" not in pending.metadata
    assert pending.baseline_build is None
    assert [entry.version for entry in policy.special_releases] == ["26H1"]
    assert [entry.version for entry in policy.excluded_for_existing_devices] == ["26H1"]
    assert policy.supported_build_families[26300] == "26H2"


def test_release_health_parser_hold_leaves_older_releases_without_b_rows_unflagged():
    html = _pending_26h2_html().replace(_history_row("2026-09 B", "2026-09-08", "22631.7582", "KB5122880"), "", 1)
    policy = parse_windows11_release_health_html(html)

    assert _current_entry(policy, "23H2").baseline_build is None
    assert _current_entry(policy, "26H2").metadata["pending_first_b_release"] is True
    assert "not_broad_target" not in _current_entry(policy, "23H2").metadata
    assert "pending_first_b_release" not in _current_entry(policy, "23H2").metadata


def test_release_health_parser_reports_pending_first_b_release_as_dashboard_notice():
    policy = parse_windows11_release_health_html(_pending_26h2_html())

    events = [
        event
        for event in policy.source_diagnostics["parser"]["events"]
        if event.get("kind") == "broad_target_pending_b_release"
    ]
    assert len(events) == 1
    event = events[0]
    assert event["severity"] == "notice"
    assert (event["release"], event["build_family"], event["build"]) == ("26H2", 26300, "26300.9550")
    assert event["held_release"] == "25H2"
    assert event["held_required_baseline_build"] == "26200.9445"
    assert event["affects_broad_target"] is True
    assert event["affects_required_baseline"] is False
    assert "26H2" in event["message"] and "25H2" in event["message"]


def test_release_health_parser_promotes_new_h2_after_its_first_b_release():
    policy = parse_windows11_release_health_html(_pending_26h2_html_after_october_patch_tuesday())

    target = policy.broad_target_existing_devices
    assert target is not None
    assert (target.version, target.build_family) == ("26H2", 26300)
    assert target.required_baseline_build == "26300.9700"
    assert "pending_first_b_release" not in _current_entry(policy, "26H2").metadata
    assert "not_broad_target" not in _current_entry(policy, "26H2").metadata
    assert not [
        event
        for event in policy.source_diagnostics["parser"]["events"]
        if event.get("kind") == "broad_target_pending_b_release"
    ]


def test_release_health_parser_fails_closed_when_patch_tuesday_passed_without_b_for_new_h2():
    with pytest.raises(PolicyParseError, match="B-release required baseline.*26H2/26300"):
        parse_windows11_release_health_html(_pending_26h2_html_with_patch_tuesday_missing_for_26h2())


def test_release_health_parser_fails_closed_when_only_a_newer_release_could_hold_the_target():
    html = _pending_26h2_html()
    for version in ("25H2", "24H2", "23H2"):
        row_start = html.index(f"      <tr>\n        <td>{version}</td>")
        row_end = html.index("      </tr>\n", row_start) + len("      </tr>\n")
        html = html[:row_start] + html[row_end:]
    newer_h1_row = (
        "      <tr>\n        <td>27H1</td>\n        <td>General Availability Channel</td>\n"
        "        <td>2026-02-10</td>\n        <td>2029-03-13</td>\n        <td>2030-03-12</td>\n"
        "        <td>2026-09 B</td>\n        <td>2026-09-08</td>\n        <td>28100.1000</td>\n      </tr>\n"
    )
    first_current_row = html.index("      <tr>\n        <td>26H2</td>")
    html = html[:first_current_row] + newer_h1_row + html[first_current_row:]
    newer_h1_history = (
        "  <h3>Version 27H1 (OS build 28100)</h3>\n  <table>\n    <thead>\n      <tr>\n"
        "        <th>Servicing option</th>\n        <th>Update type</th>\n        <th>Availability date</th>\n"
        "        <th>Build</th>\n        <th>KB article</th>\n      </tr>\n    </thead>\n    <tbody>\n"
        + _history_row("2026-09 B", "2026-09-08", "28100.1000", "KB5124099")
        + "    </tbody>\n  </table>\n\n"
    )
    html = html.replace("  <h3>Version 26H1 (OS build 28000)</h3>", newer_h1_history + "  <h3>Version 26H1 (OS build 28000)</h3>", 1)

    with pytest.raises(PolicyParseError, match="B-release required baseline.*26H2/26300"):
        parse_windows11_release_health_html(html)


def test_release_health_parser_uses_release_history_date_when_current_availability_is_blank():
    html = _pending_26h2_html().replace("<td>2026-09-29</td>\n        <td>2028-10-10</td>", "<td></td>\n        <td>2028-10-10</td>", 1)

    policy = parse_windows11_release_health_html(html)

    assert policy.broad_target_existing_devices.version == "25H2"
    assert _current_entry(policy, "26H2").metadata["pending_first_b_release"] is True


def test_release_health_parser_fails_closed_when_pending_release_has_no_dates():
    html = _pending_26h2_html().replace("<td>2026-09-29</td>", "<td></td>")

    with pytest.raises(PolicyParseError, match="B-release required baseline.*26H2/26300"):
        parse_windows11_release_health_html(html)


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


def test_non_json_non_html_source_raises_policy_parse_error():
    with pytest.raises(PolicyParseError, match="neither JSON nor HTML"):
        load_policy_bytes(b"plain text")
