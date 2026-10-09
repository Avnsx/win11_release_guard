from __future__ import annotations

import json
import pytest
from win11_release_guard.config import DEFAULT_POLICY_URL, DEFAULT_PUBLISHED_POLICY_URLS, DEFAULT_RELEASE_HEALTH_URL
from win11_release_guard.exceptions import PolicyParseError
from win11_release_guard.remote_policy import load_policy_bytes, load_policy_text
from tests.support.remote_policy_helpers import _json_policy


ATOM_SOURCE_DIAGNOSTIC_ID = "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480"


HASH_SOURCE_DIAGNOSTIC_ID = "wrg-source-diagnostic-v1:1111111111111111"


SIBLING_HASH_SOURCE_DIAGNOSTIC_ID = "wrg-source-diagnostic-v1:2222222222222222"


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


def test_non_json_non_html_source_raises_policy_parse_error():
    with pytest.raises(PolicyParseError, match="neither JSON nor HTML"):
        load_policy_bytes(b"plain text")
