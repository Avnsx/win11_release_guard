from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path
import pytest
from win11_release_guard.exceptions import PolicyParseError
from win11_release_guard.models import QualityPolicy, ReleasePolicy
import win11_release_guard.policy_generator as policy_generator_module
from win11_release_guard.policy_generator import SOURCE_DIAGNOSTIC_ID_PREFIX, generate_policy, write_policy_outputs
from win11_release_guard.policy_schema import is_source_diagnostic_id, validate_policy_document
from tests.support.policy_generator_helpers import (
    FAKE_MSRC_CVRF_WITH_KB5094126,
    KB5094126_SUPPORT_HTML,
    KB5094126_SUPPORT_URL,
    _assert_no_raw_support_article_leakage,
    _generated_output_bundle,
    _html,
    _html_file,
    _kb5094126_atom_event,
    _kb5094126_generated_fixture_policy,
    _kb5094126_msrc_fixture,
    _kb5094126_policy_with_support_html,
    _kb5094126_support_fixture,
    _kb5094126_toc_fixture,
    _release_health_caught_up_to_kb5094126,
    _support_article_html,
    _toc,
    _toc_document_with_extra,
    _toc_entry,
    _toc_with_new_b_release,
    _with_25h2_current_latest_build,
    _with_oob_row,
)


def _kb5094126_fixture_policy() -> ReleasePolicy:
    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        assert url == KB5094126_SUPPORT_URL
        return _kb5094126_support_fixture()

    def msrc_fetcher(url: str, timeout: float, max_bytes: int) -> dict[str, object]:
        if url.endswith("/2026-Jun"):
            return _kb5094126_msrc_fixture()
        return {"Vulnerability": []}

    return generate_policy(
        release_health_html=_html_file("windows11-release-health-header-variants.html"),
        servicing_toc_json=_kb5094126_toc_fixture(),
        generated_at_utc="2026-06-11T00:00:00+00:00",
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )


def _rendered_diagnostic_ids(index: str) -> list[str]:
    return re.findall(
        r'data-diagnostic-id="(wrg-source-diagnostic-v1:(?:[0-9a-f]{16}|uuid:[0-9a-f-]{36};id=[1-9][0-9]*))"',
        index,
    )


def _assert_unique_source_diagnostic_ids(policy_data: dict[str, object], index: str) -> None:
    source_diagnostics = policy_data["source_diagnostics"]
    assert isinstance(source_diagnostics, dict)
    events = source_diagnostics["events"]
    assert isinstance(events, list)
    event_ids = [str(event["id"]) for event in events if isinstance(event, dict)]
    row_ids = _rendered_diagnostic_ids(index)
    assert event_ids
    assert len(event_ids) == len(set(event_ids))
    assert row_ids
    assert len(row_ids) == len(set(row_ids))
    assert set(event_ids) <= set(row_ids)
    assert "function visibleDiagnosticEntries()" in index
    assert "diagnostic_id:row.getAttribute('data-diagnostic-id')||''" in index


def _toc_with_new_preview_release() -> str:
    return _toc_document_with_extra(
        _toc_entry(
            "June 9, 2026—KB5089601 (OS Build 26200.8461) Preview",
            "2026/06/june-9-2026-kb5089601-os-build-26200-8461",
        )
    )


def _with_26h2_ga(html: str) -> str:
    row = """      <tr>
        <td>26H2</td>
        <td>General Availability Channel</td>
        <td>2026-10-01</td>
        <td>2028-10-10</td>
        <td>2029-10-09</td>
        <td>2026-10-13</td>
        <td>28200.1000</td>
      </tr>
"""
    history = """
  <h3>Version 26H2 (OS build 28200)</h3>
  <table>
    <thead>
      <tr>
        <th>Servicing option</th>
        <th>Update type</th>
        <th>Availability date</th>
        <th>Build</th>
        <th>KB article</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>General Availability Channel</td>
        <td>2026-10 B</td>
        <td>2026-10-13</td>
        <td>28200.1000</td>
        <td>KB5090001</td>
      </tr>
    </tbody>
  </table>
"""
    html = html.replace("      <tr>\n        <td>26H1</td>", row + "      <tr>\n        <td>26H1</td>", 1)
    return html.replace("  <h3>Version 26H1 (OS build 28000)</h3>", history + "\n  <h3>Version 26H1 (OS build 28000)</h3>", 1)


def _with_27h1_special(html: str) -> str:
    note = """
  <p>
    Windows 11, version 27H1 is scoped to support new devices and is not
    designed as a feature update for existing devices. This version is not
    offered as an in-place update from 25H2 or 26H2 on existing devices.
  </p>
"""
    row = """      <tr>
        <td>27H1</td>
        <td>General Availability Channel</td>
        <td>2027-02-10</td>
        <td>2029-03-13</td>
        <td>2030-03-12</td>
        <td>2027-02-10</td>
        <td>29000.1000</td>
      </tr>
"""
    history = """
  <h3>Version 27H1 (OS build 29000)</h3>
  <table>
    <thead>
      <tr>
        <th>Servicing option</th>
        <th>Update type</th>
        <th>Availability date</th>
        <th>Build</th>
        <th>KB article</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>General Availability Channel</td>
        <td>2027-02 B</td>
        <td>2027-02-10</td>
        <td>29000.1000</td>
        <td>KB5097001</td>
      </tr>
    </tbody>
  </table>
"""
    html = html.replace("  <h2>Windows 11 current versions by servicing option</h2>", note + "\n  <h2>Windows 11 current versions by servicing option</h2>", 1)
    html = html.replace("      <tr>\n        <td>26H2</td>", row + "      <tr>\n        <td>26H2</td>", 1)
    return html.replace("  <h3>Version 26H2 (OS build 28200)</h3>", history + "\n  <h3>Version 26H2 (OS build 28200)</h3>", 1)


def _without_26h1_special_note(html: str) -> str:
    start = html.index("  <p>\n    Windows 11, version 26H1")
    end = html.index("  </p>", start) + len("  </p>\n")
    return html[:start] + html[end:]


def test_fixture_with_26h1_25h2_24h2_chooses_25h2():
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    special = {entry.version: entry for entry in policy.special_releases}
    assert special["26H1"].metadata["special_release"] is True
    assert special["26H1"].metadata["new_devices_only"] is True
    assert special["26H1"].metadata["not_broad_target_existing_devices"] is True


def test_generate_policy_from_release_health_current_d_preview_fixture():
    policy = generate_policy(
        release_health_html=_html_file("windows11-release-health-current-d-26h1.html"),
        servicing_toc_json=_toc(),
    )
    target = policy.broad_target_existing_devices
    baseline = policy.quality_baselines["25H2"][QualityPolicy.B_RELEASE_ONLY.value]

    assert target is not None
    assert target.latest_observed_build == "26200.8524"
    assert target.required_baseline_build == "26200.8457"
    assert baseline["build"] == "26200.8457"
    current_25h2 = next(entry for entry in policy.current_versions if entry.version == "25H2")
    assert current_25h2.latest_build == "26200.8524"
    assert current_25h2.latest_observed_build == "26200.8524"
    assert current_25h2.baseline_build == "26200.8457"
    assert current_25h2.required_baseline_build == "26200.8457"
    assert any(item["build"] == "26200.8524" for item in policy.preview_builds)
    assert {entry.version for entry in policy.special_releases} == {"26H1"}


def test_generate_policy_fails_on_release_health_26h1_without_special_note():
    with pytest.raises(PolicyParseError, match="26H1 new-devices-only special release note"):
        generate_policy(release_health_html=_without_26h1_special_note(_html()), servicing_toc_json=_toc())


def test_future_26h2_ga_chooses_26h2():
    policy = generate_policy(release_health_html=_with_26h2_ga(_html()), servicing_toc_json=_toc())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "26H2"
    assert policy.broad_target_existing_devices.build_family == 28200


def test_future_27h1_special_does_not_choose_27h1():
    policy = generate_policy(release_health_html=_with_27h1_special(_with_26h2_ga(_html())), servicing_toc_json=_toc())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "26H2"
    special = {entry.version for entry in policy.special_releases}
    assert "27H1" in special


def test_atom_feed_marks_preview_when_table_is_ambiguous():
    html = _html().replace("2026-04 D", "2026-04")
    policy = generate_policy(release_health_html=html, servicing_toc_json=_toc())
    row = next(row for row in policy.release_history if row.kb_article == "KB5083631")

    assert row.preview is True
    assert row.update_type_letter == "D"
    assert row.metadata["atom_enriched"] is True
    assert "atom_entry_id" not in row.metadata
    assert "atom_support_article_id" not in row.metadata
    assert "diagnostic_id_hint" not in row.metadata
    assert row.kb_url == (
        "https://support.microsoft.com/en-us/servicing/os/windows-11/"
        "2026/04/april-30-2026-kb5083631-os-builds-26200-8328-and-26100-8328-preview"
    )
    assert row.catalog_url == "https://www.catalog.update.microsoft.com/Search.aspx?q=KB5083631"


def test_atom_feed_marks_oob_when_table_is_ambiguous():
    policy = generate_policy(release_health_html=_with_oob_row(_html()), servicing_toc_json=_toc())
    row = next(row for row in policy.release_history if row.kb_article == "KB5089550")

    assert row.out_of_band is True
    assert row.update_type_letter == "OOB"
    assert row.metadata["atom_enriched"] is True
    assert any(item["kb_article"] == "KB5089550" for item in policy.out_of_band_builds)


def test_source_diagnostics_notice_when_atom_oob_is_newer_than_release_history():
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=_toc(),
        generated_at_utc="2026-05-20T00:00:00+00:00",
    )
    diagnostics = policy.source_diagnostics
    drift = diagnostics["drift"]["atom_newer_than_release_history"]
    events = diagnostics["events"]

    assert drift[0]["build"] == "26200.8460"
    assert drift[0]["kb_article"] == "KB5089550"
    assert drift[0]["out_of_band"] is True
    assert diagnostics["drift"]["generated_after_newest_source_hours"] == 96.0
    assert any(
        event["kind"] == "atom_newer_than_release_history"
        and event["severity"] == "notice"
        and event["id"].startswith(f"{SOURCE_DIAGNOSTIC_ID_PREFIX}:")
        and event["affects_required_baseline"] is False
        for event in events
    )
    assert not any(event["kind"] == "source_drift_unresolved_after_24h" for event in events)
    assert not any("Servicing index shows a newer non-preview build" in warning for warning in policy.validation_warnings)


def test_source_diagnostics_notice_when_atom_preview_is_newer_than_release_history():
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=_toc_with_new_preview_release(),
        generated_at_utc="2026-06-10T00:00:00+00:00",
    )
    events = policy.source_diagnostics["events"]

    event = next(
        event
        for event in events
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8461"
    )
    assert event["severity"] == "notice"
    assert event["release"] == "25H2"
    assert event["kb_article"] == "KB5089601"
    assert event["affects_broad_target"] is True
    assert event["affects_required_baseline"] is False
    assert not any("newer non-preview build for the broad target" in warning for warning in policy.validation_warnings)


def test_source_diagnostics_notice_when_atom_newer_is_not_broad_target() -> None:
    toc = json.dumps(
        {
            "items": [
                {
                    "toc_title": "June 9, 2026-KB5089602 (OS Build 28000.2114)",
                    "href": "2026/06/june-9-2026-kb5089602-os-build-28000-2114",
                },
            ]
        }
    )
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=toc,
        generated_at_utc="2026-06-10T00:00:00+00:00",
    )

    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "28000.2114"
    )
    assert event["severity"] == "notice"
    assert event["release"] == "26H1"
    assert event["affects_broad_target"] is False
    assert event["affects_required_baseline"] is False
    assert not any("newer non-preview build for the broad target" in warning for warning in policy.validation_warnings)


def test_source_diagnostics_notice_when_atom_build_family_has_no_release_mapping() -> None:
    toc = json.dumps(
        {
            "items": [
                {
                    "toc_title": "June 9, 2026-KB5089603 (OS Build 29999.1000)",
                    "href": "2026/06/june-9-2026-kb5089603-os-build-29999-1000",
                },
            ]
        }
    )
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=toc,
        generated_at_utc="2026-06-10T00:00:00+00:00",
    )

    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "29999.1000"
    )
    assert event["severity"] == "notice"
    assert event["release"] is None
    assert event["build_family"] == 29999
    assert event["affects_broad_target"] is False
    assert event["affects_required_baseline"] is False


def test_source_diagnostics_warn_when_atom_has_newer_b_release_for_broad_target():
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=_toc_with_new_b_release(),
        generated_at_utc="2026-06-10T00:00:00+00:00",
    )
    events = policy.source_diagnostics["events"]

    event = next(
        event
        for event in events
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8461"
    )
    assert event["severity"] == "warning"
    assert event["release"] == "25H2"
    assert event["affects_broad_target"] is True
    assert event["affects_required_baseline"] is True
    assert re.fullmatch(r"wrg-source-diagnostic-v1:[0-9a-f]{16}", event["id"])
    assert any("newer non-preview build for the broad target" in warning for warning in policy.validation_warnings)


def test_kb5094126_multi_build_atom_events_get_unique_diagnostic_ids() -> None:
    policy = _kb5094126_fixture_policy()
    events = [
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history"
        and event["kb_article"] == "KB5094126"
        and event["build"] in {"26100.8655", "26200.8655"}
    ]

    assert [(event["severity"], event["release"], event["build"]) for event in events] == [
        ("notice", "24H2", "26100.8655"),
        ("warning", "25H2", "26200.8655"),
    ]
    ids = [event["id"] for event in events]
    assert len(set(ids)) == len(ids)

    notice = next(event for event in events if event["build"] == "26100.8655")
    warning = next(event for event in events if event["build"] == "26200.8655")
    assert is_source_diagnostic_id(warning["id"])
    assert is_source_diagnostic_id(notice["id"])
    assert notice["id"] != warning["id"]
    for event in (notice, warning):
        assert "atom_entry_id" not in event
        assert "atom_support_article_id" not in event
        assert event["support_url"] == KB5094126_SUPPORT_URL
        assert event["source_url"] == KB5094126_SUPPORT_URL
    validate_policy_document(policy.to_dict())


def test_kb5094126_dashboard_rows_and_visible_export_ids_are_unique(tmp_path: Path) -> None:
    policy = _kb5094126_fixture_policy()
    written = write_policy_outputs(policy, output_dir=tmp_path, write_index=True, write_manifest=True)
    index = written["index"].read_text(encoding="utf-8")
    row_ids = re.findall(
        r'data-diagnostic-id="(wrg-source-diagnostic-v1:(?:[0-9a-f]{16}|uuid:[0-9a-f-]{36};id=[1-9][0-9]*))"',
        index,
    )
    event_ids = [
        event["id"]
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history"
    ]

    assert len(set(row_ids)) == len(row_ids)
    assert set(event_ids) <= set(row_ids)
    assert event_ids and all(is_source_diagnostic_id(event_id) for event_id in event_ids)
    assert "function visibleDiagnosticEntries()" in index
    assert "diagnostic_id:row.getAttribute('data-diagnostic-id')||''" in index

    export_like_ids = [
        match.group(1)
        for match in re.finditer(
            r'<article class="diag-row [^"]+" data-diagnostic-severity="[^"]+" '
            r'data-diagnostic-id="([^"]+)"',
            index,
        )
    ]
    assert export_like_ids == row_ids
    assert len(set(export_like_ids)) == len(export_like_ids)


def test_applies_to_release_mismatch_blocks_support_summary_but_not_msrc_security() -> None:
    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        assert url == KB5094126_SUPPORT_URL
        return _support_article_html(
            applies_to="Windows 11, version 24H2",
            builds=("26200.8655",),
            security=True,
        )

    def msrc_fetcher(url: str, timeout: float, max_bytes: int) -> dict[str, object]:
        return FAKE_MSRC_CVRF_WITH_KB5094126

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        servicing_toc_json=_kb5094126_toc_fixture(),
        generated_at_utc="2026-06-11T00:00:00+00:00",
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )

    event = next(
        item
        for item in policy.source_diagnostics["events"]
        if item.get("kind") == "atom_newer_than_release_history"
        and item.get("release") == "25H2"
        and item.get("build") == "26200.8655"
    )

    assert event["support_article_validation_status"] == "mismatch"
    assert event["support_article_validation_reasons"] == ["applies_to_mismatch"]
    assert event["is_security"] is True
    assert event["security_evidence_source"] == "msrc_cvrf"
    assert "support_article_title" not in event
    assert "support_article_improvement_labels" not in event
    assert "Secure Boot" not in str(event.get("user_message") or "")
    assert "Secure Boot" not in str(event.get("summary") or "")


def test_support_article_enrichment_adds_diagnostic_context_and_dashboard_summary() -> None:
    fetched: list[tuple[str, float, int]] = []

    def fetcher(url: str, timeout: float, max_bytes: int) -> str:
        fetched.append((url, timeout, max_bytes))
        return KB5094126_SUPPORT_HTML

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        servicing_toc_json=_kb5094126_toc_fixture(),
        support_article_fetcher=fetcher,
        support_article_timeout=3.5,
    )

    assert fetched == [(KB5094126_SUPPORT_URL, 3.5, policy_generator_module.DEFAULT_MAX_SUPPORT_ARTICLE_BYTES)]
    article = policy.source_diagnostics["support_articles"][KB5094126_SUPPORT_URL]
    assert article["status"] == "ok"
    assert article["kb_article"] == "KB5094126"
    assert article["builds"] == ["26200.8655", "26100.8655"]
    assert article["is_security"] is True
    assert article["security_evidence_source"] == "support_article"
    assert article["improvement_labels"] == ["Secure Boot", "Virtualization", "desktop.ini", "AI components"]

    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8655"
    )
    assert event["support_article_status"] == "ok"
    assert event["support_article_title"] == "June 9, 2026-KB5094126 (OS Builds 26200.8655 and 26100.8655)"
    assert event["support_article_known_issue_status"] == "not_currently_aware"
    assert event["support_article_improvement_labels"] == [
        "Secure Boot",
        "Virtualization",
        "desktop.ini",
        "AI components",
    ]
    assert event["is_security"] is True
    assert event["security_evidence_source"] == "support_article"
    assert event["user_message"] == (
        "Microsoft published KB5094126 for Windows 11 25H2 build 26200.8655. This looks like the next "
        "stable broad-fleet baseline candidate, but this policy waits for Release Health baseline "
        "rules before requiring it (security update, June 2026); "
        "public notes mention Secure Boot, Virtualization, desktop.ini, and AI components."
    )

    index = policy_generator_module.render_policy_index(policy, policy_bytes=None, signature=None)
    assert event["user_message"] in index
    assert "Servicing index shows a newer non-preview build for the broad target" in index
    validate_policy_document(policy.to_dict())


def test_support_article_kb_mismatch_does_not_contaminate_summary_or_security() -> None:
    policy = _kb5094126_policy_with_support_html(
        _support_article_html(kb_article="KB5000000", builds=("26200.1111",), security=True)
    )

    event = _kb5094126_atom_event(policy)
    assert event["support_article_validation_status"] == "mismatch"
    assert event["support_article_validation_reasons"] == ["kb_mismatch", "build_missing"]
    assert event["support_article_expected_kb"] == "KB5094126"
    assert event["support_article_expected_build"] == "26200.8655"
    assert event["support_article_expected_release"] == "25H2"
    assert event["kb_article"] == "KB5094126"
    assert event["build"] == "26200.8655"
    assert "support_article_kb_article" not in event
    assert "support_article_title" not in event
    assert event.get("user_message") is None
    assert event["is_security"] is None
    assert event["security_evidence_source"] == "unavailable"
    assert event["support_article_status"] == "ok"
    assert "Security patch" not in policy_generator_module._source_diagnostic_row_from_event(event)["tags"]

    summaries = [
        str(item.get("user_message") or item.get("notice_summary") or "")
        for item in policy.source_diagnostics["events"]
    ]
    assert all("KB5000000" not in summary for summary in summaries)
    mismatch = next(
        item for item in policy.source_diagnostics["events"] if item["kind"] == "support_article_enrichment_mismatch"
    )
    assert mismatch["severity"] == "warning"
    assert mismatch["support_article_validation_reasons"] == ["kb_mismatch", "build_missing"]
    article = policy.source_diagnostics["support_articles"][KB5094126_SUPPORT_URL]
    assert article["support_article_validation_status"] == "mismatch"
    assert article["security_evidence_source"] == "unavailable"
    assert "security_signals" not in article
    validate_policy_document(policy.to_dict())


def test_support_article_build_mismatch_is_not_validation_ok() -> None:
    policy = _kb5094126_policy_with_support_html(
        _support_article_html(kb_article="KB5094126", builds=("26200.1111",), security=True)
    )

    event = _kb5094126_atom_event(policy)
    assert event["support_article_validation_status"] == "mismatch"
    assert event["support_article_validation_reasons"] == ["build_missing"]
    assert event["support_article_expected_build"] == "26200.8655"
    assert "support_article_builds" not in event
    assert event["is_security"] is None
    assert event["security_evidence_source"] == "unavailable"
    assert event.get("user_message") is None


def test_support_article_incompatible_applies_to_is_visible_but_untrusted() -> None:
    policy = _kb5094126_policy_with_support_html(
        _support_article_html(
            kb_article="KB5094126",
            builds=("26200.8655",),
            applies_to="Windows 10, version 22H2",
            security=True,
        )
    )

    event = _kb5094126_atom_event(policy)
    assert event["support_article_validation_status"] == "mismatch"
    assert event["support_article_validation_reasons"] == ["applies_to_mismatch"]
    assert event["support_article_applies_to"] == "Windows 10, version 22H2"
    assert event["support_article_expected_release"] == "25H2"
    assert event["is_security"] is None
    assert event["security_evidence_source"] == "unavailable"
    assert event.get("user_message") is None


def test_support_article_partial_compatible_article_is_degraded_atom_grounded_summary() -> None:
    policy = _kb5094126_policy_with_support_html(
        _support_article_html(
            kb_article="KB5094126",
            builds=(),
            applies_to="Windows 11, version 25H2",
            security=False,
            labels=(),
        )
    )

    event = _kb5094126_atom_event(policy)
    assert event["support_article_validation_status"] == "degraded"
    assert event["support_article_validation_reasons"] == ["builds_missing"]
    assert event["support_article_expected_kb"] == "KB5094126"
    assert event["support_article_expected_build"] == "26200.8655"
    assert event["support_article_title"] == "June 9, 2026-KB5094126"
    assert "support_article_builds" not in event
    assert event["is_security"] is None
    assert event["security_evidence_source"] == "unavailable"
    assert event["user_message"] == (
        "Microsoft published KB5094126 for Windows 11 25H2 build 26200.8655. This looks like the next "
        "stable broad-fleet baseline candidate, but this policy waits for Release Health baseline "
        "rules before requiring it (Windows update, June 2026); "
        "support article validation degraded: builds_missing."
    )
    assert "KB5000000" not in event["user_message"]
    degraded = next(
        item for item in policy.source_diagnostics["events"] if item["kind"] == "support_article_enrichment_degraded"
    )
    assert degraded["support_article_validation_reasons"] == ["builds_missing"]


def test_kb5094126_generated_output_when_release_health_has_not_caught_up(tmp_path: Path) -> None:
    policy = _kb5094126_generated_fixture_policy(_html_file("windows11-release-health-current-d-26h1.html"))
    outputs = _generated_output_bundle(policy, tmp_path)
    data = outputs["policy"]
    manifest = outputs["manifest"]
    index = str(outputs["index"])
    assert isinstance(data, dict)
    assert isinstance(manifest, dict)
    _assert_unique_source_diagnostic_ids(data, index)
    _assert_no_raw_support_article_leakage(outputs, _kb5094126_support_fixture())

    target = data["broad_target_existing_devices"]
    assert isinstance(target, dict)
    assert target["version"] == "25H2"
    assert target["latest_build"] == "26200.8524"
    assert target["latest_observed_build"] == "26200.8655"
    assert target["required_baseline_build"] == "26200.8457"
    assert target["metadata"]["latest_observed_source"] == "atom_support_article"
    assert target["metadata"]["latest_observed_source_url"] == KB5094126_SUPPORT_URL
    assert manifest["broad_target_existing_devices"]["latest_build"] == "26200.8524"
    assert manifest["broad_target_existing_devices"]["latest_observed_build"] == "26200.8655"
    assert manifest["broad_target_existing_devices"]["required_baseline_build"] == "26200.8457"
    assert manifest["latest_observed_evidence"]["latest_observed_source"] == "atom_support_article"

    events = data["source_diagnostics"]["events"]
    atom_events = [
        event
        for event in events
        if event["kind"] == "atom_newer_than_release_history"
        and event["kb_article"] == "KB5094126"
        and event["build"] in {"26100.8655", "26200.8655"}
    ]
    assert [(event["severity"], event["release"], event["build"]) for event in atom_events] == [
        ("notice", "24H2", "26100.8655"),
        ("warning", "25H2", "26200.8655"),
    ]
    notice = next(event for event in atom_events if event["release"] == "24H2")
    warning = next(event for event in atom_events if event["release"] == "25H2")
    assert is_source_diagnostic_id(warning["id"])
    assert is_source_diagnostic_id(notice["id"])
    assert notice["id"] != warning["id"]
    assert warning["support_article_validation_status"] == "ok"
    assert notice["support_article_validation_status"] == "ok"
    assert warning["id"] in _rendered_diagnostic_ids(index)
    assert "https://support.microsoft.com/help/5094126" not in index


def test_kb5094126_generated_output_when_release_health_has_caught_up(tmp_path: Path) -> None:
    policy = _kb5094126_generated_fixture_policy(_release_health_caught_up_to_kb5094126())
    outputs = _generated_output_bundle(policy, tmp_path)
    data = outputs["policy"]
    manifest = outputs["manifest"]
    index = str(outputs["index"])
    assert isinstance(data, dict)
    assert isinstance(manifest, dict)
    _assert_unique_source_diagnostic_ids(data, index)
    _assert_no_raw_support_article_leakage(outputs, _kb5094126_support_fixture())

    target = data["broad_target_existing_devices"]
    assert isinstance(target, dict)
    assert target["latest_build"] == "26200.8655"
    assert target["latest_observed_build"] == "26200.8655"
    assert target["required_baseline_build"] == "26200.8655"
    assert manifest["broad_target_existing_devices"]["latest_build"] == "26200.8655"
    assert manifest["broad_target_existing_devices"]["latest_observed_build"] == "26200.8655"
    assert manifest["broad_target_existing_devices"]["required_baseline_build"] == "26200.8655"

    events = data["source_diagnostics"]["events"]
    assert not any(
        event["kind"] == "atom_newer_than_release_history"
        and event.get("release") == "25H2"
        and event.get("build") == "26200.8655"
        for event in events
    )
    assert "Servicing index shows a newer non-preview build for the broad target" not in index


def test_caught_up_kb5094126_renders_baseline_update_notice_before_operational_panels(tmp_path: Path) -> None:
    policy = _kb5094126_generated_fixture_policy(_release_health_caught_up_to_kb5094126())
    outputs = _generated_output_bundle(policy, tmp_path)
    index = str(outputs["index"])
    data = outputs["policy"]
    assert isinstance(data, dict)
    HTMLParser().feed(index)

    notice_marker = 'class="panel span-12 baseline-update-notice"'
    freshness_marker = 'id="live-freshness-panel"'
    diagnostics_marker = 'class="panel span-7 source-diagnostics"'
    assert notice_marker in index
    assert index.index(notice_marker) < index.index(freshness_marker)
    assert index.index(notice_marker) < index.index(diagnostics_marker)
    assert 'class="grid dashboard-grid has-baseline-notice"' in index
    assert 'role="status" aria-live="polite" data-baseline-notice="active"' in index
    assert 'data-baseline-notice-build="26200.8655"' in index
    assert 'data-baseline-notice-kb="KB5094126"' in index
    assert 'data-baseline-notice-visible-until="2026-06-23T00:00:00Z"' in index
    assert f'data-baseline-notice-source-url="{KB5094126_SUPPORT_URL}"' in index
    assert 'data-baseline-notice-security-url="https://msrc.microsoft.com/update-guide"' in index
    assert "New required baseline: 25H2 build 26200.8655" in index
    assert "KB5094126" in index
    assert "2026-06 B" in index
    assert "Security confirmed by MSRC" in index
    assert "MSRC CVE entries: 2" not in index
    assert "data-cves=" not in index
    assert "data-cve-count=" not in index
    assert (
        '<div class="baseline-review"><span class="baseline-review-label">Update highlights:</span>'
        '<ul class="baseline-review-list"><li>Secure Boot: Updates hardening for startup components.</li>'
        '<li>Virtualization: Improves reliability for protected workloads.</li>'
        '<li>desktop.ini: Hardens desktop.ini processing.</li>'
        '<li>AI components: Updates Windows AI components.</li></ul>'
        f' <a class="baseline-read-more" href="{KB5094126_SUPPORT_URL}" '
        'rel="noopener noreferrer">Read more</a></div>'
    ) in index
    assert "Atom first spotted June 9, 2026 at 02:00 CEST / 00:00 UTC" in index
    assert "Support updated June 9, 2026 at 02:00 CEST / 00:00 UTC" in index
    assert "Official baseline date: 2026-06-09 (Release Health date-only)" in index
    assert "Visible until" not in index
    assert "For broad-fleet 25H2 devices, this likely marks the stable rollout floor" in index
    assert "Security evidence:" not in index
    assert "Atom first spotted 2026-06-09T00:00:00Z" not in index
    assert "Support updated 2026-06-09T00:00:00Z" not in index
    assert "update-guide/vulnerability/CVE-2026-0001" not in index
    assert "baseline update notice timer" in index
    assert "Date.parse(until)" in index
    assert "grid.classList.remove('has-baseline-notice')" in index
    assert "baseline update notice timer','dashboard grid" in index
    assert ".baseline-update-notice{position:relative" in index
    assert '<span class="baseline-chip">KB5094126</span>' in index
    assert '<span class="baseline-chip security">Security confirmed by MSRC</span>' in index
    assert '<span class="baseline-chip security">MSRC CVE entries: 2</span>' not in index
    notice_html = index[
        index.index(notice_marker) : index.index(freshness_marker)
    ]
    assert notice_html.count(f'href="{KB5094126_SUPPORT_URL}"') == 1
    assert ".baseline-read-more" in index
    assert ".dashboard-grid.has-baseline-notice .baseline-update-notice{grid-column:1/-1;grid-row:1}" in index
    assert ".dashboard-grid.has-baseline-notice #live-freshness-panel{grid-row:2/span 2}" in index
    assert ".dashboard-grid.has-baseline-notice .source-diagnostics{grid-row:2/span 2}" in index
    assert ".dashboard-grid.has-baseline-notice.diagnostics-expanded .source-diagnostics{grid-row:2/span 3}" in index
    assert ".dashboard-grid.diagnostics-expanded .source-diagnostics{grid-row:1/span 3;align-self:stretch}" in index
    assert "script src" not in index.lower()
    assert "rel=\"stylesheet\"" not in index.lower()
    assert "github_token" not in index.lower()
    assert "function visibleDiagnosticEntries()" in index
    _assert_no_raw_support_article_leakage(outputs, _kb5094126_support_fixture())
    validate_policy_document(data)
