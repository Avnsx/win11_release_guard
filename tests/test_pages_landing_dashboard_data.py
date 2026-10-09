from __future__ import annotations

from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
import re
from win11_release_guard.models import ReleasePolicy
from win11_release_guard.policy_generator import assembly as generator_assembly
from win11_release_guard.policy_generator.pages import dashboard as generator_dashboard
from win11_release_guard.policy_generator import render_policy_index
from tests.support.pages_landing_helpers import (
    FRESHNESS_SCRIPT_RE,
    REMOVED_SCHEMA_PANEL_LABELS,
    _assert_diag_count_tile,
    _diag_row_marker,
    _diagnostic_ids,
    _freshness_data,
)


def test_pages_index_source_diagnostics_rows_sort_by_severity_priority() -> None:
    policy = ReleasePolicy(
        source_diagnostics={
            "event_counts": {"notice": 1, "warning": 1, "error": 1},
            "events": [
                {
                    "severity": "notice",
                    "kind": "policy_feed_current",
                    "message": "Notice should render after blocking diagnostics.",
                },
                {
                    "severity": "warning",
                    "kind": "atom_newer_than_release_history",
                    "message": "Warning should render before notices.",
                },
                {
                    "severity": "error",
                    "kind": "release_health_parser_failed",
                    "message": "Error should render first.",
                },
            ],
        }
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert index.index("Release Health Parser Failed") < index.index("Microsoft update spotted")
    assert index.index("Microsoft update spotted") < index.index("Policy Feed Current")
    rendered_severities = re.findall(
        r'<article class="diag-row (notice|warning|error)" data-diagnostic-severity="(?:notice|warning|error)"',
        index,
    )
    assert rendered_severities[:3] == ["error", "warning", "notice"]
    assert index.count(_diag_row_marker("error")) == 1
    assert index.count(_diag_row_marker("warning")) == 1
    assert index.count(_diag_row_marker("notice")) == 1
    _assert_diag_count_tile(index, "error", 1, "Errors")
    _assert_diag_count_tile(index, "warning", 1, "Warnings")
    _assert_diag_count_tile(index, "notice", 1, "Notices")


def test_pages_index_source_diagnostics_warning_error_counts_suppress_clear_placeholder() -> None:
    policy = ReleasePolicy(
        source_diagnostics={"event_counts": {"notice": 0, "warning": 2, "error": 1}},
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert "No source issues reported" not in index
    _assert_diag_count_tile(index, "notice", 0, "Notices")
    _assert_diag_count_tile(index, "warning", 1, "Warnings")
    _assert_diag_count_tile(index, "error", 1, "Errors")
    assert index.count(_diag_row_marker("warning")) == 1
    assert index.count(_diag_row_marker("error")) == 1
    assert "2 warning diagnostic entries reported without structured row details." in index
    assert "1 error diagnostic entry reported without structured row details." in index


def test_pages_index_renderer_tolerates_sparse_legacy_policy() -> None:
    policy = ReleasePolicy(
        generated_at_utc=None,
        source_urls=("https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information?probe=<unsafe>",),
        generator_version=None,
        source_diagnostics={
            "event_counts": {"notice": "3", "warning": "not-a-number", "error": -1},
            "release_health_html": {"bytes": "not-a-number"},
        },
        validation_warnings=("Rendered warning <without raw html>",),
        min_reader_schema_version=None,
        max_reader_schema_version=None,
        api_version=None,
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert "Windows 11 Release Guard" in index
    assert "unknown" in index
    assert "unavailable" in index
    assert "not attached" in index
    assert "API version" not in index
    assert "<h2>Sources</h2>" not in index
    assert "sources-panel" not in index
    assert "source-health" in index
    assert "source-tile unknown" in index
    for removed_label in REMOVED_SCHEMA_PANEL_LABELS:
        assert removed_label not in index
    assert "No existing-device exclusions" not in index
    assert "1</strong><span>Notices" in index
    assert "1</strong><span>Warnings" in index
    assert "0</strong><span>Errors" in index
    assert "3 notice diagnostic entries reported without structured row details." in index
    assert "Rendered warning &lt;without raw html&gt;" in index
    assert 'class="grid dashboard-grid has-validation-warnings"' in index
    assert 'class="panel span-12 dashboard-warning-panel"' in index
    assert index.index('class="panel span-12 dashboard-warning-panel"') < index.index('id="live-freshness-panel"')
    assert index.index('class="panel span-12 dashboard-warning-panel"') < index.index('class="panel span-7 source-diagnostics"')
    assert ".dashboard-grid.has-validation-warnings .dashboard-warning-panel{grid-column:1/-1;grid-row:1}" in index
    assert ".dashboard-grid.has-validation-warnings #live-freshness-panel{grid-row:2/span 2}" in index
    assert ".dashboard-grid.has-validation-warnings .source-diagnostics{grid-row:2/span 2}" in index
    assert "&lt;unsafe&gt;" in index
    assert FRESHNESS_SCRIPT_RE.search(index) is not None
    assert "script src" not in index.lower()


def test_pages_index_source_health_tiles_are_integrated_and_status_colored() -> None:
    release_health_url = "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information"
    atom_url = "https://support.microsoft.com/en-us/feed/atom/4ec863cc-2ecd-e187-6cb3-b50c6545db92"
    policy = ReleasePolicy(
        source_urls=(release_health_url, atom_url),
        source_diagnostics={
            "event_counts": {"notice": 0, "warning": 0, "error": 0},
            "release_health_html": {
                "status": "ok",
                "fetched_at_utc": "2026-06-04T12:00:00+00:00",
                "bytes": 4096,
            },
            "atom_feed": {
                "status": "error",
                "fetched_at_utc": "2026-06-04T12:01:00+00:00",
                "bytes": 0,
            },
        },
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert "<h2>Sources</h2>" not in index
    assert "sources-panel" not in index
    assert "Source health" in index
    assert index.find("Source diagnostics") < index.find("Source health")
    assert 'class="source-tile ok"' in index
    assert 'class="source-status ok">ok</span>' in index
    assert 'class="source-tile error"' in index
    assert 'class="source-status error">error</span>' in index
    assert "Microsoft Release Health" in index
    assert "Microsoft Atom feed" in index
    assert "4.0 KiB" in index
    assert "Thursday, 4 June 2026, 12:00:00 UTC" in index
    assert "Thursday, 4 June 2026, 12:01:00 UTC" in index
    assert 'data-epoch="1780574400000"' in index
    assert 'data-epoch="1780574460000"' in index
    assert 'aria-label="Copy Microsoft Release Health UTC epoch millisecond timestamp 1780574400000"' in index
    assert 'aria-label="Copy Microsoft Atom feed UTC epoch millisecond timestamp 1780574460000"' in index


def test_pages_index_source_health_tiles_support_warning_status() -> None:
    atom_url = "https://support.microsoft.com/en-us/feed/atom/4ec863cc-2ecd-e187-6cb3-b50c6545db92"
    policy = ReleasePolicy(
        source_urls=(atom_url,),
        source_diagnostics={
            "event_counts": {"notice": 0, "warning": 0, "error": 0},
            "atom_feed": {
                "status": "warning",
                "fetched_at_utc": "2026-06-04T12:01:00+00:00",
                "bytes": 2048,
            },
        },
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert 'class="source-tile warning"' in index
    assert 'class="source-status warning">warning</span>' in index
    assert "2.0 KiB" in index


def test_pages_index_epoch_copy_buttons_preserve_milliseconds() -> None:
    release_health_url = "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information"
    atom_url = "https://support.microsoft.com/en-us/feed/atom/4ec863cc-2ecd-e187-6cb3-b50c6545db92"
    policy = ReleasePolicy(
        generated_at_utc="2026-06-04T12:00:00.123+00:00",
        source_urls=(release_health_url, atom_url),
        source_diagnostics={
            "event_counts": {"notice": 0, "warning": 0, "error": 0},
            "release_health_html": {
                "status": "ok",
                "fetched_at_utc": "2026-06-04T12:00:00.321+00:00",
                "bytes": 4096,
            },
            "atom_feed": {
                "status": "ok",
                "fetched_at_utc": "2026-06-04T12:00:00.654+00:00",
                "bytes": 2048,
            },
        },
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert 'data-epoch="1780574400123"' in index
    assert 'data-epoch="1780574400321"' in index
    assert 'data-epoch="1780574400654"' in index
    assert "epoch millisecond timestamp" in index
    assert "Thursday, 4 June 2026, 12:00:00 UTC" in index


def test_pages_index_does_not_emit_release_link_for_invalid_program_version(monkeypatch) -> None:
    monkeypatch.setattr(generator_assembly, "GENERATOR_VERSION", "win11_release_guard/not-a-version<script>")
    monkeypatch.setattr(generator_dashboard, "GENERATOR_VERSION", "win11_release_guard/not-a-version<script>")

    index = render_policy_index(ReleasePolicy(), policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert "Program Version" in index
    assert "releases/tag/vnot-a-version" not in index
    assert "not-a-version&lt;script&gt;" in index
    assert index.lower().count("<script") == 2
    assert "script src" not in index.lower()


def test_pages_index_escapes_freshness_json_script_payload() -> None:
    policy = ReleasePolicy(
        generated_at_utc='2026-05-31T14:11:50+00:00</script><script src="https://cdn.example/x.js">',
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert index.lower().count("<script") == 2
    assert "<script src" not in index.lower()
    freshness = _freshness_data(index)
    assert freshness["generated_at_utc"].startswith("2026-05-31T14:11:50+00:00</script>")
    assert freshness["generated_at_epoch_s"] is None


def test_pages_index_source_diagnostics_escape_event_message_without_script_injection() -> None:
    policy = ReleasePolicy(
        source_diagnostics={
            "event_counts": {"warning": 1},
            "events": [
                {
                    "severity": "warning",
                    "kind": "parser_warning",
                    "message": 'Parser saw <script src="https://cdn.example/x.js"> bad markup.',
                }
            ],
        }
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert "Parser Warning" in index
    assert "Parser saw &lt;script src=&quot;https://cdn.example/x.js&quot;&gt; bad markup." in index
    diagnostic_ids = _diagnostic_ids(index)
    assert diagnostic_ids
    assert all(diagnostic_id.startswith("wrg-source-diagnostic-v1:") for diagnostic_id in diagnostic_ids)
    assert "<script src" not in index.lower()
    assert index.lower().count("<script") == 2


def test_pages_index_source_diagnostics_collapses_overflow_events() -> None:
    events = [
        {
            "severity": "notice",
            "kind": "atom_newer_than_release_history",
            "build": f"26200.84{index}",
            "message": f"Notice event {index}",
        }
        for index in range(7)
    ]
    policy = ReleasePolicy(
        source_diagnostics={
            "event_counts": {"notice": 7, "warning": 0, "error": 0},
            "events": events,
        }
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert "8</strong><span>Notices" in index
    assert index.count(_diag_row_marker("notice")) == 8
    assert "+2 more" in index
    assert "Notice event 0" in index
    assert "Notice event 6" in index


def test_pages_index_source_diagnostics_include_stale_freshness_row() -> None:
    policy = ReleasePolicy(generated_at_utc="2000-01-01T00:00:00+00:00")

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert "Policy feed stale" in index
    assert "Policy feed currency" in index
    assert "Published policy feed is stale at render time." in index
    assert "Date.now" in index


def test_pages_index_embeds_feed_currency_thresholds_for_current_refresh_due_and_stale_dates() -> None:
    reference = datetime(2026, 6, 4, 12, 0, tzinfo=timezone.utc)
    for age_days in (0, 15, 46):
        generated = (reference - timedelta(days=age_days)).isoformat()
        index = render_policy_index(ReleasePolicy(generated_at_utc=generated), policy_bytes=None, signature=None)
        freshness = _freshness_data(index)

        assert freshness["generated_at_epoch_s"] == int((reference - timedelta(days=age_days)).timestamp())
        assert freshness["warn_after_epoch_s"] - freshness["generated_at_epoch_s"] == 14 * 24 * 60 * 60
        assert freshness["stale_after_epoch_s"] - freshness["generated_at_epoch_s"] == 45 * 24 * 60 * 60
        assert freshness["strict_stale_after_epoch_s"] == freshness["stale_after_epoch_s"]
        assert "Current" in index
        assert "Refresh Due" in index
        assert "Stale" in index


def test_pages_index_release_link_tracks_future_program_versions(monkeypatch) -> None:
    monkeypatch.setattr(generator_assembly, "GENERATOR_VERSION", "win11_release_guard/1.2.3")
    monkeypatch.setattr(generator_dashboard, "GENERATOR_VERSION", "win11_release_guard/1.2.3")

    index = render_policy_index(ReleasePolicy(), policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert 'href="https://github.com/Avnsx/win11_release_guard/releases/tag/v1.2.3"' in index
    assert "GitHub release tag" not in index
    assert '<div class="title-line"><h1>Windows 11 Release Guard</h1></div>' in index
    assert '<div class="subtitle-line"><p class="subtitle">Broad-fleet Windows 11 release and quality baseline dashboard.</p></div>' in index
    assert index.index('class="header-nav"') < index.index('class="title-version-link')
    assert index.index('class="subtitle"') < index.index('class="title-version-link')
    assert "Program Version</span> 1.2.3</a>" in index
