from __future__ import annotations

import json
from pathlib import Path

from win11_release_guard.policy_generator import DEFAULT_SERVICING_TOC_URL, generate_policy

FIXTURES = Path("tests/fixtures")
RETIRED_ATOM_EVENT_KINDS = {
    "atom_feed_missing",
    "atom_feed_parse_failed",
    "atom_feed_no_usable_entries",
    "atom_diagnostics_unavailable",
}
KB5101650_URL = (
    "https://support.microsoft.com/en-us/servicing/os/windows-11/"
    "2026/07/july-14-2026-kb5101650-os-builds-26200-8875-and-26100-8875"
)


def _html() -> str:
    return (FIXTURES / "windows11-release-health.html").read_text(encoding="utf-8")


def _toc() -> str:
    return (FIXTURES / "windows11-servicing-toc.json").read_text(encoding="utf-8")


def _july_toc() -> str:
    return (FIXTURES / "windows11-servicing-toc-july-2026.json").read_text(encoding="utf-8")


def _html_with_kb5101650() -> str:
    old = """      <tr>
        <td>General Availability Channel</td>
        <td>2026-05 B</td>
        <td>2026-05-12</td>
        <td>26200.8457</td>
        <td>KB5089549</td>
      </tr>"""
    new = """      <tr>
        <td>General Availability Channel</td>
        <td>2026-07 B</td>
        <td>2026-07-14</td>
        <td>26200.8875</td>
        <td>KB5101650</td>
      </tr>"""
    html = _html()
    assert old in html
    return html.replace(old, new, 1)


def _policy_from_july_toc():
    return generate_policy(
        release_health_html=_html_with_kb5101650(),
        servicing_toc_json=_july_toc(),
        generated_at_utc="2026-07-15T00:00:00+00:00",
    )


def test_default_servicing_toc_url_is_the_public_index() -> None:
    assert DEFAULT_SERVICING_TOC_URL == (
        "https://support.microsoft.com/en-us/servicing/os/windows-11/toc.json"
    )


def test_release_history_row_gets_the_canonical_servicing_kb_url() -> None:
    policy = _policy_from_july_toc()
    row = next(
        row
        for row in policy.release_history
        if row.kb_article == "KB5101650" and row.release == "25H2"
    )

    assert row.kb_url == KB5101650_URL
    assert row.metadata["atom_enriched"] is True
    assert row.metadata["atom_feed_url"] == KB5101650_URL


def test_servicing_toc_run_emits_no_retired_atom_source_events() -> None:
    policy = _policy_from_july_toc()
    kinds = {event["kind"] for event in policy.source_diagnostics["events"]}

    assert not kinds & RETIRED_ATOM_EVENT_KINDS


def test_servicing_toc_status_is_recorded_in_source_fetch_status() -> None:
    policy = _policy_from_july_toc()

    assert policy.source_fetch_status["servicing_toc"]["status"] == "ok"
    assert policy.source_fetch_status["servicing_toc"]["url"] == DEFAULT_SERVICING_TOC_URL
    assert policy.source_diagnostics["servicing_toc"]["source_url"] == DEFAULT_SERVICING_TOC_URL
    assert policy.source_diagnostics["servicing_toc"]["entry_count"] == 7
    assert DEFAULT_SERVICING_TOC_URL in policy.source_urls


def test_missing_servicing_toc_emits_exactly_one_warning() -> None:
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=None,
        generated_at_utc="2026-05-20T00:00:00+00:00",
    )
    events = [
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "servicing_toc_missing"
    ]

    assert len(events) == 1
    assert events[0]["severity"] == "warning"
    assert events[0]["affects_required_baseline"] is False
    assert any("Servicing TOC missing" in warning for warning in policy.validation_warnings)


def test_malformed_servicing_toc_is_a_structured_source_diagnostic() -> None:
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json='{"items": [',
        generated_at_utc="2026-05-20T00:00:00+00:00",
    )
    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "servicing_toc_parse_failed"
    )

    assert event["severity"] == "warning"
    assert "Servicing TOC could not be parsed" in event["message"]


def test_empty_servicing_toc_reports_no_usable_entries() -> None:
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json='{"items": []}',
        generated_at_utc="2026-05-20T00:00:00+00:00",
    )
    kinds = [event["kind"] for event in policy.source_diagnostics["events"]]

    assert "servicing_toc_no_usable_entries" in kinds
    assert "servicing_toc_missing" not in kinds


def test_lane_exact_match_beats_ambiguous_build_matching() -> None:
    shared_title = "May 12, 2026—KB5089549 (OS Builds 26200.8457 and 26100.8457)"
    payload = {
        "items": [
            {
                "toc_title": "Windows 11, version 25H2",
                "children": [
                    {"href": "2026/05/may-12-2026-kb5089549-for-25h2", "toc_title": shared_title}
                ],
            },
            {
                "toc_title": "Windows 11, version 24H2",
                "children": [
                    {"href": "2026/05/may-12-2026-kb5089549-for-24h2", "toc_title": shared_title}
                ],
            },
        ]
    }
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=json.dumps(payload),
        generated_at_utc="2026-05-20T00:00:00+00:00",
    )
    row_25h2 = next(
        row for row in policy.release_history if row.release == "25H2" and row.kb_article == "KB5089549"
    )
    row_24h2 = next(
        row for row in policy.release_history if row.release == "24H2" and row.kb_article == "KB5089549"
    )

    assert row_25h2.kb_url.endswith("2026/05/may-12-2026-kb5089549-for-25h2")
    assert row_24h2.kb_url.endswith("2026/05/may-12-2026-kb5089549-for-24h2")


def test_lane_entry_that_excludes_the_row_build_does_not_enrich_it() -> None:
    payload = {
        "items": [
            {
                "toc_title": "Windows 11, version 25H2",
                "children": [
                    {
                        "href": "2026/05/may-12-2026-kb5089549-wrong-build",
                        "toc_title": "May 12, 2026—KB5089549 (OS Build 26200.9999)",
                    }
                ],
            }
        ]
    }
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=json.dumps(payload),
        generated_at_utc="2026-05-20T00:00:00+00:00",
    )
    row = next(
        row for row in policy.release_history if row.release == "25H2" and row.build == "26200.8457"
    )

    assert row.kb_url is None or not row.kb_url.endswith("wrong-build")
    assert row.metadata.get("atom_enriched") is not True


def test_servicing_drift_event_resolves_the_msrc_month() -> None:
    policy = _policy_from_july_toc()
    drift = [
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history"
    ]

    assert drift
    assert all(event["msrc_cvrf_month_id"] == "2026-Jul" for event in drift)


from tools import generate_policy as generate_policy_cli


def test_generator_cli_exposes_servicing_toc_flags_only() -> None:
    help_text = generate_policy_cli._build_parser().format_help()

    assert "--servicing-toc-url" in help_text
    assert "--servicing-toc " in help_text
    assert "--atom-feed" not in help_text


def test_generator_cli_writes_policy_from_the_servicing_toc_fixture(tmp_path) -> None:
    output_dir = tmp_path / "site"

    code = generate_policy_cli.main([
        "--release-health-html",
        str(FIXTURES / "windows11-release-health.html"),
        "--servicing-toc",
        str(FIXTURES / "windows11-servicing-toc.json"),
        "--output-dir",
        str(output_dir),
        "--write-manifest",
    ])

    assert code == 0
    policy = json.loads((output_dir / "windows-release-policy.json").read_text(encoding="utf-8"))
    assert policy["source_diagnostics"]["servicing_toc"]["status"] == "ok"
    assert not any("feed/atom" in url for url in policy["source_urls"])
    assert "atom_feed" not in policy["source_fetch_status"]
