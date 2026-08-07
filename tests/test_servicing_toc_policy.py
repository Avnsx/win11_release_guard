from __future__ import annotations

import json
from pathlib import Path

import pytest

from win11_release_guard.policy_generator import (
    DEFAULT_SERVICING_TOC_URL,
    build_policy_from_sources,
    generate_policy,
)

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


def test_preview_and_out_of_band_servicing_entries_do_not_update_latest_observed() -> None:
    """The July fixture also lists a preview build (KB5101684, 26200.8973)
    and an out-of-band build (KB5121767, 26200.8894), both numerically newer
    than the KB5101650 baseline (26200.8875) that latest_observed_build does
    track. Preview/out-of-band servicing entries must never advance
    latest_observed_build past the newest normal (non-preview,
    non-out-of-band) match.
    """
    policy = _policy_from_july_toc()

    target = policy.broad_target_existing_devices
    assert target is not None
    assert target.latest_observed_build == "26200.8875"
    assert target.metadata["latest_observed_kb_article"] == "KB5101650"


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


def test_servicing_toc_dedupe_prefers_the_newest_updated_record() -> None:
    """`_atom_drift_record_is_preferred` has three tie-break levels: newest
    `updated` wins; else lowest `atom_entry_id`; else lexicographic title/url.
    Servicing-toc-derived entries never set `atom_entry_id`, so level 2 is
    permanently dead for this source and level 1 (date) is the only live,
    reachable tie-break. Two servicing-toc entries can legitimately share the
    same KB and build with different dates (e.g. a corrected/republished
    article), so this proves level 1 still selects the newer record - not
    merely that the duplicate pair collapses to a single event.
    """
    older_title = "June 9, 2026-KB5099001 (OS Build 30000.100)"
    newer_title = "June 20, 2026-KB5099001 (OS Build 30000.100)"
    toc = json.dumps(
        {
            "items": [
                {
                    "toc_title": older_title,
                    "href": "2026/06/june-9-2026-kb5099001-os-build-30000-100",
                },
                {
                    "toc_title": newer_title,
                    "href": "2026/06/june-20-2026-kb5099001-os-build-30000-100",
                },
            ]
        }
    )

    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=toc,
        generated_at_utc="2026-06-21T00:00:00+00:00",
    )
    events = [
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history"
        and event["kb_article"] == "KB5099001"
        and event["build"] == "30000.100"
    ]

    assert len(events) == 1
    event = events[0]
    # These assertions target the surviving record's identity, not just its
    # count: if the `candidate_updated > current_updated` comparison in
    # `_atom_drift_record_is_preferred` were flipped to `<`, the 2026-06-09
    # record would survive instead (verified empirically), and every
    # assertion below would fail regardless of which entry appears first in
    # the TOC JSON.
    assert event["updated"] == "2026-06-20"
    assert event["published"] == "2026-06-20"
    assert event["title"] == newer_title
    assert event["support_url"] == (
        "https://support.microsoft.com/en-us/servicing/os/windows-11/"
        "2026/06/june-20-2026-kb5099001-os-build-30000-100"
    )


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


import win11_release_guard.policy_generator as policy_generator_module


def test_retired_atom_parameters_are_rejected() -> None:
    """atom_feed_xml/atom_feed_url/atom_feed_path were previously accepted and
    silently discarded, which let a caller believe a fixture had an effect
    when it never did. They are removed entirely now, so passing any of them
    is a loud TypeError instead of a silent no-op.
    """
    with pytest.raises(TypeError):
        generate_policy(
            release_health_html=_html_with_kb5101650(),
            servicing_toc_json=_july_toc(),
            atom_feed_xml="<feed><entry><title>ignored</title></entry></feed>",
            generated_at_utc="2026-07-15T00:00:00+00:00",
        )
    with pytest.raises(TypeError):
        generate_policy(
            release_health_html=_html_with_kb5101650(),
            atom_feed_url="https://support.microsoft.com/en-us/feed/atom/ignored",
        )
    with pytest.raises(TypeError):
        build_policy_from_sources(
            release_health_html_path=FIXTURES / "windows11-release-health.html",
            atom_feed_url="https://support.microsoft.com/en-us/feed/atom/ignored",
        )
    with pytest.raises(TypeError):
        build_policy_from_sources(
            release_health_html_path=FIXTURES / "windows11-release-health.html",
            atom_feed_path=FIXTURES / "windows11-servicing-toc.json",
        )


def test_unsafe_servicing_href_is_not_fetched_and_leaves_no_url_trace() -> None:
    """A servicing-index entry whose href resolves to nothing safe (here, an
    absolute external URL rather than the expected site-relative path) must
    never be fetched, and the rejected URL must never leak into the emitted
    diagnostic. This is the servicing-index equivalent of the retired
    Atom-feed guarantee that an unsafe/malformed href is not fetched and does
    not leak: :func:`_resolve_url` in ``servicing_toc.py`` refuses any href
    containing ``:`` or ``//``, so this also covers a missing/malformed href.
    """
    toc = json.dumps(
        {
            "items": [
                {
                    "toc_title": "June 9, 2026-KB5094126 (OS Builds 26200.8655 and 26100.8655)",
                    "href": "https://evil.example/en-us/topic/kb5094126",
                },
            ]
        }
    )

    fetch_calls: list[str] = []

    def fetcher(url: str, timeout: float, max_bytes: int) -> str:
        # Record the call before raising so invocation is provable by direct
        # observation, not solely by an exception that might get swallowed.
        fetch_calls.append(url)
        raise AssertionError(f"unexpected support article fetch: {url}")

    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=toc,
        support_article_fetcher=fetcher,
    )

    assert fetch_calls == []
    target = policy.broad_target_existing_devices
    assert target is not None
    assert not policy.source_diagnostics["support_articles"]

    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_support_article_href_missing"
    )
    assert event["kb_article"] == "KB5094126"
    assert "atom_feed_url" not in event
    assert "evil.example" not in json.dumps(policy.to_dict())


def _kb_less_newer_build_toc() -> str:
    return json.dumps(
        {
            "items": [
                {
                    "toc_title": "Windows 11, version 25H2",
                    "children": [
                        {
                            "href": "2026/08/august-3-2026-servicing-update-os-build-26200-9001",
                            "toc_title": "August 3, 2026—Servicing update (OS Build 26200.9001)",
                        },
                    ],
                }
            ]
        }
    )


def test_kb_less_servicing_entry_is_a_notice_that_does_not_advance_latest_observed_or_baseline() -> None:
    """A servicing row with a valid href but no KB in its title (e.g. a bare
    "Servicing update" row) used to vanish entirely (no entry, no diagnostic).
    It must now survive parsing with kb_article=None and surface as exactly one
    notice-severity `atom_newer_than_release_history` event -- never a warning,
    since the documented escalation to warning requires a KB -- and it must not
    move latest_observed_build or required_baseline_build off of what
    Release Health alone already established.
    """
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=_kb_less_newer_build_toc(),
        generated_at_utc="2026-08-04T00:00:00+00:00",
    )

    target = policy.broad_target_existing_devices
    assert target is not None
    assert target.version == "25H2"
    # Unchanged from what Release Health's own Current Versions/history report.
    assert target.latest_observed_build == "26200.8457"
    assert target.required_baseline_build == "26200.8457"

    drift_events = [
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.9001"
    ]
    assert len(drift_events) == 1
    assert drift_events[0]["severity"] == "notice"
    assert drift_events[0]["kb_article"] is None
    assert drift_events[0]["affects_required_baseline"] is False


def test_kb_less_servicing_entry_triggers_no_support_article_fetch() -> None:
    """The enrichment work set only ever fetches a support article for a
    record with an extractable KB. A KB-less servicing entry must not reach
    the fetcher at all -- proven here with a fetcher that fails the test if it
    is ever called.
    """

    forbidden_calls: list[str] = []

    def forbidden_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        # Record the call before raising so invocation is provable by direct
        # observation, not solely by an exception that might get swallowed.
        forbidden_calls.append(url)
        raise AssertionError(f"support fetch must not be attempted for a KB-less entry, got {url}")

    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=_kb_less_newer_build_toc(),
        generated_at_utc="2026-08-04T00:00:00+00:00",
        support_article_fetcher=forbidden_fetcher,
    )

    assert forbidden_calls == []
    assert not policy.source_diagnostics["support_articles"]
    target = policy.broad_target_existing_devices
    assert target is not None
    assert target.latest_observed_build == "26200.8457"


def test_missing_servicing_toc_no_longer_reports_a_missing_atom_feed() -> None:
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=None,
        generated_at_utc="2026-05-20T00:00:00+00:00",
    )
    kinds = [event["kind"] for event in policy.source_diagnostics["events"]]

    assert kinds.count("servicing_toc_missing") == 1
    assert not set(kinds) & RETIRED_ATOM_EVENT_KINDS


def test_atom_feed_parser_is_gone() -> None:
    assert not hasattr(policy_generator_module, "parse_atom_feed")


def test_atom_fixtures_are_removed() -> None:
    assert not (FIXTURES / "windows11-atom.xml").exists()
    assert not (FIXTURES / "windows11-atom-kb5094126.xml").exists()
