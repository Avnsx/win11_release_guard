from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
import pytest
from win11_release_guard.exceptions import PolicyFetchError, PolicyParseError
import win11_release_guard.policy_generator as policy_generator_module
from win11_release_guard.policy_generator import generate_policy
from win11_release_guard.policy_schema import validate_policy_document
from tests.support.policy_generator_helpers import (
    FAKE_MSRC_CVRF_WITHOUT_KB5094126,
    FAKE_MSRC_CVRF_WITH_KB5094126,
    KB5094126_SUPPORT_HTML,
    KB5094126_SUPPORT_HTML_NO_SECURITY,
    KB5094126_SUPPORT_URL,
    _assert_no_raw_support_article_leakage,
    _generated_output_bundle,
    _html,
    _html_file,
    _kb5094126_atom_event,
    _kb5094126_generated_fixture_policy,
    _kb5094126_msrc_fixture,
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


def _release_health_caught_up_to_kb5094126_with_update_type(update_type: str) -> str:
    html = _html_file("windows11-release-health-current-d-26h1.html")
    current_old = """      <tr>
        <td>25H2</td>
        <td>General Availability Channel</td>
        <td>2025-09-30</td>
        <td>2027-10-12</td>
        <td>2028-10-10</td>
        <td>2026-05-27</td>
        <td>26200.8524</td>
      </tr>"""
    current_new = """      <tr>
        <td>25H2</td>
        <td>General Availability Channel</td>
        <td>2025-09-30</td>
        <td>2027-10-12</td>
        <td>2028-10-10</td>
        <td>2026-06-09</td>
        <td>26200.8655</td>
      </tr>"""
    history_old = """      <tr>
        <td>General Availability Channel</td>
        <td>2026-05 B</td>
        <td>2026-05-12</td>
        <td>26200.8457</td>
        <td>KB5089549</td>
      </tr>"""
    history_extra = f"""      <tr>
        <td>General Availability Channel</td>
        <td>{update_type}</td>
        <td>2026-06-09</td>
        <td>26200.8655</td>
        <td>KB5094126</td>
      </tr>
{history_old}"""
    assert current_old in html
    assert history_old in html
    return html.replace(current_old, current_new, 1).replace(history_old, history_extra, 1)


def _toc_with_duplicate_new_b_release() -> str:
    return _toc_document_with_extra(
        _toc_entry(
            "June 9, 2026—KB5089600 (OS Build 26200.8461)",
            "2026/06/june-9-2026-kb5089600-os-build-26200-8461",
        ),
        _toc_entry(
            "June 9, 2026—KB5089600 (OS Build 26200.8461)",
            "2026/06/june-9-2026-kb5089600-os-build-26200-8461-2",
        ),
    )


def test_not_caught_up_kb5094126_does_not_create_baseline_update_notice() -> None:
    policy = _kb5094126_generated_fixture_policy(_html_file("windows11-release-health-current-d-26h1.html"))

    target = policy.broad_target_existing_devices
    assert target is not None
    assert target.required_baseline_build == "26200.8457"
    assert target.latest_observed_build == "26200.8655"
    assert "baseline_update_notice" not in policy.source_diagnostics
    assert not any(
        event["kind"] == "required_baseline_matched_latest_observed"
        for event in policy.source_diagnostics["events"]
    )
    index = policy_generator_module.render_policy_index(policy, policy_bytes=None, signature=None)
    assert 'class="panel span-12 baseline-update-notice"' not in index
    assert "New required baseline:" not in index


def test_caught_up_baseline_update_notice_expires_after_visibility_window() -> None:
    support_calls: list[str] = []
    msrc_calls: list[str] = []

    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        support_calls.append(url)
        raise PolicyFetchError("support fetch should not run for expired notice")

    def msrc_fetcher(url: str, timeout: float, max_bytes: int) -> dict[str, object]:
        msrc_calls.append(url)
        raise PolicyFetchError("msrc fetch should not run for expired notice")

    policy = generate_policy(
        release_health_html=_release_health_caught_up_to_kb5094126(),
        generated_at_utc="2026-07-01T00:00:00+00:00",
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )

    assert support_calls == []
    assert msrc_calls == []
    notice = policy.source_diagnostics["baseline_update_notice"]
    assert notice["active"] is False
    assert notice["visible_from_utc"] == "2026-06-09T00:00:00Z"
    assert notice["visible_until_utc"] == "2026-06-23T00:00:00Z"
    assert not any(
        event["kind"] == "required_baseline_matched_latest_observed"
        for event in policy.source_diagnostics["events"]
    )
    assert not any(
        event["kind"] == "msrc_cvrf_enrichment_unavailable"
        for event in policy.source_diagnostics["events"]
    )
    index = policy_generator_module.render_policy_index(policy, policy_bytes=None, signature=None)
    assert 'class="panel span-12 baseline-update-notice"' not in index
    assert "New required baseline:" not in index


def test_baseline_update_notice_and_warnings_panel_use_separate_grid_rows() -> None:
    policy = _kb5094126_generated_fixture_policy(_release_health_caught_up_to_kb5094126())
    warning_policy = replace(
        policy,
        validation_warnings=("Manual validation warning for grid placement.",),
    )

    index = policy_generator_module.render_policy_index(warning_policy, policy_bytes=None, signature=None)

    assert 'class="grid dashboard-grid has-baseline-notice has-validation-warnings"' in index
    assert index.index('class="panel span-12 baseline-update-notice"') < index.index(
        'class="panel span-12 dashboard-warning-panel"'
    )
    assert index.index('class="panel span-12 dashboard-warning-panel"') < index.index(
        'id="live-freshness-panel"'
    )
    assert index.index('class="panel span-12 dashboard-warning-panel"') < index.index(
        'class="panel span-7 source-diagnostics"'
    )
    assert ".dashboard-grid.has-baseline-notice.has-validation-warnings .dashboard-warning-panel{grid-row:2}" in index
    assert ".dashboard-grid.has-baseline-notice.has-validation-warnings #live-freshness-panel{grid-row:3/span 2}" in index
    assert ".dashboard-grid.has-baseline-notice.has-validation-warnings .source-diagnostics{grid-row:3/span 2}" in index
    assert ".dashboard-grid.has-baseline-notice.has-validation-warnings .signature-panel{grid-row:5}" in index
    assert ".dashboard-grid.has-baseline-notice.has-validation-warnings.diagnostics-expanded .source-diagnostics{grid-row:3/span 3}" in index


@pytest.mark.parametrize("update_type", ("2026-06 D Preview", "2026-06 OOB"))
def test_preview_or_oob_baseline_like_rows_do_not_create_baseline_update_notice(update_type: str) -> None:
    policy = _kb5094126_generated_fixture_policy(
        _release_health_caught_up_to_kb5094126_with_update_type(update_type)
    )

    assert "baseline_update_notice" not in policy.source_diagnostics
    assert not any(
        event["kind"] == "required_baseline_matched_latest_observed"
        for event in policy.source_diagnostics["events"]
    )


def test_baseline_update_notice_keeps_release_health_facts_when_support_article_mismatches() -> None:
    policy = _kb5094126_generated_fixture_policy(
        _release_health_caught_up_to_kb5094126(),
        support_html=_support_article_html(kb_article="KB5000000", builds=("26200.1111",), security=True),
        msrc_payload=FAKE_MSRC_CVRF_WITH_KB5094126,
    )

    notice = policy.source_diagnostics["baseline_update_notice"]
    assert notice["active"] is True
    assert notice["kb_article"] == "KB5094126"
    assert notice["build"] == "26200.8655"
    assert notice["support_article_validation_status"] == "mismatch"
    assert notice["support_article_validation_reasons"] == ["kb_mismatch", "build_missing"]
    assert notice["is_security"] is True
    assert notice["security_evidence_source"] == "msrc_cvrf"
    assert "KB5000000" not in notice["summary"]
    assert "26200.1111" not in notice["summary"]
    assert "MSRC confirms it as a security update" in notice["summary"]


def test_baseline_update_notice_uses_unknown_security_when_msrc_and_article_are_untrusted() -> None:
    policy = _kb5094126_generated_fixture_policy(
        _release_health_caught_up_to_kb5094126(),
        support_html=_support_article_html(security=False, labels=()),
        msrc_error=PolicyFetchError("MSRC unavailable"),
    )

    notice = policy.source_diagnostics["baseline_update_notice"]
    assert notice["active"] is True
    assert notice["security_evidence_source"] == "unavailable"
    assert notice["security_evidence_status"] == "unknown"
    assert "is_security" not in notice
    assert "security baseline" not in notice["summary"]
    # Human-facing summary uses neutral prose, never the raw status enum.
    assert "Security classification is unavailable from the checked enrichment source." in notice["summary"]
    assert "unknown" not in notice["summary"]
    assert "B.;" not in notice["summary"]
    assert "MSRC confirms" not in notice["summary"]
    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "required_baseline_matched_latest_observed"
    )
    assert "Security patch" not in policy_generator_module._source_diagnostic_row_from_event(event)["tags"]


def test_baseline_update_notice_atom_feed_lag_uses_msrc_month_fallback() -> None:
    # Live July 2026 shape: Release Health has the new B baseline but Microsoft's
    # Update History Atom feed lags and carries no entry for the baseline KB.
    # There is still no Atom-linked support article to fetch, but the MSRC CVRF
    # for the baseline month is already published. The notice now derives the
    # MSRC month from the Release Health baseline date (2026-06-09 -> 2026-Jun),
    # joins the baseline KB exactly, and classifies security from MSRC without
    # synthesizing a /help/<KB> URL or fetching any support article.
    msrc_calls: list[str] = []
    forbidden_support_calls: list[str] = []

    def forbidden_support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        # Record the call before raising so invocation is provable by direct
        # observation, not solely by an exception that might get swallowed.
        forbidden_support_calls.append(url)
        raise AssertionError(f"support fetch must not be attempted, got {url}")

    def msrc_fetcher(url: str, timeout: float, max_bytes: int) -> object:
        assert url == "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun"
        msrc_calls.append(url)
        return _kb5094126_msrc_fixture()

    policy = generate_policy(
        release_health_html=_release_health_caught_up_to_kb5094126_with_update_type("2026-06 B"),
        servicing_toc_json=_toc(),
        generated_at_utc="2026-06-11T18:00:00+00:00",
        support_article_fetcher=forbidden_support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )

    assert forbidden_support_calls == []
    assert msrc_calls == ["https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun"]
    notice = policy.source_diagnostics["baseline_update_notice"]
    assert notice["active"] is True
    assert notice["kb_article"] == "KB5094126"
    assert notice["build"] == "26200.8655"
    assert notice["is_security"] is True
    assert notice["security_evidence_source"] == "msrc_cvrf"
    assert notice["security_evidence_status"] == "trusted"
    # No Atom link means no support article: validation stays unavailable and no
    # support/source URL is synthesized.
    assert notice["support_article_validation_status"] == "unavailable"
    assert "source_url" not in notice
    assert "atom_entry_id" not in notice
    assert "MSRC confirms it as a security update." in notice["summary"]
    assert not notice["summary"].endswith(
        "Security classification is unavailable from the checked enrichment source."
    )
    baseline_events = [
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "required_baseline_matched_latest_observed"
    ]
    assert len(baseline_events) == 1
    assert not any(
        "support_article_enrichment" in event["kind"]
        for event in policy.source_diagnostics["events"]
    )


def test_baseline_update_notice_atom_feed_lag_msrc_error_stays_unavailable_with_warning() -> None:
    # Same Atom-lag shape, but the MSRC CVRF fetch for the baseline month fails.
    # The notice must degrade honestly to unavailable/unknown with the neutral
    # sentence, and the failure must now surface as an msrc_cvrf warning event
    # instead of being silently swallowed. Support fetching stays forbidden.
    forbidden_support_calls: list[str] = []

    def forbidden_support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        # Record the call before raising so invocation is provable by direct
        # observation, not solely by an exception that might get swallowed.
        forbidden_support_calls.append(url)
        raise AssertionError(f"support fetch must not be attempted, got {url}")

    def failing_msrc_fetcher(url: str, timeout: float, max_bytes: int) -> object:
        assert url == "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun"
        raise PolicyFetchError("MSRC unavailable")

    policy = generate_policy(
        release_health_html=_release_health_caught_up_to_kb5094126_with_update_type("2026-06 B"),
        servicing_toc_json=_toc(),
        generated_at_utc="2026-06-11T18:00:00+00:00",
        support_article_fetcher=forbidden_support_fetcher,
        msrc_cvrf_fetcher=failing_msrc_fetcher,
    )

    assert forbidden_support_calls == []
    notice = policy.source_diagnostics["baseline_update_notice"]
    assert notice["active"] is True
    assert notice["kb_article"] == "KB5094126"
    assert notice["build"] == "26200.8655"
    assert notice["support_article_validation_status"] == "unavailable"
    assert notice["security_evidence_source"] == "unavailable"
    assert notice["security_evidence_status"] == "unknown"
    assert "is_security" not in notice
    assert "source_url" not in notice
    assert notice["summary"].endswith(
        "Security classification is unavailable from the checked enrichment source."
    )
    baseline_events = [
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "required_baseline_matched_latest_observed"
    ]
    assert len(baseline_events) == 1
    warning = next(
        event
        for event in policy.source_diagnostics["events"]
        if "msrc_cvrf" in event["kind"]
    )
    assert warning["severity"] == "warning"
    assert warning["kind"] == "msrc_cvrf_enrichment_unavailable"
    assert warning["msrc_cvrf_month_id"] == "2026-Jun"
    assert not any(
        "support_article_enrichment" in event["kind"]
        for event in policy.source_diagnostics["events"]
    )


def test_baseline_update_notice_support_fetch_failure_surfaces_enrichment_event() -> None:
    # Regression for the previously silent-swallowed case: the baseline record
    # has an Atom-linked support URL, but the support-article fetch fails. Before,
    # support-enrichment events for baseline records were unconditionally
    # suppressed; now a real fetch failure surfaces as a standard
    # support_article_enrichment_unavailable event while the notice fields degrade
    # exactly as they do today.
    def failing_support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        assert url == KB5094126_SUPPORT_URL
        raise PolicyFetchError("support unavailable")

    def failing_msrc_fetcher(url: str, timeout: float, max_bytes: int) -> object:
        assert url == "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun"
        raise PolicyFetchError("MSRC unavailable")

    policy = generate_policy(
        release_health_html=_release_health_caught_up_to_kb5094126(),
        servicing_toc_json=_kb5094126_toc_fixture(),
        generated_at_utc="2026-06-11T18:00:00+00:00",
        support_article_fetcher=failing_support_fetcher,
        msrc_cvrf_fetcher=failing_msrc_fetcher,
    )

    notice = policy.source_diagnostics["baseline_update_notice"]
    assert notice["active"] is True
    assert notice["kb_article"] == "KB5094126"
    # Notice fields degrade as today: both enrichment sources failed.
    assert notice["security_evidence_source"] == "unavailable"
    assert notice["security_evidence_status"] == "unknown"
    assert "is_security" not in notice
    # The support-article fetch failure for the baseline record is no longer
    # silently swallowed.
    support_event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "support_article_enrichment_unavailable"
    )
    assert support_event["severity"] == "warning"
    assert support_event["source_url"] == KB5094126_SUPPORT_URL
    assert support_event["kb_article"] == "KB5094126"


def test_generated_output_surfaces_support_article_mismatch_and_degraded_states(tmp_path: Path) -> None:
    mismatch_policy = _kb5094126_generated_fixture_policy(
        _html_file("windows11-release-health-current-d-26h1.html"),
        support_html=_support_article_html(kb_article="KB5000000", builds=("26200.1111",), security=True),
    )
    mismatch_outputs = _generated_output_bundle(mismatch_policy, tmp_path / "mismatch")
    mismatch_data = mismatch_outputs["policy"]
    mismatch_index = str(mismatch_outputs["index"])
    assert isinstance(mismatch_data, dict)
    mismatch_event = _kb5094126_atom_event(mismatch_policy)
    assert mismatch_event["support_article_validation_status"] == "mismatch"
    assert "support_article_kb_article" not in mismatch_event
    assert "support_article_title" not in mismatch_event
    assert any(
        event["kind"] == "support_article_enrichment_mismatch"
        and event["support_article_validation_reasons"] == ["kb_mismatch", "build_missing"]
        for event in mismatch_data["source_diagnostics"]["events"]
    )
    assert "Support article mismatch" in mismatch_index
    assert "KB5000000 moves" not in mismatch_index
    _assert_no_raw_support_article_leakage(
        mismatch_outputs,
        _support_article_html(kb_article="KB5000000", builds=("26200.1111",), security=True),
    )

    degraded_policy = _kb5094126_generated_fixture_policy(
        _html_file("windows11-release-health-current-d-26h1.html"),
        support_html=_support_article_html(
            kb_article="KB5094126",
            builds=(),
            applies_to="Windows 11, version 25H2",
            security=False,
            labels=(),
        ),
        msrc_payload=FAKE_MSRC_CVRF_WITHOUT_KB5094126,
    )
    degraded_outputs = _generated_output_bundle(degraded_policy, tmp_path / "degraded")
    degraded_data = degraded_outputs["policy"]
    degraded_index = str(degraded_outputs["index"])
    assert isinstance(degraded_data, dict)
    assert any(
        event["kind"] == "support_article_enrichment_degraded"
        and event["support_article_validation_reasons"] == ["builds_missing"]
        for event in degraded_data["source_diagnostics"]["events"]
    )
    assert "Support article degraded" in degraded_index
    assert "support article validation degraded: builds_missing" in degraded_index


def test_msrc_cvrf_unavailable_uses_support_article_security_fallback() -> None:
    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        return KB5094126_SUPPORT_HTML

    def msrc_fetcher(url: str, timeout: float, max_bytes: int):
        raise PolicyFetchError("MSRC unavailable")

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        servicing_toc_json=_kb5094126_toc_fixture(),
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )
    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8655"
    )

    assert policy.source_diagnostics["msrc_cvrf"]["2026-Jun"]["status"] == "error"
    assert policy.source_diagnostics["msrc_cvrf"]["2026-Jun"]["error"] == "MSRC unavailable"
    assert event["is_security"] is True
    assert event["security_evidence_source"] == "support_article"
    assert "cves" not in event
    assert event["msrc_cvrf_status"] == "error"
    assert event["msrc_cvrf_error"] == "MSRC unavailable"
    assert event["user_message"].startswith("Microsoft published KB5094126 for Windows 11 25H2")
    assert any(
        item["kind"] == "msrc_cvrf_enrichment_unavailable"
        and item["msrc_cvrf_month_id"] == "2026-Jun"
        for item in policy.source_diagnostics["events"]
    )


def test_malformed_msrc_cvrf_is_nonfatal_unknown_security_status() -> None:
    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        return KB5094126_SUPPORT_HTML_NO_SECURITY

    def msrc_fetcher(url: str, timeout: float, max_bytes: int):
        return ["not", "a", "cvrf", "object"]

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        servicing_toc_json=_kb5094126_toc_fixture(),
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )
    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8655"
    )

    assert policy.source_diagnostics["msrc_cvrf"]["2026-Jun"]["status"] == "degraded"
    assert event["is_security"] is None
    assert event["security_evidence_source"] == "unavailable"
    assert event["msrc_cvrf_status"] == "degraded"
    assert any(item["kind"] == "msrc_cvrf_enrichment_unavailable" for item in policy.source_diagnostics["events"])


def test_support_article_fetch_failure_is_source_diagnostic_metadata() -> None:
    def fetcher(url: str, timeout: float, max_bytes: int) -> str:
        raise PolicyFetchError("network unavailable")

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        servicing_toc_json=_kb5094126_toc_fixture(),
        support_article_fetcher=fetcher,
    )

    article = policy.source_diagnostics["support_articles"][KB5094126_SUPPORT_URL]
    assert article["status"] == "error"
    assert article["error"] == "network unavailable"
    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "support_article_enrichment_unavailable"
    )
    assert event["severity"] == "warning"
    assert event["support_article_status"] == "error"
    assert event["support_article_error"] == "network unavailable"
    assert event["source_url"] == KB5094126_SUPPORT_URL
    assert event["affects_broad_target"] is True
    assert event["affects_required_baseline"] is False
    atom_event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8655"
    )
    assert atom_event["support_article_status"] == "error"
    assert atom_event["support_article_error"] == "network unavailable"
    assert atom_event["is_security"] is None
    assert atom_event["security_evidence_source"] == "unavailable"


def test_malformed_support_article_html_is_degraded_metadata() -> None:
    def fetcher(url: str, timeout: float, max_bytes: int) -> str:
        return "<html><head><script>ignored()</script></head><body><svg>ignored</svg></body></html>"

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        servicing_toc_json=_kb5094126_toc_fixture(),
        support_article_fetcher=fetcher,
    )

    article = policy.source_diagnostics["support_articles"][KB5094126_SUPPORT_URL]
    assert article["status"] == "degraded"
    assert article["reason"] == "support_article_parse_incomplete"
    assert "ignored" not in json.dumps(article)
    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "support_article_enrichment_degraded"
    )
    assert event["support_article_status"] == "degraded"
    assert event["support_article_reason"] == "support_article_parse_incomplete"
    atom_event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8655"
    )
    assert atom_event["message"].startswith("Servicing index shows a newer non-preview build")
    assert atom_event["support_article_status"] == "degraded"
    assert atom_event["support_article_reason"] == "support_article_parse_incomplete"


def test_atom_support_missing_href_creates_diagnostic_without_help_fallback() -> None:
    toc = json.dumps(
        {
            "items": [
                {
                    "toc_title": "June 9, 2026-KB5094126 (OS Builds 26200.8655 and 26100.8655)",
                    "href": "../escape",
                },
            ]
        }
    )
    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        servicing_toc_json=toc,
    )
    target = policy.broad_target_existing_devices
    assert target is not None
    assert target.latest_build == "26200.8524"
    assert target.latest_observed_build == "26200.8524"
    assert "latest_observed_source_url" not in target.metadata

    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_support_article_href_missing"
    )
    assert event["severity"] == "warning"
    assert event["release"] == "25H2"
    assert event["build"] == "26200.8655"
    assert event["kb_article"] == "KB5094126"
    assert event["affects_broad_target"] is True
    assert event["affects_required_baseline"] is True
    assert "https://support.microsoft.com/help/5094126" not in json.dumps(policy.to_dict())


def test_source_diagnostics_unresolved_after_24h_only_for_warning_drift() -> None:
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=_toc_with_new_b_release(),
        generated_at_utc="2026-06-11T18:00:00+00:00",
    )
    events = policy.source_diagnostics["events"]

    assert policy.source_diagnostics["drift"]["generated_after_newest_source_hours"] == 66.0
    assert any(
        event["kind"] == "atom_newer_than_release_history"
        and event["severity"] == "warning"
        and event["affects_required_baseline"] is True
        for event in events
    )
    unresolved = next(event for event in events if event["kind"] == "source_drift_unresolved_after_24h")
    assert unresolved["severity"] == "warning"
    assert unresolved["affects_broad_target"] is True
    assert unresolved["affects_required_baseline"] is False


def test_source_diagnostics_dedupes_duplicate_atom_events():
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=_toc_with_duplicate_new_b_release(),
    )
    events = [
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history"
        and event["build"] == "26200.8461"
        and event["kb_article"] == "KB5089600"
    ]

    assert len(events) == 1


def test_source_diagnostics_warn_when_current_versions_lag_release_history():
    policy = generate_policy(release_health_html=_with_oob_row(_html()), servicing_toc_json=_toc())
    drift = policy.source_diagnostics["drift"]["current_version_latest_older_than_release_history"]

    assert drift[0]["version"] == "25H2"
    assert drift[0]["latest_build"] == "26200.8457"
    assert drift[0]["newest_release_history_build"] == "26200.8460"
    assert any("Current Versions latest_build appears older" in warning for warning in policy.validation_warnings)


def test_policy_schema_accepts_source_diagnostics_without_unknown_key_warning():
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc())

    warnings = validate_policy_document(policy.to_dict())

    assert not any("unknown top-level key 'source_diagnostics'" in warning for warning in warnings)


def test_policy_schema_accepts_structured_source_diagnostics_events():
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc_with_new_b_release())
    data = policy.to_dict()

    validate_policy_document(data)

    assert data["source_diagnostics"]["events"]
    assert all(
        re.fullmatch(r"wrg-source-diagnostic-v1:[0-9a-f]{16}", event["id"])
        for event in data["source_diagnostics"]["events"]
    )
    assert data["source_diagnostics"]["event_counts"]["warning"] >= 1


def test_policy_schema_accepts_newer_latest_observed_without_baseline_change():
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc())
    data = policy.to_dict()
    target = data["broad_target_existing_devices"]
    target["latest_observed_build"] = "26200.8655"
    target["required_baseline_build"] = "26200.8457"
    current_25h2 = next(
        entry
        for entry in data["current_versions"]
        if entry["version"] == "25H2" and entry["build_family"] == 26200
    )
    current_25h2["latest_observed_build"] = "26200.8655"
    current_25h2["required_baseline_build"] = "26200.8457"

    validate_policy_document(data)

    assert target["latest_build"] == "26200.8457"
    assert target["latest_observed_build"] == "26200.8655"
    assert target["required_baseline_build"] == "26200.8457"
    assert current_25h2["latest_build"] == "26200.8457"
    assert current_25h2["latest_observed_build"] == "26200.8655"
    assert current_25h2["required_baseline_build"] == "26200.8457"


def test_policy_schema_rejects_older_latest_observed_build():
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc())
    data = policy.to_dict()
    data["broad_target_existing_devices"]["latest_observed_build"] = "26200.7000"

    with pytest.raises(PolicyParseError, match="latest_observed_build must not be older than latest_build"):
        validate_policy_document(data)


def test_policy_schema_rejects_invalid_source_diagnostics_event_id():
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc_with_new_b_release())
    data = policy.to_dict()
    data["source_diagnostics"]["events"][0]["id"] = "not-a-diagnostic-id"

    with pytest.raises(PolicyParseError, match=r"source_diagnostics\.events\[0\]\.id"):
        validate_policy_document(data)
