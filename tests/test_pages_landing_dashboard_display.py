from __future__ import annotations

from html.parser import HTMLParser
import re
from win11_release_guard.models import ReleasePolicy, ReleasePolicyEntry
import win11_release_guard.policy_generator as policy_generator_module
from win11_release_guard.policy_generator import clock as generator_clock
from win11_release_guard.policy_generator import render_policy_index
from tests.support.pages_landing_helpers import _assert_diag_count_tile, _assert_no_external_page_dependencies, _diag_row_marker


ATOM_ENTRY_ID = "uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480"


ATOM_SOURCE_DIAGNOSTIC_ID = f"wrg-source-diagnostic-v1:{ATOM_ENTRY_ID}"


KB5094126_SUPPORT_URL = (
    "https://support.microsoft.com/en-us/topic/"
    "june-9-2026-kb5094126-os-builds-26200-8655-and-26100-8655-"
    "1a9bcba6-5f53-4075-8156-fe11ac631737"
)


def test_pages_index_renders_day_hour_freshness_visual_state(monkeypatch) -> None:
    monkeypatch.setattr(generator_clock, "utc_now", lambda: "2026-06-07T15:00:00+00:00")
    policy = ReleasePolicy(generated_at_utc="2026-06-01T00:00:00+00:00")

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert (
        'id="live-generated-age" class="freshness-metric age-wide" aria-live="polite" '
        'title="Published feed age 6 days, 15 hours, 0 minutes" '
        'aria-label="Published feed age 6 days, 15 hours, 0 minutes">6d 15h</div>'
        in index
    )
    assert ".freshness-panel{container-type:inline-size;align-content:start;grid-auto-rows:max-content}" in index
    assert ".freshness-panel .freshness-layout{grid-template-columns:1fr;gap:clamp(24px,3vw,34px)}" in index
    assert (
        ".freshness-panel .freshness-hero{grid-template-columns:minmax(104px,120px) "
        "minmax(0,1fr);gap:clamp(28px,3vw,40px);max-width:100%}"
        in index
    )
    assert ".freshness-metric{white-space:normal;overflow-wrap:normal;word-break:normal;text-wrap:balance}" in index
    assert ".freshness-callout{margin-top:clamp(14px,2vw,22px)}" in index
    assert "@supports(margin-top:1cqw){.freshness-callout{margin-top:clamp(14px,3cqw,24px)}}" in index
    assert ".freshness-panel .thresholds{grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}" in index
    assert ".freshness-panel .thresholds{grid-template-columns:1fr;gap:12px}" in index
    assert ".freshness-age-copy{gap:8px;padding-inline-start:2px}" in index
    assert "days+'d '+hours+'h" in index
    _assert_no_external_page_dependencies(index)


def test_pages_index_signature_trust_pulse_is_lightweight_and_can_render_red() -> None:
    policy = ReleasePolicy(metadata={"signature_status": "invalid"})

    index = render_policy_index(
        policy,
        policy_bytes=b'{"policy":"demo"}',
        signature={"algorithm": "ed25519", "key_id": "test-key", "signature": "bad"},
    )
    HTMLParser().feed(index)

    assert "html{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}" in index
    assert 'class="trust-indicator error">Signed policy trust</span>' in index
    assert '<section class="panel span-5 signature-panel error">' in index
    assert 'class="signature-status-card error"' in index
    assert "font-size:12px;font-weight:620;white-space:nowrap" in index
    assert "width:max-content;overflow:hidden;border:1px solid #a9ddb7" in index
    assert (
        ".trust-indicator.error{color:var(--err);background:linear-gradient(180deg,var(--err-soft),#fff8f6);"
        "border-color:#f6b7ad"
        in index
    )
    assert "--trust-ring:rgba(180,35,24,.2)" in index
    assert ".signature-panel.error{border-color:#f6b7ad;background:linear-gradient(180deg,#fff7f5,#fffdfc)}" in index
    assert ".signature-panel.error:before{background:linear-gradient(90deg,var(--err),rgba(180,35,24,.22))}" in index
    assert ".signature-status-card.error{border-color:#f6b7ad;background:linear-gradient(135deg,var(--err-soft),#fff8f6)}" in index
    assert "box-shadow:0 0 0 4px var(--trust-ring)" in index
    assert "width:9px;height:9px" in index
    assert "animation:trustPulse 2.2s cubic-bezier(.4,0,.2,1) infinite" in index
    assert "will-change:transform" in index
    keyframes = index.split("@keyframes trustPulse", 1)[1].split(".trust-indicator.warning", 1)[0]
    assert "transform:scale(1.48)" in keyframes
    assert "transform:scale(1.12)" in keyframes
    assert "box-shadow" not in keyframes
    assert "animation:none!important" in index


def test_pages_index_signature_boxes_hover_without_double_animating_api_rows() -> None:
    index = render_policy_index(ReleasePolicy(), policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert (
        ".signature-kv div{display:grid;grid-template-columns:minmax(104px,30%) minmax(0,1fr);"
        "gap:12px;align-items:center;border:1px solid #d5e2f0;border-radius:8px;"
        "background:linear-gradient(180deg,#fbfdff,#f5f8fc);padding:10px 12px;"
        "box-shadow:inset 0 1px 0 rgba(255,255,255,.7);"
        "transition:transform .16s ease,border-color .16s ease,background-color .16s ease}"
        in index
    )
    assert ".signature-kv dd{margin:0;color:#172033;font-weight:600;line-height:1.25;overflow-wrap:anywhere}" in index
    assert ".signature-kv .mono{font-size:13px;font-weight:600}" in index
    assert (
        ".signature-kv div:hover{border-color:#b8c9dd;background:#fff;"
        "box-shadow:0 7px 16px rgba(31,79,143,.07);transform:translateY(-1px)}"
        in index
    )
    assert (
        ".api-endpoint-row{display:grid;grid-template-columns:auto minmax(0,1fr) auto;"
        "gap:10px;align-items:center;border:1px solid var(--line);border-radius:8px;"
        "background:linear-gradient(180deg,#f8fafc,#f3f6fa);padding:10px 11px;"
        "color:inherit;text-decoration:none}"
        in index
    )
    assert "api-row-icon" in index
    assert ".api-endpoint-row:hover{border-color:#aecded" in index
    api_hover_rules = re.findall(r"\.api-endpoint-row:hover\{([^}]*)\}", index)
    assert api_hover_rules
    assert all("transform:" not in rule for rule in api_hover_rules)
    assert ".api-endpoint-row:focus-visible{outline:3px solid rgba(0,120,212,.28)" in index
    assert ".signature-kv div:hover{transform:none!important}" in index


def test_pages_index_uses_balanced_ui_font_weights() -> None:
    index = render_policy_index(ReleasePolicy(), policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    explicit_weights = [int(weight) for weight in re.findall(r"font-weight:(\d+)", index)]
    assert explicit_weights
    assert max(explicit_weights) <= 760

    trust_rule = index.split(".trust-indicator{", 1)[1].split("}", 1)[0]
    assert "font-weight:620" in trust_rule
    assert "font-weight:7" not in trust_rule

    assert ".title-line h1{font-size:clamp(34px,4rem,64px);line-height:1.04;margin:0 0 10px;font-weight:760" in index
    assert ".title-version-link{display:inline-flex;align-items:center;gap:8px;margin-left:auto" in index
    assert "font-size:16px;font-weight:700" in index
    assert ".eyebrow{display:inline-flex;align-items:center;gap:8px;margin-bottom:8px;color:#004de6;font-size:20px;font-weight:740" in index
    assert "h2{font-size:12px;font-weight:720;text-transform:uppercase" in index
    assert ".signature-head h2{margin:0;color:#475569;font-weight:720}" in index
    assert ".source-health h3{margin:0;color:var(--muted);font-size:11px;font-weight:720" in index
    assert ".source-name strong{font-weight:700}" in index

    assert ".metric{font-size:31px;font-weight:680" in index
    assert ".kpi-card .metric{font-size:54px;font-weight:720" in index
    assert ".freshness-metric{font-size:46px;font-weight:720" in index
    assert ".kv dd{margin:0;font-weight:600;overflow-wrap:anywhere}" in index
    assert ".thresholds strong{display:block;font-size:17px;font-weight:640}" in index
    assert ".diag-tile strong{display:block;font-size:22px;font-weight:650" in index
    assert ".diag-row-head strong{font-size:13px;font-weight:640}" in index
    assert ".severity-badge,.source-chip,.diag-tags span,.diag-tags a{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:2px 7px;font-size:11px;font-weight:600" in index
    assert ".api-endpoint-row strong{display:block;color:#172033;font-size:13px;font-weight:640" in index
    assert "footer{position:relative;display:grid;gap:8px;justify-items:center;margin-top:34px;padding:20px 12px 4px" in index
    assert "footer:before{content:'';width:min(640px,100%);height:1px;margin-bottom:8px" in index
    assert ".footer-source{display:flex;flex-wrap:wrap;align-items:center;justify-content:center;gap:4px 6px;margin-top:2px}" in index
    assert ".footer-github{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.82);padding:2px 8px;color:#075985;font-weight:600" in index
    assert "footer{margin-top:28px;padding-top:18px}" in index


def test_pages_index_source_diagnostics_empty_state_is_compact() -> None:
    policy = ReleasePolicy(
        source_diagnostics={"event_counts": {"notice": 0, "warning": 0, "error": 0}},
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert "No source issues reported" in index
    assert "Release Health, servicing index, parser, and freshness checks have no warning or error events." in index
    assert "1</strong><span>Notices" in index
    assert "0</strong><span>Warnings" in index
    assert "0</strong><span>Errors" in index
    _assert_diag_count_tile(index, "notice", 1, "Notices")
    _assert_diag_count_tile(index, "warning", 0, "Warnings")
    _assert_diag_count_tile(index, "error", 0, "Errors")
    assert _diag_row_marker("notice") in index
    assert index.count(_diag_row_marker("notice")) == 1
    assert _diag_row_marker("warning") not in index
    assert _diag_row_marker("error") not in index
    assert "diag-feed" in index
    assert "diag-events-empty" in index
    assert 'id="source-diagnostics-empty" class="diag-filter-empty" hidden' in index
    assert "This category currently contains no entries." in index
    assert "setEmptyState" in index
    assert "labels={notice:'notice',warning:'warning',error:'error'}" in index
    assert "No warnings" in index
    assert "No errors" in index
    assert "26H1 excluded for existing devices" not in index
    assert "diag-empty" not in index


def test_pages_index_excluded_release_notice_is_data_driven() -> None:
    policy = ReleasePolicy(
        excluded_for_existing_devices=(
            ReleasePolicyEntry(
                version="26H1",
                build_family=26200,
                latest_build="26200.1000",
                reason="new devices only",
            ),
        ),
        source_diagnostics={"event_counts": {"notice": 0, "warning": 0, "error": 0}},
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert "Release policy notes" not in index
    assert "release-note" not in index
    assert "2</strong><span>Notices" in index
    assert "0</strong><span>Warnings" in index
    assert "0</strong><span>Errors" in index
    assert "No source issues reported" in index
    assert "26H1 excluded for existing devices" in index
    assert "Release policy" in index
    assert "Notice" in index
    assert "Release 26H1" in index
    assert "Existing devices" in index
    assert index.count(_diag_row_marker("notice")) == 2
    assert index.find("No source issues reported") < index.find("26H1 excluded for existing devices")


def test_pages_index_source_diagnostics_render_structured_warning_event() -> None:
    event = {
        "severity": "warning",
        "kind": "atom_newer_than_release_history",
        "release": "25H2",
        "build_family": 26200,
        "build": "26200.8461",
        "kb_article": "KB5089600",
        "affects_broad_target": True,
        "affects_required_baseline": True,
        "updated": "2026-06-09T18:00:00Z",
        "message": "Atom feed reports a newer baseline build.",
    }
    policy = ReleasePolicy(
        source_diagnostics={
            "event_counts": {"notice": 0, "warning": 1, "error": 0},
            "events": [event],
        }
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert _diag_row_marker("warning") in index
    assert "New baseline candidate for Windows 11 25H2" in index
    assert "Atom feed" in index
    assert "Warning" in index
    assert "Release 25H2" in index
    assert "Build 26200.8461" in index
    assert "KB5089600" in index
    assert "Required baseline" in index
    assert "Atom feed reports a newer baseline build." in index
    expected_id = policy_generator_module._source_diagnostic_id_for_event(event)
    assert f'data-diagnostic-id="{expected_id}"' in index
    _assert_diag_count_tile(index, "warning", 1, "Warnings")
    _assert_diag_count_tile(index, "notice", 0, "Notices")
    assert '<span class="severity-badge warning">Warning</span>' in index
    assert "No source issues reported" not in index


def test_pages_index_source_diagnostics_render_enriched_atom_summary_and_export_fields() -> None:
    user_message = (
        "Microsoft published KB5094126 for Windows 11 25H2 build 26200.8655. This looks like the next "
        "stable broad-fleet baseline candidate, but this policy waits for Release Health baseline "
        "rules before requiring it (security update, June 2026); "
        "public notes mention Secure Boot."
    )
    technical_message = (
        "Atom feed shows a newer non-preview build 26200.8655 for 25H2 than Release Health history."
    )
    event = {
        "id": ATOM_SOURCE_DIAGNOSTIC_ID,
        "severity": "warning",
        "kind": "atom_newer_than_release_history",
        "release": "25H2",
        "build_family": 26200,
        "build": "26200.8655",
        "kb_article": "KB5094126",
        "affects_broad_target": True,
        "affects_required_baseline": True,
        "updated": "2026-06-10T17:20:31Z",
        "message": technical_message,
        "user_message": user_message,
        "kb_update_bucket": "OS Build Update",
        "kb_update_bucket_confidence": "low",
        "is_security": True,
        "security_evidence_source": "msrc_cvrf",
        "support_article_url": KB5094126_SUPPORT_URL,
        "atom_entry_id": ATOM_ENTRY_ID,
        "atom_support_article_id": "968480",
        "cves": ["CVE-2026-0001", "CVE-2026-0002"],
    }
    policy = ReleasePolicy(
        source_diagnostics={
            "event_counts": {"notice": 0, "warning": 1, "error": 0},
            "events": [event],
        }
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert _diag_row_marker("warning") in index
    assert f'data-diagnostic-id="{ATOM_SOURCE_DIAGNOSTIC_ID}"' in index
    assert "New baseline candidate for Windows 11 25H2" in index
    assert f'data-user-message="{user_message}"' in index
    assert 'data-kb-update-bucket="OS Build Update"' in index
    assert 'data-kb-update-bucket-confidence="low"' in index
    assert 'data-is-security="true"' in index
    assert 'data-security-evidence-source="msrc_cvrf"' in index
    assert f'data-support-article-url="{KB5094126_SUPPORT_URL}"' in index
    assert f'data-source-url="{KB5094126_SUPPORT_URL}"' in index
    assert f'data-read-more-url="{KB5094126_SUPPORT_URL}"' in index
    assert 'data-security-url="https://msrc.microsoft.com/update-guide"' in index
    assert 'data-cves=' not in index
    assert 'data-cve-count=' not in index
    assert f'data-atom-entry-id="{ATOM_ENTRY_ID}"' in index
    assert 'data-atom-support-article-id="968480"' in index
    assert (
        f'<p class="diag-user-message">{user_message} '
        f'<a class="diag-read-more-inline" href="{KB5094126_SUPPORT_URL}" '
        'rel="noopener noreferrer">Read more</a></p>'
        f'<p class="diag-technical-message">{technical_message}</p>'
    ) in index
    for tag in (
        "Release 25H2",
        "Build 26200.8655",
        "Family 26200",
        "Required baseline",
        "id=968480",
    ):
        assert f"<span>{tag}</span>" in index
    assert "<span>KB5094126</span>" in index
    assert "<span>Security patch</span>" in index
    assert '<span class="security-evidence">Security confirmed by MSRC</span>' in index
    assert "<span>CVEs 2</span>" not in index
    assert "update-guide/vulnerability/CVE-2026-0001" not in index
    assert "This patch contains" not in index
    assert "<span>June 10, 2026 at 19:20 CEST / 17:20 UTC</span>" in index
    assert "<span>2026-06-10T17:20:31Z</span>" not in index
    assert (
        "message:compactText(row.querySelector('.diag-technical-message'))"
        "||compactText(row.querySelector('p'))"
    ) in index
    for export_attr in (
        "addAttr('data-user-message','user_message')",
        "addAttr('data-kb-update-bucket','kb_update_bucket')",
        "addAttr('data-kb-update-bucket-confidence','kb_update_bucket_confidence')",
        "addAttr('data-security-evidence-source','security_evidence_source')",
        "addAttr('data-support-article-url','support_article_url')",
        "addAttr('data-source-url','source_url')",
        "addAttr('data-read-more-url','read_more_url')",
        "addAttr('data-security-url','security_url')",
        "addAttr('data-atom-entry-id','atom_entry_id')",
        "addAttr('data-atom-support-article-id','atom_support_article_id')",
    ):
        assert export_attr in index
    assert "addAttr('data-cves','cves')" not in index
    assert "addAttr('data-cve-count','cve_count')" not in index
    assert "if(isSecurity==='true'){entry.is_security=true;}else if(isSecurity==='false')" in index
    assert "export_schema:'win11_release_guard.source_diagnostics.visible.v1'" in index
    assert "do not override signed policy verdicts" in index
    assert ".diag-read-more-inline" in index
    _assert_no_external_page_dependencies(index)


def test_pages_index_source_diagnostics_do_not_link_unsafe_evidence_urls() -> None:
    event = {
        "id": ATOM_SOURCE_DIAGNOSTIC_ID,
        "severity": "warning",
        "kind": "atom_newer_than_release_history",
        "release": "25H2",
        "build_family": 26200,
        "build": "26200.8655",
        "kb_article": "KB5094126",
        "affects_broad_target": True,
        "affects_required_baseline": True,
        "message": "Atom feed shows a newer non-preview build for the broad target.",
        "is_security": True,
        "security_evidence_source": "support_article",
        "support_article_url": "https://evil.example/kb5094126",
        "source_url": "https://evil.example/kb5094126",
        "cves": ["not-a-cve"],
    }
    policy = ReleasePolicy(
        source_diagnostics={
            "event_counts": {"notice": 0, "warning": 1, "error": 0},
            "events": [event],
        }
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert "https://evil.example" not in index
    assert 'data-read-more-url=' not in index
    assert 'data-security-url=' not in index
    assert 'data-cves=' not in index
    assert 'class="diag-row-actions"' not in index
    assert '<span>KB5094126</span>' in index
    assert '<span>Security patch</span>' in index
    assert "not-a-cve" not in index


def test_pages_index_latest_observed_label_uses_atom_support_metadata() -> None:
    target = ReleasePolicyEntry(
        version="25H2",
        build_family=26200,
        latest_build="26200.8524",
        latest_observed_build="26200.8655",
        required_baseline_build="26200.8457",
        metadata={
            "latest_observed_source": "atom_support_article",
            "latest_observed_source_url": KB5094126_SUPPORT_URL,
            "latest_observed_kb_article": "KB5094126",
            "latest_observed_atom_entry_id": ATOM_ENTRY_ID,
            "latest_observed_atom_support_article_id": "968480",
        },
    )
    policy = ReleasePolicy(broad_target_existing_devices=target)

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert '<h2><span>Latest observed</span>' in index
    assert (
        '<div class="metric">26200.8655</div><span class="label">'
        "Microsoft Support article</span>"
    ) in index
    assert (
        '<div class="metric">26200.8655</div><span class="label">'
        "Microsoft Current Versions table</span>"
    ) not in index


def test_pages_index_source_diagnostics_ticket_link_is_static_hover_only_metadata() -> None:
    event = {
        "severity": "warning",
        "kind": "atom_newer_than_release_history",
        "release": "25H2",
        "build_family": 26200,
        "build": "26200.8461",
        "kb_article": "KB5089600",
        "affects_broad_target": True,
        "affects_required_baseline": True,
        "message": "Atom feed reports a newer baseline build.",
    }
    diagnostic_id = policy_generator_module._source_diagnostic_id_for_event(event)
    without_issue_status = render_policy_index(
        ReleasePolicy(source_diagnostics={"event_counts": {"notice": 0, "warning": 1, "error": 0}, "events": [event]}),
        policy_bytes=None,
        signature=None,
    )

    assert '<a class="diag-ticket-link"' not in without_issue_status
    assert "#Ticket 42" not in without_issue_status

    policy = ReleasePolicy(
        source_diagnostics={
            "event_counts": {"notice": 0, "warning": 1, "error": 0},
            "events": [event],
            "issue_status": {
                diagnostic_id: {
                    "number": 42,
                    "state": "open",
                    "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
                }
            },
        }
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert f'data-diagnostic-id="{diagnostic_id}"' in index
    assert (
        '<a class="diag-ticket-link" '
        'href="https://github.com/Avnsx/win11_release_guard/issues/42" '
        'aria-label="GitHub issue 42 status open">'
    ) in index
    assert "diag-ticket-link-icon" in index
    assert "#Ticket 42" in index
    assert '<svg class="github-icon"' in index
    assert ".diag-row:hover .diag-ticket-link,.diag-row:focus-within .diag-ticket-link" in index
    assert "opacity:0;pointer-events:none" in index
    _assert_no_external_page_dependencies(index)


def test_pages_index_source_diagnostics_suppresses_closed_issue_rows() -> None:
    open_event = {
        "severity": "warning",
        "kind": "atom_newer_than_release_history",
        "release": "25H2",
        "build": "26200.8461",
        "message": "Open warning remains visible.",
    }
    closed_event = {
        "severity": "error",
        "kind": "missing_broad_target_baseline",
        "release": "25H2",
        "build_family": 26200,
        "message": "Closed issue should suppress this diagnostic.",
    }
    open_id = policy_generator_module._source_diagnostic_id_for_event(open_event)
    closed_id = policy_generator_module._source_diagnostic_id_for_event(closed_event)
    policy = ReleasePolicy(
        source_diagnostics={
            "event_counts": {"notice": 0, "warning": 1, "error": 1},
            "events": [open_event, closed_event],
            "issue_status": {
                open_id: {
                    "number": 42,
                    "state": "open",
                    "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
                },
                closed_id: {
                    "number": 43,
                    "state": "closed",
                    "url": "https://github.com/Avnsx/win11_release_guard/issues/43",
                },
            },
        }
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert f'data-diagnostic-id="{open_id}"' in index
    assert f'data-diagnostic-id="{closed_id}"' not in index
    assert "Open warning remains visible." in index
    assert "Closed issue should suppress this diagnostic." not in index
    assert "#Ticket 42" in index
    assert "#Ticket 43" not in index
    _assert_diag_count_tile(index, "warning", 1, "Warnings")
    _assert_diag_count_tile(index, "error", 0, "Errors")
    assert "error diagnostic entry reported without structured row details" not in index
    _assert_no_external_page_dependencies(index)


def test_pages_index_source_diagnostics_renders_issue_sync_unavailable_status() -> None:
    policy = ReleasePolicy(
        source_diagnostics={
            "event_counts": {"notice": 0, "warning": 0, "error": 0},
            "events": [],
            "issue_sync": {
                "status": "unavailable",
                "reason": "github_issues_sync_failed",
                "message": "GitHub Issues sync failed during publish-policy.",
            },
        }
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert 'data-issue-sync-status="unavailable"' in index
    assert "Issue sync unavailable" in index
    assert "GitHub Issues sync failed during publish-policy." in index
    assert "github_issues_sync_failed" in index
    assert "#Ticket" not in index
    _assert_no_external_page_dependencies(index)


def test_pages_index_source_diagnostics_render_warning_and_error_color_states() -> None:
    policy = ReleasePolicy(
        source_diagnostics={
            "event_counts": {"notice": 0, "warning": 1, "error": 1},
            "events": [
                {
                    "severity": "warning",
                    "kind": "current_versions_lag_release_history",
                    "release": "25H2",
                    "build": "26200.8461",
                    "message": "Current Versions is behind Release History.",
                },
                {
                    "severity": "error",
                    "kind": "missing_broad_target_baseline",
                    "release": "25H2",
                    "build_family": 26200,
                    "message": "Required baseline cannot be derived.",
                },
            ],
        }
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    _assert_diag_count_tile(index, "warning", 1, "Warnings")
    _assert_diag_count_tile(index, "error", 1, "Errors")
    _assert_diag_count_tile(index, "notice", 0, "Notices")
    assert _diag_row_marker("warning") in index
    assert _diag_row_marker("error") in index
    assert '<article class="diag-row warning" data-diagnostic-severity="warning" hidden' not in index
    assert '<article class="diag-row error" data-diagnostic-severity="error" hidden' not in index
    assert '<span class="severity-badge warning">Warning</span>' in index
    assert '<span class="severity-badge error">Error</span>' in index
    assert "Release Health lag for Windows 11 25H2" in index
    assert "Missing baseline for Windows 11 25H2" in index
    assert "Current Versions is behind Release History." in index
    assert "Required baseline cannot be derived." in index
    assert "No source issues reported" not in index
