from __future__ import annotations

from html.parser import HTMLParser
import re
from pathlib import Path
from win11_release_guard.models import ReleasePolicy, ReleasePolicyEntry
import win11_release_guard.policy_generator as policy_generator_module
from win11_release_guard.policy_generator import render_policy_index
from tests.support.pages_landing_helpers import (
    REMOVED_SCHEMA_PANEL_LABELS,
    WIKI_SCALE_DECLARATION,
    WIKI_VISUAL_SCALE,
    _assert_diag_count_tile,
    _assert_no_external_page_dependencies,
    _diag_row_marker,
    _diagnostic_ids,
    _freshness_data,
    _render_landing,
)


CURATED_26H1_SUMMARY = (
    "26H1 is excluded for existing devices because Microsoft scopes it to new devices and does not offer "
    "it as an in-place update from 24H2/25H2."
)


def _assert_glass_dashboard_ui_contract(index: str) -> None:
    assert "main{position:relative;z-index:1;width:calc(100% - 80px);max-width:1580px" in index
    assert "backdrop-filter:blur(28px)" in index
    assert "body:before" in index
    assert "body:after" in index
    assert 'class="winmark"' in index
    assert "winmark{width:132px;height:132px" in index
    assert "kpi-card" in index
    assert "icon-bubble" in index
    assert 'class="ui-icon' in index
    assert "<svg" in index
    assert "freshness-ring" in index
    assert "panel-action" in index
    assert "diag-row-icon" in index
    assert "container-type:inline-size" in index
    assert "text-wrap:balance" in index
    assert "@media(max-width:1400px)" in index
    assert "@media(max-width:900px)" in index
    assert "@media(max-width:640px)" in index
    assert "@media(max-width:360px)" in index
    _assert_no_external_page_dependencies(index)


def test_excluded_release_summary_uses_curated_26h1_copy(tmp_path: Path) -> None:
    index = _render_landing(tmp_path)

    assert "existing devi." not in index
    assert "26H1 excluded for existing devices" in index
    assert CURATED_26H1_SUMMARY in index
    assert "Release policy notes" not in index
    assert "release-note" not in index
    assert "Release policy" in index


def test_pages_index_shows_generated_age_and_source_diagnostics_summary(tmp_path: Path) -> None:
    index = _render_landing(tmp_path)

    assert "<title>Windows 11 Release Guard</title>" in index
    assert '<link rel="icon" href="data:image/svg+xml,' in index
    assert (
        '<meta name="description" content="Windows 11 Release Guard dashboard for Windows 11 release compliance, '
        "signed public policy feed freshness, 25H2 target status, source diagnostics, and fleet administration "
        'checks.">'
        in index
    )
    assert '<link rel="canonical" href="https://avnsx.github.io/win11_release_guard/">' in index
    assert '<meta property="og:title" content="Windows 11 Release Guard">' in index
    assert '<meta property="og:url" content="https://avnsx.github.io/win11_release_guard/">' in index
    assert '<meta name="twitter:card" content="summary">' in index
    assert "<h1>Windows 11 Release Guard</h1>" in index
    assert 'id="policy-status-pill"' not in index
    assert "Generated age" not in index
    assert "Policy Feed Currency" in index
    assert "Published feed age" in index
    assert "days at render-time fallback" in index
    assert "Browser recalculates published policy feed age from the GitHub Actions generated timestamp" in index
    assert "Date.now" in index
    assert "Published policy feed currency: Unknown" in index
    assert "Full feed metadata" not in index
    assert '<details class="freshness-metadata"' not in index
    assert '<summary>Full feed metadata</summary>' not in index
    assert '<div class="freshness-metadata"><dl class="kv metadata">' in index
    assert ".freshness-metadata summary" not in index
    assert ".freshness-metadata[open]" not in index
    assert ".freshness-state.current{color:var(--ok)" in index
    assert ".freshness-state.refresh-due{color:var(--warn)" in index
    assert ".freshness-state.stale{color:var(--err)" in index
    assert ".freshness-state.unknown{color:var(--unknown)" in index
    assert "navigator.clipboard.writeText" in index
    assert "document.execCommand('copy')" in index
    assert "reportUiError" in index
    assert "data-ui-last-error" in index
    assert "dataset.uiLastError" in index
    assert "data-ui-error-count" in index
    assert "reportMissingNode" in index
    assert "missing '+name" in index
    assert "console.warn('Windows 11 Release Guard UI '+label+' failed')" in index
    assert "console.warn('Windows 11 Release Guard UI '+scope+' failed',error)" not in index
    assert "shutdownUi" in index
    assert "pagehide" in index
    # A download link fires beforeunload without leaving the page, so it must not stop the UI.
    assert "beforeunload" not in index
    assert "if(event&&event.persisted){return;}" in index
    assert "pageshow" in index
    assert "safeSetTimeout" in index
    assert "safeSetInterval" in index
    assert "safeRequestFrame" in index
    assert "safeCancelFrame" in index
    assert "timer setup" in index
    assert "interval setup" in index
    assert "animation frame request" in index
    assert "animation cancel" in index
    assert "timer cancel" in index
    assert "button.isConnected" in index
    assert "nav.isConnected" in index
    assert "passive:true" in index
    assert "header nav pointer" in index
    assert "header nav focus" in index
    assert "header nav leave" in index
    assert "header nav focusout" in index
    assert "freshness update" in index
    assert "freshness update','data" in index
    assert "@media(prefers-reduced-motion:reduce)" in index
    assert "animation:none!important" in index
    assert "epoch-copy" in index
    assert 'aria-label="Copy policy generated UTC epoch millisecond timestamp 1780236710000"' in index
    assert 'data-epoch="1780236710000"' in index
    assert "Sunday, 31 May 2026, 14:11:50 UTC" in index
    assert "<dt>UTC</dt>" not in index
    assert "<dt>Time (UTC):</dt>" in index
    assert "<dt>Published feed age:</dt>" in index
    assert "<dt>Workflow refresh:</dt>" in index
    assert "<dt>Fetched:</dt>" in index
    assert "<dt>Bytes:</dt>" in index
    assert "<dt>Algorithm</dt>" in index
    assert "<dt>key_id</dt>" in index
    assert "<dt>Policy SHA-256</dt>" in index
    assert "<dt>Signature status</dt>" in index
    assert "Refresh Due" in index
    assert "Stale" in index
    assert "Current" in index
    assert "Published policy feed is within the 14-day maintenance threshold." in index
    assert "Published policy feed refresh is due. Verify automation health before treating this data as production-current." in index
    assert "Published policy feed is stale. Do not treat this data as production-current until automation refresh succeeds." in index
    assert "Workflow refresh" in index
    assert "GitHub workflow static feed generation" in index
    assert "Release Health fetched" not in index
    assert "Atom feed fetched" not in index
    assert "Berlin, Germany" in index
    assert "Program versioning" not in index
    assert "Program Version" in index
    assert 'class="header-actions"' in index
    assert 'class="header-top-actions"' in index
    assert 'class="header-nav"' in index
    assert 'class="pypi-download-link"' in index
    assert 'class="nav-hover-label"' in index
    assert "nav-binoculars" not in index
    assert 'aria-label="Header navigation"' in index
    assert 'aria-label="Download win11_release_guard from PyPI"' in index
    assert 'href="https://pypi.org/project/win11-release-guard/"' in index
    assert 'src="assets/images/download_from_pypi.png"' in index
    assert 'alt="Download from PyPI"' in index
    assert ".pypi-download-link{display:inline-flex" in index
    header_actions_rule = re.search(r"\.header-actions\{([^}]*)\}", index)
    assert header_actions_rule
    assert "z-index:2" in header_actions_rule.group(1)
    assert "opacity:1" in header_actions_rule.group(1)
    assert "visibility:visible" in header_actions_rule.group(1)
    header_nav_rule = re.search(r"\.header-nav\{([^}]*)\}", index)
    assert header_nav_rule
    assert "z-index:2" in header_nav_rule.group(1)
    assert "opacity:1" in header_nav_rule.group(1)
    assert "visibility:visible" in header_nav_rule.group(1)
    nav_inner_rule = re.search(r"\.header-nav \.nav-inner\{([^}]*)\}", index)
    assert nav_inner_rule
    assert "opacity:1" in nav_inner_rule.group(1)
    assert "visibility:visible" in nav_inner_rule.group(1)
    assert "backdrop-filter" not in nav_inner_rule.group(1)
    title_version_rule = re.search(r"\.title-version-link\{([^}]*)\}", index)
    assert title_version_rule
    assert "z-index:2" in title_version_rule.group(1)
    assert "opacity:1" in title_version_rule.group(1)
    assert "visibility:visible" in title_version_rule.group(1)
    assert "backdrop-filter" not in title_version_rule.group(1)
    assert (tmp_path / "assets" / "images" / "download_from_pypi.png").is_file()
    assert 'id="policy-summary"' in index
    assert 'href="https://avnsx.github.io/win11_release_guard/"' in index
    _assert_glass_dashboard_ui_contract(index)
    assert "--item-size:42px" in index
    assert "@media(max-width:900px)" in index
    assert ".nav-hover-label{display:none}" in index
    assert 'data-nav-label="Repository"' in index
    assert '<a href="https://github.com/Avnsx/win11_release_guard" aria-label="Repository" data-nav-label="Repository"><svg class="github-icon"' in index
    assert 'data-nav-label="Dashboard"' in index
    assert index.index('data-nav-label="Repository"') < index.index('data-nav-label="Dashboard"')
    assert "Dashboard" in index
    assert 'data-nav-label="Write a Issue Ticket"' in index
    assert "Write a Issue Ticket" in index
    assert "https://github.com/Avnsx/win11_release_guard/issues/new" in index
    assert 'data-nav-label="Wiki"' in index
    assert "Wiki" in index
    assert "https://avnsx.github.io/win11_release_guard/wiki/" in index
    assert "https://github.com/Avnsx/win11_release_guard/wiki" not in index
    assert "animations/auto" not in index
    assert "auto-table-of-content" not in index
    assert "esm.sh" not in index
    assert "initHeaderNav" in index
    assert "requestAnimationFrame" in index
    assert "pointermove" in index
    assert "--label-x" in index
    assert "Bookmarks" not in index
    assert "Blogs" not in index
    assert "E-books" not in index
    assert "Account" not in index
    assert "Menu" not in index
    program_version = policy_generator_module.GENERATOR_VERSION.rsplit("/", 1)[-1]
    assert f"https://github.com/Avnsx/win11_release_guard/releases/tag/v{program_version}" in index
    assert "GitHub release tag" not in index
    assert "Logic ID" not in index
    assert "Policy generated by" not in index
    assert "public /api/v1 lane" not in index
    assert "signed policy document schema" not in index
    assert "API version" not in index
    assert "Policy Schema Version" not in index
    for removed_label in REMOVED_SCHEMA_PANEL_LABELS:
        assert removed_label not in index
    assert "Source diagnostics" in index
    assert "diag-feed" in index
    assert 'aria-label="Source diagnostic event feed"' in index
    assert index.count('class="dashboard-info-link"') == 6
    assert ".dashboard-info-link:after{display:none}" in index
    # The hover tooltip must stay anchored to its icon (connected to the caret),
    # not position:fixed (which a backdrop-filter ancestor pushes off-screen).
    assert ".dashboard-info-tooltip{position:absolute;top:calc(100% + 11px);left:50%;" in index
    assert ".dashboard-info-tooltip{position:fixed" not in index
    assert ".dashboard-info-tooltip-action{margin-top:7px;color:#0067c0" in index
    assert "class=\"ui-icon dashboard-info-icon\"" in index
    for info_link_html in index.split('class="dashboard-info-link"')[1:]:
        assert " title=" not in info_link_html.split(">", 1)[0]
    assert index.count(
        'class="dashboard-info-tooltip-action">Click to navigate to related wiki page</span>'
    ) == 6
    assert (
        'href="https://avnsx.github.io/win11_release_guard/wiki/Policy-Feed-and-Trust-Model/'
        '#baseline-and-preview-semantics" aria-label="Learn more about latest observed build semantics"'
        in index
    )
    assert (
        'href="https://avnsx.github.io/win11_release_guard/wiki/Policy-Feed-and-Trust-Model/'
        '#baseline-and-preview-semantics" aria-label="Learn more about required baseline semantics"'
        in index
    )
    assert (
        'href="https://avnsx.github.io/win11_release_guard/wiki/Anti-Static-Freshness/'
        '#dashboard-behavior" aria-label="Learn more about policy feed currency"'
        in index
    )
    assert (
        'href="https://avnsx.github.io/win11_release_guard/wiki/Source-Diagnostics/'
        '#diagnostic-sources" aria-label="Learn more about source diagnostics"'
        in index
    )
    assert (
        'href="https://avnsx.github.io/win11_release_guard/wiki/Policy-Feed-and-Trust-Model/'
        '#trust-rules" aria-label="Learn more about signature trust"'
        in index
    )
    assert (
        'href="https://avnsx.github.io/win11_release_guard/wiki/GitHub-Pages-Dashboard/'
        '#dashboard-sections" aria-label="Learn more about the programmatic API"'
        in index
    )
    assert "Newest Windows build found in Microsoft source data" in index
    assert "Minimum signed build this policy currently requires for existing Windows 11 fleet devices" in index
    assert "Shows when the current parsed policy results were last compiled" in index
    assert "Workflow timing is traceable in publish-policy.yml" in index
    assert "Source diagnostics show parser, drift, and upstream feed events" in index
    assert "distinguish informational notices from publish-blocking errors" in index
    assert "The public policy feed is accepted only after detached Ed25519 verification" in index
    assert "The API links expose the canonical signed policy, signature, manifest" in index
    assert "Feed currency compares the signed generation timestamp with live browser time" not in index
    assert "Learn how latest observed builds differ from the required broad-fleet baseline." not in index
    assert "Learn how detached Ed25519 signatures make the public feed trustworthy." not in index
    assert "Notices" in index
    assert "Warnings" in index
    assert "Errors" in index
    # 3 source notices plus one latest-update notice for each of the 4 dated Release Health versions.
    _assert_diag_count_tile(index, "notice", 7, "Notices")
    assert index.count(_diag_row_marker("notice")) == 7
    diagnostic_ids = _diagnostic_ids(index)
    assert len(diagnostic_ids) >= 3
    assert len(set(diagnostic_ids)) == len(diagnostic_ids)
    assert "data-diagnostic-id=&quot;" not in index
    assert 'id="source-diagnostics-feed"' in index
    assert (
        '<button type="button" class="panel-action diag-filter-reset" '
        'data-diagnostic-filter="all" aria-controls="source-diagnostics-feed" '
        'aria-pressed="true">View all</button>'
        '<button type="button" class="panel-action diag-expand-toggle" '
        'data-diagnostics-expand-toggle="true" aria-controls="source-diagnostics-feed" '
        'aria-expanded="false" aria-label="Expand Source Diagnostics view">Expand View</button>'
        in index
    )
    assert '<a class="panel-action" href="#source-health">Source health</a>' not in index
    assert '<button type="button" class="panel-action" data-source-health' not in index
    assert ">Source health</button>" not in index
    assert 'id="source-diagnostics-filter-status" class="diag-filter-status" aria-live="polite"' in index
    assert "Showing all 7 source diagnostic rows." in index
    assert 'id="source-diagnostics-empty" class="diag-filter-empty" hidden' in index
    assert "This category currently contains no entries." in index
    assert 'class="diag-feed-bar"' in index
    assert (
        '<button type="button" class="epoch-copy diag-export-copy" '
        'data-diagnostics-copy="visible-json" '
        'aria-label="Copy visible Source Diagnostics as JSON" '
        'title="Copy visible Source Diagnostics JSON">'
        in index
    )
    assert ".diag-feed-bar{display:flex;align-items:center;justify-content:space-between" in index
    assert "margin:-4px 0 -8px;min-height:22px" in index
    assert ".diag-export-copy{align-self:center;width:22px;height:22px;min-width:22px" in index
    assert "border-color:transparent;border-radius:5px;background:transparent;box-shadow:none" in index
    assert ".diag-export-copy:hover{border-color:transparent;background:transparent;box-shadow:none" in index
    assert '.diag-export-copy[data-copy-state="copied"]{border-color:transparent;background:transparent;color:var(--ok)}' in index
    assert '.diag-export-copy[data-copy-state="failed"]{border-color:transparent;background:transparent;color:var(--err)}' in index
    assert ".diag-export-copy svg{width:16px;height:16px}" in index
    assert ".diag-export-copy{align-self:flex-end;width:30px;height:30px" not in index
    assert "source diagnostics export copy" in index
    assert "data-diagnostics-copy=\"visible-json\"" in index
    assert "function visibleDiagnosticEntries()" in index
    assert "function sourceDiagnosticsExportPayload()" in index
    assert "export_schema:'win11_release_guard.source_diagnostics.visible.v1'" in index
    assert "dashboard_counts_by_severity:dashboardDiagnosticCounts()" in index
    assert "visible_counts_by_severity:visibleCounts" in index
    assert "active_filter:root.getAttribute('data-active-diagnostic-filter')||'all'" in index
    assert "diagnostic_id:row.getAttribute('data-diagnostic-id')||''" in index
    assert "issue_url:issueLink ? (issueLink.getAttribute('href')||null) : null" in index
    assert "display_index:index+1" in index
    assert "copyText(JSON.stringify(payload,null,2))" in index
    assert "DOM export of currently visible Source Diagnostics rows for technical triage" in index
    assert "These rows describe source, parser, drift, freshness, or dashboard-derived context" in index
    assert "do not override signed policy verdicts" in index
    assert "data-diagnostic-filter-root" in index
    assert "initDiagnosticFilters" in index
    assert "source diagnostics filter init" in index
    assert "source diagnostics filter" in index
    assert "guard('source diagnostics filter'" in index
    assert "source diagnostics filter','root" in index
    assert "source diagnostics filter','feed" in index
    assert "source diagnostics filter','controls" in index
    assert "source diagnostics filter','rows" in index
    assert "source diagnostics filter','status" in index
    assert "source diagnostics filter','empty state" in index
    assert "source diagnostics expansion','dashboard grid" in index
    assert "source diagnostics expansion','programmatic api" in index
    assert "source diagnostics expansion','expand toggle" in index
    assert "source diagnostics export copy','button" in index
    assert 'data-diagnostics-expanded="false"' in index
    assert "data-active-diagnostic-filter" in index
    assert ".dashboard-grid.diagnostics-expanded .source-diagnostics{grid-row:1/span 3;align-self:stretch}" in index
    assert ".dashboard-grid.diagnostics-expanded .programmatic-api{display:none!important}" in index
    assert '.source-diagnostics[data-diagnostics-expanded="true"] .diag-feed' in index
    assert "height:clamp(680px,82vh,900px)" in index
    assert "programmatic.hidden=diagnosticsExpanded" in index
    assert (
        "expandToggle.textContent=diagnosticsExpanded?'Collapse View':'Expand View'"
        in index
    )
    assert "diagnosticsExpanded?'Collapse Source Diagnostics view':'Expand Source Diagnostics view'" in index
    assert "grid.classList.toggle('diagnostics-expanded',diagnosticsExpanded)" in index
    assert "expandToggle.addEventListener('click',function(event){guard('source diagnostics expansion'" in index
    assert "setDiagnosticsExpanded(!diagnosticsExpanded)" in index
    assert "applyFilter(control.getAttribute('data-diagnostic-filter')||'all')" in index
    assert "block.hidden=false;block.open=diagnosticsExpanded;" in index
    assert ".diag-row[hidden]" in index
    assert ".diag-more[hidden]" in index
    assert "row.hidden=!match" in index
    assert "var labels={notice:'notice',warning:'warning',error:'error'}" in index
    assert "function normalizedFilter(value){return labels[value] ? value : '';}" in index
    assert "row.getAttribute('data-diagnostic-severity')===severity" in index
    assert "applyFilter(control.getAttribute('data-diagnostic-filter')||'all')" in index
    assert "status.textContent='Showing '+shown+' '+labels[severity]+' diagnostic '+rowWord(shown)+'.'" in index
    assert "status.textContent='No '+labels[severity]+' diagnostic rows are currently reported.'" in index
    assert "control.setAttribute('aria-pressed',severity ? String(value===severity) : String(value==='all'))" in index
    assert "aria-pressed" in index
    assert "data-diagnostic-filter" in index
    assert "data-diagnostic-severity" in index
    assert "data-diagnostic-id" in index
    assert ".diag-tile.notice{border-color:#bfdbfe" in index
    assert ".diag-tile.notice strong,.diag-tile.notice .diag-tile-icon{color:var(--blue)}" in index
    assert ".severity-badge.notice{color:var(--blue-strong)" in index
    assert ".diag-tile.warning{border-color:#f6d493" in index
    assert ".diag-tile.warning strong,.diag-tile.warning .diag-tile-icon{color:var(--warn)}" in index
    assert ".diag-tile.error{border-color:#f6b7ad" in index
    assert ".diag-tile.error strong,.diag-tile.error .diag-tile-icon{color:var(--err)}" in index
    assert ".diag-row.warning{border-color:#f6d493" in index
    assert ".diag-row.error{border-color:#f6b7ad" in index
    assert ".diag-feed{height:340px;min-height:340px;max-height:340px" in index
    assert "scrollbar-gutter:stable" in index
    assert "background:linear-gradient(180deg,rgba(255,255,255,.76),rgba(238,247,255,.68))" in index
    assert "scrollbar-color:#8eb7df rgba(232,243,255,.68)" in index
    assert ".diag-feed::-webkit-scrollbar-thumb" in index
    assert ".diag-events{gap:10px;padding:2px 4px 12px 2px}" in index
    assert "diag-row-icon" in index
    assert '<article class="diag-row notice" data-diagnostic-severity="notice" hidden' not in index
    assert '<article class="diag-row warning" data-diagnostic-severity="warning" hidden' not in index
    assert '<article class="diag-row error" data-diagnostic-severity="error" hidden' not in index
    assert "source-chip src-diagnostics" in index
    assert "source-chip src-atom-feed" in index
    assert "source-chip src-release-policy" in index
    assert "Signature" in index
    assert "Signature metadata" in index
    assert "Signature status" in index
    assert "signature-head" in index
    assert "signature-status-card" in index
    assert "Document trust state" in index
    assert "Detached signature metadata for the published policy artifact." in index
    assert "signature-kv" in index
    assert ".signature-panel{position:relative;overflow:hidden;display:flex;flex-direction:column" in index
    assert ".signature-panel:before{content:'';position:absolute;inset:0 0 auto;height:3px" in index
    assert ".signature-kv div{display:grid;grid-template-columns:minmax(104px,30%) minmax(0,1fr)" in index
    assert "<h2>Sources</h2>" not in index
    assert "Programmatic JSON endpoint for automation and fleet dashboards." not in index
    assert "Independent Windows release-policy dashboard. Not affiliated with Microsoft." in index
    assert "&copy; 2026 Mikail (&quot;Avnsx&quot;) C. Maintained as an open-source project." in index
    assert "Source code and documentation are available on" in index
    assert "provided under the" in index
    assert "footer-legal" not in index
    assert "footer-repo-line" not in index
    assert "footer-symbol" not in index
    assert "</span></a>.</span></p>" not in index
    assert 'class="footer-github" href="https://github.com/Avnsx/win11_release_guard"' in index
    assert "<span>GitHub</span>" in index
    assert (
        'class="footer-license-basic" href="https://github.com/Avnsx/win11_release_guard/blob/main/LICENSE.txt"'
        in index
    )
    assert "MIT license" in index
    assert "MIT license</a>.</p>" not in index
    assert 'class="footer-license"' not in index
    assert "github-icon" in index
    assert ">LICENSE.txt<" not in index
    assert "sources-panel" not in index
    assert "source-health" in index
    assert "source-tile" in index
    assert "source-status" in index
    assert "endpoint-pill" not in index
    assert "api-endpoints" in index
    assert "api-endpoint-row" in index
    assert "Signed policy JSON" in index
    assert "Primary signed policy document used by automation and fleet dashboards." in index
    assert "Detached signature" in index
    assert "Ed25519 signature that lets clients verify the policy before trusting it." in index
    assert "Policy manifest" in index
    assert "Compact metadata for hashes, freshness thresholds, source state, and API aliases." in index
    assert "API v1 policy alias" in index
    assert "Backward-compatible policy endpoint for stable reader integrations." in index
    assert "API v1 manifest alias" in index
    assert "Backward-compatible manifest endpoint for stable reader integrations." in index
    assert '<section class="panel span-5 signature-panel">' in index
    assert '<section class="panel span-7 programmatic-api">' in index
    assert ".programmatic-api{grid-column:6/span 7;grid-row:3}" in index
    assert ".signature-panel{grid-column:1/span 5;grid-row:3}" in index
    assert ".api-endpoint-row{grid-template-columns:auto minmax(0,1fr)" in index
    assert ".signature-panel,.programmatic-api{grid-column:1/-1}" in index
    assert "Programmatic API" in index
    _assert_no_external_page_dependencies(index)
    freshness = _freshness_data(index)
    assert freshness["generated_at_utc"] == "2026-05-31T14:11:50+00:00"
    assert freshness["generated_at_epoch_s"] == 1780236710
    assert freshness["warn_after_epoch_s"] == 1781446310
    assert freshness["stale_after_epoch_s"] == 1784124710
    assert freshness["max_ok_age_seconds"] == 14 * 24 * 60 * 60
    assert freshness["warning_age_seconds"] == 14 * 24 * 60 * 60
    assert freshness["strict_stale_age_seconds"] == 45 * 24 * 60 * 60
    assert freshness["freshness_policy"]["client_recomputes_age"] is True


def test_pages_index_derived_source_diagnostic_rows_do_not_render_ticket_links() -> None:
    excluded_entry = ReleasePolicyEntry(
        version="26H1",
        build_family=26200,
        latest_build="26200.1000",
        reason="new devices only",
    )
    preview_policy = ReleasePolicy(
        excluded_for_existing_devices=(excluded_entry,),
        source_diagnostics={"event_counts": {"notice": 0, "warning": 0, "error": 0}},
    )
    clear_id = policy_generator_module._source_diagnostic_row_id(
        policy_generator_module._clear_source_diagnostic_row()
    )
    excluded_id = policy_generator_module._source_diagnostic_row_id(
        policy_generator_module._excluded_release_diagnostic_rows(preview_policy)[0]
    )
    policy = ReleasePolicy(
        excluded_for_existing_devices=(excluded_entry,),
        source_diagnostics={
            "event_counts": {"notice": 0, "warning": 0, "error": 0},
            "issue_status": {
                clear_id: {
                    "number": 70,
                    "state": "open",
                    "url": "https://github.com/Avnsx/win11_release_guard/issues/70",
                },
                excluded_id: {
                    "number": 71,
                    "state": "open",
                    "url": "https://github.com/Avnsx/win11_release_guard/issues/71",
                },
            },
        },
    )

    index = render_policy_index(policy, policy_bytes=None, signature=None)
    HTMLParser().feed(index)

    assert "No source issues reported" in index
    assert "26H1 excluded for existing devices" in index
    assert (
        f'<article class="diag-row notice" data-diagnostic-severity="notice" data-diagnostic-id="{clear_id}">'
        in index
    )
    assert (
        f'<article class="diag-row notice" data-diagnostic-severity="notice" data-diagnostic-id="{excluded_id}">'
        in index
    )
    assert f'data-diagnostic-id="{clear_id}"' in index
    assert f'data-diagnostic-id="{excluded_id}"' in index
    assert index.count(_diag_row_marker("notice")) == 2
    _assert_diag_count_tile(index, "notice", 2, "Notices")
    assert "row.getAttribute('data-diagnostic-severity')===severity" in index
    assert "root.setAttribute('data-active-diagnostic-filter',severity||'all')" in index
    assert (
        '<button type="button" class="panel-action diag-filter-reset" '
        'data-diagnostic-filter="all" aria-controls="source-diagnostics-feed" '
        'aria-pressed="true">View all</button>'
    ) in index
    assert "#Ticket 70" not in index
    assert "#Ticket 71" not in index
    assert '<a class="diag-ticket-link"' not in index


def test_excluded_release_reason_summaries_do_not_end_with_half_words(tmp_path: Path) -> None:
    index = _render_landing(tmp_path)
    summaries = re.findall(
        r"<article class=\"diag-row notice\" data-diagnostic-severity=\"notice\" "
        r"data-diagnostic-id=\"wrg-source-diagnostic-v1:[0-9a-f]{16}\">.*?"
        r"<strong>[^<]*excluded for existing devices</strong>.*?"
        r"<p class=\"diag-technical-message\">(.*?)</p>",
        index,
        re.DOTALL,
    )

    assert summaries
    for summary in summaries:
        assert not summary.endswith("devi.")
        last_word = re.search(r"([A-Za-z]+)\.$", summary)
        assert last_word is None or len(last_word.group(1)) >= 5


def test_wiki_changelog_pages_use_wiki_scale_tokens() -> None:
    pages = policy_generator_module.render_changelog_pages()
    assert pages, "expected generated changelog pages"
    for name, html in pages.items():
        assert name.startswith("wiki/changelog/")
        assert WIKI_SCALE_DECLARATION in html


def test_pages_index_dashboard_scale_is_unchanged_by_wiki_fix(tmp_path: Path) -> None:
    # Guardrail: the wiki scale must not leak into the dashboard shell.
    dashboard = _render_landing(tmp_path)
    assert WIKI_VISUAL_SCALE not in dashboard
    _assert_no_external_page_dependencies(dashboard)
