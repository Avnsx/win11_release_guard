from __future__ import annotations

import json
import hashlib
import re
from datetime import datetime, timezone
from html import escape as html_escape
from pathlib import Path
from urllib.parse import urlparse
import pytest
from tools import generate_policy as generate_policy_cli
from win11_release_guard.config import DEFAULT_POLICY_STRICT_STALE_AGE_SECONDS, DEFAULT_POLICY_URL, DEFAULT_POLICY_WARNING_AGE_SECONDS, DEFAULT_PUBLISHED_POLICY_URLS, DEFAULT_RELEASE_HEALTH_URL
from win11_release_guard.models import ReleasePolicy
import win11_release_guard.policy_generator as policy_generator_module
from win11_release_guard.policy_generator import generate_policy, render_robots_txt, write_policy_outputs
from win11_release_guard.policy_schema import GENERATOR_VERSION, is_source_diagnostic_id
from tests.support.policy_generator_helpers import (
    EXPECTED_ROBOTS_TXT,
    FIXTURES,
    _generated_output_bundle,
    _html,
    _pending_26h2_policy,
    _pending_b_release_events,
    _toc,
    offline_enrichment_fetchers,
)


REMOVED_SCHEMA_PANEL_LABELS = (
    "API " + "and schema",
    "Policy " + "schema",
    "Reader " + "range",
)


FRESH_FIXTURE_RENDER_REFERENCE_UTC = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _assert_local_fragment_links_resolve(html: str) -> None:
    ids = set(re.findall(r'\bid="([^"]+)"', html))
    fragments = re.findall(r'href="#([^"]*)"', html)
    assert "" not in fragments
    assert [fragment for fragment in fragments if fragment not in ids] == []


def test_generator_cli_rejects_invalid_source_diagnostic_issue_status_key(tmp_path, capsys, offline_enrichment_fetchers):
    output_dir = tmp_path / "site"
    issue_status = tmp_path / "issue-status.json"
    issue_status.write_text(json.dumps({"issue_status": {"not-a-diagnostic-id": {"number": 42}}}), encoding="utf-8")

    code = generate_policy_cli.main([
        "--release-health-html",
        str(FIXTURES / "windows11-release-health.html"),
        "--servicing-toc",
        str(FIXTURES / "windows11-servicing-toc.json"),
        "--output-dir",
        str(output_dir),
        "--source-diagnostic-issue-status-file",
        str(issue_status),
    ])

    captured = capsys.readouterr()
    assert code == 1
    assert "source diagnostic issue status keys must be deterministic diagnostic IDs" in captured.err


def test_generator_cli_rejects_noncanonical_source_diagnostic_issue_status_url(tmp_path, capsys, offline_enrichment_fetchers):
    output_dir = tmp_path / "site"
    diagnostic_id = "wrg-source-diagnostic-v1:1111111111111111"
    issue_status = tmp_path / "issue-status.json"
    issue_status.write_text(
        json.dumps(
            {
                "issue_status": {
                    diagnostic_id: {
                        "number": 42,
                        "state": "open",
                        "url": "https://github.com/Avnsx/win11_release_guard/issues/42?token=blocked",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    code = generate_policy_cli.main([
        "--release-health-html",
        str(FIXTURES / "windows11-release-health.html"),
        "--servicing-toc",
        str(FIXTURES / "windows11-servicing-toc.json"),
        "--output-dir",
        str(output_dir),
        "--source-diagnostic-issue-status-file",
        str(issue_status),
    ])

    captured = capsys.readouterr()
    assert code == 1
    assert "source diagnostic issue status URL must be canonical" in captured.err


def test_signed_pages_output_contains_manifest_aliases_and_polished_index(tmp_path):
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=_toc(),
        generated_at_utc="2026-05-31T14:11:50+00:00",
        signature_status="valid",
    )
    written = write_policy_outputs(
        policy,
        output_dir=tmp_path,
        signing_key="krtF2muLgucP7JDVNKk2g+YQfz92c7xM49dzszxHxjs=",
        key_id="test-policy-key",
        write_index=True,
        write_robots=True,
        write_sitemap=True,
        write_manifest=True,
        generated_age_reference=FRESH_FIXTURE_RENDER_REFERENCE_UTC,
    )

    expected = {
        "index.html",
        "windows-release-policy.json",
        "windows-release-policy.json.sig",
        "policy-manifest.json",
        "api/v1/policy.json",
        "api/v1/policy.sig",
        "api/v1/manifest.json",
        "robots.txt",
        "sitemap.xml",
        ".nojekyll",
        "wiki/index.html",
        "wiki/Quick-Start/index.html",
        "wiki/changelog/index.html",
        "wiki/changelog/v0.3.3/index.html",
        "wiki/changelog/v0.3.2/index.html",
    }
    actual = {path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*") if path.is_file()}

    assert expected <= actual
    assert (tmp_path / "api/v1/policy.json").read_bytes() == (tmp_path / "windows-release-policy.json").read_bytes()
    assert (tmp_path / "api/v1/policy.sig").read_bytes() == (tmp_path / "windows-release-policy.json.sig").read_bytes()
    assert (tmp_path / "api/v1/manifest.json").read_bytes() == (tmp_path / "policy-manifest.json").read_bytes()

    policy_bytes = (tmp_path / "windows-release-policy.json").read_bytes()
    signature_bytes = (tmp_path / "windows-release-policy.json.sig").read_bytes()
    signature_record = json.loads(signature_bytes.decode("utf-8"))
    manifest = json.loads((tmp_path / "policy-manifest.json").read_text(encoding="utf-8"))
    generated_policy = json.loads((tmp_path / "windows-release-policy.json").read_text(encoding="utf-8"))
    api_policy = json.loads((tmp_path / "api/v1/policy.json").read_text(encoding="utf-8"))
    api_manifest = json.loads((tmp_path / "api/v1/manifest.json").read_text(encoding="utf-8"))
    assert manifest["policy_sha256"] == hashlib.sha256(policy_bytes).hexdigest()
    assert manifest["signature_sha256"] == hashlib.sha256(signature_bytes).hexdigest()
    assert manifest["signature_algorithm"] == "ed25519"
    assert manifest["key_id"] == "test-policy-key"
    assert manifest["signature_sha256"]
    assert "signature" not in manifest
    assert signature_record["signature"] not in (tmp_path / "index.html").read_text(encoding="utf-8")
    assert signature_record["signature"] not in (tmp_path / "policy-manifest.json").read_text(encoding="utf-8")
    assert signature_record["signature"] not in (tmp_path / "api/v1/manifest.json").read_text(encoding="utf-8")
    assert manifest["policy_schema_version"] == 1
    assert manifest["min_reader_schema_version"] == 1
    assert manifest["max_reader_schema_version"] == 1
    assert manifest["api_version"] == "v1"
    assert manifest["compatibility"]["required_core_schema_version"] == 1
    assert manifest["generated_at_epoch_s"] == 1780236710
    assert manifest["warn_after_epoch_s"] == 1781446310
    assert manifest["stale_after_epoch_s"] == 1784124710
    assert manifest["strict_stale_after_epoch_s"] == 1784124710
    assert manifest["max_ok_age_seconds"] == DEFAULT_POLICY_WARNING_AGE_SECONDS
    assert manifest["warning_age_seconds"] == DEFAULT_POLICY_WARNING_AGE_SECONDS
    assert manifest["strict_stale_age_seconds"] == DEFAULT_POLICY_STRICT_STALE_AGE_SECONDS
    assert manifest["freshness_policy"] == {
        "warning_after_days": 14,
        "strict_stale_after_days": 45,
        "max_ok_age_seconds": DEFAULT_POLICY_WARNING_AGE_SECONDS,
        "warning_age_seconds": DEFAULT_POLICY_WARNING_AGE_SECONDS,
        "strict_stale_age_seconds": DEFAULT_POLICY_STRICT_STALE_AGE_SECONDS,
        "client_recomputes_age": True,
    }
    assert api_policy == generated_policy
    assert api_manifest == manifest
    assert manifest["timezone"] == "Europe/Berlin"
    assert manifest["status"] == "Policy current"
    assert manifest["published_urls"]["policy"] == DEFAULT_POLICY_URL
    assert manifest["published_urls"]["api_policy"].endswith("/api/v1/policy.json")
    assert manifest["source_diagnostics"]["servicing_toc"]["newest_servicing_build"] == "26200.8460"
    source_diagnostic_ids = [
        event["id"] for event in generated_policy["source_diagnostics"]["events"]
    ]
    assert source_diagnostic_ids
    assert all(
        re.fullmatch(r"wrg-source-diagnostic-v1:[0-9a-f]{16}", diagnostic_id)
        for diagnostic_id in source_diagnostic_ids
    )
    assert [
        event["id"] for event in manifest["source_diagnostics"]["events"]
    ] == source_diagnostic_ids
    assert manifest["broad_target_existing_devices"]["latest_observed_build"] == "26200.8457"
    assert manifest["broad_target_existing_devices"]["required_baseline_build"] == "26200.8457"
    assert manifest["required_baseline_build"] == "26200.8457"
    assert generated_policy["published_urls"] == DEFAULT_PUBLISHED_POLICY_URLS
    assert generated_policy["metadata"]["freshness_policy"]["warning_after_days"] == 14
    assert generated_policy["metadata"]["freshness_policy"]["strict_stale_after_days"] == 45
    assert generated_policy["metadata"]["freshness_policy"]["client_recomputes_age"] is True
    roundtripped_policy = ReleasePolicy.from_dict(generated_policy)
    assert roundtripped_policy.metadata["freshness_policy"]["warning_age_seconds"] == DEFAULT_POLICY_WARNING_AGE_SECONDS
    assert DEFAULT_RELEASE_HEALTH_URL in generated_policy["source_urls"]
    source_hosts = {urlparse(url).hostname for url in generated_policy["source_urls"]}
    assert "avnsx.github.io" not in source_hosts

    sitemap = (tmp_path / "sitemap.xml").read_text(encoding="utf-8")
    assert "https://avnsx.github.io/win11_release_guard/wiki/changelog/" in sitemap
    assert "https://avnsx.github.io/win11_release_guard/wiki/changelog/v0.3.3/" in sitemap
    assert "https://avnsx.github.io/win11_release_guard/wiki/changelog/v0.3.2/" in sitemap

    changelog = (tmp_path / "wiki/changelog/index.html").read_text(encoding="utf-8")
    changelog_version = (tmp_path / "wiki/changelog/v0.3.3/index.html").read_text(encoding="utf-8")
    changelog_version_032 = (tmp_path / "wiki/changelog/v0.3.2/index.html").read_text(encoding="utf-8")
    wiki_home = (tmp_path / "wiki/index.html").read_text(encoding="utf-8")
    wiki_quick_start = (tmp_path / "wiki/Quick-Start/index.html").read_text(encoding="utf-8")
    assert "<title>Changelog | Windows 11 Release Guard Wiki</title>" in changelog
    assert 'id="wiki-content" class="wiki-content changelog-content" tabindex="-1"' in changelog
    assert 'class="wiki-breadcrumbs" aria-label="Breadcrumb"' in changelog
    assert 'class="skip-link" href="#wiki-content"' in changelog
    assert '<link rel="canonical" href="https://avnsx.github.io/win11_release_guard/wiki/changelog/">' in changelog
    assert '<meta property="og:url" content="https://avnsx.github.io/win11_release_guard/wiki/changelog/">' in changelog
    assert '<meta name="twitter:card" content="summary">' in changelog
    assert "Windows 11 release compliance" in changelog
    assert "signed public policy feed" in changelog
    assert "RMM" in changelog
    assert changelog.index("[Unreleased]") < changelog.index("v0.3.3 - 2026-06-11")
    assert changelog.index("v0.3.3 - 2026-06-11") < changelog.index("v0.3.2 - 2026-06-10")
    assert changelog.index("v0.3.2 - 2026-06-10") < changelog.index("v0.3.1 - 2026-06-05")
    assert "Version 0.3.3 hardens how Microsoft source evidence is matched and validated" in changelog
    assert "Version 0.3.2 adds the first-party Pages wiki and changelog" in changelog
    assert "https://avnsx.github.io/win11_release_guard/wiki/Release-v0.3.3/" in changelog
    assert "Versions" in changelog
    assert ".changelog-content h2[id]" in changelog
    assert 'class="wiki-heading-icon wiki-icon-changelog"' in changelog
    assert 'class="wiki-heading-icon wiki-icon-release"' in changelog
    assert "white-space: nowrap;" in changelog
    assert ">pre-release</a>" in changelog
    assert 'class="changelog-pre-release-badge">pre-release</a>' in changelog
    assert "border-color: #f0c74c;" in changelog
    assert "margin-top: 4.75rem;" in changelog
    assert "margin: -0.25rem 0 1.9rem 1.05rem;" in changelog
    assert ".changelog-version-nav ol {" in changelog
    assert "margin: 0.3rem 0 0 0.65rem;" in changelog
    assert ".changelog-version-nav .version-meta a {" in changelog
    assert "font-size: 0.76rem;" in changelog
    assert ">Changelog section</a>" in changelog
    assert ">Version page</a>" in changelog
    assert ">GitHub release</a>" in changelog
    assert 'title="Open pre-release section" class="changelog-pre-release-badge">pre-release</a>' in changelog
    assert 'title="Open section on Pages changelog">Section</a>' in changelog
    assert 'title="Open version page">Version page</a>' in changelog
    assert 'title="Open GitHub release">GH release</a>' in changelog
    assert 'href="#v0.3.3"' in changelog
    assert 'href="https://github.com/Avnsx/win11_release_guard/releases/tag/v0.3.3"' in changelog
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/changelog/v0.3.3/"' in changelog
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/changelog/v0.3.2/"' in changelog
    assert "<title>Changelog v0.3.3 | Windows 11 Release Guard Wiki</title>" in changelog_version
    assert (
        '<link rel="canonical" href="https://avnsx.github.io/win11_release_guard/wiki/changelog/v0.3.3/">'
        in changelog_version
    )
    assert "Multi-build Atom entries get unique Source Diagnostic IDs." in changelog_version
    assert "<title>Changelog v0.3.2 | Windows 11 Release Guard Wiki</title>" in changelog_version_032
    assert "Python 3.13 and 3.14 support and CI coverage." in changelog_version_032
    assert "<title>Windows 11 Release Guard Wiki</title>" in wiki_home
    assert 'class="wiki-brand-icon"' in wiki_home
    assert '<a class="wiki-brand" href="https://avnsx.github.io/win11_release_guard/">' in wiki_home
    assert 'id="wiki-content" class="wiki-content" tabindex="-1"' in wiki_home
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/changelog/"' in wiki_home
    assert wiki_home.index('href="https://avnsx.github.io/win11_release_guard/wiki/changelog/"') < wiki_home.index(
        'href="https://avnsx.github.io/win11_release_guard/wiki/Quick-Start/"'
    )
    assert "prefers-reduced-motion: reduce" in wiki_home
    assert "@media (max-width: 860px)" in wiki_home
    assert '<link rel="canonical" href="https://avnsx.github.io/win11_release_guard/wiki/">' in wiki_home
    assert "signed public JSON policy feed" in wiki_home
    assert '<meta property="og:site_name" content="Windows 11 Release Guard">' in wiki_home
    assert '<link rel="canonical" href="https://avnsx.github.io/win11_release_guard/wiki/Quick-Start/">' in wiki_quick_start
    for generated_html in (wiki_home, wiki_quick_start, changelog, changelog_version, changelog_version_032):
        _assert_local_fragment_links_resolve(generated_html)
        assert generated_html.count("<style>") == 1
        assert generated_html.count("</style>") == 1
    for rendered_changelog in (changelog, changelog_version, changelog_version_032):
        lower_changelog = rendered_changelog.lower()
        assert 'data-section-scrollspy="true"' in rendered_changelog
        assert ".wiki-sidebar a.is-active-section" in rendered_changelog
        assert 'if (!sidebar || !content) return;' in rendered_changelog
        assert "script src" not in lower_changelog
        assert 'rel="stylesheet"' not in lower_changelog
        assert "cdn.jsdelivr" not in lower_changelog
        assert "esm.sh" not in lower_changelog
        assert "fonts.googleapis" not in lower_changelog

    index = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "<title>Windows 11 Release Guard</title>" in index
    assert '<link rel="icon" href="data:image/svg+xml,' in index
    assert "<h1>Windows 11 Release Guard</h1>" in index
    assert "Broad-fleet Windows 11 release and quality baseline dashboard." in index
    assert 'class="header-nav"' in index
    assert 'class="pypi-download-link"' in index
    assert 'href="https://pypi.org/project/win11-release-guard/"' in index
    assert 'src="assets/images/download_from_pypi.png"' in index
    assert 'class="nav-hover-label"' in index
    assert "nav-binoculars" not in index
    assert "main{position:relative;z-index:1;width:calc(100% - 80px);max-width:1580px" in index
    assert "backdrop-filter:blur(28px)" in index
    assert "body:before" in index
    assert "body:after" in index
    assert 'class="winmark"' in index
    assert "kpi-card" in index
    assert "icon-bubble" in index
    assert 'class="ui-icon' in index
    assert "freshness-ring" in index
    assert "panel-action" in index
    assert "diag-row-icon" in index
    assert "--item-size:42px" in index
    assert ".nav-hover-label{display:none}" in index
    assert 'id="policy-summary"' in index
    assert 'href="https://avnsx.github.io/win11_release_guard/"' in index
    assert 'data-nav-label="Dashboard"' in index
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
    assert "reportUiError" in index
    assert "data-ui-last-error" in index
    assert "dataset.uiLastError" in index
    assert "data-ui-error-count" in index
    assert "reportMissingNode" in index
    assert "shutdownUi" in index
    assert "pagehide" in index
    assert "beforeunload" in index
    assert "safeSetTimeout" in index
    assert "safeSetInterval" in index
    assert "safeRequestFrame" in index
    assert "safeCancelFrame" in index
    assert "header nav leave" in index
    assert "header nav focusout" in index
    assert "button.isConnected" in index
    assert "nav.isConnected" in index
    assert "freshness update" in index
    assert "freshness update','data" in index
    assert "Bookmarks" not in index
    assert "Blogs" not in index
    assert "E-books" not in index
    assert "Account" not in index
    assert "Menu" not in index
    assert "Policy current" not in index
    assert "25H2" in index
    assert "Latest observed" in index
    assert "Required baseline" in index
    assert "26200" in index
    assert "26200.8457" in index
    assert "b_release_only" in index
    assert "26H1 excluded for existing devices" in index
    assert (
        "26H1 is excluded for existing devices because Microsoft scopes it to new devices and does not offer "
        "it as an in-place update from 24H2/25H2."
    ) in index
    assert "Release policy notes" not in index
    assert "release-note" not in index
    assert "No source issues reported" in index
    assert index.find("No source issues reported") < index.find("26H1 excluded for existing devices")
    assert "existing devi." not in index
    assert "Microsoft Release Health" in index
    assert "Microsoft servicing index" in index
    assert "Ed25519" in index or "ed25519" in index
    assert "test-policy-key" in index
    assert "/windows-release-policy.json" in index
    assert "/windows-release-policy.json.sig" in index
    assert "/policy-manifest.json" in index
    assert "/api/v1/policy.json" in index
    assert "/api/v1/manifest.json" in index
    assert "Programmatic JSON endpoint" not in index
    assert "Independent Windows release-policy dashboard. Not affiliated with Microsoft." in index
    assert "&copy; 2026 Mikail (&quot;Avnsx&quot;) C. Maintained as an open-source project." in index
    assert "Source code and documentation are available on" in index
    assert "provided under the" in index
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
    assert "https://github.com/Avnsx/win11_release_guard/blob/main/LICENSE.txt" in index
    assert "github-icon" in index
    assert ">LICENSE.txt<" not in index
    assert "Europe/Berlin" not in index
    assert "Sunday, 31 May 2026, 16:11:50 CEST" in index
    assert "Generated age" not in index
    assert "Policy Feed Currency" in index
    assert "Published feed age" in index
    assert "days at render-time fallback" in index
    assert "Full feed metadata" not in index
    assert '<details class="freshness-metadata"' not in index
    assert '<summary>Full feed metadata</summary>' not in index
    assert '<div class="freshness-metadata"><dl class="kv metadata">' in index
    assert ".freshness-metadata summary" not in index
    assert ".freshness-metadata[open]" not in index
    assert "Browser recalculates published policy feed age from the GitHub Actions generated timestamp" in index
    assert "Date.now" in index
    assert "Current" in index
    assert "Refresh Due" in index
    assert "Stale" in index
    assert "Published policy feed currency: Unknown" in index
    assert "Workflow refresh" in index
    assert "GitHub workflow static feed generation" in index
    assert "Release Health fetched" not in index
    assert "Atom feed fetched" not in index
    assert "Berlin, Germany" in index
    assert "Program versioning" not in index
    assert "Program Version" in index
    program_version = GENERATOR_VERSION.rsplit("/", 1)[-1]
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
    assert "data-diagnostic-id" in index
    assert f'data-diagnostic-id="{source_diagnostic_ids[0]}"' in index
    assert "data-diagnostic-filter-root" in index
    assert "guard('source diagnostics filter'" in index
    assert "source diagnostics filter','root" in index
    assert "source diagnostics filter','status" in index
    assert 'id="source-diagnostics-empty" class="diag-filter-empty" hidden' in index
    assert "This category currently contains no entries." in index
    assert '<article class="diag-row notice" data-diagnostic-severity="notice" hidden' not in index
    assert "<h2>Sources</h2>" not in index
    assert "sources-panel" not in index
    assert "source-health" in index
    assert "source-tile ok" in index
    assert "source-status" in index
    assert "Signed policy trust" in index
    assert "Signature status" in index
    assert "signature-head" in index
    assert "signature-status-card" in index
    assert "Document trust state" in index
    assert "Detached signature metadata for the published policy artifact." in index
    assert "signature-kv" in index
    assert "<dt>Algorithm</dt>" in index
    assert "<dt>key_id</dt>" in index
    assert "<dt>Policy SHA-256</dt>" in index
    assert "<dt>Signature status</dt>" in index
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
    assert ".signature-panel,.programmatic-api{grid-column:1/-1}" in index
    assert "Notices" in index
    assert "Warnings" in index
    assert "Errors" in index
    assert "auth" not in index.lower()
    assert "token" not in index.lower()
    assert "private-" + "key" not in index.lower()
    assert "http://cdn" not in index.lower()
    assert "https://cdn" not in index.lower()
    assert 'rel="stylesheet"' not in index.lower()
    assert "@import" not in index.lower()
    assert "fonts.googleapis" not in index.lower()
    assert "fonts.gstatic" not in index.lower()
    assert '<script type="application/json" id="policy-freshness-data">' in index
    assert "script src" not in index.lower()

    assert render_robots_txt() == EXPECTED_ROBOTS_TXT
    assert (tmp_path / "robots.txt").read_bytes() == EXPECTED_ROBOTS_TXT.encode("utf-8")

    sitemap = (tmp_path / "sitemap.xml").read_text(encoding="utf-8")
    assert "https://avnsx.github.io/win11_release_guard/" in sitemap
    assert "https://avnsx.github.io/win11_release_guard/windows-release-policy.json" in sitemap
    assert "https://avnsx.github.io/win11_release_guard/policy-manifest.json" in sitemap


# ---------------------------------------------------------------------------
# Source-aware baseline-notice security wording. The user-facing summary must
# only claim MSRC confirmation for msrc_cvrf evidence, attribute Support article
# evidence to Microsoft Support, and stay neutral when evidence is absent.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "evidence_source, expected_phrase, forbidden_phrase",
    [
        ("msrc_cvrf", "MSRC confirms it as a security update", None),
        (
            "support_article",
            "Microsoft Support notes it includes the security update",
            "MSRC confirms",
        ),
    ],
)
def test_baseline_notice_summary_security_wording_is_source_aware(
    evidence_source: str, expected_phrase: str, forbidden_phrase: str | None
) -> None:
    summary = policy_generator_module._baseline_notice_summary(
        release="25H2",
        build="26200.8655",
        kb_article="KB5094126",
        update_type="2026-06 B",
        official_release_date="2026-06-09",
        is_security=True,
        security_evidence_source=evidence_source,
    )
    assert expected_phrase in summary
    assert "B.;" not in summary
    if forbidden_phrase is not None:
        assert forbidden_phrase not in summary


@pytest.mark.parametrize("evidence_source", ["unavailable", "none", "unknown", "", None])
def test_baseline_notice_summary_stays_neutral_without_trusted_evidence(evidence_source) -> None:
    summary = policy_generator_module._baseline_notice_summary(
        release="25H2",
        build="26200.8655",
        kb_article="KB5094126",
        update_type="2026-06 B",
        official_release_date="2026-06-09",
        is_security=None,
        security_evidence_source=evidence_source,
    )
    assert "MSRC confirms" not in summary
    assert "Microsoft Support notes" not in summary
    assert "Security classification is unavailable from the checked enrichment source." in summary
    # No raw status enums or punctuation artifacts leak into human copy.
    for token in ("not_security", "msrc_cvrf", "support_article", "B.;", "security evidence is"):
        assert token not in summary


def test_baseline_notice_summary_non_security_has_no_confirmation() -> None:
    summary = policy_generator_module._baseline_notice_summary(
        release="25H2",
        build="26200.8655",
        kb_article="KB5094126",
        update_type="2026-06 B",
        official_release_date="2026-06-09",
        is_security=False,
        security_evidence_source="none",
    )
    assert "MSRC confirms" not in summary
    assert "Microsoft Support notes" not in summary
    assert "Checked evidence does not classify it as a security update." in summary
    for token in ("not_security", "msrc_cvrf", "support_article", "B.;"):
        assert token not in summary


# ---------------------------------------------------------------------------
# Baseline-notice date hardening: impossible ISO-shaped dates degrade instead of
# crashing; non-zero-padded dates are accepted and normalized; window stays 14d.
# ---------------------------------------------------------------------------


def _history_row_with_date(date_text: str) -> "policy_generator_module.ReleaseHistoryEntry":
    return policy_generator_module.ReleaseHistoryEntry(
        release="25H2",
        build_family=26200,
        build="26200.8655",
        availability_date=date_text,
        update_type="2026-06 B",
        update_type_letter="B",
        kb_article="KB5094126",
    )


@pytest.mark.parametrize(
    "bad_date",
    ["2026-02-30", "2026-13-01", "2026-00-10", "2026-06-00", "2026-06-31", "not-a-date", "20260609", ""],
)
def test_baseline_notice_window_degrades_on_impossible_or_malformed_dates(bad_date: str) -> None:
    row = _history_row_with_date(bad_date)
    assert policy_generator_module._baseline_notice_visibility_window(row) is None
    assert (
        policy_generator_module._baseline_notice_is_active(
            row, generated_at_utc="2026-06-15T00:00:00+00:00"
        )
        is False
    )


@pytest.mark.parametrize(
    "source_date, expected",
    [("2026-6-9", "2026-06-09"), ("2026-06-09", "2026-06-09"), ("2026-12-1", "2026-12-01")],
)
def test_baseline_notice_window_accepts_and_normalizes_non_zero_padded_dates(
    source_date: str, expected: str
) -> None:
    window = policy_generator_module._baseline_notice_visibility_window(
        _history_row_with_date(source_date)
    )
    assert window is not None
    official_date, precision, visible_from, visible_until = window
    assert official_date == expected
    assert precision == "date"
    assert visible_from == f"{expected}T00:00:00Z"
    from datetime import datetime

    delta = datetime.fromisoformat(visible_until.replace("Z", "+00:00")) - datetime.fromisoformat(
        visible_from.replace("Z", "+00:00")
    )
    assert delta.days == 14


# ---------------------------------------------------------------------------
# Repo-controlled Markdown reads must not crash generation on invalid UTF-8.
# ---------------------------------------------------------------------------


def test_read_markdown_source_preserves_valid_and_replaces_invalid(tmp_path: Path) -> None:
    good = tmp_path / "good.md"
    good.write_text("# Title\n\nAll good - ünïcödé.\n", encoding="utf-8")
    assert policy_generator_module._read_markdown_source(good) == (
        "# Title\n\nAll good - ünïcödé.\n"
    )

    bad = tmp_path / "bad.md"
    bad.write_bytes(b"# Title\n\nbroken \xff\xfe bytes\n")
    text = policy_generator_module._read_markdown_source(bad)
    assert "broken" in text
    assert "�" in text


def test_render_wiki_pages_survives_invalid_utf8_source(tmp_path: Path) -> None:
    wiki_dir = tmp_path / "wiki"
    wiki_dir.mkdir()
    (wiki_dir / "Home.md").write_text("# Home\n\nWelcome.\n", encoding="utf-8")
    (wiki_dir / "Broken-Page.md").write_bytes(b"# Broken \xff\xfe Page\n\nContent.\n")

    pages = policy_generator_module.render_wiki_pages(wiki_dir=wiki_dir)
    assert pages
    assert any(name.endswith("index.html") for name in pages)


# ---------------------------------------------------------------------------
# Wiki/changelog Markdown: a bullet authored across wrapped source lines renders
# as one list item with correct hanging indent, not a spilled full-width paragraph.
# ---------------------------------------------------------------------------


def test_wiki_list_merges_wrapped_bullet_continuation_lines() -> None:
    markdown = (
        "* First bullet that wraps across\n"
        "  multiple source lines into one item.\n"
        "* Second bullet that also wraps to a\n"
        "  second source line.\n"
    )
    html, _headings, _broken = policy_generator_module._render_wiki_markdown_fragment(markdown, {})
    assert (
        "<ul>"
        "<li>First bullet that wraps across multiple source lines into one item.</li>"
        "<li>Second bullet that also wraps to a second source line.</li>"
        "</ul>"
    ) in html
    # The wrapped continuation must not leak out as a separate full-width paragraph.
    assert "<p>multiple source lines" not in html
    assert "<p>second source line" not in html


def test_wiki_list_continuation_stops_at_blank_line_then_paragraph() -> None:
    markdown = (
        "* A bullet item.\n"
        "\n"
        "A following paragraph after the list.\n"
    )
    html, _headings, _broken = policy_generator_module._render_wiki_markdown_fragment(markdown, {})
    assert "<ul><li>A bullet item.</li></ul>" in html
    assert "<p>A following paragraph after the list.</p>" in html


def test_generated_pending_b_release_notice_is_dashboard_only(tmp_path):
    from tools.sync_source_diagnostics_issues import diagnostics_from_policy

    outputs = _generated_output_bundle(_pending_26h2_policy(), tmp_path)
    data = outputs["policy"]

    events = _pending_b_release_events(data)
    assert len(events) == 1
    event = events[0]
    assert event["severity"] == "notice"
    assert is_source_diagnostic_id(event["id"])
    assert event["message"] in data["source_diagnostics"]["notices"]
    assert event["message"] not in data["source_diagnostics"]["warnings"]
    assert all(issue.kind != "broad_target_pending_b_release" for issue in diagnostics_from_policy(data))
    index = outputs["index"]
    assert "Windows 11 26H2 awaits its first B release" in index
    assert html_escape(event["user_message"]) in index
    assert "stays the broad target with required baseline 26200.9445" in event["user_message"]
    assert "ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE" in event["user_message"]
    assert "the broad target stays on 25H2 (required baseline 26200.9445)" in index
