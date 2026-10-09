"""Every public name a split module defined before the v0.6.0 refactor stays importable from that module."""

from __future__ import annotations

import importlib

import pytest

# Public (non-underscore) top-level definitions of each module at the last commit before it was split.
PUBLIC_NAMES = {
    "win11_release_guard.policy_generator": (
        "AtomFeedEntry", "CHANGELOG_SOURCE_PATH", "CURATED_EXCLUDED_RELEASE_SUMMARIES", "ChangelogSection",
        "DEFAULT_MAX_MSRC_CVRF_BYTES", "DEFAULT_MAX_SERVICING_TOC_BYTES", "DEFAULT_MAX_SUPPORT_ARTICLE_BYTES",
        "DEFAULT_SERVICING_TOC_URL", "GITHUB_ISSUES_BASE_URL", "GITHUB_LICENSE_URL", "GITHUB_RELEASES_BASE_URL",
        "GITHUB_REPOSITORY_URL", "MSRC_CVRF_API_BASE_URL", "MSRC_CVRF_CVE_LIMIT", "MSRC_CVRF_PRODUCT_LIMIT",
        "MSRC_CVRF_SEVERITY_LIMIT", "MSRC_UPDATE_GUIDE_URL", "MsrcCvrfFetcher", "PAGES_TIMEZONE",
        "PROGRAMMING_ERROR_TYPES", "PYPI_DOWNLOAD_IMAGE_PATH", "PYPI_PROJECT_URL", "ROBOTS_TXT", "RenderedWikiPage",
        "SOURCE_DIAGNOSTIC_ID_HASH_LENGTH", "SOURCE_DIAGNOSTIC_ID_PREFIX", "SourceText", "SupportArticleFetcher",
        "WIKI_FAVICON_DATA_URL", "WIKI_HELPER_PAGE_NAMES", "WIKI_SOURCE_DIR",
        "WINDOWS_UPDATE_PROBE_CORROBORATION_KIND", "WINDOWS_UPDATE_PROBE_OFFER_LIMIT",
        "WINDOWS_UPDATE_PROBE_UNAVAILABLE_KIND", "WikiHeading", "WikiPageSource", "WindowsUpdateProbe",
        "build_policy_from_sources", "generate_policy", "generate_policy_json", "load_source_text",
        "render_changelog_pages", "render_policy_index", "render_policy_manifest", "render_robots_txt",
        "render_sitemap_xml", "render_wiki_pages", "sign_policy_bytes", "write_changelog_pages",
        "write_policy_outputs", "write_wiki_pages"
    ),
    "win11_release_guard.remote_policy": (
        "HttpGet", "fetch_policy_bytes", "fetch_release_policy", "load_policy_bytes", "load_policy_text",
        "parse_windows11_release_health_html", "policy_from_dict", "policy_to_dict", "require_broad_target"
    ),
    "win11_release_guard.evaluator": (
        "derive_display_os_name", "derive_local_consensus", "determine_installed_build_origin", "evaluate",
        "evaluate_windows_update_state", "infer_installed_release", "local_signal_set", "select_broad_fleet_target",
        "select_quality_baseline"
    ),
    "win11_release_guard.models": (
        "BuildEvidenceSource", "EditionScope", "EvaluationResult", "EvaluationStatus",
        "InstalledBuildClassification", "InstalledBuildOrigin", "InstalledReleaseInference", "LocalConsensus",
        "LocalSignal", "LocalSignalSet", "LocalWindowsState", "QualityPolicy", "ReleaseHistoryEntry",
        "ReleasePolicy", "ReleasePolicyEntry", "ServicingChannel", "SourceProblem", "SourceStatus"
    ),
    "win11_release_guard.local_state": (
        "BUILD_SIGNAL_TRUST", "CURRENT_VERSION_REGISTRY_PATH", "DEFAULT_BUILD_FAMILY_RELEASES", "KERNEL_IMAGE_PATH",
        "NATIVE_OS_INFO_KEYS", "PANTHER_LOG_PATHS", "PRODUCT_INFO_EDITION_SCOPES", "SERVER_PRODUCT_INFO_CODES",
        "collect_local_windows_state", "extract_release", "get_local_windows_state",
        "infer_release_from_build_family"
    ),
    "win11_release_guard.api": (
        "PolicySourceResult", "SOURCE_STATUS_CLASSES", "SourceDegradationDecision", "check_current_system",
        "decide_source_degradation"
    ),
    "win11_release_guard.__main__": (
        "EXIT_ABOVE_BROAD_TARGET", "EXIT_ARGUMENT_ERROR", "EXIT_COMPLIANT", "EXIT_UNKNOWN_OR_POLICY_ERROR",
        "EXIT_UPDATE_REQUIRED", "PublicFetchResult", "RELEVANT_WUA_CLASSIFICATIONS", "main"
    ),
    "tools.sync_source_diagnostics_issues": (
        "ATOM_DIAGNOSTIC_ID_PREFIX", "ATOM_PUBLIC_ID_RE", "DEFAULT_CREATE_LIMIT", "DEFAULT_REQUEST_DELAY_SECONDS",
        "DIAGNOSTIC_ID_COMMENT_PREFIX", "DIAGNOSTIC_ID_COMMENT_RE", "DiagnosticIssue", "GitHubApiError",
        "GitHubClient", "LABEL_BY_SEVERITY", "LEGACY_NOTICE_LABEL", "MANAGED_LABELS", "REPOSITORY_RE",
        "RestGitHubClient", "SyncSummary", "comment_body", "diagnostics_from_policy", "issue_body",
        "issue_tip_markdown", "issue_title", "load_policy", "main", "stale_comment_body", "sync_diagnostics",
        "write_dry_run_report_output", "write_issue_status_output"
    ),
}


@pytest.mark.parametrize("module_name", sorted(PUBLIC_NAMES))
def test_split_module_keeps_its_public_names(module_name: str) -> None:
    module = importlib.import_module(module_name)
    missing = [name for name in PUBLIC_NAMES[module_name] if not hasattr(module, name)]
    assert missing == [], f"{module_name} no longer exposes {missing}; re-export them from the module that defines them"
