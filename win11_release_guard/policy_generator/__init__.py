from __future__ import annotations

from ..config import DEFAULT_HTTP_TIMEOUT_SECONDS  # noqa: F401  re-exported
from ..models import ReleaseHistoryEntry  # noqa: F401  re-exported
from ..policy_schema import GENERATOR_VERSION  # noqa: F401  re-exported
from .assembly import (
    _raise_on_client_target_disagreement,
    build_policy_from_sources,
    generate_policy,
    generate_policy_json,
)
from .baseline_notice import _baseline_notice_is_active, _baseline_notice_summary, _baseline_notice_visibility_window
from .pages.changelog import render_changelog_pages, write_changelog_pages
from .constants import (
    DEFAULT_MAX_MSRC_CVRF_BYTES,
    DEFAULT_MAX_SUPPORT_ARTICLE_BYTES,
    DEFAULT_SERVICING_TOC_URL,
    SOURCE_DIAGNOSTIC_ID_PREFIX,
)
from .pages.dashboard import render_policy_index
from .diagnostic_ids import _source_diagnostic_id_for_event
from .pages.diagnostic_panel import _clear_source_diagnostic_row
from .pages.diagnostic_rows import (
    _excluded_release_diagnostic_rows,
    _source_diagnostic_row_from_event,
    _source_diagnostic_row_id,
    _source_diagnostic_rows,
)
from .msrc_cvrf import _cvrf_client_product_names, _cvrf_kb_join, _cvrf_product_names_by_id
from .outputs import (
    render_policy_manifest,
    render_robots_txt,
    render_sitemap_xml,
    sign_policy_bytes,
    write_policy_outputs,
)
from .security_events import _msrc_cvrf_payloads
from .servicing_match import _enrich_history, _match_atom
from .sources import (
    AtomFeedEntry,
    SourceText,
    WindowsUpdateProbe,
    load_source_text,
)
from .support_articles import (
    _atom_title_bucket,
    _extract_support_article_facts,
    _kb_url,
    _msrc_month_id_from_atom_date,
    _record_msrc_month_id,
    _safe_atom_support_article_url,
    _safe_support_article_url,
    _support_article_enrichment,
)
from .support_validation import (
    _records_for_support_article_enrichment,
    _release_history_enrichment_record,
    _support_article_applies_to_compatibility,
    _support_article_validation_for_record,
)
from .pages.wiki_markdown import _render_wiki_markdown_fragment
from .pages.wiki_page import _PAGES_WIKI_VISUAL_SCALE, render_wiki_pages, write_wiki_pages
from .pages.wiki_sources import _read_markdown_source
# Public names this module defined before the v0.6.0 split stay importable from it.
from .constants import (
    CHANGELOG_SOURCE_PATH,
    CURATED_EXCLUDED_RELEASE_SUMMARIES,
    DEFAULT_MAX_SERVICING_TOC_BYTES,
    GITHUB_ISSUES_BASE_URL,
    GITHUB_LICENSE_URL,
    GITHUB_RELEASES_BASE_URL,
    GITHUB_REPOSITORY_URL,
    MSRC_CVRF_API_BASE_URL,
    MSRC_CVRF_CVE_LIMIT,
    MSRC_CVRF_PRODUCT_LIMIT,
    MSRC_CVRF_SEVERITY_LIMIT,
    MSRC_UPDATE_GUIDE_URL,
    PAGES_TIMEZONE,
    PROGRAMMING_ERROR_TYPES,
    PYPI_DOWNLOAD_IMAGE_PATH,
    PYPI_PROJECT_URL,
    ROBOTS_TXT,
    SOURCE_DIAGNOSTIC_ID_HASH_LENGTH,
    WIKI_FAVICON_DATA_URL,
    WIKI_HELPER_PAGE_NAMES,
    WIKI_SOURCE_DIR,
    WINDOWS_UPDATE_PROBE_CORROBORATION_KIND,
    WINDOWS_UPDATE_PROBE_OFFER_LIMIT,
    WINDOWS_UPDATE_PROBE_UNAVAILABLE_KIND,
)
from .msrc_cvrf import MsrcCvrfFetcher
from .pages.wiki_model import (
    ChangelogSection,
    RenderedWikiPage,
    WikiHeading,
    WikiPageSource,
)
from .support_articles import SupportArticleFetcher


__all__ = [
    "DEFAULT_SERVICING_TOC_URL",
    "AtomFeedEntry",
    "SourceText",
    "build_policy_from_sources",
    "generate_policy",
    "generate_policy_json",
    "load_source_text",
    "render_changelog_pages",
    "render_policy_index",
    "render_policy_manifest",
    "render_robots_txt",
    "render_sitemap_xml",
    "render_wiki_pages",
    "sign_policy_bytes",
    "write_policy_outputs",
    "write_changelog_pages",
    "write_wiki_pages",
]
