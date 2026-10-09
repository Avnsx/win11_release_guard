"""Shared constants for policy generation and the static Pages site."""

from __future__ import annotations

import re
from pathlib import Path
from ..servicing_toc import SERVICING_TOC_URL


# Fetcher/parser injection boundaries catch broad Exception so a genuine source
# failure (network, IO, malformed payload) degrades into a status record
# instead of blocking generation. That contract is narrower than "catch
# everything": it must not also swallow a programming error in our own code or
# in an injected test double. These types are re-raised immediately at those
# boundaries instead of being folded into a degraded-status record.
PROGRAMMING_ERROR_TYPES = (AssertionError, TypeError, AttributeError, NameError)

DEFAULT_SERVICING_TOC_URL = SERVICING_TOC_URL

DEFAULT_MAX_SUPPORT_ARTICLE_BYTES = 2 * 1024 * 1024

DEFAULT_MAX_MSRC_CVRF_BYTES = 48 * 1024 * 1024

# The servicing index is a small JSON listing (tens of KB in production); this
# cap leaves generous headroom for years of future releases while staying far
# below the general-purpose DEFAULT_MAX_MICROSOFT_SOURCE_BYTES ceiling.
DEFAULT_MAX_SERVICING_TOC_BYTES = 1 * 1024 * 1024

WINDOWS_UPDATE_PROBE_UNAVAILABLE_KIND = "windows_update_probe_unavailable"

WINDOWS_UPDATE_PROBE_CORROBORATION_KIND = "windows_update_probe_corroboration"

WINDOWS_UPDATE_PROBE_OFFER_LIMIT = 4

_WINDOWS_UPDATE_PROBE_BUILD_RE = re.compile(r"^\d{5,6}\.\d{1,5}$")

_WINDOWS_UPDATE_PROBE_KB_RE = re.compile(r"^KB\d{6,8}$")

MSRC_CVRF_CVE_LIMIT = 12

MSRC_CVRF_SEVERITY_LIMIT = 8

MSRC_CVRF_PRODUCT_LIMIT = 16

MSRC_CVRF_API_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf"

MSRC_UPDATE_GUIDE_URL = "https://msrc.microsoft.com/update-guide"

GITHUB_RELEASES_BASE_URL = "https://github.com/Avnsx/win11_release_guard/releases/tag"

GITHUB_LICENSE_URL = "https://github.com/Avnsx/win11_release_guard/blob/main/LICENSE.txt"

GITHUB_REPOSITORY_URL = "https://github.com/Avnsx/win11_release_guard"

GITHUB_ISSUES_BASE_URL = f"{GITHUB_REPOSITORY_URL}/issues"

PYPI_PROJECT_URL = "https://pypi.org/project/win11-release-guard/"

PYPI_DOWNLOAD_IMAGE_PATH = Path("assets") / "images" / "download_from_pypi.png"

PAGES_TIMEZONE = "Europe/Berlin"

ROBOTS_TXT = (
    "User-agent: *\n"
    "Allow: /\n"
    "Sitemap: https://avnsx.github.io/win11_release_guard/sitemap.xml\n"
)

CURATED_EXCLUDED_RELEASE_SUMMARIES = {
    "26H1": (
        "26H1 is excluded for existing devices because Microsoft scopes it to new devices and does not offer "
        "it as an in-place update from 24H2/25H2."
    )
}

WIKI_SOURCE_DIR = Path("wiki")

WIKI_HELPER_PAGE_NAMES = frozenset({"_sidebar.md", "_footer.md"})

CHANGELOG_SOURCE_PATH = Path("CHANGELOG.md")

WIKI_FAVICON_DATA_URL = (
    "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E"
    "%3Crect width='32' height='32' rx='8' fill='%230f6cbd'/%3E"
    "%3Cpath fill='white' d='M8 8.5h6.5v6.5H8zm7.5 0H22v6.5h-6.5zM8 16h6.5v6.5H8zm7.5 0H22v6.5h-6.5z'/%3E"
    "%3C/svg%3E"
)

_MARKDOWN_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")

_CHANGELOG_VERSION_HEADING_RE = re.compile(
    r"^##\s+(?P<title>(?:\[?Unreleased\]?|v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9_.-]+)?)(?:\s+[-–]\s+.+)?)\s*$",
    re.IGNORECASE,
)

_CHANGELOG_RELEASE_VERSION_RE = re.compile(r"\bv?(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9_.-]+)?)\b")

_ORDERED_LIST_RE = re.compile(r"^\s*\d+\.\s+(.+?)\s*$")

_UNORDERED_LIST_RE = re.compile(r"^\s*[-*]\s+(.+?)\s*$")

_LIST_ITEM_RE = re.compile(r"^(?P<indent>\s*)(?P<marker>(?:[-*])|(?:\d+\.))\s+(?P<text>.+?)\s*$")

_TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$")

_RELEASE_VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")

_SOURCE_DIAGNOSTIC_SEVERITY_PRIORITY = {"error": 0, "warning": 1, "notice": 2}

SOURCE_DIAGNOSTIC_ID_PREFIX = "wrg-source-diagnostic-v1"

SOURCE_DIAGNOSTIC_ID_HASH_LENGTH = 16

_SOURCE_DIAGNOSTIC_KB_TAG_RE = re.compile(r"^KB\s*(\d+)$", re.IGNORECASE)

_SOURCE_DIAGNOSTIC_TIMESTAMP_TAG_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$",
    re.IGNORECASE,
)
