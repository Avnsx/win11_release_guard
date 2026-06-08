from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import urllib.request
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse
from xml.etree import ElementTree

from .config import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    DEFAULT_PAGES_BASE_URL,
    DEFAULT_PUBLISHED_POLICY_URLS,
    DEFAULT_POLICY_STRICT_STALE_AGE_DAYS,
    DEFAULT_POLICY_WARNING_AGE_DAYS,
    DEFAULT_RELEASE_HEALTH_URL,
    DEFAULT_TRUSTED_POLICY_KEY_ID,
    DEFAULT_USER_AGENT,
)
from .exceptions import PolicyFetchError, PolicyParseError
from .freshness import (
    epoch_milliseconds_from_iso,
    freshness_policy_metadata,
    freshness_thresholds,
    parse_iso_utc_datetime,
)
from .json_utils import DEFAULT_MAX_MICROSOFT_SOURCE_BYTES
from .models import QualityPolicy, ReleaseHistoryEntry, ReleasePolicy, ReleasePolicyEntry
from .policy_schema import (
    GENERATOR_VERSION,
    SUPPORTED_POLICY_SCHEMA_VERSION,
    policy_document_to_json,
    validate_policy_document,
)
from .remote_policy import parse_windows11_release_health_html
from .signing import sign_policy_bytes as sign_ed25519_policy_bytes


DEFAULT_WINDOWS11_ATOM_FEED_URL = "https://support.microsoft.com/en-us/feed/atom/4ec863cc-2ecd-e187-6cb3-b50c6545db92"
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
CHANGELOG_SOURCE_PATH = Path("CHANGELOG.md")
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
SOURCE_DIAGNOSTIC_ID_PREFIX = "wrg-source-diagnostic-v1"
SOURCE_DIAGNOSTIC_ID_HASH_LENGTH = 16
_SOURCE_DIAGNOSTIC_KB_TAG_RE = re.compile(r"^KB\s*(\d+)$", re.IGNORECASE)
_SOURCE_DIAGNOSTIC_TIMESTAMP_TAG_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SourceText:
    text: str
    status: Mapping[str, Any]


@dataclass(frozen=True)
class WikiHeading:
    level: int
    text: str
    slug: str


@dataclass(frozen=True)
class WikiPageSource:
    path: Path
    title: str
    slug: str
    lookup_keys: tuple[str, ...]


@dataclass(frozen=True)
class RenderedWikiPage:
    source: WikiPageSource
    html: str
    headings: tuple[WikiHeading, ...]
    broken_links: tuple[str, ...]


@dataclass(frozen=True)
class ChangelogSection:
    title: str
    slug: str
    markdown: str
    version: str | None = None
    release_href: str | None = None


_LAST_UTC_NOW_MS = 0


@dataclass(frozen=True)
class AtomFeedEntry:
    title: str
    link: str | None = None
    published: str | None = None
    updated: str | None = None
    content: str | None = None
    kb_article: str | None = None
    builds: tuple[str, ...] = ()
    preview: bool = False
    out_of_band: bool = False


def _utc_now() -> str:
    global _LAST_UTC_NOW_MS
    epoch_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    if epoch_ms <= _LAST_UTC_NOW_MS:
        epoch_ms = _LAST_UTC_NOW_MS + 1
    _LAST_UTC_NOW_MS = epoch_ms
    seconds, milliseconds = divmod(epoch_ms, 1000)
    return datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=milliseconds * 1000).isoformat(
        timespec="milliseconds"
    )


def _parse_policy_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc).replace(microsecond=0)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc).replace(microsecond=0)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _last_sunday(year: int, month: int) -> datetime:
    if month == 12:
        day = datetime(year + 1, 1, 1, tzinfo=timezone.utc) - timedelta(days=1)
    else:
        day = datetime(year, month + 1, 1, tzinfo=timezone.utc) - timedelta(days=1)
    while day.weekday() != 6:
        day -= timedelta(days=1)
    return day.replace(hour=1, minute=0, second=0, microsecond=0)


def _berlin_offset_hours(utc_dt: datetime) -> tuple[int, str]:
    start = _last_sunday(utc_dt.year, 3)
    end = _last_sunday(utc_dt.year, 10)
    if start <= utc_dt < end:
        return 2, "CEST"
    return 1, "CET"


def _generated_at_human(value: str | None) -> str:
    utc_dt = _parse_policy_datetime(value)
    offset_hours, label = _berlin_offset_hours(utc_dt)
    local_dt = utc_dt.replace(tzinfo=None) + timedelta(hours=offset_hours)
    weekdays = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
    months = (
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    )
    return (
        f"{weekdays[local_dt.weekday()]}, {local_dt.day} {months[local_dt.month - 1]} "
        f"{local_dt.year}, {local_dt:%H:%M:%S} {label}"
    )


def _generated_at_local_date(value: str | None) -> str:
    utc_dt = _parse_policy_datetime(value)
    offset_hours, _label = _berlin_offset_hours(utc_dt)
    local_dt = utc_dt.replace(tzinfo=None) + timedelta(hours=offset_hours)
    months = (
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    )
    return f"{months[local_dt.month - 1]} {local_dt.day}, {local_dt.year}"


def _generated_at_local_time(value: str | None) -> str:
    utc_dt = _parse_policy_datetime(value)
    offset_hours, label = _berlin_offset_hours(utc_dt)
    local_dt = utc_dt.replace(tzinfo=None) + timedelta(hours=offset_hours)
    return f"{local_dt:%H:%M:%S} {label}"


def _utc_time_human(value: str | None) -> str:
    utc_dt = parse_iso_utc_datetime(value)
    if utc_dt is None:
        return "unavailable"
    weekdays = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
    months = (
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    )
    return (
        f"{weekdays[utc_dt.weekday()]}, {utc_dt.day} {months[utc_dt.month - 1]} "
        f"{utc_dt.year}, {utc_dt:%H:%M:%S} UTC"
    )


def _epoch_copy_icon_html() -> str:
    return (
        '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">'
        '<path d="M8 7.5A2.5 2.5 0 0 1 10.5 5h6A2.5 2.5 0 0 1 19 7.5v6A2.5 2.5 0 0 1 16.5 16h-6A2.5 2.5 0 0 1 8 13.5z" '
        'fill="none" stroke="currentColor" stroke-width="1.8"/>'
        '<path d="M5 10.5A2.5 2.5 0 0 1 7.5 8H8v5.5A2.5 2.5 0 0 0 10.5 16H16v.5A2.5 2.5 0 0 1 13.5 19h-6A2.5 2.5 0 0 1 5 16.5z" '
        'fill="none" stroke="currentColor" stroke-width="1.8"/>'
        "</svg>"
    )


def _ui_icon_html(name: str, *, class_name: str = "ui-icon") -> str:
    icons = {
        "shield": '<path d="M12 3 19 6v5c0 4.1-2.6 7.6-7 9-4.4-1.4-7-4.9-7-9V6l7-3z"/>',
        "shield-check": (
            '<path d="M12 3 19 6v5c0 4.1-2.6 7.6-7 9-4.4-1.4-7-4.9-7-9V6l7-3z"/>'
            '<path d="m9 12 2 2 4-5"/>'
        ),
        "target": (
            '<circle cx="11" cy="13" r="7.5"/><circle cx="11" cy="13" r="3.5"/>'
            '<path d="M11 13 20 4"/><path d="M16.5 4H20v3.5"/><path d="M18.8 5.2 21 3"/>'
        ),
        "chip": (
            '<rect x="6" y="6" width="12" height="12" rx="2"/>'
            '<rect x="10" y="10" width="4" height="4" rx="1"/>'
            '<path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>'
        ),
        "eye": (
            '<path d="M3 12s3.5-6 9-6 9 6 9 6-3.5 6-9 6-9-6-9-6z"/>'
            '<circle cx="12" cy="12" r="2.5"/>'
        ),
        "calendar": '<rect x="4" y="5" width="16" height="17" rx="2"/><path d="M8 3v4M16 3v4M4 10h16"/>',
        "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        "pin": '<path d="M12 21s7-5.6 7-12a7 7 0 0 0-14 0c0 6.4 7 12 7 12z"/><circle cx="12" cy="9" r="2.5"/>',
        "check": '<path d="m5 13 4 4L19 7"/>',
        "megaphone": '<path d="M4 13h3l9 4V5L7 9H4v4z"/><path d="m7 13 1 5M18 9l3-2M18 13l3 2"/>',
        "warning": '<path d="M12 4 21 20H3L12 4z"/><path d="M12 9v5M12 17h.01"/>',
        "error": '<circle cx="12" cy="12" r="9"/><path d="m8 8 8 8M16 8l-8 8"/>',
        "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 7h.01"/>',
        "document": '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5M10 13h6M10 17h4"/>',
        "key": '<circle cx="8" cy="12" r="3"/><path d="M11 12h10M17 12v3M20 12v2"/>',
        "api": '<path d="M8 8 4 12l4 4M16 8l4 4-4 4M14 5l-4 14"/>',
        "link": '<path d="M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1"/>',
        "database": '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/>',
    }
    body = icons.get(str(name or "").strip().lower(), icons["info"])
    return (
        f'<svg class="{escape(class_name, quote=True)}" viewBox="0 0 24 24" '
        'aria-hidden="true" focusable="false" fill="none" stroke="currentColor" '
        f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{body}</svg>'
    )


def _github_icon_html() -> str:
    return (
        '<svg class="github-icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false">'
        '<path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38'
        ' 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52'
        '-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2'
        '-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82'
        '.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08'
        ' 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48'
        ' 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/>'
        "</svg>"
    )


def _footer_html() -> str:
    return (
        "<footer>"
        '<p class="footer-note footer-disclaimer">Independent Windows release-policy dashboard. Not affiliated with Microsoft.</p>'
        '<p class="footer-note footer-owner">&copy; 2026 Mikail (&quot;Avnsx&quot;) C. Maintained as an open-source project.</p>'
        '<p class="footer-note footer-source">'
        "<span>Source code and documentation are available on</span>"
        f'<a class="footer-github" href="{escape(GITHUB_REPOSITORY_URL, quote=True)}">'
        f"{_github_icon_html()}<span>GitHub</span></a>"
        "<span>and provided under the</span>"
        f'<a class="footer-license-basic" href="{escape(GITHUB_LICENSE_URL, quote=True)}">GPL-3.0 license</a></p>'
        "</footer>"
    )


def _time_with_epoch_copy_html(value: str | None, *, label: str) -> str:
    utc_dt = parse_iso_utc_datetime(value)
    epoch_ms = epoch_milliseconds_from_iso(value)
    if utc_dt is None or epoch_ms is None:
        return '<span class="time-copy unavailable">unavailable</span>'
    iso_value = utc_dt.isoformat()
    display = _utc_time_human(iso_value)
    escaped_epoch = escape(str(epoch_ms), quote=True)
    escaped_label = escape(label, quote=True)
    return (
        '<span class="time-copy">'
        f'<time datetime="{escape(iso_value, quote=True)}">{escape(display)}</time>'
        '<button type="button" class="epoch-copy" '
        f'data-epoch="{escaped_epoch}" '
        f'aria-label="Copy {escaped_label} epoch millisecond timestamp {escaped_epoch}" '
        f'title="Copy epoch millisecond timestamp {escaped_epoch}">'
        f"{_epoch_copy_icon_html()}"
        "</button></span>"
    )


def _generated_age_days(value: str | None, *, reference: datetime | None = None) -> float:
    generated = _parse_policy_datetime(value)
    now = reference or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return round(max(0.0, (now.astimezone(timezone.utc) - generated).total_seconds() / 86400), 2)


def _age_unit_text(value: int, unit: str) -> str:
    return f"{value} {unit}" if value == 1 else f"{value} {unit}s"


def _dashboard_exact_age_text(seconds: int) -> str:
    seconds = max(0, int(seconds))
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    parts: list[str] = []
    if days:
        parts.append(_age_unit_text(days, "day"))
    if hours or days:
        parts.append(_age_unit_text(hours, "hour"))
    parts.append(_age_unit_text(minutes, "minute"))
    return ", ".join(parts)


def _dashboard_age_display(
    value: str | None,
    *,
    reference: datetime | None = None,
) -> tuple[str, str, str]:
    generated = parse_iso_utc_datetime(value)
    if generated is None:
        return "unknown", "age-wide", "Published feed age unknown"

    now = reference or parse_iso_utc_datetime(_utc_now()) or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    seconds = max(0, int((now.astimezone(timezone.utc) - generated).total_seconds()))
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    full = f"Published feed age {_dashboard_exact_age_text(seconds)}"
    if days >= 1:
        return f"{days}d {hours}h", "age-compact" if days >= 10 else "age-wide", full
    hour_value = seconds / 3600
    if hour_value >= 2:
        hours_text = f"{hour_value:.1f}"
        if hours_text.endswith(".0"):
            hours_text = hours_text[:-2]
        return f"{hours_text} hours", "age-wide" if hour_value >= 10 else "", full
    return _age_unit_text(minutes, "minute"), "age-wide" if minutes >= 100 else "", full


def _content_length_from_headers(headers: Mapping[str, object] | None) -> int | None:
    if headers is None:
        return None
    value = None
    if hasattr(headers, "get"):
        value = headers.get("content-length") or headers.get("Content-Length")
    if value is None and hasattr(headers, "items"):
        for key, candidate in headers.items():
            if str(key).lower() == "content-length":
                value = candidate
                break
    if value is None:
        return None
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _fetch_url(
    url: str,
    *,
    timeout: float,
    max_bytes: int = DEFAULT_MAX_MICROSOFT_SOURCE_BYTES,
) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/atom+xml,application/xml,text/xml",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        content_length = _content_length_from_headers(response.headers)
        if content_length is not None and content_length > max_bytes:
            raise PolicyFetchError(
                f"Microsoft source response is too large: exceeds safety cap of {max_bytes} bytes."
            )
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise PolicyFetchError(
                f"Microsoft source response is too large: exceeds safety cap of {max_bytes} bytes."
            )
        return data.decode(charset, errors="replace")


def load_source_text(
    *,
    url: str,
    fixture_path: str | Path | None = None,
    source_name: str,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    required: bool = True,
) -> SourceText:
    if fixture_path is not None:
        path = Path(fixture_path)
        try:
            text = path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            if required:
                raise PolicyFetchError(f"{source_name} source failure: could not read {path}: {exc}") from exc
            return SourceText(
                text="",
                status={
                    "url": url,
                    "source": "fixture",
                    "path": str(path),
                    "status": "error",
                    "error": str(exc),
                    "fetched_at_utc": _utc_now(),
                },
            )
        return SourceText(
            text=text,
            status={
                "url": url,
                "source": "fixture",
                "path": str(path),
                "status": "ok",
                "bytes": len(text.encode("utf-8")),
                "fetched_at_utc": _utc_now(),
            },
        )

    try:
        text = _fetch_url(url, timeout=timeout)
    except Exception as exc:
        if required:
            raise PolicyFetchError(f"{source_name} source failure: could not fetch {url}: {exc}") from exc
        return SourceText(
            text="",
            status={
                "url": url,
                "source": "network",
                "status": "error",
                "error": str(exc),
                "fetched_at_utc": _utc_now(),
            },
        )
    return SourceText(
        text=text,
        status={
            "url": url,
            "source": "network",
            "status": "ok",
            "bytes": len(text.encode("utf-8")),
            "fetched_at_utc": _utc_now(),
        },
    )


def _text(element: ElementTree.Element, name: str, ns: Mapping[str, str]) -> str | None:
    child = element.find(name, ns)
    if child is None or child.text is None:
        return None
    text = re.sub(r"\s+", " ", child.text).strip()
    return text or None


def _link(element: ElementTree.Element, ns: Mapping[str, str]) -> str | None:
    for link in element.findall("atom:link", ns):
        href = link.attrib.get("href")
        if href:
            return href
    return None


def _extract_kb(text: str | None) -> str | None:
    match = re.search(r"\bKB\d{6,8}\b", text or "", flags=re.IGNORECASE)
    return match.group(0).upper() if match else None


def _extract_builds(text: str | None) -> tuple[str, ...]:
    return tuple(dict.fromkeys(re.findall(r"\b\d{5}\.\d+\b", text or "")))


def _is_preview(text: str) -> bool:
    return "preview" in text.lower()


def _is_out_of_band(text: str) -> bool:
    normalized = text.lower().replace("_", "-")
    return "out-of-band" in normalized or "out of band" in normalized or re.search(r"\boob\b", normalized) is not None


def parse_atom_feed(xml_text: str) -> tuple[AtomFeedEntry, ...]:
    if not xml_text.strip():
        return ()

    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise PolicyParseError(f"Atom feed is malformed: {exc}") from exc

    ns = {"atom": "http://www.w3.org/2005/Atom"}
    entries = root.findall("atom:entry", ns)
    if not entries:
        entries = root.findall("entry")

    parsed: list[AtomFeedEntry] = []
    for entry in entries:
        title = _text(entry, "atom:title", ns) or _text(entry, "title", ns) or ""
        content = _text(entry, "atom:content", ns) or _text(entry, "content", ns)
        published = _text(entry, "atom:published", ns) or _text(entry, "published", ns)
        updated = _text(entry, "atom:updated", ns) or _text(entry, "updated", ns)
        link = _link(entry, ns)
        blob = " ".join(part for part in (title, content or "") if part)
        kb_article = _extract_kb(blob)
        parsed.append(
            AtomFeedEntry(
                title=title,
                link=link,
                published=published,
                updated=updated,
                content=content,
                kb_article=kb_article,
                builds=_extract_builds(blob),
                preview=_is_preview(blob),
                out_of_band=_is_out_of_band(blob),
            )
        )
    return tuple(parsed)


def _release_key(release: str | None) -> tuple[int, int]:
    match = re.fullmatch(r"(\d{2})H([12])", release or "", flags=re.IGNORECASE)
    if not match:
        return (-1, -1)
    return int(match.group(1)), int(match.group(2))


def _build_key(build: str | None) -> tuple[int, int]:
    if not build:
        return (-1, -1)
    try:
        major, minor = str(build).split(".", 1)
        return int(major), int(minor)
    except ValueError:
        return (-1, -1)


def _history_sort_key(row: ReleaseHistoryEntry) -> tuple[str, tuple[int, int]]:
    return row.availability_date or "", _build_key(row.build)


def _kb_url(kb_article: str | None, feed_entry: AtomFeedEntry | None = None) -> str | None:
    if feed_entry and feed_entry.link:
        return feed_entry.link
    kb = _extract_kb(kb_article)
    if not kb:
        return None
    return f"https://support.microsoft.com/help/{kb[2:]}"


def _catalog_url(kb_article: str | None) -> str | None:
    kb = _extract_kb(kb_article)
    if not kb:
        return None
    return f"https://www.catalog.update.microsoft.com/Search.aspx?q={kb}"


def _match_atom(row: ReleaseHistoryEntry, entries: tuple[AtomFeedEntry, ...]) -> AtomFeedEntry | None:
    row_kb = _extract_kb(row.kb_article)
    if row_kb:
        for entry in entries:
            if entry.kb_article == row_kb:
                return entry
    for entry in entries:
        if row.build in entry.builds:
            return entry
    return None


def _enrich_history(
    release_history: tuple[ReleaseHistoryEntry, ...],
    atom_entries: tuple[AtomFeedEntry, ...],
) -> tuple[ReleaseHistoryEntry, ...]:
    enriched: list[ReleaseHistoryEntry] = []
    for row in release_history:
        atom_entry = _match_atom(row, atom_entries)
        preview = row.preview or bool(atom_entry and atom_entry.preview)
        out_of_band = row.out_of_band or bool(atom_entry and atom_entry.out_of_band)
        update_type_letter = row.update_type_letter
        if out_of_band:
            update_type_letter = "OOB"
        elif preview and not update_type_letter:
            update_type_letter = "D"

        metadata = dict(row.metadata)
        if atom_entry:
            metadata.update(
                {
                    "atom_enriched": True,
                    "atom_feed_title": atom_entry.title,
                    "atom_feed_url": atom_entry.link,
                    "atom_published": atom_entry.published,
                    "atom_updated": atom_entry.updated,
                }
            )

        enriched.append(
            replace(
                row,
                preview=preview,
                out_of_band=out_of_band,
                update_type_letter=update_type_letter,
                kb_url=_kb_url(row.kb_article, atom_entry) or row.kb_url,
                catalog_url=_catalog_url(row.kb_article) or row.catalog_url,
                metadata=metadata,
            )
        )
    return tuple(enriched)


def _entry_with_special_flag(entry: ReleasePolicyEntry) -> ReleasePolicyEntry:
    metadata = dict(entry.metadata)
    if metadata.get("not_broad_target"):
        metadata["not_broad_target_existing_devices"] = True
    return replace(entry, metadata=metadata)


def _baseline_for(
    rows: tuple[ReleaseHistoryEntry, ...],
    release: str,
    policy: QualityPolicy,
) -> ReleaseHistoryEntry | None:
    release_rows = [row for row in rows if row.release == release.upper()]
    if policy is QualityPolicy.B_RELEASE_ONLY:
        candidates = [
            row
            for row in release_rows
            if row.update_type_letter == "B" and not row.preview
        ]
    elif policy is QualityPolicy.LATEST_NON_PREVIEW:
        candidates = [row for row in release_rows if not row.preview]
    else:
        candidates = release_rows
    if not candidates:
        return None
    return max(candidates, key=_history_sort_key)


def _quality_baselines(release_history: tuple[ReleaseHistoryEntry, ...]) -> dict[str, dict[str, dict[str, Any]]]:
    releases = sorted({row.release for row in release_history}, key=_release_key)
    baselines: dict[str, dict[str, dict[str, Any]]] = {}
    for release in releases:
        release_baselines: dict[str, dict[str, Any]] = {}
        for policy in (
            QualityPolicy.B_RELEASE_ONLY,
            QualityPolicy.LATEST_NON_PREVIEW,
            QualityPolicy.LATEST_ANYTHING,
        ):
            baseline = _baseline_for(release_history, release, policy)
            if baseline is not None:
                release_baselines[policy.value] = baseline.to_dict()
        if release_baselines:
            baselines[release] = release_baselines
    return baselines


def _parse_source_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            parsed = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
        else:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _newest_timestamp(values: list[str | None]) -> str | None:
    candidates = [(parsed, value) for value in values if (parsed := _parse_source_timestamp(value))]
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1]


def _newest_current_version_revision_date(entries: tuple[ReleasePolicyEntry, ...]) -> str | None:
    values: list[str | None] = []
    for entry in entries:
        raw = entry.metadata.get("raw") if isinstance(entry.metadata.get("raw"), Mapping) else {}
        if isinstance(raw, Mapping):
            values.append(str(raw.get("Latest revision date") or "") or None)
        values.append(str(entry.metadata.get("latest_revision_date") or "") or None)
    return _newest_timestamp(values)


def _newest_release_history_availability_date(rows: tuple[ReleaseHistoryEntry, ...]) -> str | None:
    return _newest_timestamp([row.availability_date for row in rows])


def _newest_atom_timestamp(entries: tuple[AtomFeedEntry, ...], field: str) -> str | None:
    return _newest_timestamp([getattr(entry, field) for entry in entries])


def _history_release_by_family(rows: tuple[ReleaseHistoryEntry, ...]) -> dict[int, str]:
    releases: dict[int, str] = {}
    for row in rows:
        current = releases.get(row.build_family)
        if current is None or _release_key(row.release) > _release_key(current):
            releases[row.build_family] = row.release
    return releases


def _history_build_maps(rows: tuple[ReleaseHistoryEntry, ...]) -> tuple[dict[int, tuple[int, int]], set[str], set[str]]:
    newest_by_family: dict[int, tuple[int, int]] = {}
    builds: set[str] = set()
    kbs: set[str] = set()
    for row in rows:
        builds.add(row.build)
        kb = _extract_kb(row.kb_article)
        if kb:
            kbs.add(kb)
        current = newest_by_family.get(row.build_family, (-1, -1))
        newest_by_family[row.build_family] = max(current, _build_key(row.build))
    return newest_by_family, builds, kbs


def _atom_newer_than_history(
    atom_entries: tuple[AtomFeedEntry, ...],
    release_history: tuple[ReleaseHistoryEntry, ...],
) -> tuple[dict[str, Any], ...]:
    newest_by_family, history_builds, history_kbs = _history_build_maps(release_history)
    release_by_family = _history_release_by_family(release_history)
    missing: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None]] = set()
    for entry in atom_entries:
        kb = _extract_kb(entry.kb_article)
        for build in entry.builds:
            family = _build_key(build)[0]
            if family < 0:
                continue
            if build in history_builds:
                continue
            if _build_key(build) <= newest_by_family.get(family, (-1, -1)):
                continue
            key = (build, kb)
            if key in seen:
                continue
            seen.add(key)
            missing.append(
                {
                    "release": release_by_family.get(family),
                    "build": build,
                    "build_family": family,
                    "kb_article": kb,
                    "preview": entry.preview,
                    "out_of_band": entry.out_of_band,
                    "kb_missing_from_release_history": bool(kb and kb not in history_kbs),
                    "published": entry.published,
                    "updated": entry.updated,
                    "title": entry.title,
                }
            )
    return tuple(missing)


def _current_version_latest_older_than_history(
    current_versions: tuple[ReleasePolicyEntry, ...],
    release_history: tuple[ReleaseHistoryEntry, ...],
) -> tuple[dict[str, Any], ...]:
    newest_by_family, _history_builds, _history_kbs = _history_build_maps(release_history)
    stale: list[dict[str, Any]] = []
    for entry in current_versions:
        newest_history_key = newest_by_family.get(entry.build_family)
        if newest_history_key is None or _build_key(entry.latest_build) >= newest_history_key:
            continue
        newest_history_build = max(
            (row.build for row in release_history if row.build_family == entry.build_family),
            key=_build_key,
        )
        stale.append(
            {
                "version": entry.version,
                "build_family": entry.build_family,
                "latest_build": entry.latest_build,
                "newest_release_history_build": newest_history_build,
            }
        )
    return tuple(stale)


def _newest_atom_build(entries: tuple[AtomFeedEntry, ...]) -> str | None:
    builds = [build for entry in entries for build in entry.builds]
    if not builds:
        return None
    return max(builds, key=_build_key)


def _event_key(item: Mapping[str, Any]) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    return (
        str(item.get("severity")) if item.get("severity") is not None else None,
        str(item.get("kind")) if item.get("kind") is not None else None,
        str(item.get("release")) if item.get("release") is not None else None,
        str(item.get("build")) if item.get("build") is not None else None,
        str(item.get("kb_article")) if item.get("kb_article") is not None else None,
    )


def _dedupe_source_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str | None, str | None, str | None, str | None, str | None]] = set()
    for event in events:
        key = _event_key(event)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(dict(event))
    return deduped


def _source_event_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"notice": 0, "warning": 0, "error": 0}
    for event in events:
        severity = str(event.get("severity") or "")
        if severity in counts:
            counts[severity] += 1
    return counts


def _atom_newer_event(item: Mapping[str, Any], target: ReleasePolicyEntry | None) -> dict[str, Any]:
    release = str(item.get("release") or "") or None
    build_family = item.get("build_family")
    affects_broad_target = bool(
        target is not None
        and release == target.version
        and build_family == target.build_family
    )
    affects_required_baseline = affects_broad_target and not bool(item.get("preview") or item.get("out_of_band"))
    severity = "warning" if affects_required_baseline else "notice"
    build = str(item.get("build") or "")
    kb_article = item.get("kb_article")
    if severity == "warning":
        message = (
            "Atom feed shows a newer non-preview build for the broad target that is not present "
            f"in Release Health release_history: {kb_article or 'unknown KB'} build {build}."
        )
    else:
        message = (
            "Atom feed has newer Preview/OOB or non-baseline update information not present in "
            f"Release Health release_history: {kb_article or 'unknown KB'} build {build}."
        )
    return {
        "severity": severity,
        "kind": "atom_newer_than_release_history",
        "release": release,
        "build_family": build_family,
        "build": build or None,
        "kb_article": kb_article,
        "affects_broad_target": affects_broad_target,
        "affects_required_baseline": affects_required_baseline,
        "message": message,
    }


def _current_versions_lag_event(item: Mapping[str, Any], target: ReleasePolicyEntry | None) -> dict[str, Any]:
    release = str(item.get("version") or "") or None
    build_family = item.get("build_family")
    build = item.get("newest_release_history_build")
    affects_broad_target = bool(
        target is not None
        and release == target.version
        and build_family == target.build_family
    )
    return {
        "severity": "warning",
        "kind": "current_versions_lag_release_history",
        "release": release,
        "build_family": build_family,
        "build": build,
        "kb_article": None,
        "affects_broad_target": affects_broad_target,
        "affects_required_baseline": False,
        "message": (
            "Current Versions latest_build appears older than Release History for "
            f"{release}/{build_family}: {item.get('latest_build') or 'unknown'} < {build}."
        ),
    }


def _source_diagnostic_messages(events: list[dict[str, Any]], *, minimum: str = "warning") -> list[str]:
    severities = {"notice": 0, "warning": 1, "error": 2}
    threshold = severities[minimum]
    return [
        str(event["message"])
        for event in events
        if severities.get(str(event.get("severity") or ""), -1) >= threshold
        and event.get("message")
    ]


def _source_diagnostic_notices(events: list[dict[str, Any]]) -> list[str]:
    return [
        str(event["message"])
        for event in events
        if event.get("severity") == "notice" and event.get("message")
    ]


def _source_input_event(kind: str, message: str, *, severity: str = "warning") -> dict[str, Any]:
    return {
        "severity": severity,
        "kind": kind,
        "release": None,
        "build_family": None,
        "build": None,
        "kb_article": None,
        "affects_broad_target": False,
        "affects_required_baseline": False,
        "message": message,
    }


def _source_status(
    source_fetch_status: Mapping[str, Any],
    key: str,
    *,
    source_url: str | None,
    text: str | None = None,
    generated_at_utc: str,
) -> dict[str, Any]:
    status = dict(source_fetch_status.get(key) or {})
    status.setdefault("url", source_url)
    status.setdefault("source", "direct")
    status.setdefault("status", "ok" if text else "missing")
    if text is not None:
        status.setdefault("bytes", len(text.encode("utf-8")))
    status.setdefault("fetched_at_utc", generated_at_utc)
    return status


def _source_diagnostics(
    *,
    current_versions: tuple[ReleasePolicyEntry, ...],
    release_history: tuple[ReleaseHistoryEntry, ...],
    atom_entries: tuple[AtomFeedEntry, ...],
    broad_target: ReleasePolicyEntry | None,
    parser_diagnostics: tuple[Mapping[str, Any], ...] = (),
    source_input_events: tuple[Mapping[str, Any], ...] = (),
    source_fetch_status: Mapping[str, Any],
    release_health_url: str,
    atom_feed_url: str | None,
    release_health_html: str,
    atom_feed_xml: str | None,
    generated_at_utc: str,
) -> dict[str, Any]:
    release_health_status = _source_status(
        source_fetch_status,
        "release_health_html",
        source_url=release_health_url,
        text=release_health_html,
        generated_at_utc=generated_at_utc,
    )
    atom_status = _source_status(
        source_fetch_status,
        "atom_feed",
        source_url=atom_feed_url,
        text=atom_feed_xml,
        generated_at_utc=generated_at_utc,
    )
    newest_current_revision = _newest_current_version_revision_date(current_versions)
    newest_history_availability = _newest_release_history_availability_date(release_history)
    newest_atom_updated = _newest_atom_timestamp(atom_entries, "updated")
    newest_atom_published = _newest_atom_timestamp(atom_entries, "published")
    atom_newer = _atom_newer_than_history(atom_entries, release_history)
    current_stale = _current_version_latest_older_than_history(current_versions, release_history)
    events = _dedupe_source_events(
        [
            *(dict(item) for item in parser_diagnostics),
            *(dict(item) for item in source_input_events),
            *(_atom_newer_event(item, broad_target) for item in atom_newer),
            *(_current_versions_lag_event(item, broad_target) for item in current_stale),
        ]
    )

    source_times = [
        newest_current_revision,
        newest_history_availability,
        newest_atom_updated,
        newest_atom_published,
    ]
    newest_source_timestamp = _newest_timestamp(source_times)
    generated_after_hours = None
    generated_dt = _parse_source_timestamp(generated_at_utc)
    newest_source_dt = _parse_source_timestamp(newest_source_timestamp)
    if generated_dt and newest_source_dt:
        generated_after_hours = round((generated_dt - newest_source_dt).total_seconds() / 3600, 2)

    if generated_after_hours is not None and generated_after_hours >= 24:
        has_unresolved_warning = any(str(event.get("severity")) in {"warning", "error"} for event in events)
        if has_unresolved_warning:
            events.append(
                {
                    "severity": "warning",
                    "kind": "source_drift_unresolved_after_24h",
                    "release": broad_target.version if broad_target else None,
                    "build_family": broad_target.build_family if broad_target else None,
                    "build": broad_target.latest_build if broad_target else None,
                    "kb_article": None,
                    "affects_broad_target": bool(broad_target),
                    "affects_required_baseline": False,
                    "message": (
                        "Policy was generated more than 24 hours after the newest source timestamp while "
                        "warning-level source drift diagnostics remain unresolved."
                    ),
                }
            )
    if (
        generated_after_hours is not None
        and generated_after_hours >= 24
        and not atom_entries
        and atom_status.get("status") != "ok"
    ):
        events.append(
            {
                "severity": "warning",
                "kind": "atom_diagnostics_unavailable",
                "release": broad_target.version if broad_target else None,
                "build_family": broad_target.build_family if broad_target else None,
                "build": broad_target.latest_build if broad_target else None,
                "kb_article": None,
                "affects_broad_target": bool(broad_target),
                "affects_required_baseline": False,
                "message": (
                    "Policy was generated more than 24 hours after the newest Release Health timestamp and "
                    "Atom diagnostics are unavailable; preview/out-of-band enrichment may be incomplete."
                ),
            }
        )
    events = _source_diagnostic_events_with_ids(_dedupe_source_events(events))
    parser_events = _source_diagnostic_events_with_ids(
        [dict(item) for item in parser_diagnostics if isinstance(item, Mapping)]
    )
    warnings = list(dict.fromkeys(_source_diagnostic_messages(events, minimum="warning")))
    notices = list(dict.fromkeys(_source_diagnostic_notices(events)))

    return {
        "release_health_html": {
            "source_url": release_health_status.get("url"),
            "fetched_at_utc": release_health_status.get("fetched_at_utc"),
            "bytes": release_health_status.get("bytes"),
            "status": release_health_status.get("status"),
            "newest_current_version_revision_date": newest_current_revision,
            "newest_release_history_availability_date": newest_history_availability,
        },
        "atom_feed": {
            "source_url": atom_status.get("url"),
            "fetched_at_utc": atom_status.get("fetched_at_utc"),
            "bytes": atom_status.get("bytes"),
            "status": atom_status.get("status"),
            "newest_atom_updated": newest_atom_updated,
            "newest_atom_published": newest_atom_published,
            "newest_atom_build": _newest_atom_build(atom_entries),
        },
        "drift": {
            "atom_newer_than_release_history": [dict(item) for item in atom_newer],
            "current_version_latest_older_than_release_history": [dict(item) for item in current_stale],
            "newest_source_timestamp": newest_source_timestamp,
            "generated_after_newest_source_hours": generated_after_hours,
        },
        "parser": {
            "events": parser_events,
        },
        "events": events,
        "event_counts": _source_event_counts(events),
        "notices": notices,
        "warnings": warnings,
    }


def _known_notes(policy: ReleasePolicy) -> tuple[dict[str, Any], ...]:
    notes: list[dict[str, Any]] = []
    for entry in policy.special_releases:
        flags = [
            flag
            for flag in (
                "special_release",
                "new_devices_only",
                "not_broad_target_existing_devices",
            )
            if entry.metadata.get(flag)
        ]
        notes.append(
            {
                "type": "special_release",
                "release": entry.version,
                "build_family": entry.build_family,
                "note": entry.reason,
                "flags": flags,
            }
        )
    return tuple(notes)


def _entry_with_b_release_baseline(
    entry: ReleasePolicyEntry,
    quality_baselines: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> ReleasePolicyEntry:
    baseline = quality_baselines.get(entry.version, {}).get(QualityPolicy.B_RELEASE_ONLY.value)
    if not isinstance(baseline, Mapping):
        return entry
    build = baseline.get("build")
    if not build:
        return entry
    baseline_build = str(build)
    return replace(
        entry,
        baseline_build=baseline_build,
        required_baseline_build=baseline_build,
    )


def _policy_with_enrichment(
    base_policy: ReleasePolicy,
    *,
    release_history: tuple[ReleaseHistoryEntry, ...],
    atom_entries: tuple[AtomFeedEntry, ...],
    generated_at_utc: str,
    release_health_url: str,
    atom_feed_url: str | None,
    release_health_html: str,
    atom_feed_xml: str | None,
    source_fetch_status: Mapping[str, Any],
    validation_warnings: tuple[str, ...],
    source_input_events: tuple[Mapping[str, Any], ...] = (),
    signature_status: str,
    published_urls: Mapping[str, str] | None = None,
) -> ReleasePolicy:
    quality_baselines = _quality_baselines(release_history)
    special_releases = tuple(
        _entry_with_b_release_baseline(_entry_with_special_flag(entry), quality_baselines)
        for entry in base_policy.special_releases
    )
    excluded = tuple(
        _entry_with_b_release_baseline(_entry_with_special_flag(entry), quality_baselines)
        for entry in base_policy.excluded_for_existing_devices
    )
    current_versions = tuple(
        _entry_with_b_release_baseline(_entry_with_special_flag(entry), quality_baselines)
        for entry in base_policy.current_versions
    )
    preview_builds = tuple(row.to_dict() for row in release_history if row.preview)
    out_of_band_builds = tuple(row.to_dict() for row in release_history if row.out_of_band)
    source_urls = [release_health_url]
    if atom_feed_url:
        source_urls.append(atom_feed_url)

    target = base_policy.broad_target_existing_devices
    if target is not None:
        baseline_found = False
        baseline = quality_baselines.get(target.version, {}).get(QualityPolicy.B_RELEASE_ONLY.value)
        if isinstance(baseline, Mapping):
            build = baseline.get("build")
            if build:
                baseline_found = True
                baseline_build = str(build)
                target = replace(
                    target,
                    baseline_build=baseline_build,
                    required_baseline_build=baseline_build,
                )
        if not baseline_found:
            raise PolicyParseError(
                "Could not select B-release required baseline for broad_target_existing_devices "
                f"{target.version}/{target.build_family} from Release Health release_history."
            )

    metadata = dict(base_policy.metadata)
    metadata["signature_status"] = signature_status
    metadata["generator"] = GENERATOR_VERSION
    metadata["freshness_policy"] = freshness_policy_metadata()
    parser_source = base_policy.source_diagnostics.get("parser")
    parser_diagnostics: tuple[Mapping[str, Any], ...] = ()
    if isinstance(parser_source, Mapping):
        parser_events = parser_source.get("events")
        if isinstance(parser_events, list):
            parser_diagnostics = tuple(item for item in parser_events if isinstance(item, Mapping))
    source_diagnostics = _source_diagnostics(
        current_versions=current_versions,
        release_history=release_history,
        atom_entries=atom_entries,
        broad_target=target,
        parser_diagnostics=parser_diagnostics,
        source_input_events=source_input_events,
        source_fetch_status=source_fetch_status,
        release_health_url=release_health_url,
        atom_feed_url=atom_feed_url,
        release_health_html=release_health_html,
        atom_feed_xml=atom_feed_xml,
        generated_at_utc=generated_at_utc,
    )
    combined_warnings = tuple(
        dict.fromkeys([*validation_warnings, *source_diagnostics.get("warnings", [])])
    )

    enriched = replace(
        base_policy,
        schema_version=SUPPORTED_POLICY_SCHEMA_VERSION,
        min_reader_schema_version=SUPPORTED_POLICY_SCHEMA_VERSION,
        max_reader_schema_version=SUPPORTED_POLICY_SCHEMA_VERSION,
        api_version="v1",
        compatibility={
            "additive_unknown_top_level_keys": "warning",
            "extension_namespaces": ["extensions", "x_*"],
            "required_core_schema_version": SUPPORTED_POLICY_SCHEMA_VERSION,
        },
        generated_at_utc=generated_at_utc,
        generator_version=GENERATOR_VERSION,
        source_urls=tuple(source_urls),
        published_urls=dict(published_urls or DEFAULT_PUBLISHED_POLICY_URLS),
        source_fetch_status=dict(source_fetch_status),
        source_diagnostics=source_diagnostics,
        current_versions=current_versions,
        release_history=release_history,
        special_releases=special_releases,
        supported_releases=current_versions,
        excluded_for_existing_devices=excluded,
        broad_target_existing_devices=target,
        quality_baselines=quality_baselines,
        preview_builds=preview_builds,
        out_of_band_builds=out_of_band_builds,
        known_notes=_known_notes(replace(base_policy, special_releases=special_releases)),
        validation_warnings=combined_warnings,
        metadata=metadata,
    )
    return enriched


def generate_policy(
    *,
    release_health_html: str,
    atom_feed_xml: str | None = None,
    release_health_url: str = DEFAULT_RELEASE_HEALTH_URL,
    atom_feed_url: str | None = DEFAULT_WINDOWS11_ATOM_FEED_URL,
    generated_at_utc: str | None = None,
    signature_status: str = "unsigned",
    source_fetch_status: Mapping[str, Any] | None = None,
    published_urls: Mapping[str, str] | None = None,
) -> ReleasePolicy:
    warnings: list[str] = []
    source_input_events: list[dict[str, Any]] = []
    generated = generated_at_utc or _utc_now()
    effective_source_fetch_status = {
        "release_health_html": _source_status(
            source_fetch_status or {},
            "release_health_html",
            source_url=release_health_url,
            text=release_health_html,
            generated_at_utc=generated,
        ),
        "atom_feed": _source_status(
            source_fetch_status or {},
            "atom_feed",
            source_url=atom_feed_url,
            text=atom_feed_xml,
            generated_at_utc=generated,
        ),
    }
    base_policy = parse_windows11_release_health_html(release_health_html)
    atom_entries: tuple[AtomFeedEntry, ...] = ()
    if atom_feed_xml:
        try:
            atom_entries = parse_atom_feed(atom_feed_xml)
        except PolicyParseError as exc:
            message = f"Atom feed could not be parsed: {exc}"
            warnings.append(message)
            source_input_events.append(_source_input_event("atom_feed_parse_failed", message))
    else:
        message = "Atom feed missing; preview/out-of-band enrichment unavailable."
        warnings.append(message)
        source_input_events.append(_source_input_event("atom_feed_missing", message))

    if atom_feed_xml and not atom_entries:
        message = "Atom feed contained no usable entries."
        warnings.append(message)
        source_input_events.append(_source_input_event("atom_feed_no_usable_entries", message))

    release_history = _enrich_history(base_policy.release_history, atom_entries)
    policy = _policy_with_enrichment(
        base_policy,
        release_history=release_history,
        atom_entries=atom_entries,
        generated_at_utc=generated,
        release_health_url=release_health_url,
        atom_feed_url=atom_feed_url,
        release_health_html=release_health_html,
        atom_feed_xml=atom_feed_xml,
        source_fetch_status=effective_source_fetch_status,
        validation_warnings=tuple(dict.fromkeys(warnings)),
        source_input_events=tuple(source_input_events),
        signature_status=signature_status,
        published_urls=published_urls,
    )
    validate_policy_document(policy.to_dict())
    return policy


def generate_policy_json(**kwargs: Any) -> str:
    policy = generate_policy(**kwargs)
    return policy_document_to_json(policy.to_dict())


def sign_policy_bytes(
    data: bytes,
    signing_key: str | bytes,
    *,
    key_id: str = DEFAULT_TRUSTED_POLICY_KEY_ID,
) -> dict[str, str]:
    signature = sign_ed25519_policy_bytes(data, signing_key, key_id=key_id)
    signature["signed_at_utc"] = _utc_now()
    return signature


def _write_public_artifact_bytes(path: Path, data: bytes) -> None:
    # Detached signatures and policy manifests are public Pages artifacts, not secrets.
    # codeql[py/clear-text-storage-sensitive-data]
    path.write_bytes(data)


def _write_public_artifact_text(path: Path, text: str) -> None:
    # Generated Pages text files contain public policy metadata only.
    # codeql[py/clear-text-storage-sensitive-data]
    path.write_text(text, encoding="utf-8", newline="\n")


def _public_verification_metadata(record: Mapping[str, Any] | None) -> dict[str, str] | None:
    if not record:
        return None
    metadata: dict[str, str] = {}
    for field in ("algorithm", "key_id", "signed_at_utc"):
        value = record.get(field)
        if value is not None:
            metadata[field] = str(value)
    return metadata or None


def _copy_pypi_download_image(output_dir: Path) -> Path:
    source_path = PYPI_DOWNLOAD_IMAGE_PATH
    if not source_path.is_file():
        raise FileNotFoundError(f"Required Pages image asset is missing: {source_path.as_posix()}")
    target_path = output_dir / PYPI_DOWNLOAD_IMAGE_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_path, target_path)
    return target_path


def _wiki_page_url_slug(stem: str) -> str:
    slug = re.sub(r"\s+", "-", stem.strip())
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", slug)
    slug = re.sub(r"-{2,}", "-", slug).strip("-")
    return slug or "page"


def _wiki_lookup_key(value: str) -> str:
    normalized = value.strip()
    if normalized.lower().endswith(".md"):
        normalized = normalized[:-3]
    normalized = normalized.replace("_", "-")
    normalized = re.sub(r"\s+", "-", normalized)
    normalized = re.sub(r"-{2,}", "-", normalized)
    return normalized.strip("-").casefold()


def _wiki_first_heading(text: str) -> str | None:
    for line in text.splitlines():
        match = _MARKDOWN_HEADING_RE.match(line)
        if match:
            return _plain_wiki_inline_text(match.group(2)).strip() or None
    return None


def _wiki_title_from_path(path: Path, text: str) -> str:
    heading = _wiki_first_heading(text)
    if heading:
        return heading
    if path.stem.casefold() == "home":
        return "Home"
    return path.stem.replace("-", " ").replace("_", " ").strip() or path.stem


def _plain_wiki_inline_text(text: str) -> str:
    text = re.sub(r"!\[([^\]\n]*)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"\[([^\]\n]+)\]\([^)]+\)", r"\1", text)

    def replace_wiki_link(match: re.Match[str]) -> str:
        value = match.group(1)
        if "|" in value:
            label, _target = value.split("|", 1)
            return label.strip()
        return value.strip()

    text = re.sub(r"\[\[([^\]\n]+)\]\]", replace_wiki_link, text)
    text = text.replace("**", "").replace("__", "").replace("`", "")
    return text


def _heading_slug_base(text: str) -> str:
    normalized = _plain_wiki_inline_text(text).casefold()
    normalized = re.sub(r"[^a-z0-9]+", "-", normalized)
    normalized = normalized.strip("-")
    return normalized or "section"


def _unique_heading_slug(text: str, used_slugs: dict[str, int]) -> str:
    base = _heading_slug_base(text)
    count = used_slugs.get(base, 0) + 1
    used_slugs[base] = count
    if count == 1:
        return base
    return f"{base}-{count}"


def _unique_slug(base: str, used_slugs: dict[str, int]) -> str:
    clean_base = base.strip() or "section"
    count = used_slugs.get(clean_base, 0) + 1
    used_slugs[clean_base] = count
    if count == 1:
        return clean_base
    return f"{clean_base}-{count}"


def _wiki_home_source(wiki_dir: Path) -> WikiPageSource:
    title = "Home"
    slug = _wiki_page_url_slug(title)
    lookup_keys = tuple(dict.fromkeys((_wiki_lookup_key(title), _wiki_lookup_key(slug))))
    return WikiPageSource(path=wiki_dir / "Home.md", title=title, slug=slug, lookup_keys=lookup_keys)


def _fallback_wiki_home_markdown(message: str) -> str:
    return "\n".join(("# Home", "", message, ""))


def _wiki_dir_display_name(source_dir: Path) -> str:
    if source_dir.is_absolute():
        return source_dir.name or "wiki"
    return source_dir.as_posix()


def _wiki_source_display_name(path: Path) -> str:
    if path.is_absolute():
        return path.name
    return path.as_posix()


def _discover_wiki_sources(wiki_dir: str | Path = WIKI_SOURCE_DIR) -> tuple[tuple[WikiPageSource, ...], dict[Path, str]]:
    source_dir = Path(wiki_dir)
    if not source_dir.exists():
        return (), {}
    texts: dict[Path, str] = {}
    sources: list[WikiPageSource] = []
    for path in sorted(source_dir.glob("*.md"), key=lambda item: item.name.casefold()):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        texts[path] = text
        title = _wiki_title_from_path(path, text)
        slug = _wiki_page_url_slug(path.stem)
        lookup_keys = tuple(
            dict.fromkeys(
                (
                    _wiki_lookup_key(path.stem),
                    _wiki_lookup_key(slug),
                    _wiki_lookup_key(title),
                    _wiki_lookup_key(path.stem.replace("-", " ")),
                    _wiki_lookup_key(path.stem.replace("_", " ")),
                )
            )
        )
        sources.append(WikiPageSource(path=path, title=title, slug=slug, lookup_keys=lookup_keys))
    return tuple(sources), texts


def _prepare_wiki_sources(
    wiki_dir: str | Path = WIKI_SOURCE_DIR,
) -> tuple[tuple[WikiPageSource, ...], dict[Path, str], tuple[str, ...]]:
    source_dir = Path(wiki_dir)
    source_dir_label = _wiki_dir_display_name(source_dir)
    sources, texts = _discover_wiki_sources(source_dir)
    warnings: list[str] = []
    if not source_dir.exists():
        fallback_source = _wiki_home_source(source_dir)
        warnings.append(f"{source_dir_label} is missing; generated a fallback Wiki index page.")
        texts[fallback_source.path] = _fallback_wiki_home_markdown(
            f"The source directory `{source_dir_label}` is missing. Add `wiki/Home.md` and related Markdown "
            "sources to publish a full Pages Wiki."
        )
        return (fallback_source,), texts, tuple(warnings)
    if not sources:
        fallback_source = _wiki_home_source(source_dir)
        warnings.append(f"{source_dir_label} contains no Markdown sources; generated a fallback Wiki index page.")
        texts[fallback_source.path] = _fallback_wiki_home_markdown(
            f"The source directory `{source_dir_label}` contains no Markdown files. Add `wiki/Home.md` "
            "to publish a full Pages Wiki."
        )
        return (fallback_source,), texts, tuple(warnings)
    if not any(source.path.stem.casefold() == "home" for source in sources):
        fallback_source = _wiki_home_source(source_dir)
        warnings.append("wiki/Home.md is missing; generated a fallback Wiki index page from discovered sources.")
        texts[fallback_source.path] = _fallback_wiki_home_markdown(
            "`wiki/Home.md` is missing. This fallback index keeps the Pages Wiki reachable while the source "
            "Markdown is repaired."
        )
        sources = (fallback_source, *sources)
    return sources, texts, tuple(warnings)


def _wiki_page_map(sources: Sequence[WikiPageSource]) -> dict[str, WikiPageSource]:
    pages: dict[str, WikiPageSource] = {}
    for source in sources:
        for key in source.lookup_keys:
            pages.setdefault(key, source)
    return pages


def _wiki_output_relative_path(source: WikiPageSource) -> Path:
    if source.path.stem.casefold() == "home":
        return Path("wiki") / "index.html"
    return Path("wiki") / source.slug / "index.html"


def _pages_wiki_url(*, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    return f"{base_url.rstrip('/')}/wiki/"


def _pages_root_url(*, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    return f"{base_url.rstrip('/')}/"


def _pypi_download_image_url(*, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    _ = base_url
    return PYPI_DOWNLOAD_IMAGE_PATH.as_posix()


def _wiki_page_href(source: WikiPageSource, *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    wiki_base = _pages_wiki_url(base_url=base_url)
    if source.path.stem.casefold() == "home":
        return wiki_base
    return f"{wiki_base}{source.slug}/"


def _resolve_wiki_target(
    target: str,
    pages: Mapping[str, WikiPageSource],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> tuple[str | None, str | None]:
    page_name, separator, fragment = target.strip().partition("#")
    if not page_name and separator:
        return f"#{_heading_slug_base(fragment)}", None
    page = pages.get(_wiki_lookup_key(page_name))
    if not page:
        return None, page_name.strip() or target.strip()
    href = _wiki_page_href(page, base_url=base_url)
    if fragment:
        href = f"{href}#{_heading_slug_base(fragment)}"
    return href, None


def _is_allowed_absolute_url(target: str) -> bool:
    lower = target.casefold()
    return lower.startswith(("https://", "http://", "mailto:"))


def _has_url_scheme(target: str) -> bool:
    return bool(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", target))


def _render_broken_wiki_link(label: str, target: str, broken_links: list[str]) -> str:
    clean_target = target.strip()
    if clean_target:
        broken_links.append(clean_target)
    return (
        f'<span class="broken-link" data-broken-link="{escape(clean_target)}">'
        f"{escape(label.strip() or clean_target or 'broken link')}</span>"
    )


def _render_wiki_link(
    value: str,
    pages: Mapping[str, WikiPageSource],
    broken_links: list[str],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    if "|" in value:
        label, target = value.split("|", 1)
    else:
        label = target = value
    href, missing = _resolve_wiki_target(target, pages, base_url=base_url)
    if missing:
        return _render_broken_wiki_link(label, missing, broken_links)
    return f'<a href="{escape(href or "#")}">{escape(label.strip() or target.strip())}</a>'


def _render_markdown_link(
    label: str,
    target: str,
    pages: Mapping[str, WikiPageSource],
    broken_links: list[str],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    clean_target = target.strip()
    clean_label = label.strip() or clean_target
    if not clean_target:
        return escape(clean_label)
    if clean_target.startswith("#"):
        href = f"#{_heading_slug_base(clean_target[1:])}"
        return f'<a href="{escape(href)}">{escape(clean_label)}</a>'
    if _is_allowed_absolute_url(clean_target):
        rel = ' rel="noopener noreferrer"' if clean_target.casefold().startswith(("http://", "https://")) else ""
        return f'<a href="{escape(clean_target)}"{rel}>{escape(clean_label)}</a>'
    if _has_url_scheme(clean_target):
        return _render_broken_wiki_link(clean_label, clean_target, broken_links)
    if clean_target.startswith("/") and not clean_target.startswith("//"):
        href = f"{base_url.rstrip('/')}{clean_target}"
        return f'<a href="{escape(href)}">{escape(clean_label)}</a>'
    if clean_target.startswith(("./", "../")):
        return f'<a href="{escape(clean_target)}">{escape(clean_label)}</a>'
    if "/" in clean_target and not clean_target.startswith("//"):
        return f'<a href="{escape(clean_target)}">{escape(clean_label)}</a>'
    href, missing = _resolve_wiki_target(clean_target, pages, base_url=base_url)
    if missing:
        return _render_broken_wiki_link(clean_label, missing, broken_links)
    return f'<a href="{escape(href or "#")}">{escape(clean_label)}</a>'


def _render_markdown_image(alt: str, target: str) -> str:
    clean_target = target.strip()
    if not _is_allowed_absolute_url(clean_target):
        return escape(alt.strip())
    return (
        f'<img src="{escape(clean_target)}" alt="{escape(alt.strip())}" '
        'loading="lazy" decoding="async">'
    )


def _render_wiki_inline(
    text: str,
    pages: Mapping[str, WikiPageSource],
    broken_links: list[str],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    parts: list[str] = []
    index = 0
    while index < len(text):
        if text.startswith("![", index):
            label_end = text.find("](", index + 2)
            target_end = text.find(")", label_end + 2) if label_end != -1 else -1
            if label_end != -1 and target_end != -1:
                parts.append(_render_markdown_image(text[index + 2 : label_end], text[label_end + 2 : target_end]))
                index = target_end + 1
                continue
        if text.startswith("[[", index):
            end = text.find("]]", index + 2)
            if end != -1:
                parts.append(_render_wiki_link(text[index + 2 : end], pages, broken_links, base_url=base_url))
                index = end + 2
                continue
        if text.startswith("[", index):
            label_end = text.find("](", index + 1)
            target_end = text.find(")", label_end + 2) if label_end != -1 else -1
            if label_end != -1 and target_end != -1:
                parts.append(
                    _render_markdown_link(
                        text[index + 1 : label_end],
                        text[label_end + 2 : target_end],
                        pages,
                        broken_links,
                        base_url=base_url,
                    )
                )
                index = target_end + 1
                continue
        if text.startswith("**", index):
            end = text.find("**", index + 2)
            if end != -1:
                inner = _render_wiki_inline(text[index + 2 : end], pages, broken_links, base_url=base_url)
                parts.append(f"<strong>{inner}</strong>")
                index = end + 2
                continue
        if text.startswith("`", index):
            end = text.find("`", index + 1)
            if end != -1:
                parts.append(f"<code>{escape(text[index + 1 : end])}</code>")
                index = end + 1
                continue
        next_special = len(text)
        for marker in ("![", "[[", "[", "**", "`"):
            marker_index = text.find(marker, index + 1)
            if marker_index != -1:
                next_special = min(next_special, marker_index)
        parts.append(escape(text[index:next_special]))
        index = next_special
    return "".join(parts)


def _split_markdown_table_row(line: str) -> list[str]:
    cells: list[str] = []
    current: list[str] = []
    escaped_pipe = False
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    for char in stripped:
        if char == "|" and not escaped_pipe:
            cells.append("".join(current).strip())
            current = []
            continue
        if char == "\\" and not escaped_pipe:
            escaped_pipe = True
            continue
        if escaped_pipe:
            current.append(char)
            escaped_pipe = False
            continue
        current.append(char)
    cells.append("".join(current).strip())
    return cells


def _is_table_start(lines: Sequence[str], index: int) -> bool:
    if index + 1 >= len(lines):
        return False
    return "|" in lines[index] and bool(_TABLE_SEPARATOR_RE.match(lines[index + 1]))


def _render_wiki_table(
    rows: Sequence[str],
    pages: Mapping[str, WikiPageSource],
    broken_links: list[str],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    header = _split_markdown_table_row(rows[0])
    body_rows = rows[2:]
    thead = "".join(
        f"<th>{_render_wiki_inline(cell, pages, broken_links, base_url=base_url)}</th>" for cell in header
    )
    tbody_lines: list[str] = []
    for row in body_rows:
        cells = _split_markdown_table_row(row)
        tbody_lines.append(
            "<tr>"
            + "".join(f"<td>{_render_wiki_inline(cell, pages, broken_links, base_url=base_url)}</td>" for cell in cells)
            + "</tr>"
        )
    return f"<table><thead><tr>{thead}</tr></thead><tbody>{''.join(tbody_lines)}</tbody></table>"


def _list_indent_width(value: str) -> int:
    return len(value.replace("\t", "    "))


def _list_tag(marker: str) -> str:
    return "ol" if marker.endswith(".") else "ul"


def _render_wiki_list(
    lines: Sequence[str],
    index: int,
    pages: Mapping[str, WikiPageSource],
    broken_links: list[str],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
    base_indent: int | None = None,
    expected_tag: str | None = None,
) -> tuple[str, int]:
    first_match = _LIST_ITEM_RE.match(lines[index])
    if not first_match:
        return "", index
    if base_indent is None:
        base_indent = _list_indent_width(first_match.group("indent"))
    tag = expected_tag or _list_tag(first_match.group("marker"))
    items: list[str] = []
    while index < len(lines):
        match = _LIST_ITEM_RE.match(lines[index])
        if not match:
            break
        indent = _list_indent_width(match.group("indent"))
        current_tag = _list_tag(match.group("marker"))
        if indent < base_indent:
            break
        if indent > base_indent:
            if not items:
                break
            nested_html, index = _render_wiki_list(
                lines,
                index,
                pages,
                broken_links,
                base_url=base_url,
                base_indent=indent,
                expected_tag=current_tag,
            )
            items[-1] += nested_html
            continue
        if current_tag != tag:
            break
        items.append(_render_wiki_inline(match.group("text"), pages, broken_links, base_url=base_url))
        index += 1
    body = "".join(f"<li>{item}</li>" for item in items)
    return f"<{tag}>{body}</{tag}>", index


def _render_wiki_markdown_fragment(
    text: str,
    pages: Mapping[str, WikiPageSource],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
    heading_slug_overrides: Mapping[str, str | Sequence[str]] | None = None,
) -> tuple[str, tuple[WikiHeading, ...], tuple[str, ...]]:
    lines = text.splitlines()
    blocks: list[str] = []
    headings: list[WikiHeading] = []
    broken_links: list[str] = []
    used_heading_slugs: dict[str, int] = {}
    slug_override_counts: dict[str, int] = {}
    slug_overrides = heading_slug_overrides or {}
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            index += 1
            continue
        if stripped.startswith("```"):
            language = re.sub(r"[^A-Za-z0-9_+-]+", "", stripped[3:].strip())
            code_lines: list[str] = []
            index += 1
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code_lines.append(lines[index])
                index += 1
            if index < len(lines):
                index += 1
            class_attr = f' class="language-{escape(language)}"' if language else ""
            blocks.append(f"<pre><code{class_attr}>{escape(chr(10).join(code_lines))}</code></pre>")
            continue
        heading_match = _MARKDOWN_HEADING_RE.match(line)
        if heading_match:
            level = len(heading_match.group(1))
            heading_text = _plain_wiki_inline_text(heading_match.group(2)).strip()
            slug_override = slug_overrides.get(heading_text)
            if isinstance(slug_override, str):
                slug = slug_override
            elif slug_override:
                override_index = slug_override_counts.get(heading_text, 0)
                slug_override_counts[heading_text] = override_index + 1
                slug = slug_override[min(override_index, len(slug_override) - 1)]
            else:
                slug = _unique_heading_slug(heading_text, used_heading_slugs)
            if slug_override:
                slug = _unique_slug(slug, used_heading_slugs)
            headings.append(WikiHeading(level=level, text=heading_text, slug=slug))
            inline_heading = _render_wiki_inline(heading_match.group(2), pages, broken_links, base_url=base_url)
            blocks.append(f'<h{level} id="{escape(slug)}">{inline_heading}</h{level}>')
            index += 1
            continue
        if stripped == "---":
            blocks.append("<hr>")
            index += 1
            continue
        if _is_table_start(lines, index):
            table_rows = [lines[index], lines[index + 1]]
            index += 2
            while index < len(lines) and lines[index].strip() and "|" in lines[index]:
                table_rows.append(lines[index])
                index += 1
            blocks.append(_render_wiki_table(table_rows, pages, broken_links, base_url=base_url))
            continue
        if _LIST_ITEM_RE.match(line):
            list_html, index = _render_wiki_list(lines, index, pages, broken_links, base_url=base_url)
            blocks.append(list_html)
            continue
        paragraph_lines = [stripped]
        index += 1
        while index < len(lines):
            candidate = lines[index]
            candidate_stripped = candidate.strip()
            if not candidate_stripped:
                break
            if (
                candidate_stripped.startswith("```")
                or _MARKDOWN_HEADING_RE.match(candidate)
                or candidate_stripped == "---"
                or _is_table_start(lines, index)
                or _LIST_ITEM_RE.match(candidate)
            ):
                break
            paragraph_lines.append(candidate_stripped)
            index += 1
        paragraph = " ".join(paragraph_lines)
        blocks.append(f"<p>{_render_wiki_inline(paragraph, pages, broken_links, base_url=base_url)}</p>")
    return "\n".join(blocks), tuple(headings), tuple(dict.fromkeys(broken_links))


def _render_wiki_toc(headings: Sequence[WikiHeading]) -> str:
    if not headings:
        return ""
    items = "".join(
        f'<li class="toc-level-{heading.level}"><a href="#{escape(heading.slug)}">{escape(heading.text)}</a></li>'
        for heading in headings
    )
    return f'<section class="wiki-toc" aria-label="Table of contents"><h2>On this page</h2><ol>{items}</ol></section>'


def _wiki_navigation_html(site_navigation_html: str, *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    changelog_href = _changelog_pages_base_url(base_url=base_url)
    return (
        '<section class="wiki-primary-nav" aria-label="Primary wiki navigation">'
        "<h2>Wiki</h2>"
        f'<ul><li class="wiki-nav-changelog"><a href="{escape(changelog_href, quote=True)}">'
        "Changelog</a></li></ul></section>"
        '<section class="wiki-source-nav" aria-label="Wiki source navigation">'
        f"{site_navigation_html}</section>"
    )


def _wiki_breadcrumbs_html(source: WikiPageSource, *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    dashboard_url = _pages_root_url(base_url=base_url)
    wiki_url = _pages_wiki_url(base_url=base_url)
    items = [
        f'<li><a href="{escape(dashboard_url, quote=True)}">Dashboard</a></li>',
        f'<li><a href="{escape(wiki_url, quote=True)}">Wiki</a></li>',
    ]
    if source.slug.startswith("changelog/"):
        items.append(
            f'<li><a href="{escape(_changelog_pages_base_url(base_url=base_url), quote=True)}">Changelog</a></li>'
        )
    items.append(f'<li aria-current="page">{escape(source.title)}</li>')
    return f'<nav class="wiki-breadcrumbs" aria-label="Breadcrumb"><ol>{"".join(items)}</ol></nav>'


def _render_default_wiki_navigation(sources: Sequence[WikiPageSource], *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    items = "".join(
        f'<li><a href="{escape(_wiki_page_href(source, base_url=base_url))}">{escape(source.title)}</a></li>'
        for source in sources
    )
    return f'<h2>Wiki</h2><ul>{items}</ul>'


def _render_wiki_broken_links(broken_links: Sequence[str]) -> str:
    if not broken_links:
        return ""
    items = "".join(f"<li>{escape(link)}</li>" for link in broken_links)
    return f'<section class="wiki-broken-links"><h2>Broken wiki links</h2><ul>{items}</ul></section>'


def _render_wiki_warnings(warnings: Sequence[str]) -> str:
    if not warnings:
        return ""
    items = "".join(f"<li>{escape(warning)}</li>" for warning in dict.fromkeys(warnings))
    return f'<section class="wiki-render-warnings"><h2>Generator warnings</h2><ul>{items}</ul></section>'


def _clean_meta_text(text: str) -> str:
    cleaned = _plain_wiki_inline_text(text)
    cleaned = re.sub(r"<[^>]+>", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def _meta_description(text: str, *, fallback: str, max_length: int = 180) -> str:
    cleaned = _clean_meta_text(text) or fallback
    if len(cleaned) <= max_length:
        return cleaned
    truncated = cleaned[: max_length - 1].rsplit(" ", 1)[0].strip()
    return (truncated or cleaned[: max_length - 1]).rstrip(".,;:") + "."


def _first_markdown_paragraph(text: str) -> str:
    lines = text.splitlines()
    paragraph: list[str] = []
    in_fence = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if not stripped:
            if paragraph:
                break
            continue
        if not paragraph and (
            stripped.startswith("#")
            or stripped.startswith("|")
            or stripped.startswith(("- ", "* "))
            or _ORDERED_LIST_RE.match(stripped)
            or stripped == "---"
        ):
            continue
        paragraph.append(stripped)
    return " ".join(paragraph)


def _wiki_meta_description(source: WikiPageSource, markdown_text: str) -> str:
    fallback = (
        f"{source.title} documentation for Windows 11 Release Guard, Windows 11 release compliance, "
        "the signed public policy feed, and fleet administration."
    )
    return _meta_description(_first_markdown_paragraph(markdown_text), fallback=fallback, max_length=280)


def _wiki_document_title(title: str) -> str:
    suffix = "Windows 11 Release Guard Wiki"
    return title if title.strip().casefold() == suffix.casefold() else f"{title} | {suffix}"


def _seo_meta_html(
    *,
    title: str,
    description: str,
    canonical_url: str,
    og_type: str = "website",
) -> str:
    safe_title = escape(title, quote=True)
    safe_description = escape(description, quote=True)
    safe_url = escape(canonical_url, quote=True)
    safe_type = escape(og_type, quote=True)
    return (
        f'  <meta name="description" content="{safe_description}">\n'
        f'  <link rel="canonical" href="{safe_url}">\n'
        f'  <meta property="og:title" content="{safe_title}">\n'
        f'  <meta property="og:description" content="{safe_description}">\n'
        f'  <meta property="og:type" content="{safe_type}">\n'
        f'  <meta property="og:url" content="{safe_url}">\n'
        '  <meta property="og:site_name" content="Windows 11 Release Guard">\n'
        '  <meta name="twitter:card" content="summary">\n'
        f'  <meta name="twitter:title" content="{safe_title}">\n'
        f'  <meta name="twitter:description" content="{safe_description}">\n'
    )


def _wiki_section_scrollspy_script_html() -> str:
    return """  <script>
    (function () {
      var sidebar = document.querySelector(".wiki-sidebar");
      var content = document.getElementById("wiki-content");
      if (!sidebar || !content) return;

      function isVersionMetaLink(link) {
        var node = link;
        while (node && node !== sidebar) {
          if (node.classList && node.classList.contains("version-meta")) return true;
          node = node.parentElement;
        }
        return false;
      }

      function samePageHash(link) {
        var href = link.getAttribute("href") || "";
        if (!href || isVersionMetaLink(link)) return "";
        if (href.charAt(0) === "#") return href;
        if (typeof URL === "undefined") return "";
        try {
          var url = new URL(href, window.location.href);
          if (url.origin !== window.location.origin || url.pathname !== window.location.pathname) return "";
          return url.hash || "";
        } catch (error) {
          return "";
        }
      }

      function hashId(hash) {
        try {
          return decodeURIComponent(hash.slice(1));
        } catch (error) {
          return hash.slice(1);
        }
      }

      var items = Array.prototype.slice.call(sidebar.querySelectorAll("a[href]")).map(function (link) {
        var hash = samePageHash(link);
        if (!hash || hash === "#") return null;
        var target = document.getElementById(hashId(hash));
        if (!target || !content.contains(target)) return null;
        return { link: link, item: link.closest ? link.closest("li") : null, target: target };
      }).filter(Boolean);
      if (!items.length) return;

      function setActive(active) {
        items.forEach(function (entry) {
          var selected = entry === active;
          entry.link.classList.toggle("is-active-section", selected);
          if (entry.item) entry.item.classList.toggle("is-active-section", selected);
          if (selected) {
            entry.link.setAttribute("aria-current", "location");
          } else {
            entry.link.removeAttribute("aria-current");
          }
        });
      }

      function updateActiveSection() {
        var activationLine = Math.min(window.innerHeight * 0.28, 180);
        var active = items[0];
        items.forEach(function (entry) {
          if (entry.target.getBoundingClientRect().top <= activationLine) active = entry;
        });
        if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) {
          active = items[items.length - 1];
        }
        setActive(active);
      }

      var requestFrame = window.requestAnimationFrame || function (callback) { return window.setTimeout(callback, 16); };
      var scheduled = false;
      function scheduleUpdate() {
        if (scheduled) return;
        scheduled = true;
        requestFrame(function () {
          scheduled = false;
          updateActiveSection();
        });
      }

      window.addEventListener("scroll", scheduleUpdate, { passive: true });
      window.addEventListener("resize", scheduleUpdate);
      window.addEventListener("hashchange", scheduleUpdate);
      if ("IntersectionObserver" in window) {
        var observer = new IntersectionObserver(scheduleUpdate, { rootMargin: "-18% 0px -70% 0px", threshold: [0, 1] });
        items.forEach(function (entry) { observer.observe(entry.target); });
      }
      updateActiveSection();
    })();
  </script>
"""


def _wiki_page_html(
    source: WikiPageSource,
    body_html: str,
    headings: Sequence[WikiHeading],
    *,
    site_navigation_html: str,
    footer_html: str,
    broken_links: Sequence[str],
    warnings: Sequence[str] = (),
    canonical_url: str,
    description: str,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    wiki_url = _pages_wiki_url(base_url=base_url)
    dashboard_url = _pages_root_url(base_url=base_url)
    page_title = _wiki_document_title(source.title)
    title = escape(source.title)
    seo_meta = _seo_meta_html(title=page_title, description=description, canonical_url=canonical_url)
    navigation_html = _wiki_navigation_html(site_navigation_html, base_url=base_url)
    breadcrumbs_html = _wiki_breadcrumbs_html(source, base_url=base_url)
    toc_html = _render_wiki_toc(headings)
    broken_html = _render_wiki_broken_links(broken_links)
    warning_html = _render_wiki_warnings(warnings)
    content_class = "wiki-content changelog-content" if source.slug.startswith("changelog") else "wiki-content"
    scrollspy_script = _wiki_section_scrollspy_script_html()
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(page_title)}</title>
{seo_meta}  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f9ff;
      --surface: #ffffff;
      --surface-soft: #eef6ff;
      --border: #c8ddf7;
      --text: #172033;
      --muted: #53657f;
      --brand: #0f6cbd;
      --brand-strong: #0b4f8a;
      --brand-soft: #e8f3ff;
      --brand-line: #9cccf6;
      --focus: #005fb8;
      --warn-bg: #fff7e6;
      --warn-border: #f2c36b;
      --shadow: 0 18px 45px rgba(15, 108, 189, 0.12);
    }}
    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: "Segoe UI", Arial, sans-serif;
      line-height: 1.55;
      color: var(--text);
      background:
        linear-gradient(180deg, rgba(232, 243, 255, 0.96), rgba(245, 249, 255, 1) 18rem),
        var(--bg);
    }}
    a {{ color: var(--brand); text-decoration-thickness: 0.08em; text-underline-offset: 0.18em; }}
    a:hover {{ color: var(--brand-strong); }}
    a:focus-visible, summary:focus-visible {{
      outline: 3px solid rgba(0, 95, 184, 0.34);
      outline-offset: 3px;
      border-radius: 4px;
    }}
    .skip-link {{
      position: absolute;
      left: 1rem;
      top: 0.75rem;
      z-index: 20;
      transform: translateY(-160%);
      border: 1px solid var(--brand-line);
      border-radius: 6px;
      background: #ffffff;
      box-shadow: var(--shadow);
      color: var(--brand-strong);
      font-weight: 700;
      padding: 0.6rem 0.85rem;
      text-decoration: none;
    }}
    .skip-link:focus {{ transform: translateY(0); }}
    .wiki-topbar {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 1rem clamp(1rem, 4vw, 3rem);
      background: rgba(255, 255, 255, 0.92);
      border-bottom: 1px solid var(--border);
      box-shadow: 0 8px 24px rgba(15, 108, 189, 0.08);
    }}
    .wiki-brand {{ color: var(--text); font-weight: 750; text-decoration: none; }}
    .wiki-brand span {{ color: var(--brand); }}
    .wiki-topbar nav {{ display: flex; flex-wrap: wrap; gap: 0.55rem; font-size: 0.94rem; }}
    .wiki-topbar nav a {{
      display: inline-flex;
      align-items: center;
      min-height: 2rem;
      border: 1px solid transparent;
      border-radius: 999px;
      padding: 0.28rem 0.7rem;
      text-decoration: none;
      font-weight: 650;
    }}
    .wiki-topbar nav a:hover {{ border-color: var(--brand-line); background: var(--brand-soft); }}
    .wiki-layout {{
      display: grid;
      grid-template-columns: minmax(15rem, 20rem) minmax(0, 1fr);
      gap: clamp(1rem, 3vw, 2.5rem);
      width: min(1220px, calc(100% - 2rem));
      margin: 1.6rem auto 3rem;
      align-items: start;
    }}
    .wiki-sidebar {{
      position: sticky;
      top: 1rem;
      display: grid;
      gap: 1.25rem;
      padding: 1rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      box-shadow: 0 12px 30px rgba(15, 108, 189, 0.08);
      max-height: calc(100vh - 2rem);
      overflow: auto;
    }}
    .wiki-sidebar h1, .wiki-sidebar h2, .wiki-sidebar h3 {{
      margin: 0.35rem 0 0.2rem;
      font-size: 0.88rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0;
    }}
    .wiki-sidebar ul, .wiki-sidebar ol {{ margin: 0; padding-left: 1.2rem; }}
    .wiki-sidebar li {{ margin: 0.32rem 0; }}
    .wiki-sidebar a {{ overflow-wrap: anywhere; }}
    .wiki-sidebar a.is-active-section {{
      display: inline-flex;
      align-items: center;
      max-width: 100%;
      margin-left: -0.35rem;
      border-radius: 6px;
      background: linear-gradient(90deg, rgba(15, 108, 189, 0.14), rgba(232, 243, 255, 0.52));
      box-shadow: inset 3px 0 0 var(--brand);
      color: var(--brand-strong);
      font-weight: 800;
      padding: 0.1rem 0.35rem;
      text-decoration: none;
    }}
    .wiki-sidebar li.is-active-section > a {{
      text-decoration: none;
    }}
    .wiki-primary-nav {{
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.9rem;
    }}
    .wiki-primary-nav ul {{ list-style: none; padding: 0; }}
    .wiki-nav-changelog a {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      min-height: 2.35rem;
      border: 1px solid var(--brand-line);
      border-radius: 8px;
      background: linear-gradient(180deg, #ffffff, var(--brand-soft));
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.9);
      color: var(--brand-strong);
      font-weight: 750;
      padding: 0.45rem 0.7rem;
      text-decoration: none;
    }}
    .wiki-nav-changelog a::after {{ content: "Release history"; color: var(--muted); font-size: 0.78rem; font-weight: 600; }}
    .wiki-source-nav {{
      display: grid;
      gap: 0.75rem;
    }}
    .wiki-toc ol {{ list-style: none; padding-left: 0; }}
    .wiki-toc a {{ text-decoration: none; }}
    .wiki-toc .toc-level-2 {{ padding-left: 0.6rem; }}
    .wiki-toc .toc-level-3, .wiki-toc .toc-level-4, .wiki-toc .toc-level-5, .wiki-toc .toc-level-6 {{
      padding-left: 1.2rem;
    }}
    .wiki-content {{
      min-width: 0;
      padding: clamp(1.25rem, 4vw, 2.25rem);
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }}
    .wiki-content:focus {{ outline: none; }}
    .wiki-breadcrumbs {{
      margin: 0 0 1.15rem;
      color: var(--muted);
      font-size: 0.92rem;
    }}
    .wiki-breadcrumbs ol {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      list-style: none;
      margin: 0;
      padding: 0;
    }}
    .wiki-breadcrumbs li {{ display: inline-flex; align-items: center; gap: 0.4rem; }}
    .wiki-breadcrumbs li + li::before {{ content: "/"; color: #8aa3bd; }}
    .wiki-breadcrumbs [aria-current="page"] {{ color: var(--text); font-weight: 650; }}
    .wiki-content h1, .wiki-content h2, .wiki-content h3 {{ line-height: 1.2; letter-spacing: 0; scroll-margin-top: 1rem; }}
    .wiki-content h1 {{ margin-top: 0; font-size: clamp(1.8rem, 3vw, 2.55rem); }}
    .wiki-content h2 {{ margin-top: 2rem; padding-top: 0.3rem; border-top: 1px solid var(--border); }}
    .wiki-content h3 {{ margin-top: 1.45rem; color: #21395d; }}
    .wiki-content p, .wiki-content li {{ color: var(--text); }}
    .wiki-content p {{ max-width: 74ch; }}
    .wiki-content code {{
      padding: 0.1rem 0.28rem;
      background: var(--surface-soft);
      border-radius: 4px;
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 0.92em;
    }}
    .wiki-content pre {{
      overflow: auto;
      padding: 1rem;
      background: #0b1f33;
      color: #eaf4ff;
      border-radius: 8px;
    }}
    .wiki-content pre code {{ padding: 0; background: transparent; color: inherit; }}
    .wiki-content table {{
      width: 100%;
      border-collapse: collapse;
      margin: 1rem 0;
      font-size: 0.95rem;
      box-shadow: 0 1px 0 rgba(15, 108, 189, 0.06);
    }}
    .wiki-content th, .wiki-content td {{ padding: 0.65rem 0.75rem; border: 1px solid var(--border); text-align: left; }}
    .wiki-content th {{ background: var(--surface-soft); }}
    .wiki-content img {{ max-width: 100%; height: auto; border-radius: 8px; border: 1px solid var(--border); }}
    .broken-link {{
      color: #8a4b00;
      background: var(--warn-bg);
      border-bottom: 1px dotted #8a4b00;
    }}
    .wiki-broken-links {{
      margin-top: 2rem;
      padding: 1rem;
      background: var(--warn-bg);
      border: 1px solid var(--warn-border);
      border-radius: 8px;
    }}
    .wiki-render-warnings {{
      margin: 1.2rem 0;
      padding: 1rem;
      background: var(--warn-bg);
      border: 1px solid var(--warn-border);
      border-radius: 8px;
    }}
    .wiki-render-warnings h2, .wiki-broken-links h2 {{ margin-top: 0; color: #8a4b00; }}
    .changelog-version-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.55rem;
      margin: -0.35rem 0 1.2rem;
    }}
    .changelog-version-actions a, .changelog-version-nav .version-meta a {{
      display: inline-flex;
      align-items: center;
      min-height: 1.8rem;
      padding: 0.18rem 0.5rem;
      border: 1px solid var(--border);
      border-radius: 999px;
      background: var(--surface-soft);
      font-size: 0.86rem;
      font-weight: 600;
      text-decoration: none;
    }}
    .changelog-content h2[id] {{
      border: 1px solid var(--border);
      border-left: 4px solid var(--brand);
      border-radius: 8px;
      background: linear-gradient(180deg, #ffffff, #f7fbff);
      box-shadow: 0 8px 22px rgba(15, 108, 189, 0.07);
      padding: 0.85rem 1rem;
    }}
    .changelog-version-nav .version-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.35rem;
      margin-top: 0.25rem;
    }}
    .wiki-footer {{
      width: min(1220px, calc(100% - 2rem));
      margin: 0 auto 2rem;
      color: var(--muted);
      font-size: 0.94rem;
    }}
    @media (prefers-reduced-motion: reduce) {{
      html {{ scroll-behavior: auto; }}
      *, *::before, *::after {{
        animation-duration: 0.001ms !important;
        animation-iteration-count: 1 !important;
        scroll-behavior: auto !important;
        transition-duration: 0.001ms !important;
      }}
    }}
    @media (max-width: 860px) {{
      .wiki-layout {{ grid-template-columns: 1fr; margin-top: 1rem; }}
      .wiki-sidebar {{ position: static; max-height: none; }}
      .wiki-topbar {{ align-items: flex-start; flex-direction: column; }}
      .wiki-nav-changelog a {{ align-items: flex-start; flex-direction: column; gap: 0.1rem; }}
      .wiki-content table {{ display: block; overflow-x: auto; }}
    }}
    @media (max-width: 520px) {{
      .wiki-layout {{ width: min(100% - 1rem, 1220px); }}
      .wiki-content, .wiki-sidebar {{ padding: 0.9rem; }}
      .wiki-topbar {{ padding: 0.85rem 0.75rem; }}
      .wiki-topbar nav a {{ padding-inline: 0.55rem; }}
    }}
  </style>
</head>
<body>
  <a class="skip-link" href="#wiki-content">Skip to content</a>
  <header class="wiki-topbar">
    <a class="wiki-brand" href="{escape(dashboard_url)}"><span>Windows 11</span> Release Guard</a>
    <nav aria-label="Site">
      <a href="{escape(dashboard_url)}">Dashboard</a>
      <a href="{escape(wiki_url)}">Wiki</a>
      <a href="{escape(_changelog_pages_base_url(base_url=base_url))}">Changelog</a>
      <a href="{escape(GITHUB_REPOSITORY_URL)}">Repository</a>
    </nav>
  </header>
  <main class="wiki-layout">
    <aside class="wiki-sidebar" aria-label="Wiki navigation" data-section-scrollspy="true">
      <nav aria-label="Wiki pages">{navigation_html}</nav>
      {toc_html}
    </aside>
    <article id="wiki-content" class="{content_class}" tabindex="-1">
      {breadcrumbs_html}
      {warning_html}
      {body_html}
      {broken_html}
    </article>
  </main>
  <footer class="wiki-footer">{footer_html}</footer>
{scrollspy_script}</body>
</html>
"""


def render_wiki_pages(
    *,
    wiki_dir: str | Path = WIKI_SOURCE_DIR,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> dict[str, str]:
    sources, texts, global_warnings = _prepare_wiki_sources(wiki_dir)
    pages = _wiki_page_map(sources)
    sidebar_source = next((source for source in sources if source.path.name.casefold() == "_sidebar.md"), None)
    footer_source = next((source for source in sources if source.path.name.casefold() == "_footer.md"), None)
    if sidebar_source:
        site_navigation_html, _nav_headings, sidebar_broken = _render_wiki_markdown_fragment(
            texts[sidebar_source.path], pages, base_url=base_url
        )
    else:
        site_navigation_html = _render_default_wiki_navigation(sources, base_url=base_url)
        sidebar_broken = ()
        global_warnings = (*global_warnings, "wiki/_Sidebar.md is missing; generated default Wiki navigation.")
    if footer_source:
        footer_html, _footer_headings, footer_broken = _render_wiki_markdown_fragment(
            texts[footer_source.path], pages, base_url=base_url
        )
    else:
        footer_html = f'<p>Windows 11 Release Guard documentation for <a href="{escape(GITHUB_REPOSITORY_URL)}">win11_release_guard</a>.</p>'
        footer_broken = ()
        global_warnings = (*global_warnings, "wiki/_Footer.md is missing; generated default Wiki footer.")

    rendered: dict[str, str] = {}
    for source in sources:
        source_text = texts[source.path]
        source_warnings = list(global_warnings)
        if not source_text.strip():
            source_warnings.append(
                f"{_wiki_source_display_name(source.path)} is empty; generated an empty Wiki page with this warning."
            )
        body_html, headings, body_broken = _render_wiki_markdown_fragment(source_text, pages, base_url=base_url)
        broken_links = tuple(dict.fromkeys((*body_broken, *sidebar_broken, *footer_broken)))
        html = _wiki_page_html(
            source,
            body_html,
            headings,
            site_navigation_html=site_navigation_html,
            footer_html=footer_html,
            broken_links=broken_links,
            warnings=source_warnings,
            canonical_url=_wiki_page_href(source, base_url=base_url),
            description=_wiki_meta_description(source, source_text),
            base_url=base_url,
        )
        rendered[_wiki_output_relative_path(source).as_posix()] = html
    return rendered


def write_wiki_pages(
    output_dir: str | Path,
    *,
    wiki_dir: str | Path = WIKI_SOURCE_DIR,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> dict[str, Path]:
    output_path = Path(output_dir)
    written: dict[str, Path] = {}
    for relative_path, html in render_wiki_pages(wiki_dir=wiki_dir, base_url=base_url).items():
        target = output_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_public_artifact_text(target, html)
        written[relative_path] = target
    return written


def _wiki_sitemap_urls(*, wiki_dir: str | Path = WIKI_SOURCE_DIR, base_url: str = DEFAULT_PAGES_BASE_URL) -> tuple[str, ...]:
    sources, _texts, _warnings = _prepare_wiki_sources(wiki_dir)
    if not sources:
        return ()
    urls = [_wiki_page_href(source, base_url=base_url) for source in sources]
    return tuple(dict.fromkeys(urls))


def _changelog_anchor_slug(title: str) -> str:
    if "unreleased" in title.casefold():
        return "unreleased"
    version = _changelog_version_from_title(title)
    if version:
        return version
    return _heading_slug_base(title)


def _changelog_version_from_title(title: str) -> str | None:
    if "unreleased" in title.casefold():
        return None
    match = _CHANGELOG_RELEASE_VERSION_RE.search(title)
    if not match:
        return None
    return f"v{match.group(1)}"


def _changelog_release_href(version: str | None) -> str | None:
    if not version:
        return None
    return f"{GITHUB_RELEASES_BASE_URL}/{version}"


def _changelog_index_description() -> str:
    return (
        "Windows 11 Release Guard changelog for Windows 11 release compliance, signed public policy feed "
        "changes, RMM, and fleet administration release history."
    )


def _changelog_section_description(section: ChangelogSection) -> str:
    version_label = section.version or section.title
    description = (
        f"Windows 11 Release Guard {version_label} changelog covering Windows 11 release compliance, "
        "signed public policy feed changes, RMM, and fleet administration."
    )
    lower_markdown = section.markdown.casefold()
    if "25h2" in lower_markdown or "26h1" in lower_markdown:
        description += " Includes Windows 11 25H2 and 26H1 release targeting notes."
    return description


def _parse_changelog_sections(text: str) -> tuple[ChangelogSection, ...]:
    lines = text.splitlines()
    starts: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        match = _CHANGELOG_VERSION_HEADING_RE.match(line)
        if match:
            starts.append((index, _plain_wiki_inline_text(match.group("title")).strip()))
    sections: list[ChangelogSection] = []
    used_slugs: dict[str, int] = {}
    for position, (start, title) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        markdown = "\n".join(lines[start:end]).strip() + "\n"
        version = _changelog_version_from_title(title)
        slug = _unique_slug(_changelog_anchor_slug(title), used_slugs)
        sections.append(
            ChangelogSection(
                title=title,
                slug=slug,
                markdown=markdown,
                version=version,
                release_href=_changelog_release_href(version),
            )
        )
    return tuple(sections)


def _changelog_render_warnings(text: str, sections: Sequence[ChangelogSection]) -> tuple[str, ...]:
    warnings: list[str] = []
    if not text.strip():
        warnings.append("CHANGELOG.md is empty; generated a changelog page with no release history.")
    elif not sections:
        warnings.append(
            "CHANGELOG.md contains no recognized version sections; use h2 headings like [Unreleased] or vX.Y.Z."
        )
    recognized_titles = {section.title.casefold() for section in sections}
    for line in text.splitlines():
        if not line.startswith("## "):
            continue
        title = _plain_wiki_inline_text(line[3:]).strip()
        if title and title.casefold() not in recognized_titles:
            warnings.append(f"CHANGELOG.md h2 heading is not a recognized version section: {title}")
    titles = [section.title.casefold() for section in sections]
    if len(set(titles)) != len(titles):
        warnings.append("CHANGELOG.md contains duplicate version headings; generated duplicate-safe anchors.")
    return tuple(dict.fromkeys(warnings))


def _changelog_pages_base_url(*, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    return f"{base_url.rstrip('/')}/wiki/changelog/"


def _changelog_section_href(section: ChangelogSection, *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    return f"{_changelog_pages_base_url(base_url=base_url)}#{section.slug}"


def _changelog_version_page_href(section: ChangelogSection, *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str | None:
    if not section.version:
        return None
    return f"{_changelog_pages_base_url(base_url=base_url)}{section.version}/"


def _changelog_heading_overrides(sections: Sequence[ChangelogSection]) -> dict[str, str | tuple[str, ...]]:
    grouped: dict[str, list[str]] = {}
    for section in sections:
        grouped.setdefault(section.title, []).append(section.slug)
    return {title: slugs[0] if len(slugs) == 1 else tuple(slugs) for title, slugs in grouped.items()}


def _render_changelog_version_actions(
    section: ChangelogSection,
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    links = [
        f'<a href="{escape(_changelog_section_href(section, base_url=base_url))}">Pages anchor</a>',
    ]
    version_page_href = _changelog_version_page_href(section, base_url=base_url)
    if version_page_href:
        links.append(f'<a href="{escape(version_page_href)}">Version page</a>')
    if section.release_href:
        links.append(f'<a href="{escape(section.release_href)}" rel="noopener noreferrer">GitHub Release</a>')
    return f'<nav class="changelog-version-actions" aria-label="{escape(section.title)} links">{"".join(links)}</nav>'


def _inject_changelog_version_actions(
    body_html: str,
    sections: Sequence[ChangelogSection],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    updated = body_html
    for section in sections:
        heading = f'<h2 id="{escape(section.slug)}">{escape(section.title)}</h2>'
        if heading in updated:
            updated = updated.replace(
                heading,
                heading + "\n" + _render_changelog_version_actions(section, base_url=base_url),
                1,
            )
    return updated


def _render_changelog_navigation(
    sections: Sequence[ChangelogSection],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
    local_anchors: bool = True,
) -> str:
    if not sections:
        return "<h2>Changelog</h2><p>No changelog versions found.</p>"
    items: list[str] = []
    for section in sections:
        section_href = f"#{section.slug}" if local_anchors else _changelog_section_href(section, base_url=base_url)
        links = [f'<a href="{escape(_changelog_section_href(section, base_url=base_url))}">Pages</a>']
        version_page_href = _changelog_version_page_href(section, base_url=base_url)
        if version_page_href:
            links.append(f'<a href="{escape(version_page_href)}">Page</a>')
        if section.release_href:
            links.append(f'<a href="{escape(section.release_href)}" rel="noopener noreferrer">Release</a>')
        items.append(
            '<li>'
            f'<a href="{escape(section_href)}">{escape(section.title)}</a>'
            f'<div class="version-meta">{"".join(links)}</div>'
            '</li>'
        )
    return f'<section class="changelog-version-nav" aria-label="Changelog versions"><h2>Versions</h2><ol>{"".join(items)}</ol></section>'


def _render_changelog_body(
    markdown: str,
    sections: Sequence[ChangelogSection],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> tuple[str, tuple[WikiHeading, ...], tuple[str, ...]]:
    wiki_sources, _texts = _discover_wiki_sources()
    pages = _wiki_page_map(wiki_sources)
    body_html, headings, broken_links = _render_wiki_markdown_fragment(
        markdown,
        pages,
        base_url=base_url,
        heading_slug_overrides=_changelog_heading_overrides(sections),
    )
    return _inject_changelog_version_actions(body_html, sections, base_url=base_url), headings, broken_links


def render_changelog_pages(
    *,
    changelog_path: str | Path = CHANGELOG_SOURCE_PATH,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> dict[str, str]:
    source = Path(changelog_path)
    if not source.is_file():
        return {}
    text = source.read_text(encoding="utf-8")
    sections = _parse_changelog_sections(text)
    changelog_warnings = _changelog_render_warnings(text, sections)
    body_html, _headings, broken_links = _render_changelog_body(text, sections, base_url=base_url)
    navigation_html = _render_changelog_navigation(sections, base_url=base_url)
    version_navigation_html = _render_changelog_navigation(sections, base_url=base_url, local_anchors=False)
    footer_html = (
        f'<p>Rendered from <code>CHANGELOG.md</code>. Historical version sections remain in source order for '
        f'<a href="{escape(_changelog_pages_base_url(base_url=base_url))}">Pages changelog</a>, release history, '
        "SEO, and auditability.</p>"
    )
    index_source = WikiPageSource(path=source, title="Changelog", slug="changelog", lookup_keys=())
    rendered = {
        "wiki/changelog/index.html": _wiki_page_html(
            index_source,
            body_html,
            (),
            site_navigation_html=navigation_html,
            footer_html=footer_html,
            broken_links=broken_links,
            warnings=changelog_warnings,
            canonical_url=_changelog_pages_base_url(base_url=base_url),
            description=_changelog_index_description(),
            base_url=base_url,
        )
    }
    for section in sections:
        if not section.version:
            continue
        version_body, _version_headings, version_broken = _render_changelog_body(
            f"# Changelog\n\n{section.markdown}",
            (section,),
            base_url=base_url,
        )
        version_source = WikiPageSource(
            path=source,
            title=f"Changelog {section.version}",
            slug=section.version,
            lookup_keys=(),
        )
        rendered[f"wiki/changelog/{section.version}/index.html"] = _wiki_page_html(
            version_source,
            version_body,
            (),
            site_navigation_html=version_navigation_html,
            footer_html=footer_html,
            broken_links=version_broken,
            warnings=changelog_warnings,
            canonical_url=_changelog_version_page_href(section, base_url=base_url) or _changelog_section_href(
                section, base_url=base_url
            ),
            description=_changelog_section_description(section),
            base_url=base_url,
        )
    return rendered


def write_changelog_pages(
    output_dir: str | Path,
    *,
    changelog_path: str | Path = CHANGELOG_SOURCE_PATH,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> dict[str, Path]:
    output_path = Path(output_dir)
    written: dict[str, Path] = {}
    for relative_path, html in render_changelog_pages(changelog_path=changelog_path, base_url=base_url).items():
        target = output_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_public_artifact_text(target, html)
        written[relative_path] = target
    return written


def _changelog_sitemap_urls(
    *,
    changelog_path: str | Path = CHANGELOG_SOURCE_PATH,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> tuple[str, ...]:
    source = Path(changelog_path)
    if not source.is_file():
        return ()
    sections = _parse_changelog_sections(source.read_text(encoding="utf-8"))
    urls = [_changelog_pages_base_url(base_url=base_url)]
    urls.extend(
        href
        for href in (_changelog_version_page_href(section, base_url=base_url) for section in sections)
        if href
    )
    return tuple(dict.fromkeys(urls))


def write_policy_outputs(
    policy: ReleasePolicy,
    *,
    output_dir: str | Path,
    signing_key: str | bytes | None = None,
    key_id: str = DEFAULT_TRUSTED_POLICY_KEY_ID,
    write_index: bool = False,
    write_robots: bool = False,
    write_sitemap: bool = False,
    write_manifest: bool = False,
) -> dict[str, Path]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    policy_file = output_path / "windows-release-policy.json"
    json_text = policy_document_to_json(policy.to_dict())
    policy_bytes = json_text.encode("utf-8")
    _write_public_artifact_bytes(policy_file, policy_bytes)
    written = {"policy": policy_file}

    signature: dict[str, str] | None = None
    signature_bytes: bytes | None = None
    verification_metadata: dict[str, str] | None = None
    if signing_key:
        signature = sign_policy_bytes(policy_bytes, signing_key, key_id=key_id)
        verification_metadata = _public_verification_metadata(signature)
        signature_file = output_path / "windows-release-policy.json.sig"
        signature_bytes = (json.dumps(signature, indent=2, sort_keys=True) + "\n").encode("utf-8")
        _write_public_artifact_bytes(signature_file, signature_bytes)
        written["signature"] = signature_file

    manifest_text: str | None = None
    if write_index:
        index_file = output_path / "index.html"
        _write_public_artifact_text(
            index_file,
            render_policy_index(
                policy,
                policy_bytes=policy_bytes,
                verification_metadata=verification_metadata,
            ),
        )
        written["index"] = index_file
        written["asset:pypi_download"] = _copy_pypi_download_image(output_path)
        for relative_path, wiki_file in write_wiki_pages(output_path).items():
            written[f"wiki:{relative_path}"] = wiki_file
        for relative_path, changelog_file in write_changelog_pages(output_path).items():
            written[f"changelog:{relative_path}"] = changelog_file

    if write_robots:
        robots_file = output_path / "robots.txt"
        _write_public_artifact_text(robots_file, render_robots_txt())
        written["robots"] = robots_file

    if write_sitemap:
        sitemap_file = output_path / "sitemap.xml"
        _write_public_artifact_text(sitemap_file, render_sitemap_xml(policy))
        written["sitemap"] = sitemap_file

    if write_manifest:
        manifest_file = output_path / "policy-manifest.json"
        manifest_text = render_policy_manifest(
            policy,
            policy_bytes=policy_bytes,
            signature_bytes=signature_bytes,
            verification_metadata=verification_metadata,
        )
        _write_public_artifact_text(manifest_file, manifest_text)
        written["manifest"] = manifest_file

    if any((write_index, write_robots, write_sitemap, write_manifest)):
        nojekyll_file = output_path / ".nojekyll"
        _write_public_artifact_text(nojekyll_file, "")
        written["nojekyll"] = nojekyll_file

    if write_manifest:
        api_dir = output_path / "api" / "v1"
        api_dir.mkdir(parents=True, exist_ok=True)
        policy_alias = api_dir / "policy.json"
        shutil.copyfile(policy_file, policy_alias)
        written["api_policy"] = policy_alias
        if signature_bytes is not None:
            signature_alias = api_dir / "policy.sig"
            _write_public_artifact_bytes(signature_alias, signature_bytes)
            written["api_signature"] = signature_alias
        if manifest_text is not None:
            manifest_alias = api_dir / "manifest.json"
            _write_public_artifact_text(manifest_alias, manifest_text)
            written["api_manifest"] = manifest_alias

    return written


def _sha256_hex(data: bytes | None) -> str | None:
    if data is None:
        return None
    return hashlib.sha256(data).hexdigest()


def _short_hash(value: str | None) -> str:
    return value[:12] if value else "unavailable"


def _signature_field(signature: Mapping[str, Any] | None, key: str) -> str | None:
    if not signature:
        return None
    value = signature.get(key)
    return str(value) if value not in (None, "") else None


def _signature_trust_class(*, signature_attached: bool, signature_status: str) -> str:
    normalized = signature_status.strip().lower()
    if normalized == "valid":
        return ""
    if not signature_attached and normalized in {"unsigned", "unsigned local preview"}:
        return " warning"
    return " error"


def _reason_summary(value: str | None, *, max_length: int = 150) -> str:
    text = re.sub(r"\s+", " ", value or "").strip()
    if not text:
        return "Excluded by signed release policy."
    if len(text) <= max_length:
        return text
    boundary = text.rfind(" ", 0, max_length - 1)
    if boundary < max_length // 2:
        boundary = max_length - 1
    return text[:boundary].rstrip(" ,;:-.") + "."


def _excluded_release_summary(entry: ReleasePolicyEntry) -> str:
    curated = CURATED_EXCLUDED_RELEASE_SUMMARIES.get(entry.version.upper())
    if curated:
        return curated
    return _reason_summary(entry.reason)


def _source_label(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    path_segments = [segment for segment in parsed.path.lower().split("/") if segment]
    has_release_health_path = any(
        left == "windows" and right == "release-health"
        for left, right in zip(path_segments, path_segments[1:])
    )
    has_atom_feed_path = any(
        left == "feed" and right == "atom"
        for left, right in zip(path_segments, path_segments[1:])
    )
    if host == "learn.microsoft.com" and has_release_health_path:
        return "Microsoft Release Health"
    if host == "support.microsoft.com" and has_atom_feed_path:
        return "Microsoft Atom feed"
    return url


def _status_text(policy: ReleasePolicy) -> str:
    return "Warning state" if policy.validation_warnings else "Policy current"


def _source_event_counts_for_policy(policy: ReleasePolicy) -> dict[str, int]:
    source_diagnostics = policy.source_diagnostics if isinstance(policy.source_diagnostics, Mapping) else {}
    raw_counts = source_diagnostics.get("event_counts") if isinstance(source_diagnostics, Mapping) else {}
    counts = {"notice": 0, "warning": 0, "error": 0}
    if isinstance(raw_counts, Mapping):
        for key in counts:
            try:
                counts[key] = max(0, int(raw_counts.get(key) or 0))
            except (TypeError, ValueError):
                counts[key] = 0
    return counts


def _source_diagnostics_for_policy(policy: ReleasePolicy) -> Mapping[str, Any]:
    source_diagnostics = policy.source_diagnostics if isinstance(policy.source_diagnostics, Mapping) else {}
    return source_diagnostics


def _short_diagnostic_text(value: Any, *, max_length: int = 150) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= max_length:
        return text
    boundary = text.rfind(" ", 0, max_length - 1)
    if boundary < max_length // 2:
        boundary = max_length - 1
    return text[:boundary].rstrip(" ,;:-.") + "."


def _source_diagnostic_event_severity(value: Any) -> str:
    severity = str(value or "").strip().lower()
    return severity if severity in {"notice", "warning", "error"} else "warning"


def _source_diagnostic_id_text(value: Any) -> str:
    try:
        text = str(value or "")
    except Exception:
        return ""
    return re.sub(r"\s+", " ", text).strip()


def _source_diagnostic_id_component(value: Any) -> dict[str, Any]:
    text = _source_diagnostic_id_text(value)
    return {
        "length": len(text),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def _source_diagnostic_id_tag_values(tags: Any) -> tuple[str, ...]:
    if tags in (None, ""):
        return ()
    if isinstance(tags, Mapping):
        raw_items = (
            f"{key}: {value}"
            for key, value in sorted(tags.items(), key=lambda item: str(item[0]))
        )
    elif isinstance(tags, (str, bytes)):
        raw_items = (tags,)
    else:
        try:
            raw_items = iter(tags)
        except TypeError:
            raw_items = (tags,)
    normalized: list[str] = []
    for tag in raw_items:
        text = _source_diagnostic_id_text(tag)
        if text:
            normalized.append(text)
    return tuple(normalized)


def _source_diagnostic_id_field(value: Any) -> str | None:
    text = _source_diagnostic_id_text(value)
    return text or None


def _source_diagnostic_id_kb(value: Any) -> str | None:
    text = _source_diagnostic_id_text(value)
    if not text:
        return None
    compact = re.sub(r"\s+", "", text).upper()
    match = _SOURCE_DIAGNOSTIC_KB_TAG_RE.fullmatch(compact)
    return f"KB{match.group(1)}" if match else compact


def _source_diagnostic_id_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return None
    text = _source_diagnostic_id_text(value).lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return None


def _source_diagnostic_id_url_host_path(value: Any) -> str | None:
    text = _source_diagnostic_id_text(value)
    if not text:
        return None
    parsed = urlparse(text)
    if not parsed.netloc:
        return None
    path = re.sub(r"/+", "/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")
    return f"{parsed.netloc.lower()}{path}"


def _source_diagnostic_id_tag_fields(tags: Any) -> dict[str, Any]:
    candidates: dict[str, list[Any]] = {}

    def add_candidate(key: str, value: Any) -> None:
        candidates.setdefault(key, []).append(value)

    for tag in _source_diagnostic_id_tag_values(tags):
        if _SOURCE_DIAGNOSTIC_TIMESTAMP_TAG_RE.fullmatch(tag):
            continue
        lower = tag.lower()
        for prefix, field_name in (
            ("release ", "release"),
            ("build ", "build"),
            ("family ", "build_family"),
        ):
            if lower.startswith(prefix):
                value = _source_diagnostic_id_field(tag[len(prefix) :])
                if value is not None:
                    add_candidate(field_name, value)
                break
        else:
            kb_article = _source_diagnostic_id_kb(tag)
            if kb_article and _SOURCE_DIAGNOSTIC_KB_TAG_RE.fullmatch(kb_article):
                add_candidate("kb_article", kb_article)
            elif lower == "required baseline":
                add_candidate("affects_broad_target", True)
                add_candidate("affects_required_baseline", True)
            elif lower == "broad target":
                add_candidate("affects_broad_target", True)
            elif lower == "not broad target":
                add_candidate("affects_broad_target", False)
    return {
        key: sorted(set(values), key=lambda value: json.dumps(value, sort_keys=True))[0]
        for key, values in sorted(candidates.items())
        if values
    }


def _source_diagnostic_has_id_value(value: Any) -> bool:
    return value not in (None, "")


def _source_diagnostic_id_payload_field(value: Any) -> dict[str, Any]:
    return _source_diagnostic_id_component(_source_diagnostic_id_field(value) or "")


def _source_diagnostic_id(
    *,
    severity: Any,
    source: Any,
    title: Any,
    message: Any,
    tags: Any,
    kind: Any = None,
    release: Any = None,
    build_family: Any = None,
    build: Any = None,
    kb_article: Any = None,
    affects_broad_target: Any = None,
    affects_required_baseline: Any = None,
    source_url: Any = None,
    allow_message_fallback: bool = False,
) -> str:
    tag_fields = _source_diagnostic_id_tag_fields(tags)
    category = kind if _source_diagnostic_has_id_value(kind) else title
    fields: dict[str, Any] = {
        "category": _source_diagnostic_id_payload_field(category),
        "source": _source_diagnostic_id_payload_field(source),
    }
    for key, value in (
        ("release", release),
        ("build_family", build_family),
        ("build", build),
        ("kb_article", kb_article),
    ):
        selected = value if _source_diagnostic_has_id_value(value) else tag_fields.get(key)
        if key == "kb_article":
            normalized = _source_diagnostic_id_kb(selected)
        else:
            normalized = _source_diagnostic_id_field(selected)
        if normalized:
            fields[key] = _source_diagnostic_id_payload_field(normalized)

    for key, value in (
        ("affects_broad_target", affects_broad_target),
        ("affects_required_baseline", affects_required_baseline),
    ):
        selected = value if _source_diagnostic_has_id_value(value) else tag_fields.get(key)
        normalized_bool = _source_diagnostic_id_bool(selected)
        if normalized_bool is not None:
            fields[key] = normalized_bool

    normalized_source_url = _source_diagnostic_id_url_host_path(source_url)
    if normalized_source_url:
        fields["source_url"] = _source_diagnostic_id_payload_field(normalized_source_url)

    if allow_message_fallback and not any(
        key in fields
        for key in (
            "release",
            "build_family",
            "build",
            "kb_article",
            "affects_broad_target",
            "affects_required_baseline",
            "source_url",
        )
    ):
        fields["message_fallback"] = _source_diagnostic_id_payload_field(message)

    payload = {
        "severity": _source_diagnostic_event_severity(severity),
        "fields": fields,
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(payload_bytes).hexdigest()[:SOURCE_DIAGNOSTIC_ID_HASH_LENGTH]
    return f"{SOURCE_DIAGNOSTIC_ID_PREFIX}:{digest}"


def _source_diagnostic_event_label(kind: Any) -> str:
    text = re.sub(r"[_-]+", " ", str(kind or "source diagnostic")).strip()
    if not text:
        return "Source diagnostic"
    acronyms = {"kb", "oob", "esu", "lcu"}
    return " ".join(part.upper() if part.lower() in acronyms else part.capitalize() for part in text.split())


def _source_diagnostic_source_label(kind: Any) -> str:
    text = str(kind or "").strip().lower()
    if "atom" in text:
        return "Atom feed"
    if "manifest" in text:
        return "Manifest"
    if (
        "freshness" in text
        or "stale" in text
        or "aging" in text
        or "currency" in text
        or "refresh" in text
        or "policy_feed" in text
    ):
        return "Policy feed currency"
    if "parser" in text or "parse" in text:
        return "Parser"
    if "release_health" in text or "current_versions" in text or "release_history" in text:
        return "Release Health"
    if "signature" in text:
        return "Signature"
    return "Source"


def _source_diagnostic_timestamp(event: Mapping[str, Any]) -> str | None:
    for key in ("occurred_at_utc", "fetched_at_utc", "published", "updated", "timestamp", "generated_at_utc"):
        value = event.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _source_diagnostic_event_tags(event: Mapping[str, Any]) -> tuple[str, ...]:
    tags: list[str] = []
    for key, label in (
        ("release", "Release"),
        ("build", "Build"),
    ):
        value = event.get(key)
        if value not in (None, ""):
            tags.append(f"{label} {value}")
    kb_article = event.get("kb_article")
    if kb_article not in (None, ""):
        kb_text = str(kb_article)
        tags.append(kb_text if kb_text.upper().startswith("KB") else f"KB {kb_text}")
    build_family = event.get("build_family")
    if build_family not in (None, ""):
        tags.append(f"Family {build_family}")
    if event.get("affects_required_baseline"):
        tags.append("Required baseline")
    elif event.get("affects_broad_target"):
        tags.append("Broad target")
    timestamp = _source_diagnostic_timestamp(event)
    if timestamp:
        tags.append(timestamp)
    return tuple(tags)


def _source_diagnostic_id_for_event(event: Mapping[str, Any]) -> str:
    kind = event.get("kind")
    severity = _source_diagnostic_event_severity(event.get("severity"))
    title = _source_diagnostic_event_label(kind)
    message = _short_diagnostic_text(event.get("message") or event.get("title") or title)
    return _source_diagnostic_id(
        severity=severity,
        source=_source_diagnostic_source_label(kind),
        title=title,
        message=message,
        tags=_source_diagnostic_event_tags(event),
        kind=kind,
        release=event.get("release"),
        build_family=event.get("build_family"),
        build=event.get("build"),
        kb_article=event.get("kb_article"),
        affects_broad_target=event.get("affects_broad_target"),
        affects_required_baseline=event.get("affects_required_baseline"),
        source_url=event.get("source_url") or event.get("url") or event.get("atom_feed_url"),
    )


def _source_diagnostic_event_with_id(event: Mapping[str, Any]) -> dict[str, Any]:
    item = dict(event)
    item["id"] = _source_diagnostic_id_for_event(item)
    return item


def _source_diagnostic_events_with_ids(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_source_diagnostic_event_with_id(event) for event in events]


def _source_diagnostic_row_from_event(event: Mapping[str, Any]) -> dict[str, Any]:
    kind = event.get("kind")
    severity = _source_diagnostic_event_severity(event.get("severity"))
    title = _source_diagnostic_event_label(kind)
    message = _short_diagnostic_text(event.get("message") or event.get("title") or title)
    source = _source_diagnostic_source_label(kind)
    tags = _source_diagnostic_event_tags(event)
    diagnostic_id = _source_diagnostic_id_text(event.get("id"))
    if not _is_source_diagnostic_id(diagnostic_id):
        diagnostic_id = _source_diagnostic_id(
            severity=severity,
            source=source,
            title=title,
            message=message,
            tags=tags,
            kind=kind,
            release=event.get("release"),
            build_family=event.get("build_family"),
            build=event.get("build"),
            kb_article=event.get("kb_article"),
            affects_broad_target=event.get("affects_broad_target"),
            affects_required_baseline=event.get("affects_required_baseline"),
            source_url=event.get("source_url") or event.get("url") or event.get("atom_feed_url"),
        )
    return {
        "id": diagnostic_id,
        "severity": severity,
        "title": title,
        "source": source,
        "message": message,
        "tags": tags,
        "issue_sync_event": True,
    }


def _source_diagnostic_row_from_text(severity: str, message: Any, *, source: str, title: str) -> dict[str, Any]:
    normalized_severity = _source_diagnostic_event_severity(severity)
    normalized_message = _short_diagnostic_text(message)
    return {
        "id": _source_diagnostic_id(
            severity=normalized_severity,
            source=source,
            title=title,
            message=normalized_message,
            tags=(),
            allow_message_fallback=True,
        ),
        "severity": normalized_severity,
        "title": title,
        "source": source,
        "message": normalized_message,
        "tags": (),
    }


def _raw_diagnostic_messages(source_diagnostics: Mapping[str, Any], key: str) -> tuple[str, ...]:
    values = source_diagnostics.get(key)
    if not isinstance(values, list):
        return ()
    return tuple(str(item) for item in values if str(item or "").strip())


def _freshness_diagnostic_row(generated_age_days: float) -> dict[str, Any] | None:
    if generated_age_days >= DEFAULT_POLICY_STRICT_STALE_AGE_DAYS:
        return _source_diagnostic_row_from_text(
            "error",
            (
                "Published policy feed is stale at render time. Do not treat this data as "
                "production-current until automation refresh succeeds."
            ),
            source="Policy feed currency",
            title="Policy feed stale",
        )
    if generated_age_days >= DEFAULT_POLICY_WARNING_AGE_DAYS:
        return _source_diagnostic_row_from_text(
            "warning",
            (
                "Published policy feed refresh is due at render time. Verify automation health "
                "before treating this data as production-current."
            ),
            source="Policy feed currency",
            title="Policy feed refresh due",
        )
    return None


def _source_diagnostic_rows(policy: ReleasePolicy, *, generated_age_days: float) -> tuple[dict[str, Any], ...]:
    source_diagnostics = _source_diagnostics_for_policy(policy)
    raw_events = source_diagnostics.get("events")
    rows: list[dict[str, Any]] = []
    if isinstance(raw_events, list):
        rows.extend(
            _source_diagnostic_row_from_event(event)
            for event in raw_events
            if isinstance(event, Mapping)
        )

    if not rows:
        for message in _raw_diagnostic_messages(source_diagnostics, "errors"):
            rows.append(_source_diagnostic_row_from_text("error", message, source="Source", title="Source error"))
        for message in _raw_diagnostic_messages(source_diagnostics, "warnings"):
            rows.append(_source_diagnostic_row_from_text("warning", message, source="Source", title="Source warning"))
        for message in _raw_diagnostic_messages(source_diagnostics, "notices"):
            rows.append(_source_diagnostic_row_from_text("notice", message, source="Source", title="Source notice"))
        for message in policy.validation_warnings:
            rows.append(
                _source_diagnostic_row_from_text(
                    "warning",
                    message,
                    source="Policy",
                    title="Policy warning",
                )
            )

    has_freshness_row = any(
        str(row.get("source") or "") in {"Freshness", "Policy feed currency"} for row in rows
    )
    freshness_row = _freshness_diagnostic_row(generated_age_days)
    if freshness_row is not None and not has_freshness_row:
        rows.append(freshness_row)

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        key = (str(row.get("severity") or ""), str(row.get("title") or ""), str(row.get("message") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return tuple(deduped)


def _excluded_release_diagnostic_rows(policy: ReleasePolicy) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in policy.excluded_for_existing_devices:
        version = str(entry.version or "").strip().upper()
        if not version or version in seen:
            continue
        seen.add(version)
        severity = "notice"
        title = f"{version} excluded for existing devices"
        source = "Release policy"
        message = _excluded_release_summary(entry)
        tags = (
            f"Release {version}",
            "Existing devices",
            "Not broad target",
        )
        rows.append(
            {
                "id": _source_diagnostic_id(
                    severity=severity,
                    source=source,
                    title=title,
                    message=message,
                    tags=tags,
                    release=version,
                    affects_broad_target=False,
                ),
                "severity": severity,
                "title": title,
                "source": source,
                "message": message,
                "tags": tags,
            }
        )
    return tuple(rows)


def _display_source_event_counts(rows: tuple[Mapping[str, Any], ...]) -> dict[str, int]:
    display_counts = {"notice": 0, "warning": 0, "error": 0}
    for row in rows:
        severity = _source_diagnostic_event_severity(row.get("severity"))
        display_counts[severity] += 1
    return display_counts


def _source_diagnostic_text(value: Any, *, fallback: str = "") -> str:
    if value in (None, ""):
        return fallback
    try:
        text = str(value)
    except Exception:
        return fallback
    text = re.sub(r"\s+", " ", text).strip()
    return text or fallback


def _is_source_diagnostic_id(value: str) -> bool:
    suffix = value.removeprefix(f"{SOURCE_DIAGNOSTIC_ID_PREFIX}:")
    return (
        value.startswith(f"{SOURCE_DIAGNOSTIC_ID_PREFIX}:")
        and len(suffix) == SOURCE_DIAGNOSTIC_ID_HASH_LENGTH
        and all(char in "0123456789abcdef" for char in suffix)
    )


def _source_diagnostic_issue_number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _source_diagnostic_issue_state(value: Any) -> str:
    text = _source_diagnostic_text(value).lower()
    return text if text in {"open", "closed"} else "tracked"


def _canonical_source_diagnostic_issue_url(number: int) -> str:
    return f"{GITHUB_ISSUES_BASE_URL}/{number}"


def _source_diagnostic_issue_record(
    diagnostic_id: str,
    value: Any,
) -> tuple[str, dict[str, Any]] | None:
    if not _is_source_diagnostic_id(diagnostic_id) or not isinstance(value, Mapping):
        return None
    number = _source_diagnostic_issue_number(value.get("number") or value.get("issue_number"))
    if number is None:
        return None
    canonical_url = _canonical_source_diagnostic_issue_url(number)
    supplied_url = _source_diagnostic_text(value.get("url") or value.get("html_url"))
    if supplied_url and supplied_url != canonical_url:
        return None
    state = _source_diagnostic_issue_state(value.get("state") or value.get("status"))
    return diagnostic_id, {
        "number": number,
        "state": state,
        "url": canonical_url,
    }


def _source_diagnostic_issue_records(source_diagnostics: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    raw = source_diagnostics.get("issue_status")
    records: list[tuple[str, Any]] = []
    if isinstance(raw, Mapping):
        records.extend((str(key), value) for key, value in raw.items())
    elif isinstance(raw, list):
        for item in raw:
            if not isinstance(item, Mapping):
                continue
            diagnostic_id = _source_diagnostic_text(
                item.get("diagnostic_id") or item.get("source_diagnostic_id") or item.get("id")
            )
            records.append((diagnostic_id, item))
    issue_records: dict[str, dict[str, Any]] = {}
    for diagnostic_id, value in records:
        record = _source_diagnostic_issue_record(diagnostic_id, value)
        if record is None:
            continue
        key, metadata = record
        issue_records[key] = metadata
    return issue_records


def _source_diagnostic_source_class(source: Any) -> str:
    text = _source_diagnostic_text(source, fallback="source").lower()
    if "atom" in text or "feed" in text:
        return "src-atom-feed"
    if "release policy" in text:
        return "src-release-policy"
    if "release health" in text:
        return "src-release-health"
    if "source diagnostics" in text:
        return "src-diagnostics"
    if "freshness" in text or "currency" in text:
        return "src-freshness"
    if "signature" in text:
        return "src-signature"
    if "parser" in text:
        return "src-parser"
    if "policy" in text:
        return "src-policy"
    return "src-source"


def _source_diagnostic_tag_items_html(tags: Any) -> str:
    if tags in (None, ""):
        return ""
    if isinstance(tags, Mapping):
        raw_items = (
            f"{_source_diagnostic_text(key, fallback='field')}: {_source_diagnostic_text(value, fallback='unavailable')}"
            for key, value in tags.items()
        )
    elif isinstance(tags, (str, bytes)):
        raw_items = (tags,)
    else:
        try:
            raw_items = iter(tags)
        except TypeError:
            raw_items = (tags,)
    rendered: list[str] = []
    for tag in raw_items:
        text = _source_diagnostic_text(tag)
        if text:
            rendered.append(f"<span>{escape(text)}</span>")
    return "".join(rendered)


def _source_diagnostic_issue_link_html(issue: Mapping[str, Any] | None) -> str:
    if not isinstance(issue, Mapping):
        return ""
    number = _source_diagnostic_issue_number(issue.get("number"))
    if number is None:
        return ""
    url = _source_diagnostic_text(issue.get("url"))
    canonical_url = _canonical_source_diagnostic_issue_url(number)
    if url != canonical_url:
        return ""
    state = _source_diagnostic_issue_state(issue.get("state"))
    issue_text = f"#Ticket {number}"
    return (
        f"<a class=\"diag-ticket-link\" href=\"{escape(canonical_url, quote=True)}\" "
        f"aria-label=\"GitHub issue {int(number)} status {escape(state, quote=True)}\">"
        f"{_ui_icon_html('link', class_name='ui-icon diag-ticket-link-icon')}"
        f"<span>{escape(issue_text)}</span>{_github_icon_html()}</a>"
    )


def _source_diagnostic_row_id(row: Mapping[str, Any]) -> str:
    existing_id = _source_diagnostic_text(row.get("id"))
    if _is_source_diagnostic_id(existing_id):
        return existing_id
    severity = _source_diagnostic_event_severity(row.get("severity"))
    title = _source_diagnostic_text(row.get("title"), fallback="Source diagnostic")
    source = _source_diagnostic_text(row.get("source"), fallback="Source")
    message = _source_diagnostic_text(row.get("message"))
    return _source_diagnostic_id(
        severity=severity,
        source=source,
        title=title,
        message=message,
        tags=row.get("tags"),
        kind=row.get("kind"),
        release=row.get("release"),
        build_family=row.get("build_family"),
        build=row.get("build"),
        kb_article=row.get("kb_article"),
        affects_broad_target=row.get("affects_broad_target"),
        affects_required_baseline=row.get("affects_required_baseline"),
        source_url=row.get("source_url") or row.get("url") or row.get("atom_feed_url"),
    )


def _placeholder_rows_for_unexplained_counts(
    counts: Mapping[str, int],
    rows: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    rows_by_severity = {"notice": 0, "warning": 0, "error": 0}
    for row in rows:
        rows_by_severity[_source_diagnostic_event_severity(row.get("severity"))] += 1
    placeholders: list[dict[str, Any]] = []
    for severity, title in (
        ("error", "Error diagnostics reported"),
        ("warning", "Warning diagnostics reported"),
        ("notice", "Notice diagnostics reported"),
    ):
        missing = max(0, int(counts.get(severity, 0)) - rows_by_severity[severity])
        if missing:
            label = "entry" if missing == 1 else "entries"
            placeholders.append(
                _source_diagnostic_row_from_text(
                    severity,
                    f"{missing} {severity} diagnostic {label} reported without structured row details.",
                    source="Source",
                    title=title,
                )
            )
    return tuple(placeholders)


def _render_source_diagnostic_row(
    row: Mapping[str, Any],
    *,
    issue_metadata: Mapping[str, Any] | None = None,
) -> str:
    if not isinstance(row, Mapping):
        row = {}
    severity = _source_diagnostic_event_severity(row.get("severity"))
    title = _source_diagnostic_text(row.get("title"), fallback="Source diagnostic")
    source = _source_diagnostic_text(row.get("source"), fallback="Source")
    source_class = _source_diagnostic_source_class(source)
    message = _source_diagnostic_text(row.get("message"))
    tag_items = _source_diagnostic_tag_items_html(row.get("tags"))
    diagnostic_id = _source_diagnostic_row_id(row)
    issue_link = _source_diagnostic_issue_link_html(issue_metadata)
    return (
        f"<article class=\"diag-row {severity}\" data-diagnostic-severity=\"{severity}\" "
        f"data-diagnostic-id=\"{escape(diagnostic_id, quote=True)}\">"
        "<span class=\"diag-stripe\" aria-hidden=\"true\"></span>"
        f"{_source_diagnostic_icon_html(row)}"
        f"{issue_link}"
        "<div>"
        "<div class=\"diag-row-head\">"
        f"<span class=\"severity-badge {severity}\">{escape(severity.capitalize())}</span>"
        f"<strong>{escape(title)}</strong>"
        f"<span class=\"source-chip {source_class}\">{escape(source)}</span>"
        "</div>"
        f"<p>{escape(message)}</p>"
        f"<div class=\"diag-tags\">{tag_items}</div>"
        "</div>"
        "</article>"
    )


def _diagnostic_filter_button_html(severity: str, count: int, label: str, icon_name: str) -> str:
    escaped_severity = escape(severity, quote=True)
    escaped_label = escape(label, quote=True)
    return (
        f"<button type=\"button\" class=\"diag-tile {escaped_severity}\" "
        f"data-diagnostic-filter=\"{escaped_severity}\" "
        f"data-diagnostic-severity=\"{escaped_severity}\" "
        "aria-pressed=\"false\" aria-controls=\"source-diagnostics-feed\" "
        f"aria-label=\"Show {escaped_severity} source diagnostics ({int(count)})\">"
        f"<strong>{int(count)}</strong><span>{escaped_label}</span>"
        f"{_ui_icon_html(icon_name, class_name='ui-icon diag-tile-icon')}</button>"
    )


def _source_diagnostic_icon_html(row: Mapping[str, Any]) -> str:
    severity = _source_diagnostic_event_severity(row.get("severity"))
    if severity in {"warning", "error"}:
        icon = severity
    else:
        title = _source_diagnostic_text(row.get("title")).lower()
        source = _source_diagnostic_text(row.get("source")).lower()
        if title == "no source issues reported":
            icon = "megaphone"
        elif "atom" in title or "feed" in title or "atom" in source or "feed" in source:
            icon = "document"
        elif "release policy" in source or "excluded" in title:
            icon = "info"
        else:
            icon = "megaphone"
    return (
        f"<span class=\"diag-row-icon {severity}\" aria-hidden=\"true\">"
        f"{_ui_icon_html(icon, class_name='ui-icon')}</span>"
    )


def _clear_source_diagnostic_row() -> dict[str, Any]:
    severity = "notice"
    title = "No source issues reported"
    source = "Source diagnostics"
    message = "Release Health, Atom feed, parser, and freshness checks have no warning or error events."
    tags = ("No warnings", "No errors")
    return {
        "id": _source_diagnostic_id(
            severity=severity,
            source=source,
            title=title,
            message=message,
            tags=tags,
        ),
        "severity": severity,
        "title": title,
        "source": source,
        "message": message,
        "tags": tags,
    }


def _source_diagnostic_issue_sync_notice_html(source_diagnostics: Mapping[str, Any]) -> str:
    raw = source_diagnostics.get("issue_sync")
    if not isinstance(raw, Mapping):
        return ""
    status = _source_diagnostic_text(raw.get("status")).lower()
    if status not in {"degraded", "unavailable"}:
        return ""
    label = "Issue sync unavailable" if status == "unavailable" else "Issue sync degraded"
    message = _source_diagnostic_text(
        raw.get("message"),
        fallback="GitHub Issues status metadata is currently unavailable; diagnostic ticket links may be missing.",
    )
    reason = _source_diagnostic_text(raw.get("reason"))
    reason_html = f"<span>{escape(reason)}</span>" if reason else ""
    return (
        f"<p class=\"diag-issue-sync-status {escape(status, quote=True)}\" "
        f"data-issue-sync-status=\"{escape(status, quote=True)}\" role=\"status\">"
        f"{_ui_icon_html('warning', class_name='ui-icon diag-issue-sync-icon')}"
        f"<strong>{escape(label)}</strong><span>{escape(message)}</span>{reason_html}</p>"
    )


def _render_source_diagnostics_panel(
    policy: ReleasePolicy,
    counts: Mapping[str, int],
    *,
    generated_age_days: float,
    generated_at_utc: str,
) -> str:
    source_diagnostics = _source_diagnostics_for_policy(policy)
    issue_records = _source_diagnostic_issue_records(source_diagnostics)
    issue_sync_notice = _source_diagnostic_issue_sync_notice_html(source_diagnostics)
    def render_row(row: Mapping[str, Any]) -> str:
        issue_metadata = None
        if row.get("issue_sync_event") is True:
            issue_metadata = issue_records.get(_source_diagnostic_row_id(row))
        return _render_source_diagnostic_row(row, issue_metadata=issue_metadata)

    base_rows = _source_diagnostic_rows(policy, generated_age_days=generated_age_days)
    excluded_rows = _excluded_release_diagnostic_rows(policy)
    counted_rows = (*base_rows, *excluded_rows)
    rows = (*counted_rows, *_placeholder_rows_for_unexplained_counts(counts, counted_rows))
    rendered_rows: tuple[Mapping[str, Any], ...]
    if not rows:
        clear_row = _clear_source_diagnostic_row()
        rendered_rows = (clear_row,)
        rendered_clear_row = render_row(clear_row)
        details = f"<div class=\"diag-events diag-events-empty\">{rendered_clear_row}</div>"
    else:
        has_warning_or_error = any(
            _source_diagnostic_event_severity(row.get("severity")) in {"warning", "error"}
            for row in rows
        )
        lead_row: Mapping[str, Any] | None = None
        if not has_warning_or_error:
            lead_row = _clear_source_diagnostic_row()
        rendered_rows = (lead_row, *rows) if lead_row is not None else rows
        visible_rows = rows[:5]
        hidden_rows = rows[5:]
        rendered_visible = (
            (render_row(lead_row) if lead_row is not None else "")
            + "".join(render_row(row) for row in visible_rows)
        )
        overflow = ""
        if hidden_rows:
            rendered_hidden = "".join(render_row(row) for row in hidden_rows)
            overflow = (
                f"<details class=\"diag-more\"><summary>+{len(hidden_rows)} more</summary>"
                f"<div class=\"diag-events\">{rendered_hidden}</div></details>"
            )
        details = f"<div class=\"diag-events\">{rendered_visible}</div>{overflow}"
    display_counts = _display_source_event_counts(rendered_rows)
    count_tiles = (
        "<div class=\"diag-summary\" aria-label=\"Source diagnostic counts\">"
        f"{_diagnostic_filter_button_html('notice', display_counts['notice'], 'Notices', 'megaphone')}"
        f"{_diagnostic_filter_button_html('warning', display_counts['warning'], 'Warnings', 'warning')}"
        f"{_diagnostic_filter_button_html('error', display_counts['error'], 'Errors', 'error')}"
        "</div>"
    )
    total_rows = sum(display_counts.values())
    return (
        "<section class=\"panel span-7 source-diagnostics\" data-diagnostic-filter-root>"
        "<div class=\"panel-head\"><h2>Source diagnostics</h2>"
        "<div class=\"panel-actions\">"
        "<button type=\"button\" class=\"panel-action diag-filter-reset\" "
        "data-diagnostic-filter=\"all\" aria-controls=\"source-diagnostics-feed\" aria-pressed=\"true\">View all</button>"
        "</div></div>"
        f"{count_tiles}{issue_sync_notice}"
        "<p id=\"source-diagnostics-filter-status\" class=\"diag-filter-status\" aria-live=\"polite\">"
        f"Showing all {total_rows} source diagnostic rows.</p>"
        "<div id=\"source-diagnostics-feed\" class=\"diag-feed\" role=\"region\" aria-label=\"Source diagnostic event feed\">"
        "<div id=\"source-diagnostics-empty\" class=\"diag-filter-empty\" hidden>"
        "No diagnostic rows match the selected severity filter.</div>"
        f"{details}</div>{_render_source_tiles(policy, generated_at_utc=generated_at_utc)}</section>\n"
    )


def _program_version_from_generator(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return "unknown"
    return text.rsplit("/", 1)[-1] if "/" in text else text


def _program_release_url(version: str | None) -> str | None:
    text = str(version or "").strip()
    if not _RELEASE_VERSION_PATTERN.fullmatch(text):
        return None
    return f"{GITHUB_RELEASES_BASE_URL}/v{text}"


def _program_title_version_html(version: str | None) -> str:
    text = str(version or "").strip() or "unknown"
    url = _program_release_url(text)
    escaped_text = escape(text)
    label = f"Program Version {escaped_text}"
    if url is None:
        return (
            '<span class="title-version-link">'
            f'<span class="title-version-label">Program Version</span> {escaped_text}'
            "</span>"
        )
    escaped_url = escape(url, quote=True)
    return (
        f'<a class="title-version-link mono" href="{escaped_url}" '
        f'aria-label="{escape(label, quote=True)} release">'
        '<span class="title-version-label">Program Version</span> '
        f"{escaped_text}</a>"
    )


def _pypi_download_link_html(*, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    image_url = _pypi_download_image_url(base_url=base_url)
    return (
        f'<a class="pypi-download-link" href="{escape(PYPI_PROJECT_URL, quote=True)}" '
        'aria-label="Download win11_release_guard from PyPI" data-nav-label="PyPI">'
        f'<img src="{escape(image_url, quote=True)}" alt="Download from PyPI" width="96" height="96">'
        "</a>"
    )


def _header_nav_html(*, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    dashboard_icon = (
        '<svg viewBox="0 0 48 48" aria-hidden="true" focusable="false">'
        '<path d="M20,4H6A2,2,0,0,0,4,6V20a2,2,0,0,0,2,2H20a2,2,0,0,0,2-2V6A2,2,0,0,0,20,4Z"/>'
        '<path d="M42,4H28a2,2,0,0,0-2,2V20a2,2,0,0,0,2,2H42a2,2,0,0,0,2-2V6A2,2,0,0,0,42,4Z"/>'
        '<path d="M20,26H6a2,2,0,0,0-2,2V42a2,2,0,0,0,2,2H20a2,2,0,0,0,2-2V28A2,2,0,0,0,20,26Z"/>'
        '<path d="M42,26H28a2,2,0,0,0-2,2V42a2,2,0,0,0,2,2H42a2,2,0,0,0,2-2V28A2,2,0,0,0,42,26Z"/>'
        "</svg>"
    )
    issue_icon = (
        '<svg viewBox="0 0 512 512" aria-hidden="true" focusable="false">'
        '<path d="M421.073 221.719c-.578 11.719-9.469 26.188-23.797 40.094v183.25c-.016 4.719-1.875 8.719-5.016 11.844-3.156 3.063-7.25 4.875-12.063 4.906H81.558c-4.781-.031-8.891-1.844-12.047-4.906-3.141-3.125-4.984-7.125-5-11.844V152.219c.016-4.703 1.859-8.719 5-11.844 3.156-3.063 7.266-4.875 12.047-4.906h158.609c12.828-16.844 27.781-34.094 44.719-49.906.078-.094.141-.188.219-.281H81.558c-18.75-.016-35.984 7.531-48.25 19.594-12.328 12.063-20.016 28.938-20 47.344v292.844c-.016 18.406 7.672 35.313 20 47.344C45.573 504.469 62.808 512 81.558 512h298.641c18.781 0 36.016-7.531 48.281-19.594 12.297-12.031 20-28.938 19.984-47.344V203.469c0 0-.125-.156-.328-.313-7.766 6.657-16.813 13-27.063 18.563z"/>'
        '<path d="M498.058 0s-15.688 23.438-118.156 58.109C275.417 93.469 211.104 237.313 211.104 237.313c-15.484 29.469-76.688 151.906-76.688 151.906-16.859 31.625 14.031 50.313 32.156 17.656 34.734-62.688 57.156-119.969 109.969-121.594 77.047-2.375 129.734-69.656 113.156-66.531-21.813 9.5-69.906.719-41.578-3.656 68-5.453 109.906-56.563 96.25-60.031-24.109 9.281-46.594.469-51-2.188C513.386 138.281 498.058 0 498.058 0z"/>'
        "</svg>"
    )
    wiki_icon = (
        '<svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">'
        '<path d="M5 0C3.343 0 2 1.343 2 3v10c0 1.657 1.343 3 3 3h9v-2H4v-2h10V0H5z"/>'
        "</svg>"
    )
    items = (
        ("Dashboard", _pages_root_url(base_url=base_url), dashboard_icon),
        ("Write a Issue Ticket", "https://github.com/Avnsx/win11_release_guard/issues/new", issue_icon),
        ("Wiki", _pages_wiki_url(base_url=base_url), wiki_icon),
    )
    links = "".join(
        (
            f'<li><a href="{escape(href, quote=True)}" aria-label="{escape(label, quote=True)}" '
            f'data-nav-label="{escape(label, quote=True)}">'
            f"{icon}<span class=\"sr-only\">{escape(label)}</span></a></li>"
        )
        for label, href, icon in items
    )
    return (
        '<nav class="header-nav" aria-label="Header navigation">'
        '<span class="nav-hover-label" aria-hidden="true">Dashboard</span>'
        f'<ul class="nav-inner">{links}</ul>'
        "</nav>"
    )


def _format_bytes(value: Any) -> str:
    try:
        size = int(value)
    except (TypeError, ValueError):
        return "unavailable"
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KiB"
    return f"{size / (1024 * 1024):.1f} MiB"


def _hash_html(value: str | None) -> str:
    short = _short_hash(value)
    title = f' title="{escape(value, quote=True)}"' if value else ""
    return f'<span class="mono hash"{title}>{escape(short)}</span>'


def _source_status_for_url(policy: ReleasePolicy, url: str, *, generated_at_utc: str) -> Mapping[str, Any]:
    label = _source_label(url)
    if label == "Microsoft Release Health":
        source = _source_diagnostics_for_policy(policy).get("release_health_html")
    elif label == "Microsoft Atom feed":
        source = _source_diagnostics_for_policy(policy).get("atom_feed")
    else:
        source = None
    if not isinstance(source, Mapping):
        return {
            "status": "recorded",
            "fetched_at_utc": generated_at_utc,
            "bytes": None,
        }
    return source


def _source_status_class(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"ok", "success", "valid", "healthy", "current"}:
        return "ok"
    if any(token in text for token in ("warn", "degraded", "aging", "partial", "stale")):
        return "warning"
    if any(token in text for token in ("error", "err", "fail", "invalid", "blocked", "unavailable")):
        return "error"
    return "unknown"


def _render_source_tiles(policy: ReleasePolicy, *, generated_at_utc: str) -> str:
    if not policy.source_urls:
        return (
            "<div id=\"source-health\" class=\"source-health\" aria-label=\"Policy source status\">"
            "<h3>Source health</h3><div class=\"source-health-grid\">"
            "<div class=\"source-tile unknown\"><div class=\"source-tile-head\">"
            f"<span class=\"source-name\">{_ui_icon_html('database', class_name='ui-icon source-icon')}<strong>None recorded</strong></span>"
            "<span class=\"source-status unknown\">unknown</span></div>"
            "<span>No source URLs are present in this policy.</span></div>"
            "</div></div>"
        )
    items: list[str] = []
    for url in policy.source_urls:
        label = _source_label(url)
        source_icon = "database" if label == "Microsoft Release Health" else "document"
        status = _source_status_for_url(policy, url, generated_at_utc=generated_at_utc)
        fetched_at = str(status.get("fetched_at_utc") or "")
        fetched_at_html = _time_with_epoch_copy_html(fetched_at, label=f"{label} UTC")
        status_text = str(status.get("status") or "unknown")
        status_class = _source_status_class(status_text)
        bytes_text = _format_bytes(status.get("bytes"))
        escaped_url = escape(url, quote=True)
        items.append(
            f"<div class=\"source-tile {status_class}\">"
            "<div class=\"source-tile-head\">"
            f"<span class=\"source-name\">{_ui_icon_html(source_icon, class_name='ui-icon source-icon')}<strong>{escape(label)}</strong></span>"
            f"<span class=\"source-status {status_class}\">{escape(status_text)}</span>"
            "</div>"
            f"<a href=\"{escaped_url}\" title=\"{escaped_url}\">{escape(url)}</a>"
            "<dl class=\"mini-kv\">"
            f"<dt>Fetched:</dt><dd>{fetched_at_html}</dd>"
            f"<dt>Bytes:</dt><dd>{escape(bytes_text)}</dd>"
            "</dl>"
            "</div>"
        )
    return (
        "<div id=\"source-health\" class=\"source-health\" aria-label=\"Policy source status\">"
        "<h3>Source health</h3>"
        f"<div class=\"source-health-grid\">{''.join(items)}</div></div>"
    )


def _render_endpoint_links() -> str:
    endpoints = (
        (
            "Signed policy JSON",
            "windows-release-policy.json",
            "Primary signed policy document used by automation and fleet dashboards.",
            "document",
        ),
        (
            "Detached signature",
            "windows-release-policy.json.sig",
            "Ed25519 signature that lets clients verify the policy before trusting it.",
            "key",
        ),
        (
            "Policy manifest",
            "policy-manifest.json",
            "Compact metadata for hashes, freshness thresholds, source state, and API aliases.",
            "database",
        ),
        (
            "API v1 policy alias",
            "api/v1/policy.json",
            "Backward-compatible policy endpoint for stable reader integrations.",
            "api",
        ),
        (
            "API v1 manifest alias",
            "api/v1/manifest.json",
            "Backward-compatible manifest endpoint for stable reader integrations.",
            "api",
        ),
    )
    return "".join(
        (
            f'<a class="api-endpoint-row" href="{escape(endpoint, quote=True)}">'
            f"{_ui_icon_html(icon, class_name='ui-icon api-row-icon')}"
            f"<span><strong>{escape(title)}</strong><em>{escape(description)}</em></span>"
            f"<code>/{escape(endpoint)}</code></a>"
        )
        for title, endpoint, description, icon in endpoints
    )


def _safe_json_script_payload(data: Mapping[str, Any]) -> str:
    return (
        json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def render_policy_index(
    policy: ReleasePolicy,
    *,
    policy_bytes: bytes | None = None,
    signature: Mapping[str, Any] | None = None,
    verification_metadata: Mapping[str, Any] | None = None,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    target = policy.broad_target_existing_devices
    policy_hash = _sha256_hex(policy_bytes)
    generated_at_utc = policy.generated_at_utc or _utc_now()
    generated_human = _generated_at_human(generated_at_utc)
    generated_local_date = _generated_at_local_date(generated_at_utc)
    generated_local_time = _generated_at_local_time(generated_at_utc)
    generated_age_days = _generated_age_days(generated_at_utc)
    generated_age_text, generated_age_size, generated_age_label = _dashboard_age_display(generated_at_utc)
    generated_age_class = "freshness-metric" + (f" {generated_age_size}" if generated_age_size else "")
    verification = verification_metadata if verification_metadata is not None else _public_verification_metadata(signature)
    signature_attached = verification is not None
    raw_signature_status = str(policy.metadata.get("signature_status") or "unavailable")
    if signature_attached:
        signature_algorithm = _signature_field(verification, "algorithm") or "unavailable"
        key_id = _signature_field(verification, "key_id") or "legacy default key"
        signature_status = raw_signature_status
        trust_indicator = "Signed policy trust"
    else:
        signature_algorithm = "not attached"
        key_id = "not attached"
        signature_status = "unsigned local preview" if raw_signature_status == "unsigned" else raw_signature_status
        trust_indicator = "Unsigned local preview" if signature_status == "unsigned local preview" else "Signature metadata"
    trust_class = _signature_trust_class(
        signature_attached=signature_attached,
        signature_status=signature_status,
    )
    source_event_counts = _source_event_counts_for_policy(policy)
    source_diagnostics_panel = _render_source_diagnostics_panel(
        policy,
        source_event_counts,
        generated_age_days=generated_age_days,
        generated_at_utc=generated_at_utc,
    )
    program_version = _program_version_from_generator(GENERATOR_VERSION)
    workflow_run = os.environ.get("GITHUB_RUN_ID") or "not available in local render"
    endpoint_links = _render_endpoint_links()
    freshness_data = {
        "generated_at_utc": generated_at_utc,
        **freshness_thresholds(generated_at_utc),
        "freshness_policy": freshness_policy_metadata(),
    }
    warning_items = "\n".join(f"<li>{escape(warning)}</li>" for warning in policy.validation_warnings)
    warning_block = (
        f"      <section class=\"panel span-12\"><h2>Warnings</h2><ul class=\"warnings\">{warning_items}</ul></section>"
        if warning_items
        else ""
    )
    target_release = target.version if target else "unknown"
    target_family = str(target.build_family) if target else "unknown"
    target_latest_observed = target.latest_observed_build if target else None
    target_baseline = target.required_baseline_build if target else None
    dashboard_url = _pages_root_url(base_url=base_url)
    dashboard_description = (
        "Windows 11 Release Guard dashboard for Windows 11 release compliance, signed public policy feed "
        f"freshness, {target_release} target status, source diagnostics, and fleet administration checks."
    )
    dashboard_seo_meta = _seo_meta_html(
        title="Windows 11 Release Guard",
        description=dashboard_description,
        canonical_url=dashboard_url,
    )
    return (
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"utf-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "  <title>Windows 11 Release Guard</title>\n"
        f"{dashboard_seo_meta}"
        "  <style>\n"
        "    :root{color-scheme:light;--bg:#f4f8fd;--ink:#172033;--muted:#667085;--soft:#f8fbff;--line:#d8e3f0;--panel:#ffffff;--blue:#0078d4;--blue-strong:#0067c0;--blue-soft:#e8f3ff;--ok:#107c10;--ok-soft:#eaf7ed;--warn:#b45309;--warn-soft:#fff4df;--err:#b42318;--err-soft:#fff0ed;--unknown:#64748b;--unknown-soft:#f1f5f9;--code:#063f63;--shadow:0 18px 55px rgba(31,79,143,.12)}\n"
        "    *{box-sizing:border-box}html{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}html,body{max-width:100%;overflow-x:hidden}body{position:relative;isolation:isolate;margin:0;min-height:100vh;background:radial-gradient(circle at 14% 9%,#8ee4ff 0,#39b9ff 15%,rgba(57,185,255,0) 34%),radial-gradient(circle at 78% -10%,#78d6ff 0,#168df0 22%,rgba(22,141,240,0) 43%),radial-gradient(circle at 72% 78%,#0036bd 0,#005bd8 27%,rgba(0,91,216,0) 48%),linear-gradient(145deg,#34c8ff 0%,#0587ee 33%,#0058d4 61%,#002b99 100%);color:var(--ink);font-family:Segoe UI,Arial,sans-serif;line-height:1.45}body:before,body:after{content:'';position:fixed;pointer-events:none;z-index:0}body:before{width:115vw;height:84vh;left:-17vw;top:-18vh;border-radius:0 0 58% 52%;background:radial-gradient(ellipse at 32% 35%,rgba(255,255,255,.72),rgba(185,232,255,.38) 28%,rgba(0,120,212,0) 58%);transform:rotate(-8deg);filter:blur(2px)}body:after{width:92vw;height:76vh;right:-26vw;bottom:-29vh;border:2px solid rgba(255,255,255,.32);border-left-color:rgba(151,220,255,.48);border-radius:50%;box-shadow:-120px -82px 0 -26px rgba(255,255,255,.18),-230px -122px 0 -72px rgba(0,120,212,.34);transform:rotate(-18deg)}\n"
        "    main{position:relative;z-index:1;width:calc(100% - 80px);max-width:1580px;margin:40px auto;padding:34px;border:1px solid rgba(255,255,255,.65);border-radius:32px;background:linear-gradient(180deg,rgba(255,255,255,.86),rgba(239,248,255,.74));box-shadow:0 42px 110px rgba(0,35,126,.34),inset 0 1px 0 rgba(255,255,255,.82);backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px)}.masthead{margin-bottom:28px;padding:0 2px 10px;border:0;border-radius:0;background:transparent;box-shadow:none;backdrop-filter:none}\n"
        "    .brand{display:flex;gap:32px;align-items:center;min-width:0}.brand>div:last-child{min-width:0;flex:1}.brand-layout{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:28px;align-items:center}.brand-copy{min-width:0}.header-actions{display:flex;flex-direction:column;align-items:flex-end;justify-content:center;gap:14px;min-width:0}.header-top-actions{display:flex;align-items:center;justify-content:flex-end;gap:12px;max-width:100%;flex-wrap:wrap}.pypi-download-link{display:inline-flex;align-items:center;justify-content:center;width:96px;height:96px;line-height:0;text-decoration:none;filter:drop-shadow(0 14px 22px rgba(0,79,168,.18))}.pypi-download-link:hover{text-decoration:none;filter:drop-shadow(0 16px 26px rgba(0,79,168,.24))}.pypi-download-link:focus-visible{outline:3px solid rgba(0,120,212,.3);outline-offset:4px;border-radius:20px}.pypi-download-link img{display:block;width:96px;height:96px;object-fit:contain;border-radius:18px}.winmark{width:132px;height:132px;display:grid;grid-template-columns:1fr 1fr;gap:8px;flex:0 0 auto;filter:drop-shadow(0 18px 28px rgba(0,88,212,.22))}.winmark span{background:linear-gradient(145deg,#3fb8ff 0%,#0a84ff 42%,#0055ef 100%);border-radius:9px;box-shadow:inset 0 1px 0 rgba(255,255,255,.38),0 8px 18px rgba(0,78,184,.18)}\n"
        "    .title-line h1{font-size:clamp(34px,4rem,64px);line-height:1.04;margin:0 0 10px;font-weight:760;overflow-wrap:anywhere;color:#071632;letter-spacing:0}.subtitle-line{display:flex;align-items:baseline;gap:16px;min-width:0}.title-version-link{display:inline-flex;align-items:center;gap:8px;margin-left:auto;border:1px solid rgba(142,188,236,.72);border-radius:999px;background:rgba(255,255,255,.7);box-shadow:0 14px 30px rgba(0,79,168,.12),inset 0 1px 0 rgba(255,255,255,.85);padding:13px 20px;font-size:16px;font-weight:700;color:#0b5bd3;white-space:nowrap;flex:0 0 auto;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)}.title-version-link:after{content:'';width:7px;height:7px;border-radius:999px;background:#0b5bd3;box-shadow:0 0 0 4px rgba(11,91,211,.1)}.title-version-label{color:#233152;font-family:Segoe UI,Arial,sans-serif;font-weight:500}p{margin:0}.subtitle{font-size:23px;color:#263858;overflow-wrap:anywhere;min-width:0}.eyebrow{display:inline-flex;align-items:center;gap:8px;margin-bottom:8px;color:#004de6;font-size:20px;font-weight:740;text-transform:uppercase;letter-spacing:0}.eyebrow-icon{width:22px;height:22px;color:#0057e7}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}\n"
        "    .header-nav{--item-size:42px;--nav-gap:5px;--enter-nav:0;--label-x:21px;--label-y:0px;position:relative;isolation:isolate}.header-nav ul{list-style:none;margin:0;padding:0}.header-nav .nav-inner{display:flex;gap:var(--nav-gap);white-space:nowrap;border:1px solid rgba(142,188,236,.7);border-radius:999px;background:rgba(255,255,255,.62);box-shadow:0 14px 30px rgba(0,79,168,.13),inset 0 1px 0 rgba(255,255,255,.85);padding:4px;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)}.header-nav .nav-inner li{display:flex}.header-nav .nav-inner a{width:var(--item-size);height:38px;display:grid;place-items:center;border-radius:999px;color:#5e6b86;text-decoration:none;transition:color .16s ease,background-color .16s ease,transform .16s ease}.header-nav .nav-inner a:hover,.header-nav .nav-inner a:focus-visible{color:var(--blue-strong);background:linear-gradient(180deg,#ffffff,#eaf5ff);text-decoration:none;transform:translateY(-1px)}.header-nav .nav-inner a:focus-visible{outline:3px solid rgba(0,120,212,.24);outline-offset:3px}.header-nav svg{width:21px;height:21px;display:block;fill:currentColor}.nav-hover-label{position:absolute;left:0;bottom:calc(100% + 6px);max-width:180px;opacity:var(--enter-nav);pointer-events:none;white-space:nowrap;border:1px solid rgba(184,207,234,.95);border-radius:999px;background:rgba(239,246,255,.96);box-shadow:0 9px 18px rgba(31,79,143,.12);color:#075985;font-size:11px;font-weight:600;line-height:1;padding:7px 10px;transform:translate(calc(var(--label-x) - 50%),calc((1 - var(--enter-nav)) * 4px + var(--label-y)));transition:opacity .15s ease,transform .2s ease}.header-nav:not(:hover):not(:focus-within){--enter-nav:0}\n"
        "    .grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:16px}.kpi-grid{gap:20px;margin-bottom:22px}.dashboard-grid{align-items:stretch}.panel{background:linear-gradient(180deg,rgba(255,255,255,.94),rgba(248,252,255,.9));border:1px solid var(--line);border-radius:8px;padding:14px;min-width:0;box-shadow:0 10px 30px rgba(31,79,143,.08)}.panel *{min-width:0}.panel p,.panel span,.panel dd,.panel strong{overflow-wrap:anywhere}.panel.status-card{display:grid;gap:18px;padding:22px;border-radius:18px;background:linear-gradient(180deg,rgba(255,255,255,.96),rgba(247,252,255,.9));border-color:#c6d9ee;box-shadow:0 18px 38px rgba(31,79,143,.12),inset 0 1px 0 rgba(255,255,255,.88)}.span-3{grid-column:span 3}.span-4{grid-column:span 4}.span-5{grid-column:span 5}.span-6{grid-column:span 6}.span-7{grid-column:span 7}.span-8{grid-column:span 8}.span-12{grid-column:span 12}\n"
        "    .ui-icon{display:block;flex:0 0 auto}.kpi-card{position:relative;display:grid;align-content:start;gap:14px;min-height:188px;padding:24px;border-color:rgba(167,204,242,.82);border-radius:18px;background:linear-gradient(180deg,rgba(255,255,255,.92),rgba(246,251,255,.78));box-shadow:0 18px 38px rgba(31,79,143,.11),inset 0 1px 0 rgba(255,255,255,.92);overflow:hidden}.kpi-card:before{content:'';position:absolute;inset:0 0 auto;height:1px;background:rgba(255,255,255,.96)}.kpi-card>*{position:relative}.kpi-head{display:flex;align-items:center;gap:14px;margin-bottom:8px}.kpi-head h2{margin:0;color:#4b5d78;font-size:13px;font-weight:740;line-height:1.15;text-transform:uppercase;letter-spacing:0}.icon-bubble{display:inline-grid;place-items:center;width:54px;height:54px;border:1px solid #c9e3ff;border-radius:999px;background:linear-gradient(135deg,#e5f3ff,#f7fbff);color:var(--blue-strong);box-shadow:inset 0 1px 0 rgba(255,255,255,.92),0 10px 22px rgba(31,79,143,.1)}.kpi-icon{width:27px;height:27px}.kpi-target .icon-bubble{color:#005bd3;background:linear-gradient(135deg,#dff0ff,#f8fcff)}.kpi-family .icon-bubble,.kpi-observed .icon-bubble,.kpi-baseline .icon-bubble{color:#0b69d1}.status-pill{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:5px 11px;font-size:13px;font-weight:650;line-height:1;color:var(--unknown);background:var(--unknown-soft);white-space:nowrap}.kpi-head .status-pill{margin-left:auto}.status-pill.current{color:var(--ok);border-color:#a9ddb7;background:linear-gradient(180deg,var(--ok-soft),#f7fff8)}\n"
        "    h2{font-size:12px;font-weight:720;text-transform:uppercase;letter-spacing:0;color:var(--muted);margin:0 0 12px}.metric{font-size:31px;font-weight:680;line-height:1;color:#102a43}.kpi-card .metric{font-size:54px;font-weight:720;letter-spacing:0;color:#071632}.metric.blue,.kpi-card .metric.blue{color:#005bd3}.label{display:block;color:var(--muted);font-size:13px;margin-top:6px}.kpi-card .label{font-size:17px;color:#50627e;margin-top:0;line-height:1.25}.mono{font-family:Consolas,Menlo,monospace;color:var(--code);overflow-wrap:anywhere;word-break:break-word}.panel-heading-icon{width:16px;height:16px;color:var(--blue-strong)}\n"
        "    .kv{display:grid;grid-template-columns:minmax(126px,160px) 1fr;gap:9px 14px;font-size:14px}.kv dt{color:var(--muted)}.kv dd{margin:0;font-weight:600;overflow-wrap:anywhere}.kv dd span{display:block;margin-top:2px;color:var(--muted);font-size:12px;font-weight:500}.compact-kv{grid-template-columns:1fr;gap:4px}.compact-kv dt{font-size:12px}.compact-kv dd{margin:0 0 8px}.metadata{border-top:1px solid var(--line);padding-top:12px}.refresh{border-left:3px solid var(--blue);background:linear-gradient(90deg,var(--blue-soft),rgba(255,255,255,0));padding-left:12px}.time-copy{display:inline-flex!important;align-items:center;gap:6px;max-width:100%;min-width:0;color:inherit;font-size:inherit}.time-copy time{overflow-wrap:anywhere}.time-copy.unavailable{color:var(--muted);font-size:13px}.epoch-copy{display:inline-grid;place-items:center;width:24px;height:24px;min-width:24px;border:1px solid var(--line);border-radius:6px;background:rgba(255,255,255,.86);color:#64748b;cursor:pointer;padding:0;box-shadow:0 1px 1px rgba(15,23,42,.04)}.epoch-copy:hover{border-color:#9cccf6;color:var(--blue-strong);background:#fff}.epoch-copy:focus-visible{outline:3px solid rgba(0,120,212,.28);outline-offset:2px}.epoch-copy[data-copy-state=\"copied\"]{border-color:#b9e6c4;color:var(--ok);background:var(--ok-soft)}.epoch-copy[data-copy-state=\"failed\"]{border-color:#f6b7ad;color:var(--err);background:var(--err-soft)}.epoch-copy svg{width:14px;height:14px;display:block;pointer-events:none}\n"
        "    .panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.freshness-head h2{margin:0;color:#0f1f3d}.freshness-state{display:inline-flex;align-items:center;border-radius:999px;border:1px solid var(--line);padding:6px 12px;font-size:13px;font-weight:650;line-height:1;color:var(--unknown);background:var(--unknown-soft);white-space:nowrap}.freshness-state.current{color:var(--ok);background:var(--ok-soft);border-color:#b9e6c4}.freshness-state.refresh-due{color:var(--warn);background:var(--warn-soft);border-color:#f6d493}.freshness-state.stale{color:var(--err);background:var(--err-soft);border-color:#f6b7ad}.freshness-state.unknown{color:var(--unknown);background:var(--unknown-soft);border-color:var(--line)}.freshness-layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(176px,190px);gap:14px;align-items:center}.freshness-primary{display:grid;gap:16px}.freshness-hero{display:flex;align-items:center;gap:16px}.freshness-ring{display:inline-grid;place-items:center;width:120px;height:120px;flex:0 0 auto;border:3px solid var(--ok);border-radius:999px;background:radial-gradient(circle,#f8fff9 0,#e9f8ec 72%,#def4e4 100%);color:var(--ok);box-shadow:0 18px 34px rgba(16,124,16,.18),0 0 0 14px rgba(16,124,16,.08),inset 0 1px 0 rgba(255,255,255,.9)}.freshness-ring.refresh-due{border-color:var(--warn);color:var(--warn);background:linear-gradient(180deg,var(--warn-soft),#fffaf0);box-shadow:0 18px 34px rgba(180,83,9,.14),0 0 0 14px rgba(180,83,9,.08)}.freshness-ring.stale{border-color:var(--err);color:var(--err);background:linear-gradient(180deg,var(--err-soft),#fff8f6);box-shadow:0 18px 34px rgba(180,35,24,.14),0 0 0 14px rgba(180,35,24,.08)}.freshness-ring.unknown{border-color:#b8c5d6;color:var(--unknown);background:linear-gradient(180deg,var(--unknown-soft),#fbfdff);box-shadow:0 18px 34px rgba(100,116,139,.12),0 0 0 14px rgba(100,116,139,.06)}.freshness-ring-icon{width:64px;height:64px}.freshness-metric{font-size:46px;font-weight:720;line-height:1;color:#071632;letter-spacing:0;white-space:nowrap}.freshness-detail{color:#334155;font-size:14px}.freshness-callout{display:flex;align-items:center;gap:10px;margin:0;border:1px solid #cfe5d4;border-radius:12px;background:linear-gradient(180deg,rgba(255,255,255,.9),rgba(247,255,249,.84));padding:12px 14px;box-shadow:inset 0 1px 0 rgba(255,255,255,.86)}.freshness-callout.refresh-due{border-color:#f6d493;background:linear-gradient(180deg,var(--warn-soft),#fffaf0)}.freshness-callout.stale{border-color:#f6b7ad;background:linear-gradient(180deg,var(--err-soft),#fff8f6)}.freshness-callout.unknown{border-color:var(--line);background:linear-gradient(180deg,var(--unknown-soft),#fbfdff)}.freshness-callout-icon{width:22px;height:22px;flex:0 0 auto;color:var(--ok)}.freshness-callout.refresh-due .freshness-callout-icon{color:var(--warn)}.freshness-callout.stale .freshness-callout-icon{color:var(--err)}.freshness-callout.unknown .freshness-callout-icon{color:var(--unknown)}.thresholds{display:grid;grid-template-columns:1fr;gap:10px}.threshold-card{display:grid;grid-template-columns:auto minmax(0,1fr);gap:10px;align-items:center;border:1px solid var(--line);border-radius:12px;background:linear-gradient(180deg,#f8fbff,#f2f7ff);padding:11px}.threshold-icon{display:inline-grid;place-items:center;width:34px;height:34px;border:1px solid #c9e3ff;border-radius:10px;background:#fff;color:var(--blue-strong)}.threshold-icon svg{width:20px;height:20px}.thresholds strong{display:block;font-size:17px;font-weight:640}.thresholds span{display:block;color:var(--muted);font-size:12px}.freshness-meta-strip{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border-top:1px solid var(--line);padding-top:16px}.freshness-meta-item{display:flex;align-items:center;justify-content:center;gap:10px;color:#24344f;font-size:15px;line-height:1.2;min-width:0;white-space:nowrap}.freshness-meta-item+.freshness-meta-item{border-left:1px solid var(--line)}.freshness-meta-icon{width:25px;height:25px;flex:0 0 auto;color:#005bd3}.freshness-metadata{border:0;padding-top:0}.freshness-metadata summary{cursor:pointer;color:#64748b;font-size:12px;font-weight:650;list-style:none}.freshness-metadata summary::-webkit-details-marker{display:none}.freshness-metadata summary:before{content:'+';display:inline-grid;place-items:center;width:16px;height:16px;margin-right:6px;border:1px solid var(--line);border-radius:999px;color:#075985;background:#fff}.freshness-metadata[open] summary:before{content:'-'}.freshness-metadata dl{margin:9px 0 0}.freshness-metadata dt{font-size:12px}.freshness-metadata dd{font-size:13px}\n"
        "    ul.clean{list-style:none;margin:0;padding:0;display:grid;gap:10px}ul.clean li{display:grid;gap:3px}ul.clean span{color:var(--muted);font-size:13px}a{color:#075985;text-decoration:none;overflow-wrap:anywhere;word-break:break-word}a:hover{text-decoration:underline}a:focus-visible,summary:focus-visible{outline:3px solid rgba(0,120,212,.28);outline-offset:3px;border-radius:6px}.version-link{display:inline-flex;align-items:center;gap:6px;color:#0067c0;font-weight:600}.version-link:after{content:'\\2197';font-family:Segoe UI,Arial,sans-serif;font-size:12px}.hash{display:inline-block;max-width:100%}\n"
        "    .trust-indicator{--trust-ring:rgba(16,124,16,.18);display:inline-flex;align-items:center;gap:8px;width:max-content;overflow:hidden;border:1px solid #a9ddb7;border-radius:999px;background:linear-gradient(180deg,var(--ok-soft),#f7fff8);color:var(--ok);padding:5px 10px;font-size:12px;font-weight:620;white-space:nowrap;box-shadow:inset 0 1px 0 rgba(255,255,255,.82)}.trust-indicator:before{content:'';width:9px;height:9px;border-radius:999px;background:currentColor;box-shadow:0 0 0 4px var(--trust-ring);transform-origin:center;animation:trustPulse 2.2s cubic-bezier(.4,0,.2,1) infinite;will-change:transform}@keyframes trustPulse{0%,100%{transform:scale(1)}45%{transform:scale(1.48)}72%{transform:scale(1.12)}}.trust-indicator.warning{color:var(--warn);background:linear-gradient(180deg,var(--warn-soft),#fffaf0);border-color:#f6d493;--trust-ring:rgba(180,83,9,.2)}.trust-indicator.error{color:var(--err);background:linear-gradient(180deg,var(--err-soft),#fff8f6);border-color:#f6b7ad;--trust-ring:rgba(180,35,24,.2)}.signature-panel{position:relative;overflow:hidden;display:flex;flex-direction:column;gap:14px;padding:18px;background:linear-gradient(180deg,rgba(255,255,255,.98),rgba(247,251,255,.94));border-color:#c9d9ec}.signature-panel:before{content:'';position:absolute;inset:0 0 auto;height:3px;background:linear-gradient(90deg,var(--ok),rgba(0,120,212,.28));opacity:.5}.signature-panel.warning{border-color:#f6d493;background:linear-gradient(180deg,#fffaf1,#fffdf7)}.signature-panel.warning:before{background:linear-gradient(90deg,var(--warn),rgba(180,83,9,.22))}.signature-panel.error{border-color:#f6b7ad;background:linear-gradient(180deg,#fff7f5,#fffdfc)}.signature-panel.error:before{background:linear-gradient(90deg,var(--err),rgba(180,35,24,.22))}.signature-panel>*{position:relative}.signature-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.signature-head h2,.programmatic-api h2{display:flex;align-items:center;gap:7px}.signature-head h2{margin:0;color:#475569;font-weight:720}.signature-status-card{display:grid;gap:4px;border:1px solid #a9ddb7;border-radius:10px;background:linear-gradient(135deg,#f0fbf3,#fbfffc);padding:13px 14px;box-shadow:inset 0 1px 0 rgba(255,255,255,.8)}.signature-status-card.warning{border-color:#f6d493;background:linear-gradient(135deg,var(--warn-soft),#fffaf0)}.signature-status-card.error{border-color:#f6b7ad;background:linear-gradient(135deg,var(--err-soft),#fff8f6)}.signature-status-card span{color:var(--muted);font-size:12px}.signature-status-card strong{color:#0f172a;font-size:16px;font-weight:650;line-height:1.25}.signature-status-card.error strong{color:var(--err)}.signature-kv{display:grid;gap:9px;margin:0}.signature-kv div{display:grid;grid-template-columns:minmax(104px,30%) minmax(0,1fr);gap:12px;align-items:center;border:1px solid #d5e2f0;border-radius:8px;background:linear-gradient(180deg,#fbfdff,#f5f8fc);padding:10px 12px;box-shadow:inset 0 1px 0 rgba(255,255,255,.7);transition:transform .16s ease,border-color .16s ease,background-color .16s ease}.signature-kv div:hover{border-color:#b8c9dd;background:#fff;box-shadow:0 7px 16px rgba(31,79,143,.07);transform:translateY(-1px)}.signature-kv dt{color:var(--muted);font-size:12px}.signature-kv dd{margin:0;color:#172033;font-weight:600;line-height:1.25;overflow-wrap:anywhere}.signature-kv .mono{font-size:13px;font-weight:600}.source-health{border-top:1px solid var(--line);padding-top:10px;display:grid;gap:8px}.source-health h3{margin:0;color:var(--muted);font-size:11px;font-weight:720;text-transform:uppercase;letter-spacing:0}.source-health-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.source-tile{border:1px solid var(--line);border-radius:8px;padding:10px;min-width:0;background:var(--soft)}.source-tile.ok{border-color:#b9e6c4;background:linear-gradient(180deg,var(--ok-soft),#f8fff9)}.source-tile.warning{border-color:#f6d493;background:linear-gradient(180deg,var(--warn-soft),#fffaf0)}.source-tile.error{border-color:#f6b7ad;background:linear-gradient(180deg,var(--err-soft),#fff8f6)}.source-tile.unknown{border-color:var(--line);background:linear-gradient(180deg,var(--unknown-soft),#fbfdff)}.source-tile-head{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between}.source-name{display:inline-flex;align-items:center;gap:7px;min-width:0}.source-name strong{font-weight:700}.source-icon{width:17px;height:17px;color:var(--blue-strong)}.source-status{border:1px solid var(--line);border-radius:999px;background:#fff;color:#475569;padding:2px 7px;font-size:11px;font-weight:600}.source-status.ok{color:var(--ok);border-color:#b9e6c4;background:#fff}.source-status.warning{color:var(--warn);border-color:#f6d493;background:#fff}.source-status.error{color:var(--err);border-color:#f6b7ad;background:#fff}.source-status.unknown{color:var(--unknown);background:#fff}.source-tile a{display:block;margin:8px 0 10px;font-size:13px}.source-tile>span{display:block;margin-top:4px;color:var(--muted);font-size:13px}.mini-kv{display:grid;grid-template-columns:80px minmax(0,1fr);gap:5px 10px;margin:0;font-size:12px}.mini-kv dt{color:var(--muted)}.mini-kv dd{margin:0;font-weight:600;overflow-wrap:anywhere}\n"
        "    .source-diagnostics{display:flex;flex-direction:column;gap:10px;min-height:0;align-self:start}.diag-summary{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;flex:0 0 auto}.diag-tile{appearance:none;width:100%;display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:center;column-gap:8px;min-height:48px;border:1px solid var(--line);border-radius:8px;background:linear-gradient(180deg,#fbfdff,#f2f7ff);padding:8px 10px;color:inherit;font:inherit;text-align:left;cursor:pointer}.diag-tile:hover{border-color:#9cccf6;background:#fff}.diag-tile:focus-visible{outline:3px solid rgba(0,120,212,.28);outline-offset:2px}.diag-tile[aria-pressed=\"true\"]{box-shadow:inset 0 0 0 2px rgba(0,120,212,.18)}.diag-tile strong{display:block;font-size:22px;font-weight:650;line-height:1}.diag-tile span{color:var(--muted);font-size:12px}.diag-tile-icon{width:19px;height:19px;justify-self:end}.diag-tile.notice{border-color:#bfdbfe;background:linear-gradient(180deg,var(--blue-soft),#f8fbff)}.diag-tile.notice strong,.diag-tile.notice .diag-tile-icon{color:var(--blue)}.diag-tile.notice span{color:var(--blue-strong);font-weight:600}.diag-tile.warning{border-color:#f6d493;background:linear-gradient(180deg,var(--warn-soft),#fffaf0)}.diag-tile.warning strong,.diag-tile.warning .diag-tile-icon{color:var(--warn)}.diag-tile.warning span{color:var(--warn);font-weight:600}.diag-tile.error{border-color:#f6b7ad;background:linear-gradient(180deg,var(--err-soft),#fff8f6)}.diag-tile.error strong,.diag-tile.error .diag-tile-icon{color:var(--err)}.diag-tile.error span{color:var(--err);font-weight:600}.diag-filter-status{margin:-2px 0 0;color:var(--muted);font-size:12px;line-height:1.3}.diag-issue-sync-status{display:flex;align-items:flex-start;gap:7px;margin:0;border:1px solid #f6d493;border-radius:10px;background:linear-gradient(180deg,var(--warn-soft),#fffaf0);padding:8px 10px;color:var(--warn);font-size:12px;line-height:1.3}.diag-issue-sync-status strong{flex:0 0 auto}.diag-issue-sync-status span{color:#7c4a03}.diag-issue-sync-icon{flex:0 0 auto;width:16px;height:16px}.diag-filter-empty{border:1px dashed var(--line);border-radius:12px;background:#fff;padding:14px;color:#475569;font-size:13px}.diag-filter-empty[hidden],.diag-row[hidden],.diag-more[hidden]{display:none!important}.diag-feed{margin-top:2px;height:340px;min-height:340px;max-height:340px;overflow-y:scroll;overscroll-behavior:contain;scrollbar-gutter:stable;border:1px solid #d8dee8;border-radius:8px;background:linear-gradient(180deg,#f6f7f9,#eef1f5);padding:14px 11px 24px 14px;box-shadow:inset 0 1px 2px rgba(15,23,42,.06);scrollbar-width:thin;scrollbar-color:#a8b0bc #eef1f5}.diag-feed::-webkit-scrollbar{width:10px}.diag-feed::-webkit-scrollbar-track{background:#eef1f5;border-radius:999px}.diag-feed::-webkit-scrollbar-thumb{background:#a8b0bc;border-radius:999px;border:2px solid #eef1f5}.diag-events{display:grid;gap:10px;padding:2px 2px 24px}.diag-events-empty .diag-row{background:linear-gradient(90deg,#ffffff,#f8fafc)}.diag-row{display:grid;grid-template-columns:4px 34px minmax(0,1fr);gap:8px;align-items:start;border:1px solid var(--line);border-radius:8px;background:#fbfdff;padding:8px}.diag-row.warning{border-color:#f6d493;background:linear-gradient(90deg,#fffaf0,#ffffff)}.diag-row.error{border-color:#f6b7ad;background:linear-gradient(90deg,#fff8f6,#ffffff)}.diag-row p{margin:3px 0 0;color:#475569;font-size:13px;line-height:1.35}.diag-stripe{display:block;align-self:stretch;border-radius:999px;background:var(--blue)}.diag-row-icon{width:20px;height:20px;margin-top:2px;justify-self:center;color:var(--blue-strong)}.diag-row-icon.warning{color:var(--warn)}.diag-row-icon.error{color:var(--err)}.diag-row.warning .diag-stripe{background:var(--warn)}.diag-row.error .diag-stripe{background:var(--err)}.diag-row-head{display:flex;flex-wrap:wrap;gap:5px;align-items:center}.diag-row-head strong{font-size:13px;font-weight:640}.severity-badge,.source-chip,.diag-tags span,.diag-tags a{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:2px 7px;font-size:11px;font-weight:600;background:#fff;color:#475569}.severity-badge.notice{color:var(--blue-strong);background:var(--blue-soft);border-color:#bfdbfe}.severity-badge.warning{color:var(--warn);background:var(--warn-soft);border-color:#f6d493}.severity-badge.error{color:var(--err);background:var(--err-soft);border-color:#f6b7ad}.source-chip{font-weight:600}.diag-tags{display:flex;flex-wrap:wrap;gap:5px;margin-top:5px}.diag-tags:empty{display:none}.diag-more{border:1px solid var(--line);border-radius:8px;background:var(--soft);padding:8px}.diag-more summary{cursor:pointer;color:#075985;font-size:13px;font-weight:600}.diag-more .diag-events{margin-top:8px}\n"
        "    .diag-row{position:relative}.diag-ticket-link{position:absolute;right:10px;top:10px;z-index:2;display:inline-flex;align-items:center;gap:5px;max-width:calc(100% - 20px);border:1px solid rgba(197,216,236,.95);border-radius:999px;background:rgba(255,255,255,.96);box-shadow:0 8px 18px rgba(31,79,143,.12),inset 0 1px 0 rgba(255,255,255,.9);padding:4px 8px;color:#075985;font-size:11px;font-weight:700;line-height:1;text-decoration:none;opacity:0;pointer-events:none;transform:translateY(-2px);transition:opacity .14s ease,transform .14s ease}.diag-ticket-link:hover{text-decoration:none}.diag-row:hover .diag-ticket-link,.diag-row:focus-within .diag-ticket-link{opacity:1;pointer-events:auto;transform:translateY(0)}.diag-ticket-link-icon{width:12px;height:12px}.diag-ticket-link .github-icon{width:12px;height:12px}\n"
        "    .programmatic-api{display:flex;flex-direction:column;justify-content:flex-start}.api-endpoints{display:grid;gap:9px}.api-endpoint-row{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:10px;align-items:center;border:1px solid var(--line);border-radius:8px;background:linear-gradient(180deg,#f8fafc,#f3f6fa);padding:10px 11px;color:inherit;text-decoration:none}.api-row-icon{width:18px;height:18px;color:var(--blue-strong)}.api-endpoint-row:hover{border-color:#b8c9dd;background:#ffffff;text-decoration:none}.api-endpoint-row:focus-visible{outline:3px solid rgba(0,120,212,.28);outline-offset:3px}.api-endpoint-row strong{display:block;color:#172033;font-size:13px;font-weight:640;line-height:1.25}.api-endpoint-row em{display:block;margin-top:2px;color:var(--muted);font-size:12px;font-style:italic;font-weight:500;line-height:1.35}.api-endpoint-row code{font-family:Consolas,Menlo,monospace;font-size:12px;color:var(--code);white-space:normal;text-align:right;overflow-wrap:anywhere}.api-note{margin-bottom:12px}.warnings{margin:0;padding-left:18px;color:var(--warn)}footer{position:relative;display:grid;gap:8px;justify-items:center;margin-top:34px;padding:20px 12px 4px;color:var(--muted);font-size:12px;line-height:1.45;text-align:center;background:linear-gradient(180deg,rgba(255,255,255,0),rgba(255,255,255,.42));border-radius:14px 14px 0 0}footer:before{content:'';width:min(640px,100%);height:1px;margin-bottom:8px;background:linear-gradient(90deg,rgba(194,213,235,0),rgba(148,163,184,.55),rgba(194,213,235,0));box-shadow:0 -12px 28px rgba(31,79,143,.08)}.footer-note{max-width:900px;margin:0}.footer-disclaimer,.footer-owner{color:#64748b}.footer-source{display:flex;flex-wrap:wrap;align-items:center;justify-content:center;gap:4px 6px;margin-top:2px}.footer-github{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.82);padding:2px 8px;color:#075985;font-weight:600;white-space:nowrap;box-shadow:0 3px 10px rgba(31,79,143,.06)}.footer-license-basic{color:#075985;font-weight:600;text-decoration:none}.footer-license-basic:hover,.footer-license-basic:focus-visible{text-decoration:underline}.github-icon{width:13px;height:13px;display:block;flex:0 0 auto}@media(prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;transition:none!important;animation:none!important}.signature-kv div:hover{transform:none!important}}\n"
        "    @media(max-width:1400px){main{margin:28px auto;padding:28px;border-radius:28px}.brand{gap:24px}.winmark{width:104px;height:104px;gap:7px}.title-line h1{font-size:48px}.subtitle{font-size:19px}.eyebrow{font-size:16px}.title-version-link{padding:11px 16px;font-size:14px}.kpi-card .metric{font-size:40px}.freshness-layout{grid-template-columns:1fr}.freshness-ring{width:104px;height:104px}.freshness-ring-icon{width:56px;height:56px}.freshness-metric{font-size:40px}.thresholds{grid-template-columns:repeat(2,minmax(0,1fr))}}\n"
        "    @media(min-width:901px){#live-freshness-panel{grid-column:1/span 5;grid-row:1/span 2}.source-diagnostics{grid-column:6/span 7;grid-row:1/span 2}.signature-panel{grid-column:1/span 5;grid-row:3}.programmatic-api{grid-column:6/span 7;grid-row:3}}\n"
        "    @media(max-width:900px){main{width:calc(100% - 24px);margin:18px auto;padding:24px;border-radius:24px}.grid{grid-template-columns:repeat(6,minmax(0,1fr))}.span-3,.span-4{grid-column:span 3}.span-5,.span-6,.span-7,.span-8,.span-12{grid-column:span 6}.source-health-grid{grid-template-columns:1fr}.brand-layout{grid-template-columns:1fr}.header-actions{align-items:flex-start}.header-nav{--item-size:37px}.nav-hover-label{display:none}.title-version-link{margin-left:0}.masthead{margin-bottom:20px}}\n"
        "    @media(min-width:741px) and (max-width:900px){.signature-panel{grid-column:span 3}.programmatic-api{grid-column:span 3}.api-endpoint-row{grid-template-columns:auto 1fr}.api-endpoint-row code{grid-column:2;text-align:left}}\n"
        "    @media(max-width:740px){.signature-panel,.programmatic-api{grid-column:1/-1}.signature-head{display:grid}.signature-kv div{grid-template-columns:1fr}.api-endpoint-row{grid-template-columns:auto 1fr}.api-endpoint-row code{grid-column:2;text-align:left}}\n"
        "    @media(max-width:640px){main{width:calc(100% - 16px);margin:10px auto;padding:16px 12px;border-radius:20px}.masthead{padding:0 0 12px}.brand{display:grid;grid-template-columns:58px minmax(0,1fr);gap:14px;align-items:start}.brand-layout{grid-template-columns:1fr;gap:12px}.header-actions{align-items:flex-start;gap:12px}.header-top-actions{justify-content:flex-start;gap:10px}.pypi-download-link{width:74px;height:74px}.pypi-download-link img{width:74px;height:74px;border-radius:15px}.winmark{width:58px;height:58px;gap:4px}.winmark span{border-radius:5px}.title-line h1{font-size:34px}.subtitle-line{flex-wrap:wrap;gap:5px 12px}.eyebrow{font-size:12px}.eyebrow-icon{width:15px;height:15px}.header-nav{--item-size:35px;max-width:100%}.header-nav .nav-inner{width:max-content;max-width:100%;gap:3px;padding:3px}.header-nav .nav-inner a{height:32px}.header-nav svg{width:19px;height:19px}.title-version-link{font-size:12px;margin-left:0;padding:8px 11px}.subtitle{font-size:14px;max-width:240px}.grid{grid-template-columns:1fr;gap:12px}.span-3,.span-4,.span-5,.span-6,.span-7,.span-8,.span-12{grid-column:auto}.kpi-card .metric{font-size:34px}.freshness-hero{align-items:flex-start}.freshness-ring{width:84px;height:84px}.freshness-ring-icon{width:46px;height:46px}.freshness-metric{font-size:34px}.freshness-callout{align-items:flex-start}.freshness-meta-strip{grid-template-columns:1fr;gap:10px}.freshness-meta-item{justify-content:flex-start}.freshness-meta-item+.freshness-meta-item{border-left:0}.kv{grid-template-columns:1fr}.diag-summary,.thresholds{grid-template-columns:1fr}.diag-feed{height:300px;min-height:300px;max-height:300px}footer{margin-top:28px;padding-top:18px}}\n"
        "    .freshness-panel{gap:24px;padding:26px;overflow:hidden}.freshness-panel .panel-head{align-items:center;padding-bottom:2px}.freshness-layout{grid-template-columns:minmax(0,1fr) minmax(182px,198px);gap:22px;align-items:stretch}.freshness-primary{gap:18px;align-content:start}.freshness-hero{display:grid;grid-template-columns:minmax(90px,112px) minmax(0,1fr);gap:20px;align-items:center}.freshness-ring{position:relative;justify-self:center;width:min(112px,100%);height:auto;aspect-ratio:1;border:0;background:radial-gradient(circle at 34% 24%,#ffffff 0 14%,#ecfff0 38%,#c8f2d5 100%);box-shadow:0 18px 34px rgba(16,124,16,.18),0 0 0 12px rgba(16,124,16,.08),inset 0 1px 0 rgba(255,255,255,.9)}.freshness-ring:after{content:'';position:absolute;inset:10px;border:2px solid currentColor;border-radius:999px;opacity:.95}.freshness-ring.refresh-due{background:radial-gradient(circle at 34% 24%,#fff 0 14%,#fff8e8 42%,#fde7bd 100%);box-shadow:0 18px 34px rgba(180,83,9,.15),0 0 0 12px rgba(180,83,9,.08),inset 0 1px 0 rgba(255,255,255,.9)}.freshness-ring.stale{background:radial-gradient(circle at 34% 24%,#fff 0 14%,#fff0ed 42%,#ffd3cc 100%);box-shadow:0 18px 34px rgba(180,35,24,.15),0 0 0 12px rgba(180,35,24,.08),inset 0 1px 0 rgba(255,255,255,.9)}.freshness-ring.unknown{background:radial-gradient(circle at 34% 24%,#fff 0 14%,#f3f7fb 42%,#dce5ef 100%);box-shadow:0 18px 34px rgba(100,116,139,.13),0 0 0 12px rgba(100,116,139,.06),inset 0 1px 0 rgba(255,255,255,.9)}.freshness-ring-icon{position:relative;z-index:1;width:52px;height:52px;stroke-width:2.4;transform:translateY(-1px);filter:drop-shadow(0 4px 6px rgba(16,124,16,.16))}.freshness-age-copy{display:grid;gap:5px;align-content:center;min-width:0}.freshness-age-label{margin-top:0}.freshness-metric{font-size:clamp(34px,3.4vw,44px);line-height:1.02;max-width:100%;white-space:nowrap;overflow-wrap:normal;word-break:normal}.freshness-metric.age-wide{font-size:clamp(31px,3vw,38px)}.freshness-metric.age-compact{font-size:clamp(29px,2.8vw,36px);letter-spacing:0}.freshness-callout{gap:12px;padding:13px 15px;border-radius:14px;line-height:1.4}.freshness-callout-icon{box-sizing:content-box;width:18px;height:18px;min-width:18px;padding:5px;border:1px solid #b9e6c4;border-radius:999px;background:linear-gradient(180deg,#f8fff9,#e7f8eb);color:var(--ok)}.freshness-callout.refresh-due .freshness-callout-icon{border-color:#f6d493;background:linear-gradient(180deg,#fffaf0,#ffefd1);color:var(--warn)}.freshness-callout.stale .freshness-callout-icon{border-color:#f6b7ad;background:linear-gradient(180deg,#fff8f6,#ffe0db);color:var(--err)}.freshness-callout.unknown .freshness-callout-icon{border-color:#cbd5e1;background:linear-gradient(180deg,#fff,#f1f5f9);color:var(--unknown)}.thresholds{gap:12px;align-content:start}.threshold-card{min-height:66px;gap:12px;padding:13px 14px;border-radius:14px}.threshold-icon{width:40px;height:40px;border-radius:12px;background:linear-gradient(180deg,#fff,#eaf5ff);box-shadow:inset 0 1px 0 rgba(255,255,255,.88)}.threshold-icon svg{display:block;width:22px;height:22px;margin:auto}.threshold-card:nth-child(2) .threshold-icon{border-color:#fed7aa;background:linear-gradient(180deg,#fff,#fff3e4);color:#c85700}.freshness-meta-strip{margin-top:2px;padding-top:18px}.freshness-meta-item{gap:11px;min-height:42px}.freshness-meta-icon{box-sizing:content-box;width:20px;height:20px;padding:5px;border:1px solid #bfdbfe;border-radius:999px;background:linear-gradient(180deg,#f8fbff,#eaf5ff);box-shadow:inset 0 1px 0 rgba(255,255,255,.9);color:#005bd3}.freshness-metadata{margin-top:-4px}\n"
        "    @media(max-width:1400px){.freshness-panel{padding:24px}.freshness-layout{grid-template-columns:1fr;gap:22px}.freshness-hero{grid-template-columns:minmax(90px,112px) minmax(0,1fr);gap:22px}.freshness-ring{width:min(112px,100%)}.freshness-ring-icon{width:52px;height:52px}.freshness-metric{font-size:clamp(34px,5vw,44px)}.freshness-metric.age-wide{font-size:clamp(31px,4.4vw,38px)}.freshness-metric.age-compact{font-size:clamp(29px,4vw,36px)}}\n"
        "    @media(max-width:640px){.freshness-panel{padding:20px 16px;gap:20px}.freshness-panel .panel-head{gap:10px}.freshness-layout{gap:18px}.freshness-hero{grid-template-columns:82px minmax(0,1fr);gap:16px;align-items:center}.freshness-ring{width:82px}.freshness-ring:after{inset:7px}.freshness-ring-icon{width:40px;height:40px}.freshness-metric{font-size:30px}.freshness-metric.age-wide,.freshness-metric.age-compact{font-size:28px}.freshness-callout{padding:12px;align-items:flex-start}.threshold-card{min-height:62px}.freshness-meta-strip{padding-top:14px}.freshness-meta-item{min-height:34px}.freshness-meta-icon{width:18px;height:18px;padding:4px}.freshness-metadata{margin-top:-2px}}\n"
        "    @media(max-width:360px){.freshness-panel .panel-head{align-items:flex-start;flex-direction:column}.freshness-state{align-self:flex-start}.freshness-hero{grid-template-columns:1fr}.freshness-ring{justify-self:start;width:76px}.freshness-metric{font-size:28px}.freshness-metric.age-wide,.freshness-metric.age-compact{font-size:26px}}\n"
        "    .signature-panel,.programmatic-api{border-radius:18px;border-color:rgba(174,203,235,.86);background:linear-gradient(180deg,rgba(255,255,255,.94),rgba(246,251,255,.86));box-shadow:0 18px 38px rgba(31,79,143,.11),inset 0 1px 0 rgba(255,255,255,.9)}.signature-panel{gap:16px;padding:22px}.signature-panel:after{content:'';position:absolute;right:-58px;top:-62px;width:166px;height:166px;border-radius:999px;background:radial-gradient(circle,rgba(0,120,212,.14),rgba(0,120,212,.06) 44%,rgba(0,120,212,0) 70%);box-shadow:inset 0 0 0 1px rgba(0,120,212,.1);pointer-events:none}.signature-panel.warning:after{background:radial-gradient(circle,rgba(180,83,9,.14),rgba(180,83,9,.05) 46%,rgba(180,83,9,0) 70%)}.signature-panel.error:after{background:radial-gradient(circle,rgba(180,35,24,.14),rgba(180,35,24,.05) 46%,rgba(180,35,24,0) 70%)}.signature-head{align-items:center}.signature-head h2,.programmatic-api h2{margin:0;color:#334155;font-weight:740;gap:9px}.signature-head .panel-heading-icon,.programmatic-api .panel-heading-icon{box-sizing:content-box;width:18px;height:18px;padding:7px;border:1px solid #c9e3ff;border-radius:12px;background:linear-gradient(180deg,#fff,#eaf5ff);color:#005bd3;box-shadow:inset 0 1px 0 rgba(255,255,255,.9)}.signature-status-card{gap:5px;border-radius:14px;padding:15px 16px;background:linear-gradient(135deg,rgba(240,251,243,.98),rgba(255,255,255,.86));box-shadow:inset 0 1px 0 rgba(255,255,255,.9),0 8px 18px rgba(16,124,16,.06)}.signature-status-card strong{font-size:17px}.signature-kv{gap:10px}.signature-kv div{grid-template-columns:minmax(116px,32%) minmax(0,1fr);gap:14px;border-color:rgba(197,216,236,.88);border-radius:13px;background:linear-gradient(180deg,rgba(255,255,255,.88),rgba(246,250,255,.82));padding:13px 14px;box-shadow:inset 0 1px 0 rgba(255,255,255,.86);transition:border-color .16s ease,background-color .16s ease,box-shadow .16s ease}.signature-kv div:hover{border-color:#aecded;background:rgba(255,255,255,.96);box-shadow:0 8px 18px rgba(31,79,143,.08),inset 0 1px 0 rgba(255,255,255,.92);transform:none}.signature-kv dt{font-size:12px;font-weight:650;text-transform:uppercase;color:#65758e}.signature-kv dd{font-size:14px;color:#102033}.programmatic-api{gap:14px;padding:22px}.programmatic-api .api-note{margin:0;color:#334967;font-size:20px;line-height:1.3}.api-endpoints{gap:10px}.api-endpoint-row{grid-template-columns:auto minmax(0,1fr) max-content;gap:12px;border-color:rgba(197,216,236,.9);border-radius:13px;background:linear-gradient(180deg,rgba(255,255,255,.9),rgba(245,249,255,.84));padding:12px 13px;box-shadow:inset 0 1px 0 rgba(255,255,255,.86);transition:border-color .16s ease,background-color .16s ease,box-shadow .16s ease}.api-row-icon{box-sizing:content-box;width:18px;height:18px;padding:6px;border:1px solid #c9e3ff;border-radius:10px;background:linear-gradient(180deg,#fff,#eaf5ff);color:#005bd3}.api-endpoint-row:hover{border-color:#aecded;background:rgba(255,255,255,.96);box-shadow:0 8px 18px rgba(31,79,143,.08);text-decoration:none}.api-endpoint-row strong{font-size:13px;font-weight:700}.api-endpoint-row em{font-size:12px;color:#65758e}.api-endpoint-row code{justify-self:end;display:inline-flex;align-items:center;max-width:100%;border:1px solid #c9e3ff;border-radius:999px;background:linear-gradient(180deg,#fff,#edf6ff);padding:5px 9px;color:#064b7a;font-size:12px;line-height:1.2;white-space:nowrap;overflow-wrap:normal}.source-health{margin-top:2px;padding-top:14px;gap:10px;border-top-color:rgba(174,203,235,.78)}.source-health h3{color:#5b6d86;font-size:12px}.source-health-grid{gap:12px}.source-tile{position:relative;overflow:hidden;border-color:rgba(185,230,196,.95);border-radius:14px;background:linear-gradient(180deg,rgba(241,253,244,.96),rgba(250,255,251,.88));padding:14px;box-shadow:inset 0 1px 0 rgba(255,255,255,.9),0 8px 20px rgba(16,124,16,.06)}.source-tile:before{content:'';position:absolute;inset:0 0 auto;height:2px;background:linear-gradient(90deg,var(--ok),rgba(0,120,212,.24));opacity:.45}.source-tile.warning:before{background:linear-gradient(90deg,var(--warn),rgba(180,83,9,.2))}.source-tile.error:before{background:linear-gradient(90deg,var(--err),rgba(180,35,24,.2))}.source-tile.unknown:before{background:linear-gradient(90deg,var(--unknown),rgba(100,116,139,.18))}.source-tile-head,.source-tile>a,.source-tile>.mini-kv{position:relative}.source-name{gap:9px}.source-name strong{color:#172033;font-size:16px}.source-icon{box-sizing:content-box;width:16px;height:16px;padding:5px;border:1px solid #b9e6c4;border-radius:10px;background:linear-gradient(180deg,#fff,#ecfff0);color:var(--ok)}.source-tile.warning .source-icon{border-color:#f6d493;background:linear-gradient(180deg,#fff,#fff4df);color:var(--warn)}.source-tile.error .source-icon{border-color:#f6b7ad;background:linear-gradient(180deg,#fff,#fff0ed);color:var(--err)}.source-tile.unknown .source-icon{border-color:#cbd5e1;background:linear-gradient(180deg,#fff,#f1f5f9);color:var(--unknown)}.source-status{padding:3px 8px;background:rgba(255,255,255,.88);box-shadow:inset 0 1px 0 rgba(255,255,255,.8)}.source-tile a{margin:10px 0 12px;color:#075985;font-size:13px}.mini-kv{grid-template-columns:82px minmax(0,1fr);gap:7px 11px}.mini-kv dt{font-weight:650;color:#65758e}.mini-kv dd{color:#1f2f49}.mini-kv .time-copy{gap:7px}.mini-kv .epoch-copy{background:#fff}.warnings{border-radius:14px;background:rgba(255,250,240,.7);padding:12px 12px 12px 30px}footer{margin-top:36px;padding:18px 12px 2px;background:transparent;border-radius:0;color:#6b7a90;box-shadow:none}footer:before{width:min(760px,100%);margin-bottom:6px;background:linear-gradient(90deg,rgba(194,213,235,0),rgba(148,163,184,.44),rgba(194,213,235,0));box-shadow:none}.footer-note{max-width:920px}.footer-source{margin-top:4px;gap:5px 7px}.footer-github{border-color:rgba(197,216,236,.8);background:rgba(255,255,255,.54);box-shadow:none;color:#1d5f8f}.footer-license-basic{color:#1d5f8f}@media(max-width:1199px) and (min-width:901px){main{width:calc(100% - 44px);padding:28px}.kpi-card{padding:20px}.source-health-grid{grid-template-columns:1fr}.api-endpoint-row{grid-template-columns:auto minmax(0,1fr)}.api-endpoint-row code{grid-column:2;justify-self:start;white-space:normal}.programmatic-api .api-note{font-size:18px}}@media(max-width:900px){.dashboard-grid{align-items:start}.span-5,.span-6,.span-7,.span-8,.span-12,#live-freshness-panel,.source-diagnostics,.signature-panel,.programmatic-api{grid-column:1/-1;grid-row:auto}.signature-panel,.programmatic-api{padding:20px}.source-health-grid{grid-template-columns:1fr}.api-endpoint-row{grid-template-columns:auto minmax(0,1fr)}.api-endpoint-row code{grid-column:2;justify-self:start;white-space:normal}.signature-kv div{grid-template-columns:minmax(110px,30%) minmax(0,1fr)}}@media(max-width:640px){body:before{width:150vw;left:-42vw}body:after{width:130vw;right:-62vw}.brand{grid-template-columns:52px minmax(0,1fr)}.winmark{width:52px;height:52px}.title-line h1{font-size:30px;line-height:1.08}.subtitle{font-size:14px;max-width:100%}.signature-panel,.programmatic-api{padding:18px 14px;border-radius:16px}.signature-head{align-items:flex-start;display:grid}.trust-indicator{justify-self:start}.signature-kv div{grid-template-columns:1fr;gap:5px;padding:12px}.programmatic-api .api-note{font-size:16px}.api-endpoint-row{grid-template-columns:auto minmax(0,1fr);align-items:start}.api-row-icon{margin-top:1px}.api-endpoint-row code{grid-column:1/-1;justify-self:start;white-space:normal}.source-tile{padding:13px}.source-tile-head{align-items:flex-start}.source-name strong{font-size:15px}.mini-kv{grid-template-columns:1fr;gap:4px}footer{margin-top:26px;padding:16px 4px 0}.footer-source{display:grid;justify-items:center}.footer-github{white-space:normal}}@media(max-width:360px){.title-line h1{font-size:27px}.api-endpoint-row{padding:11px}.source-name{align-items:flex-start}.footer-note{font-size:11px}}\n"
        "    @media(max-width:1500px){.freshness-panel .freshness-layout{grid-template-columns:1fr;gap:22px}.freshness-panel .thresholds{grid-template-columns:repeat(2,minmax(0,1fr))}}\n"
        "    @media(max-width:640px){main{width:calc(100% - 20px);padding:14px 10px}.kpi-head{flex-wrap:wrap;align-items:flex-start}.kpi-head .status-pill{margin-left:0}.subtitle{max-width:250px;overflow-wrap:break-word;word-break:normal}.freshness-panel .panel-head{align-items:flex-start;flex-direction:column}.freshness-state{align-self:flex-start}.diag-feed{overflow-x:hidden}.diag-row{grid-template-columns:4px 28px minmax(0,1fr);gap:7px}.diag-row-icon{width:18px;height:18px}.diag-row-head,.diag-row p,.diag-tags{min-width:0}.severity-badge,.source-chip,.diag-tags span,.diag-tags a{max-width:100%}.source-tile a{overflow-wrap:anywhere}.time-copy{flex-wrap:wrap}.freshness-panel .thresholds{grid-template-columns:1fr}}\n"
        "    .panel-head{display:flex;align-items:center;justify-content:space-between;gap:14px}.panel-head h2{margin:0;color:#172033}.panel-actions{display:flex;flex-wrap:wrap;align-items:center;justify-content:flex-end;gap:8px}.panel-action{appearance:none;display:inline-flex;align-items:center;justify-content:center;border:1px solid rgba(197,216,236,.9);border-radius:999px;background:rgba(255,255,255,.72);box-shadow:inset 0 1px 0 rgba(255,255,255,.9);padding:7px 13px;color:#0b4fb3;font-family:inherit;font-size:13px;font-weight:650;line-height:1;text-decoration:none;white-space:nowrap;cursor:pointer}.panel-action:hover{border-color:#9cccf6;background:#fff;text-decoration:none}.panel-action:focus-visible{outline:3px solid rgba(0,120,212,.28);outline-offset:2px}.panel-action[aria-pressed=\"true\"]{border-color:#9cccf6;background:#fff}.source-diagnostics{gap:14px;padding:22px;border-radius:18px;border-color:rgba(174,203,235,.86);background:linear-gradient(180deg,rgba(255,255,255,.94),rgba(246,251,255,.86));box-shadow:0 18px 38px rgba(31,79,143,.11),inset 0 1px 0 rgba(255,255,255,.9)}.source-diagnostics>.panel-head{flex:0 0 auto}.diag-summary{gap:10px}.diag-tile{grid-template-columns:auto minmax(0,1fr) auto;min-height:64px;border-radius:13px;padding:12px 14px;box-shadow:inset 0 1px 0 rgba(255,255,255,.88)}.diag-tile strong{font-size:25px;font-weight:720}.diag-tile span{font-size:13px}.diag-tile-icon{box-sizing:content-box;width:23px;height:23px;padding:8px;border-radius:999px;background:rgba(255,255,255,.72);box-shadow:inset 0 1px 0 rgba(255,255,255,.9)}.diag-tile.notice .diag-tile-icon{border:1px solid #bfdbfe;background:linear-gradient(180deg,#fff,#eaf5ff)}.diag-tile.warning .diag-tile-icon{border:1px solid #fed7aa;background:linear-gradient(180deg,#fff,#fff3e4)}.diag-tile.error .diag-tile-icon{border:1px solid #fecaca;background:linear-gradient(180deg,#fff,#fff0ed)}.diag-feed{height:340px;min-height:340px;max-height:340px;border-color:rgba(197,216,236,.95);border-radius:14px;background:linear-gradient(180deg,rgba(255,255,255,.76),rgba(238,247,255,.68));padding:14px;box-shadow:inset 0 1px 2px rgba(31,79,143,.05);scrollbar-color:#8eb7df rgba(232,243,255,.68)}.diag-feed::-webkit-scrollbar{width:8px}.diag-feed::-webkit-scrollbar-track{background:rgba(232,243,255,.64);border-radius:999px}.diag-feed::-webkit-scrollbar-thumb{background:#8eb7df;border:2px solid rgba(232,243,255,.84);border-radius:999px}.diag-events{gap:10px;padding:2px 4px 12px 2px}.diag-row{grid-template-columns:5px 50px minmax(0,1fr);gap:12px;border-color:rgba(197,216,236,.95);border-radius:14px;background:linear-gradient(180deg,rgba(255,255,255,.96),rgba(250,253,255,.88));padding:12px;box-shadow:inset 0 1px 0 rgba(255,255,255,.9)}.diag-row.warning{background:linear-gradient(90deg,#fffaf0,#fff)}.diag-row.error{background:linear-gradient(90deg,#fff8f6,#fff)}.diag-row>div{min-width:0}.diag-stripe{width:5px}.diag-row-icon{display:grid;place-items:center;justify-self:center;align-self:start;width:42px;height:46px;margin-top:0;border:1px solid #bfdbfe;border-radius:14px;background:linear-gradient(180deg,#fff,#eaf5ff);color:var(--blue-strong);box-shadow:inset 0 1px 0 rgba(255,255,255,.9)}.diag-row-icon.warning{border-color:#fed7aa;background:linear-gradient(180deg,#fff,#fff3e4);color:var(--warn)}.diag-row-icon.error{border-color:#fecaca;background:linear-gradient(180deg,#fff,#fff0ed);color:var(--err)}.diag-row-icon .ui-icon{width:25px;height:25px}.diag-row-head{gap:6px}.diag-row-head strong{font-size:14px}.diag-row p{font-size:13px;color:#40516a;overflow-wrap:anywhere}.source-chip.src-diagnostics{color:#005bd3;background:var(--blue-soft);border-color:#bfdbfe}.source-chip.src-atom-feed{color:#005bd3;background:linear-gradient(180deg,#eef7ff,#f8fbff);border-color:#bfdbfe}.source-chip.src-release-policy,.source-chip.src-policy{color:#1d4ed8;background:linear-gradient(180deg,#edf4ff,#f8fbff);border-color:#c7d2fe}.source-chip.src-release-health{color:var(--ok);background:var(--ok-soft);border-color:#b9e6c4}.source-chip.src-freshness{color:#075985;background:#e0f2fe;border-color:#bae6fd}.source-chip.src-parser{color:var(--warn);background:var(--warn-soft);border-color:#fed7aa}.source-chip.src-signature{color:#5b21b6;background:#f3e8ff;border-color:#d8b4fe}.source-chip.src-source{color:#475569;background:#f8fafc;border-color:#cbd5e1}.diag-tags span,.diag-tags a{overflow-wrap:anywhere}.source-diagnostics #source-health{margin-top:0;padding-top:12px;border-top-color:rgba(174,203,235,.72)}\n"
        "    @media(max-width:640px){.source-diagnostics{padding:18px 14px;gap:12px}.source-diagnostics>.panel-head{align-items:flex-start;flex-direction:column}.panel-action{padding:6px 11px}.diag-summary{grid-template-columns:1fr}.diag-feed{height:320px;min-height:320px;max-height:320px;padding:12px}.diag-row{grid-template-columns:5px 40px minmax(0,1fr);gap:9px;padding:10px}.diag-row-icon{width:36px;height:40px}.diag-row-icon .ui-icon{width:21px;height:21px}.diag-row-head strong{font-size:13px}}\n"
        "    .diag-row{grid-template-columns:5px 38px minmax(0,1fr)}.diag-row-icon{width:32px;height:34px;margin-top:1px;border:0;border-radius:0;background:transparent;box-shadow:none}.diag-row-icon.warning,.diag-row-icon.error{border-color:transparent;background:transparent}.diag-row-icon .ui-icon{width:28px;height:28px;stroke-width:2}.diag-row-head{align-items:center;column-gap:7px;row-gap:4px}.diag-row-head .source-chip{font-size:10px;line-height:1.05;padding:2px 7px;font-weight:650;color:#047f9e;background:linear-gradient(180deg,#ecfeff,#f8fdff);border-color:#a5f3fc;box-shadow:inset 0 1px 0 rgba(255,255,255,.88);transform:translateY(-.5px)}.diag-row-head .source-chip.src-diagnostics,.diag-row-head .source-chip.src-atom-feed,.diag-row-head .source-chip.src-release-policy,.diag-row-head .source-chip.src-policy{color:#047f9e;background:linear-gradient(180deg,#ecfeff,#f8fdff);border-color:#a5f3fc}\n"
        "    @media(max-width:640px){.diag-row{grid-template-columns:5px 34px minmax(0,1fr)}.diag-row-icon{width:28px;height:30px;margin-top:0}.diag-row-icon .ui-icon{width:24px;height:24px}.diag-row-head .source-chip{font-size:10px;padding:2px 6px}}\n"
        "    .icon-bubble{width:62px;height:62px;border-color:#bfdcff;background:linear-gradient(135deg,#dceeff,#f8fcff);box-shadow:inset 0 1px 0 rgba(255,255,255,.94),0 12px 24px rgba(31,79,143,.13)}.kpi-icon{width:31px;height:31px;stroke-width:2}.kpi-target .kpi-icon{width:34px;height:34px}.kpi-head{gap:16px}.kpi-target .icon-bubble{background:linear-gradient(135deg,#d9edff,#f8fcff);color:#005be5}.kpi-family .icon-bubble,.kpi-observed .icon-bubble,.kpi-baseline .icon-bubble{color:#075fe0}\n"
        "    @media(max-width:640px){.icon-bubble{width:54px;height:54px}.kpi-icon{width:28px;height:28px}.kpi-target .kpi-icon{width:30px;height:30px}.kpi-head{gap:13px}}\n"
        "    .threshold-card{grid-template-columns:46px minmax(0,1fr);align-items:stretch}.threshold-icon{position:relative;align-self:center;justify-self:center;display:block;line-height:0;transform:none}.threshold-icon svg{position:absolute;left:50%;top:50%;display:block;margin:0;transform:translate(-50%,calc(-50% + 2px));transform-box:fill-box;transform-origin:center}.threshold-card>div{align-self:center;display:grid;gap:3px;line-height:1.15}.thresholds strong{line-height:1.08}.thresholds span{line-height:1.22}\n"
        "    @media(max-width:640px){.threshold-card{grid-template-columns:44px minmax(0,1fr)}.threshold-icon svg{transform:translate(-50%,calc(-50% + 1px))}.threshold-card>div{gap:2px}}\n"
        "    .panel :where(p,dd,dt,strong,em,code,a,.metric,.label){max-width:100%;min-width:0;overflow-wrap:anywhere;word-break:break-word}.kpi-card{container-type:inline-size}.kpi-card .metric{display:block;max-width:100%;white-space:normal;overflow-wrap:anywhere;word-break:break-word;text-wrap:balance;font-size:clamp(32px,3vw,50px);line-height:.98}.kpi-observed .metric,.kpi-baseline .metric{font-size:clamp(31px,2.65vw,46px)}.kpi-card .label{white-space:normal}.api-endpoint-row code{white-space:normal;overflow-wrap:anywhere;word-break:break-word}.freshness-metric{max-width:100%;overflow-wrap:anywhere}.source-tile-head,.signature-head,.panel-head{min-width:0}.source-name,.api-endpoint-row span,.signature-kv dd{min-width:0;max-width:100%}@supports(font-size:1cqw){.kpi-card .metric{font-size:clamp(32px,13cqw,50px)}.kpi-observed .metric,.kpi-baseline .metric{font-size:clamp(31px,11.8cqw,46px)}}\n"
        "    @media(max-width:900px){.kpi-card .metric{font-size:clamp(32px,8vw,46px)}.kpi-observed .metric,.kpi-baseline .metric{font-size:clamp(31px,7vw,44px)}}\n"
        "    @media(max-width:640px){.kpi-card .metric,.kpi-observed .metric,.kpi-baseline .metric{font-size:clamp(30px,10vw,38px);line-height:1.02}.kpi-card{min-height:0}}\n"
        "    .kpi-card,.freshness-panel,.source-diagnostics,.signature-panel,.programmatic-api{border-color:rgba(150,197,246,.78);box-shadow:0 20px 44px rgba(14,74,150,.13),inset 0 1px 0 rgba(255,255,255,.92)}.kpi-card,.panel.status-card,.source-diagnostics,.signature-panel,.programmatic-api{background:linear-gradient(180deg,rgba(255,255,255,.95),rgba(246,251,255,.86))}.panel h2,.kpi-head h2{color:#1c3156}.metric,.freshness-metric{color:#071632}.panel-action,.status-pill,.source-chip,.diag-tags span,.diag-tags a{box-shadow:inset 0 1px 0 rgba(255,255,255,.88)}\n"
        "    .freshness-panel{container-type:inline-size}.freshness-panel .freshness-layout{grid-template-columns:1fr;gap:clamp(24px,3vw,34px)}.freshness-panel .freshness-hero{grid-template-columns:minmax(104px,120px) minmax(0,1fr);gap:clamp(28px,3vw,40px);max-width:100%}.freshness-age-copy{gap:8px;padding-inline-start:2px}.freshness-metric{white-space:normal;overflow-wrap:normal;word-break:normal;text-wrap:balance}.freshness-callout{margin-top:clamp(14px,2vw,22px)}@supports(margin-top:1cqw){.freshness-callout{margin-top:clamp(14px,3cqw,24px)}}.freshness-panel .thresholds{grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.freshness-panel .threshold-card{column-gap:14px}.freshness-metric.age-wide{font-size:clamp(32px,3.15vw,40px)}@media(max-width:1500px){.freshness-panel .freshness-layout{gap:28px}.freshness-panel .freshness-hero{grid-template-columns:minmax(96px,112px) minmax(0,1fr);gap:28px}}@media(max-width:640px){.freshness-panel .freshness-layout{gap:22px}.freshness-panel .freshness-hero{grid-template-columns:82px minmax(0,1fr);gap:20px}.freshness-age-copy{gap:6px;padding-inline-start:0}.freshness-panel .thresholds{grid-template-columns:1fr;gap:12px}}@media(max-width:360px){.freshness-panel .freshness-hero{grid-template-columns:1fr}.freshness-ring{justify-self:start;width:76px}.freshness-metric{font-size:28px}.freshness-metric.age-wide,.freshness-metric.age-compact{font-size:26px}}\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <main>\n"
        "    <header class=\"masthead\">\n"
        f"      <div class=\"brand\"><div class=\"winmark\" aria-hidden=\"true\"><span></span><span></span><span></span><span></span></div><div class=\"brand-layout\"><div class=\"brand-copy\"><span class=\"eyebrow\">{_ui_icon_html('shield', class_name='ui-icon eyebrow-icon')}<span>Signed public policy feed</span></span><div class=\"title-line\"><h1>Windows 11 Release Guard</h1></div><div class=\"subtitle-line\"><p class=\"subtitle\">Broad-fleet Windows 11 release and quality baseline dashboard.</p></div></div><div class=\"header-actions\"><div class=\"header-top-actions\">"
        f"{_header_nav_html(base_url=base_url)}"
        f"{_pypi_download_link_html(base_url=base_url)}"
        "</div>"
        f"{_program_title_version_html(program_version)}"
        "</div></div></div>\n"
        "    </header>\n"
        "    <section class=\"grid kpi-grid\" id=\"policy-summary\" aria-label=\"Policy summary\">\n"
        "      <article class=\"panel span-3 kpi-card kpi-target\"><div class=\"kpi-head\">"
        f"<span class=\"icon-bubble\">{_ui_icon_html('target', class_name='ui-icon kpi-icon')}</span><h2>Broad target</h2><span class=\"status-pill current\">Current</span></div>"
        f"<div class=\"metric blue\">{escape(target_release)}</div><span class=\"label\">existing Windows 11 devices</span></article>\n"
        "      <article class=\"panel span-3 kpi-card kpi-family\"><div class=\"kpi-head\">"
        f"<span class=\"icon-bubble\">{_ui_icon_html('chip', class_name='ui-icon kpi-icon')}</span><h2>Build family</h2></div>"
        f"<div class=\"metric\">{escape(target_family)}</div><span class=\"label\">Windows build line</span></article>\n"
        "      <article class=\"panel span-3 kpi-card kpi-observed\"><div class=\"kpi-head\">"
        f"<span class=\"icon-bubble\">{_ui_icon_html('eye', class_name='ui-icon kpi-icon')}</span><h2>Latest observed</h2></div>"
        f"<div class=\"metric\">{escape(target_latest_observed or 'unknown')}</div><span class=\"label\">Microsoft Current Versions table</span></article>\n"
        "      <article class=\"panel span-3 kpi-card kpi-baseline\"><div class=\"kpi-head\">"
        f"<span class=\"icon-bubble\">{_ui_icon_html('shield-check', class_name='ui-icon kpi-icon')}</span><h2>Required baseline</h2></div>"
        f"<div class=\"metric\">{escape(target_baseline or 'unknown')}</div><span class=\"label\">{escape(policy.quality_policy.value)} floor</span></article>\n"
        "    </section>\n"
        "    <section class=\"grid dashboard-grid\" aria-label=\"Policy operations dashboard\">\n"
        "      <section class=\"panel span-5 status-card freshness-panel\" id=\"live-freshness-panel\" aria-label=\"Policy feed currency\">"
        "<div class=\"panel-head freshness-head\"><h2>Policy Feed Currency</h2><span id=\"live-freshness-state\" class=\"freshness-state unknown\" aria-live=\"polite\" aria-label=\"Published policy feed currency: Unknown\">Unknown</span></div>"
        "<div class=\"freshness-layout\"><div class=\"freshness-primary\"><div class=\"freshness-hero\">"
        f"<span class=\"freshness-ring unknown\" aria-hidden=\"true\">{_ui_icon_html('check', class_name='ui-icon freshness-ring-icon')}</span>"
        "<div class=\"freshness-age-copy\">"
        f"<div id=\"live-generated-age\" class=\"{escape(generated_age_class, quote=True)}\" aria-live=\"polite\" title=\"{escape(generated_age_label, quote=True)}\" aria-label=\"{escape(generated_age_label, quote=True)}\">{escape(generated_age_text)}</div>"
        "<span class=\"label freshness-age-label\">Published feed age</span></div></div>"
        "<p id=\"live-freshness-detail\" class=\"freshness-detail freshness-callout unknown\">"
        f"{_ui_icon_html('check', class_name='ui-icon freshness-callout-icon')}"
        "<span class=\"freshness-callout-text\">Render-time fallback. Browser recalculates published policy feed age from the GitHub Actions generated timestamp when JavaScript is available.</span></p></div>"
        "<div class=\"thresholds\">"
        f"<div class=\"threshold-card\"><span class=\"threshold-icon\">{_ui_icon_html('calendar', class_name='ui-icon')}</span><div><strong>{DEFAULT_POLICY_WARNING_AGE_DAYS} days</strong><span>refresh-due threshold</span></div></div>"
        f"<div class=\"threshold-card\"><span class=\"threshold-icon\">{_ui_icon_html('clock', class_name='ui-icon')}</span><div><strong>{DEFAULT_POLICY_STRICT_STALE_AGE_DAYS} days</strong><span>stale threshold</span></div></div>"
        "</div></div>"
        "<div class=\"freshness-meta-strip\" aria-label=\"Policy generation metadata\">"
        f"<div class=\"freshness-meta-item\">{_ui_icon_html('pin', class_name='ui-icon freshness-meta-icon')}<span>Berlin, Germany</span></div>"
        f"<div class=\"freshness-meta-item\">{_ui_icon_html('calendar', class_name='ui-icon freshness-meta-icon')}<span>{escape(generated_local_date)}</span></div>"
        f"<div class=\"freshness-meta-item\">{_ui_icon_html('clock', class_name='ui-icon freshness-meta-icon')}<span>{escape(generated_local_time)}</span></div></div>"
        "<details class=\"freshness-metadata\"><summary>Full feed metadata</summary><dl class=\"kv metadata\">"
        f"<dt>Berlin, Germany:</dt><dd class=\"refresh\">{escape(generated_human)}<span>GitHub workflow static feed generation</span></dd>"
        f"<dt>Time (UTC):</dt><dd>{_time_with_epoch_copy_html(generated_at_utc, label='policy generated UTC')}</dd>"
        f"<dt>Published feed age:</dt><dd>{generated_age_days:g} days at render-time fallback</dd>"
        f"<dt>Workflow refresh:</dt><dd>{escape(workflow_run)}<span>last automatic publish run, when generated in GitHub Actions</span></dd>"
        "<noscript><dt>Browser update:</dt><dd>JavaScript disabled; published feed age cannot recalculate in the browser.</dd></noscript>"
        "</dl></details></section>\n"
        f"{source_diagnostics_panel}"
        f"      <section class=\"panel span-5 signature-panel{trust_class}\"><div class=\"signature-head\"><h2>{_ui_icon_html('key', class_name='ui-icon panel-heading-icon')}<span>Signature</span></h2><span class=\"trust-indicator{trust_class}\">{escape(trust_indicator)}</span></div>"
        f"<div class=\"signature-status-card{trust_class}\"><span>Document trust state</span><strong>{escape(signature_status)}</strong><span>Detached signature metadata for the published policy artifact.</span></div>"
        "<dl class=\"signature-kv\">"
        f"<div><dt>Algorithm</dt><dd>{escape(signature_algorithm)}</dd></div>"
        f"<div><dt>key_id</dt><dd class=\"mono\">{escape(key_id)}</dd></div>"
        f"<div><dt>Policy SHA-256</dt><dd>{_hash_html(policy_hash)}</dd></div>"
        f"<div><dt>Signature status</dt><dd>{escape(signature_status)}</dd></div>"
        "</dl></section>\n"
        f"{warning_block}\n"
        f"      <section class=\"panel span-7 programmatic-api\"><h2>{_ui_icon_html('api', class_name='ui-icon panel-heading-icon')}<span>Programmatic API</span></h2>"
        "<p class=\"subtitle api-note\">Public JSON policy artifacts for fleet dashboards and scripts.</p>"
        "<div class=\"api-endpoints\">"
        f"{endpoint_links}"
        "</div></section>\n"
        "    </section>\n"
        f"    {_footer_html()}\n"
        "  </main>\n"
        f"  <script type=\"application/json\" id=\"policy-freshness-data\">{_safe_json_script_payload(freshness_data)}</script>\n"
        "  <script>\n"
        "    (function(){\n"
        "      var dataNode=document.getElementById('policy-freshness-data');\n"
        "      var panelNode=document.getElementById('live-freshness-panel');\n"
        "      var stateNode=document.getElementById('live-freshness-state');\n"
        "      var ageNode=document.getElementById('live-generated-age');\n"
        "      var detailNode=document.getElementById('live-freshness-detail');\n"
        "      var ringNode=panelNode ? panelNode.querySelector('.freshness-ring') : null;\n"
        "      var detailTextNode=detailNode ? detailNode.querySelector('.freshness-callout-text') : null;\n"
        "      var uiActive=true;\n"
        "      var uiFrames=[];\n"
        "      var uiTimers=[];\n"
        "      function reportUiError(scope,error){\n"
        "        try{\n"
        "          var root=document.documentElement;\n"
        "          var label=String(scope||'unknown');\n"
        "          if(root){\n"
        "            if(root.dataset){root.dataset.uiLastError=label;}\n"
        "            root.setAttribute('data-ui-last-error',label);\n"
        "            var count=Number(root.getAttribute('data-ui-error-count')||'0');\n"
        "            if(!Number.isFinite(count)||count<0){count=0;}\n"
        "            root.setAttribute('data-ui-error-count',String(count+1));\n"
        "          }\n"
        "        }catch(_markerError){}\n"
        "        try{if(window.console&&console.warn){console.warn('Windows 11 Release Guard UI '+label+' failed');}}catch(_consoleError){}\n"
        "      }\n"
        "      function reportMissingNode(scope,name){reportUiError(scope+' missing '+name,new Error('missing '+name));}\n"
        "      function guard(scope,fn){try{return fn();}catch(error){reportUiError(scope,error);return undefined;}}\n"
        "      function safeSetTimeout(fn,delay){\n"
        "        if(!uiActive){return 0;}\n"
        "        try{\n"
        "          var id=window.setTimeout(function(){if(uiActive){guard('timer callback',fn);}},delay);\n"
        "          uiTimers.push(['timeout',id]);\n"
        "          return id;\n"
        "        }catch(error){reportUiError('timer setup',error);return 0;}\n"
        "      }\n"
        "      function safeSetInterval(fn,delay){\n"
        "        if(!uiActive){return 0;}\n"
        "        try{\n"
        "          var id=window.setInterval(function(){if(uiActive){guard('interval callback',fn);}},delay);\n"
        "          uiTimers.push(['interval',id]);\n"
        "          return id;\n"
        "        }catch(error){reportUiError('interval setup',error);return 0;}\n"
        "      }\n"
        "      function safeRequestFrame(fn){\n"
        "        if(!uiActive){return 0;}\n"
        "        if(!window.requestAnimationFrame){return safeSetTimeout(fn,16);}\n"
        "        try{\n"
        "          var id=window.requestAnimationFrame(function(){if(uiActive){guard('animation frame',fn);}});\n"
        "          uiFrames.push(id);\n"
        "          return id;\n"
        "        }catch(error){reportUiError('animation frame request',error);return safeSetTimeout(fn,16);}\n"
        "      }\n"
        "      function safeCancelFrame(id){\n"
        "        if(!id){return;}\n"
        "        try{if(window.cancelAnimationFrame){window.cancelAnimationFrame(id);}else{window.clearTimeout(id);}}\n"
        "        catch(error){reportUiError('animation cancel',error);}\n"
        "      }\n"
        "      function shutdownUi(){\n"
        "        if(!uiActive){return;}\n"
        "        uiActive=false;\n"
        "        uiFrames.forEach(safeCancelFrame);\n"
        "        uiFrames=[];\n"
        "        uiTimers.forEach(function(entry){try{if(entry[0]==='interval'){window.clearInterval(entry[1]);}else{window.clearTimeout(entry[1]);}}catch(error){reportUiError('timer cancel',error);}});\n"
        "        uiTimers=[];\n"
        "      }\n"
        "      window.addEventListener('pagehide',function(){guard('shutdown',shutdownUi);},{once:true});\n"
        "      window.addEventListener('beforeunload',function(){guard('shutdown',shutdownUi);},{once:true});\n"
        "      function setText(node,value,scope){if(uiActive&&node&&node.isConnected){node.textContent=value;return;}if(uiActive&&scope){reportMissingNode(scope,'text target');}}\n"
        "      function setState(state,label,detail,detailLabel){\n"
        "        if(!uiActive){return;}\n"
        "        if(panelNode&&panelNode.isConnected){panelNode.setAttribute('data-freshness-state',state);}else{reportMissingNode('freshness state','panel');}\n"
        "        if(ringNode&&ringNode.isConnected){ringNode.className='freshness-ring '+state;}else{reportMissingNode('freshness state','ring');}\n"
        "        if(detailNode&&detailNode.isConnected){detailNode.className='freshness-detail freshness-callout '+state;detailNode.setAttribute('aria-label',detailLabel||detail);}else{reportMissingNode('freshness state','detail');}\n"
        "        if(stateNode&&stateNode.isConnected){stateNode.className='freshness-state '+state;stateNode.textContent=label;stateNode.setAttribute('aria-label','Published policy feed currency: '+label);}else{reportMissingNode('freshness state','label');}\n"
        "        var detailTarget=(detailTextNode&&detailTextNode.isConnected) ? detailTextNode : detailNode;\n"
        "        setText(detailTarget,detail,'freshness detail');\n"
        "      }\n"
        "      function plural(value,unit){return value+' '+unit+(value===1?'':'s');}\n"
        "      function exactAge(seconds){\n"
        "        var days=Math.floor(seconds/86400);\n"
        "        var hours=Math.floor((seconds%86400)/3600);\n"
        "        var minutes=Math.floor((seconds%3600)/60);\n"
        "        var parts=[];\n"
        "        if(days){parts.push(plural(days,'day'));}\n"
        "        if(hours||days){parts.push(plural(hours,'hour'));}\n"
        "        parts.push(plural(minutes,'minute'));\n"
        "        return parts.join(', ');\n"
        "      }\n"
        "      function formatAge(seconds){\n"
        "        seconds=Number(seconds);\n"
        "        if(!Number.isFinite(seconds)||seconds<0){return {text:'unknown',size:'age-wide',full:'Published feed age unknown'};}\n"
        "        seconds=Math.max(0,Math.floor(seconds));\n"
        "        var days=Math.floor(seconds/86400);\n"
        "        var hours=Math.floor((seconds%86400)/3600);\n"
        "        var minutes=Math.floor((seconds%3600)/60);\n"
        "        var full='Published feed age '+exactAge(seconds);\n"
        "        if(days>=1){return {text:days+'d '+hours+'h',size:days>=10?'age-compact':'age-wide',full:full};}\n"
        "        var hourValue=seconds/3600;\n"
        "        if(hourValue>=2){return {text:hourValue.toFixed(1).replace(/\\.0$/,'')+' hours',size:hourValue>=10?'age-wide':'',full:full};}\n"
        "        return {text:plural(minutes,'minute'),size:minutes>=100?'age-wide':'',full:full};\n"
        "      }\n"
        "      function setAgeDisplay(age){\n"
        "        if(!uiActive){return;}\n"
        "        if(!ageNode||!ageNode.isConnected){reportMissingNode('freshness age','metric');return;}\n"
        "        ageNode.textContent=age.text;\n"
        "        ageNode.className='freshness-metric'+(age.size?' '+age.size:'');\n"
        "        ageNode.setAttribute('title',age.full);\n"
        "        ageNode.setAttribute('aria-label',age.full);\n"
        "      }\n"
        "      function fallbackCopy(text){\n"
        "        if(!uiActive){return Promise.reject(new Error('ui inactive'));}\n"
        "        if(!document.body){reportMissingNode('copy fallback','body');return Promise.reject(new Error('copy unavailable'));}\n"
        "        var area=document.createElement('textarea');\n"
        "        area.value=text;area.setAttribute('readonly','');\n"
        "        area.style.position='fixed';area.style.left='-9999px';\n"
        "        var ok=false;\n"
        "        try{document.body.appendChild(area);area.select();ok=Boolean(document.execCommand&&document.execCommand('copy'));}catch(_error){ok=false;}finally{if(area.parentNode){area.parentNode.removeChild(area);}}\n"
        "        return ok ? Promise.resolve() : Promise.reject(new Error('copy failed'));\n"
        "      }\n"
        "      function copyText(text){\n"
        "        if(!uiActive){return Promise.reject(new Error('ui inactive'));}\n"
        "        try{if(navigator.clipboard&&navigator.clipboard.writeText){return navigator.clipboard.writeText(text);}}catch(_error){return fallbackCopy(text);}\n"
        "        return fallbackCopy(text);\n"
        "      }\n"
        "      function markCopyButton(button,state,title){\n"
        "        if(!uiActive){return;}\n"
        "        if(!button||!button.isConnected){reportMissingNode('copy button','button');return;}\n"
        "        button.setAttribute('data-copy-state',state);\n"
        "        button.setAttribute('title',title);\n"
        "        safeSetTimeout(function(){if(button&&button.isConnected){button.removeAttribute('data-copy-state');button.setAttribute('title',button.getAttribute('data-default-title')||'Copy epoch millisecond timestamp');}},1600);\n"
        "      }\n"
        "      Array.prototype.forEach.call(document.querySelectorAll('.epoch-copy[data-epoch]'),function(button){\n"
        "        button.setAttribute('data-default-title',button.getAttribute('title')||'Copy epoch millisecond timestamp');\n"
        "        button.addEventListener('click',function(){guard('copy epoch',function(){\n"
        "          if(!uiActive||!button.isConnected){return;}\n"
        "          var epoch=button.getAttribute('data-epoch')||'';\n"
        "          if(!/^\\d+$/.test(epoch)){markCopyButton(button,'failed','Epoch millisecond timestamp unavailable');return;}\n"
        "          copyText(epoch).then(function(){markCopyButton(button,'copied','Copied epoch millisecond timestamp '+epoch);}).catch(function(){markCopyButton(button,'failed','Could not copy epoch millisecond timestamp');});\n"
        "        });});\n"
        "      });\n"
        "      function initDiagnosticFilters(){\n"
        "        var root=document.querySelector('[data-diagnostic-filter-root]');\n"
        "        if(!root||!root.isConnected){reportMissingNode('source diagnostics filter','root');return;}\n"
        "        var feed=document.getElementById('source-diagnostics-feed');\n"
        "        if(!feed||!feed.isConnected){reportMissingNode('source diagnostics filter','feed');return;}\n"
        "        var controls=root.querySelectorAll('[data-diagnostic-filter]');\n"
        "        var rows=root.querySelectorAll('.diag-row[data-diagnostic-severity]');\n"
        "        if(!controls.length){reportMissingNode('source diagnostics filter','controls');return;}\n"
        "        if(!rows.length){reportMissingNode('source diagnostics filter','rows');return;}\n"
        "        var status=document.getElementById('source-diagnostics-filter-status');\n"
        "        var empty=document.getElementById('source-diagnostics-empty');\n"
        "        var moreBlocks=root.querySelectorAll('.diag-more');\n"
        "        var labels={notice:'notice',warning:'warning',error:'error'};\n"
        "        function rowWord(count){return count===1?'row':'rows';}\n"
        "        function normalizedFilter(value){return labels[value] ? value : '';}\n"
        "        function setFilterStatus(severity,shown){\n"
        "          if(!status||!status.isConnected){reportMissingNode('source diagnostics filter','status');return;}\n"
        "          if(!severity){status.textContent='Showing all '+rows.length+' source diagnostic '+rowWord(rows.length)+'.';return;}\n"
        "          if(shown){status.textContent='Showing '+shown+' '+labels[severity]+' diagnostic '+rowWord(shown)+'.';return;}\n"
        "          status.textContent='No '+labels[severity]+' diagnostic rows are currently reported.';\n"
        "        }\n"
        "        function setEmptyState(severity,shown){\n"
        "          if(!empty||!empty.isConnected){reportMissingNode('source diagnostics filter','empty state');return;}\n"
        "          if(severity&&shown===0){empty.hidden=false;empty.textContent='No '+labels[severity]+' diagnostic rows are currently reported.';return;}\n"
        "          empty.hidden=true;\n"
        "        }\n"
        "        function updateOverflow(severity){\n"
        "          Array.prototype.forEach.call(moreBlocks,function(block){\n"
        "            if(!block||!block.isConnected){return;}\n"
        "            var hasVisible=false;\n"
        "            Array.prototype.forEach.call(block.querySelectorAll('.diag-row[data-diagnostic-severity]'),function(row){if(!row.hidden){hasVisible=true;}});\n"
        "            if(severity){block.hidden=!hasVisible;if(hasVisible){block.open=true;}return;}\n"
        "            block.hidden=false;block.open=false;\n"
        "          });\n"
        "        }\n"
        "        function setPressedState(severity){\n"
        "          Array.prototype.forEach.call(controls,function(control){\n"
        "            if(!control||!control.isConnected){return;}\n"
        "            var value=control.getAttribute('data-diagnostic-filter')||'';\n"
        "            control.setAttribute('aria-pressed',severity ? String(value===severity) : String(value==='all'));\n"
        "          });\n"
        "        }\n"
        "        function applyFilter(value){\n"
        "          if(!uiActive||!root.isConnected||!feed.isConnected){return;}\n"
        "          var severity=normalizedFilter(value);\n"
        "          var shown=0;\n"
        "          Array.prototype.forEach.call(rows,function(row){\n"
        "            if(!row||!row.isConnected){return;}\n"
        "            var match=!severity||row.getAttribute('data-diagnostic-severity')===severity;\n"
        "            row.hidden=!match;\n"
        "            row.classList.toggle('is-filtered-out',!match);\n"
        "            if(match){shown+=1;}\n"
        "          });\n"
        "          updateOverflow(severity);\n"
        "          setEmptyState(severity,shown);\n"
        "          setFilterStatus(severity,shown);\n"
        "          setPressedState(severity);\n"
        "        }\n"
        "        Array.prototype.forEach.call(controls,function(control){\n"
        "          control.addEventListener('click',function(event){guard('source diagnostics filter',function(){\n"
        "            if(event&&event.preventDefault){event.preventDefault();}\n"
        "            if(!uiActive||!control.isConnected){return;}\n"
        "            applyFilter(control.getAttribute('data-diagnostic-filter')||'all');\n"
        "          });});\n"
        "        });\n"
        "        applyFilter('all');\n"
        "      }\n"
        "      guard('source diagnostics filter init',initDiagnosticFilters);\n"
        "      function initHeaderNav(){\n"
        "        var nav=document.querySelector('.header-nav');\n"
        "        if(!nav){reportMissingNode('header nav','nav');return;}\n"
        "        var items=nav.querySelectorAll('.nav-inner a');\n"
        "        if(!items.length){reportMissingNode('header nav','items');return;}\n"
        "        var frame=0;\n"
        "        var label=nav.querySelector('.nav-hover-label');\n"
        "        function setItem(item,x,y){\n"
        "          if(!uiActive||!nav.isConnected||!item||!item.isConnected){return;}\n"
        "          var navRect=nav.getBoundingClientRect();\n"
        "          var rect=item.getBoundingClientRect();\n"
        "          var text=item.getAttribute('data-nav-label')||item.getAttribute('aria-label')||'';\n"
        "          nav.style.setProperty('--enter-nav','1');\n"
        "          nav.style.setProperty('--label-x',String((rect.left-navRect.left)+(rect.width/2)+(x*5))+'px');\n"
        "          nav.style.setProperty('--label-y',String(y*3)+'px');\n"
        "          if(label&&label.isConnected&&text){label.textContent=text;}\n"
        "        }\n"
        "        function queue(item,event){\n"
        "          if(!uiActive||!item||!item.isConnected||!event){return;}\n"
        "          if(frame){safeCancelFrame(frame);}\n"
        "          frame=safeRequestFrame(function(){\n"
        "            frame=0;\n"
        "            if(!uiActive||!item.isConnected){return;}\n"
        "            var rect=item.getBoundingClientRect();\n"
        "            var x=((event.clientX-rect.left)-(rect.width/2))/rect.width;\n"
        "            var y=((event.clientY-rect.top)-(rect.height/2))/rect.height;\n"
        "            setItem(item,Math.max(-.5,Math.min(.5,x)),Math.max(-.5,Math.min(.5,y)));\n"
        "          });\n"
        "        }\n"
        "        Array.prototype.forEach.call(items,function(item,index){\n"
        "          item.addEventListener('pointermove',function(event){guard('header nav pointer',function(){queue(item,event);});},{passive:true});\n"
        "          item.addEventListener('focus',function(){guard('header nav focus',function(){setItem(item,0,0);});});\n"
        "        });\n"
        "        nav.addEventListener('pointerleave',function(){guard('header nav leave',function(){if(nav.isConnected){nav.style.setProperty('--enter-nav','0');}else{reportMissingNode('header nav','nav');}});});\n"
        "        nav.addEventListener('focusout',function(){guard('header nav focusout',function(){safeSetTimeout(function(){if(uiActive&&nav.isConnected&&!nav.contains(document.activeElement)){nav.style.setProperty('--enter-nav','0');}},0);});});\n"
        "      }\n"
        "      guard('header nav init',initHeaderNav);\n"
        "      function update(){\n"
        "        if(!uiActive){return;}\n"
        "        var data;\n"
        "        if(!dataNode||!dataNode.isConnected){reportMissingNode('freshness update','data');data={};}\n"
        "        else{try{data=JSON.parse(dataNode.textContent||'{}');}catch(error){data={};reportUiError('freshness data parse',error);}}\n"
        "        var generated=Number(data.generated_at_epoch_s);\n"
        "        if(!Number.isFinite(generated)||generated<=0){setAgeDisplay(formatAge(NaN));setState('unknown','Unknown','Policy feed timestamp is unavailable or invalid.');return;}\n"
        "        var now=Math.floor(Date.now()/1000);\n"
        "        if(!Number.isFinite(now)){setAgeDisplay(formatAge(NaN));setState('unknown','Unknown','Browser time is unavailable, so feed age cannot be calculated.');return;}\n"
        "        if(generated-now>300){setAgeDisplay(formatAge(0));setState('unknown','Clock Check','Browser clock is behind the policy timestamp; feed age is clamped to zero.');return;}\n"
        "        var ageSeconds=Math.max(0,now-generated);\n"
        "        var warningSeconds=Number(data.warning_age_seconds);\n"
        "        if(!Number.isFinite(warningSeconds)||warningSeconds<=0){warningSeconds=1209600;reportUiError('freshness warning threshold',new Error('invalid warning threshold'));}\n"
        "        var staleSeconds=Number(data.strict_stale_age_seconds);\n"
        "        if(!Number.isFinite(staleSeconds)||staleSeconds<=0){staleSeconds=3888000;reportUiError('freshness stale threshold',new Error('invalid stale threshold'));}\n"
        "        setAgeDisplay(formatAge(ageSeconds));\n"
        "        if(ageSeconds>=staleSeconds){setState('stale','Stale','Feed is stale. Refresh automation before trusting it.','Published policy feed is stale. Do not treat this data as production-current until automation refresh succeeds.');return;}\n"
        "        if(ageSeconds>=warningSeconds){setState('refresh-due','Refresh Due','Refresh is due. Verify automation health before production use.','Published policy feed refresh is due. Verify automation health before treating this data as production-current.');return;}\n"
        f"        setState('current','Current','Within the {DEFAULT_POLICY_WARNING_AGE_DAYS}-day maintenance threshold.','Published policy feed is within the {DEFAULT_POLICY_WARNING_AGE_DAYS}-day maintenance threshold.');\n"
        "      }\n"
        "      guard('freshness update',update);\n"
        "      safeSetInterval(function(){guard('freshness update',update);},60000);\n"
        "    }());\n"
        "  </script>\n"
        "</body>\n"
        "</html>\n"
    )


def render_robots_txt() -> str:
    return ROBOTS_TXT


def render_sitemap_xml(policy: ReleasePolicy, *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    generated_at = escape(policy.generated_at_utc or _utc_now())
    urls = tuple(
        dict.fromkeys(
            (
                f"{base_url}/",
                f"{base_url}/windows-release-policy.json",
                f"{base_url}/policy-manifest.json",
                *_wiki_sitemap_urls(base_url=base_url),
                *_changelog_sitemap_urls(base_url=base_url),
            )
        )
    )
    entries = "\n".join(
        (
            "  <url>\n"
            f"    <loc>{escape(url)}</loc>\n"
            f"    <lastmod>{generated_at}</lastmod>\n"
            "  </url>"
        )
        for url in urls
    )
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
        f"{entries}\n"
        "</urlset>\n"
    )


def _published_urls_for_base_url(base_url: str) -> dict[str, str]:
    normalized = base_url.rstrip("/")
    return {
        "landing": f"{normalized}/",
        "policy": f"{normalized}/windows-release-policy.json",
        "signature": f"{normalized}/windows-release-policy.json.sig",
        "manifest": f"{normalized}/policy-manifest.json",
        "api_policy": f"{normalized}/api/v1/policy.json",
        "api_signature": f"{normalized}/api/v1/policy.sig",
        "api_manifest": f"{normalized}/api/v1/manifest.json",
    }


def render_policy_manifest(
    policy: ReleasePolicy,
    *,
    policy_bytes: bytes,
    signature_bytes: bytes | None,
    signature: Mapping[str, Any] | None = None,
    verification_metadata: Mapping[str, Any] | None = None,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    target = policy.broad_target_existing_devices
    policy_sha256 = _sha256_hex(policy_bytes)
    signature_sha256 = _sha256_hex(signature_bytes)
    verification = verification_metadata if verification_metadata is not None else _public_verification_metadata(signature)
    status = _status_text(policy)
    manifest = {
        "schema_version": 1,
        "generated_at_utc": policy.generated_at_utc,
        "generated_at_human": _generated_at_human(policy.generated_at_utc),
        "timezone": PAGES_TIMEZONE,
        **freshness_thresholds(policy.generated_at_utc),
        "freshness_policy": freshness_policy_metadata(),
        "generator_version": policy.generator_version,
        "policy_schema_version": policy.schema_version,
        "min_reader_schema_version": policy.min_reader_schema_version,
        "max_reader_schema_version": policy.max_reader_schema_version,
        "api_version": policy.api_version,
        "compatibility": dict(policy.compatibility),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "commit_sha": os.environ.get("GITHUB_SHA"),
        "policy_sha256": policy_sha256,
        "signature_sha256": signature_sha256,
        "signature_algorithm": _signature_field(verification, "algorithm"),
        "key_id": _signature_field(verification, "key_id"),
        "source_urls": list(policy.source_urls),
        "source_diagnostics": dict(policy.source_diagnostics),
        "published_urls": dict(policy.published_urls or _published_urls_for_base_url(base_url)),
        "broad_target_existing_devices": (
            {
                "version": target.version,
                "build_family": target.build_family,
                "latest_build": target.latest_build,
                "latest_observed_build": target.latest_observed_build,
                "baseline_build": target.baseline_build,
                "required_baseline_build": target.required_baseline_build,
            }
            if target
            else None
        ),
        "latest_observed_build": target.latest_observed_build if target else None,
        "baseline": target.required_baseline_build if target else None,
        "required_baseline_build": target.required_baseline_build if target else None,
        "warnings": list(policy.validation_warnings),
        "status": status,
    }
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def build_policy_from_sources(
    *,
    release_health_url: str = DEFAULT_RELEASE_HEALTH_URL,
    atom_feed_url: str = DEFAULT_WINDOWS11_ATOM_FEED_URL,
    release_health_html_path: str | Path | None = None,
    atom_feed_path: str | Path | None = None,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    signature_status: str = "unsigned",
) -> ReleasePolicy:
    release_health = load_source_text(
        url=release_health_url,
        fixture_path=release_health_html_path,
        source_name="release_health_html",
        timeout=timeout,
        required=True,
    )
    atom_feed = load_source_text(
        url=atom_feed_url,
        fixture_path=atom_feed_path,
        source_name="atom_feed",
        timeout=timeout,
        required=False,
    )
    source_fetch_status = {
        "release_health_html": dict(release_health.status),
        "atom_feed": dict(atom_feed.status),
    }
    return generate_policy(
        release_health_html=release_health.text,
        atom_feed_xml=atom_feed.text or None,
        release_health_url=release_health_url,
        atom_feed_url=atom_feed_url,
        source_fetch_status=source_fetch_status,
        signature_status=signature_status,
    )


__all__ = [
    "DEFAULT_WINDOWS11_ATOM_FEED_URL",
    "AtomFeedEntry",
    "SourceText",
    "build_policy_from_sources",
    "generate_policy",
    "generate_policy_json",
    "load_source_text",
    "parse_atom_feed",
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
