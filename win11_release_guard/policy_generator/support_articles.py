"""Microsoft Support article URLs, fetching, parsing, and validation facts."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import unquote, urlparse
from ..exceptions import PolicyFetchError
from ..update_text import _extract_builds, _extract_kb
from .constants import DEFAULT_MAX_SUPPORT_ARTICLE_BYTES, PROGRAMMING_ERROR_TYPES
from .msrc_cvrf import _as_sequence
from .sources import AtomFeedEntry
from .timestamps import _parse_source_timestamp
from . import sources


SupportArticleFetcher = Callable[[str, float, int], str]


def _kb_url(kb_article: str | None, feed_entry: AtomFeedEntry | None = None) -> str | None:
    if feed_entry is not None:
        return _atom_entry_support_url(feed_entry)
    kb = _extract_kb(kb_article)
    if not kb:
        return None
    return f"https://support.microsoft.com/help/{kb[2:]}"


_MAX_SUPPORT_ARTICLE_URL_LENGTH = 2048

_MAX_SUPPORT_ARTICLE_PATH_LENGTH = 1024

_SUPPORT_ARTICLE_BLOCKED_PATH_PREFIXES = ("/api", "/assets", "/download", "/feed", "/search", "/static")

_SUPPORT_ARTICLE_HELP_PATH_RE = re.compile(r"/help/[1-9][0-9]{5,7}")

_SUPPORT_ARTICLE_TOPIC_PATH_RE = re.compile(r"/topic/[A-Za-z0-9][A-Za-z0-9._~!$&'()*+,;=:@%-]{1,900}")

_SUPPORT_ARTICLE_SERVICING_HUB_PATH_RE = re.compile(r"/servicing/os/windows-[0-9]{1,3}/?", re.IGNORECASE)

_SUPPORT_ARTICLE_SERVICING_PATH_RE = re.compile(
    r"/servicing/os/windows-[0-9]{1,3}/(?:19|20)[0-9]{2}/(?:0[1-9]|1[0-2])/"
    r"[A-Za-z0-9][A-Za-z0-9._~!$&'()*+,;=:@%-]{1,300}",
    re.IGNORECASE,
)


def _support_article_content_path(path: str) -> str:
    match = re.fullmatch(r"/[a-z]{2}-[a-z]{2}(/.*)", path, flags=re.IGNORECASE)
    return match.group(1) if match else path


def _safe_support_article_url(value: str | None) -> str | None:
    url = str(value or "").strip()
    if not url or len(url) > _MAX_SUPPORT_ARTICLE_URL_LENGTH:
        return None
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    path = parsed.path or ""
    if parsed.scheme.lower() != "https" or host != "support.microsoft.com":
        return None
    try:
        port = parsed.port
        if port not in (None, 443):
            return None
    except ValueError:
        return None
    if parsed.username or parsed.password:
        return None
    if not path.startswith("/") or path == "/" or len(path) > _MAX_SUPPORT_ARTICLE_PATH_LENGTH:
        return None

    lowered_path = path.lower()
    if "\\" in path or "%2e" in lowered_path or "%2f" in lowered_path or "%5c" in lowered_path:
        return None
    decoded_path = unquote(path)
    if "\\" in decoded_path or any(part == ".." for part in decoded_path.split("/")):
        return None

    content_path = _support_article_content_path(path)
    lowered_content_path = content_path.lower()
    if any(
        lowered_content_path == prefix or lowered_content_path.startswith(f"{prefix}/")
        for prefix in _SUPPORT_ARTICLE_BLOCKED_PATH_PREFIXES
    ):
        return None
    if "/api/" in lowered_content_path or "/feed/" in lowered_content_path:
        return None
    if _SUPPORT_ARTICLE_HELP_PATH_RE.fullmatch(lowered_content_path):
        return f"https://support.microsoft.com{path}"
    if _SUPPORT_ARTICLE_TOPIC_PATH_RE.fullmatch(content_path):
        return f"https://support.microsoft.com{path}"
    if _SUPPORT_ARTICLE_SERVICING_HUB_PATH_RE.fullmatch(content_path):
        return f"https://support.microsoft.com{path}"
    if _SUPPORT_ARTICLE_SERVICING_PATH_RE.fullmatch(content_path):
        return f"https://support.microsoft.com{path}"
    return None


_safe_atom_support_article_url = _safe_support_article_url


def _atom_entry_support_url(entry: AtomFeedEntry | None) -> str | None:
    if entry is None:
        return None
    return _safe_support_article_url(entry.link)


class _SupportArticleTextExtractor(HTMLParser):
    _SKIP_TAGS = {"script", "style", "noscript", "svg"}
    _CAPTURE_BLOCK_TAGS = {"h1", "h2", "h3", "h4", "h5", "h6", "p", "li", "dt", "dd"}
    _BLOCK_TAGS = {
        "article",
        "aside",
        "br",
        "dd",
        "div",
        "dt",
        "figcaption",
        "footer",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "li",
        "main",
        "p",
        "section",
        "td",
        "th",
        "tr",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._capture_title = False
        self._capture_h1 = False
        self._title_parts: list[str] = []
        self._h1_parts: list[str] = []
        self._text_parts: list[str] = []
        self._block_tag: str | None = None
        self._block_depth = 0
        self._block_parts: list[str] = []
        self._blocks: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized = tag.lower()
        if normalized in self._SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if normalized == "title":
            self._capture_title = True
        elif normalized == "h1":
            self._capture_h1 = True
        if normalized in self._CAPTURE_BLOCK_TAGS:
            if self._block_tag is None:
                self._block_tag = normalized
                self._block_depth = 0
                self._block_parts = []
            elif normalized == self._block_tag:
                self._block_depth += 1
        if normalized in self._BLOCK_TAGS:
            self._text_parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        normalized = tag.lower()
        if normalized in self._SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if normalized == "title":
            self._capture_title = False
        elif normalized == "h1":
            self._capture_h1 = False
        if normalized == self._block_tag:
            if self._block_depth:
                self._block_depth -= 1
            else:
                block_text = _compact_article_text(" ".join(self._block_parts))
                if block_text:
                    self._blocks.append((normalized, block_text))
                self._block_tag = None
                self._block_parts = []
        if normalized in self._BLOCK_TAGS:
            self._text_parts.append(" ")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        text = data.strip()
        if not text:
            return
        if self._capture_title:
            self._title_parts.append(text)
        if self._capture_h1:
            self._h1_parts.append(text)
        if self._block_tag is not None:
            self._block_parts.append(text)
        self._text_parts.append(text)

    @property
    def title(self) -> str | None:
        title = " ".join(self._h1_parts).strip() or " ".join(self._title_parts).strip()
        return _compact_article_text(title) or None

    @property
    def text(self) -> str:
        return _compact_article_text(" ".join(self._text_parts))

    @property
    def blocks(self) -> tuple[tuple[str, str], ...]:
        return tuple(self._blocks)


_SECURITY_ARTICLE_PHRASES = (
    "includes the latest security fixes",
    "addresses security vulnerabilities",
    "security updates",
)

_TITLE_BUCKET_RULES = (
    ("safe os dynamic update", "Safe OS Dynamic Update"),
    ("setup dynamic update", "Setup Dynamic Update"),
    ("out of box experience update", "OOBE Update"),
    ("hotpatch", "Hotpatch"),
    ("ai component update", "AI Component Update"),
    ("execution provider update", "AI Execution Provider Update"),
    ("servicing stack update", "Servicing Stack Update"),
    ("preview", "Preview OS Build Update"),
    ("out-of-band", "Out-of-band OS Build Update"),
)

_MONTH_NAMES = (
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

_MONTH_ABBREVIATIONS = (
    "",
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)

_SUPPORT_ARTICLE_HEADING_TAGS = {"h1", "h2", "h3", "h4", "h5", "h6"}

_SUPPORT_ARTICLE_APPLIES_STOP_HEADINGS = {
    "highlights",
    "improvements",
    "known issues",
    "known issues in this update",
    "summary",
    "how to get this update",
    "prerequisites",
    "release channel",
    "file information",
    "references",
}

_SUPPORT_ARTICLE_APPLIES_TO_MAX_LENGTH = 240

_SUPPORT_ARTICLE_IMPROVEMENT_HEADINGS = {"highlights", "improvements"}

_SUPPORT_ARTICLE_IMPROVEMENT_DETAIL_LIMIT = 4

_SUPPORT_ARTICLE_IMPROVEMENT_DETAIL_MAX_LENGTH = 180


def _compact_article_text(value: str | None) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def _support_article_heading_key(value: str | None) -> str:
    return _compact_article_text(value).strip(" :").lower()


def _support_article_is_applies_to_heading(value: str | None) -> bool:
    return _support_article_heading_key(value) == "applies to"


def _support_article_is_applies_stop_heading(value: str | None) -> bool:
    key = _support_article_heading_key(value)
    return any(key == stop or key.startswith(f"{stop} ") for stop in _SUPPORT_ARTICLE_APPLIES_STOP_HEADINGS)


def _clean_support_article_applies_to(value: str | None) -> str | None:
    text = _compact_article_text(value).rstrip(" .;")
    if not text:
        return None
    if len(text) <= _SUPPORT_ARTICLE_APPLIES_TO_MAX_LENGTH:
        return text
    truncated = text[:_SUPPORT_ARTICLE_APPLIES_TO_MAX_LENGTH].rsplit(" ", 1)[0].rstrip(" .;")
    return truncated or text[:_SUPPORT_ARTICLE_APPLIES_TO_MAX_LENGTH].rstrip(" .;")


def _bounded_support_article_applies_to_text(value: str | None) -> str | None:
    text = _compact_article_text(value)
    if not text:
        return None
    stop_pattern = "|".join(
        re.escape(item)
        for item in sorted(_SUPPORT_ARTICLE_APPLIES_STOP_HEADINGS, key=len, reverse=True)
    )
    match = re.search(rf"\b(?:{stop_pattern})\b", text, flags=re.IGNORECASE)
    if match:
        text = text[: match.start()]
    return _clean_support_article_applies_to(text)


def _extract_support_article_applies_to(
    blocks: Sequence[tuple[str, str]],
    searchable: str,
) -> str | None:
    for index, (tag, text) in enumerate(blocks):
        if tag not in _SUPPORT_ARTICLE_HEADING_TAGS or not _support_article_is_applies_to_heading(text):
            continue
        values: list[str] = []
        for next_tag, next_text in blocks[index + 1 :]:
            if next_tag in _SUPPORT_ARTICLE_HEADING_TAGS:
                break
            if _support_article_is_applies_stop_heading(next_text):
                break
            compact = _bounded_support_article_applies_to_text(next_text)
            if compact:
                values.append(compact)
        return _clean_support_article_applies_to("; ".join(values))

    for tag, text in blocks:
        if tag in _SUPPORT_ARTICLE_HEADING_TAGS:
            continue
        match = re.search(r"\bApplies to\s*:?\s*(.+)", text, flags=re.IGNORECASE)
        if match:
            applies_to = _bounded_support_article_applies_to_text(match.group(1))
            if applies_to:
                return applies_to

    match = re.search(r"\bApplies to\s*:?\s*(.{1,480})", searchable, flags=re.IGNORECASE)
    if match:
        return _bounded_support_article_applies_to_text(match.group(1))
    return None


def _bounded_support_article_improvement_detail(value: str | None) -> str | None:
    text = _compact_article_text(value)
    if not text:
        return None
    text = text.strip(" -\u2013\u2014")
    match = re.match(r"^\[([^\]]{1,80})\]\s*(.+)$", text)
    if match:
        label = _compact_article_text(match.group(1)).rstrip(":")
        detail = _compact_article_text(match.group(2)).rstrip(" .;")
        text = f"{label}: {detail}" if detail else label
    if len(text) > _SUPPORT_ARTICLE_IMPROVEMENT_DETAIL_MAX_LENGTH:
        text = text[:_SUPPORT_ARTICLE_IMPROVEMENT_DETAIL_MAX_LENGTH].rsplit(" ", 1)[0].rstrip(" .;,")
    return text.rstrip(" .;") + "."


def _extract_support_article_improvement_details(blocks: Sequence[tuple[str, str]]) -> list[str]:
    details: list[str] = []
    for index, (tag, text) in enumerate(blocks):
        if tag not in _SUPPORT_ARTICLE_HEADING_TAGS:
            continue
        if _support_article_heading_key(text) not in _SUPPORT_ARTICLE_IMPROVEMENT_HEADINGS:
            continue
        for next_tag, next_text in blocks[index + 1 :]:
            if next_tag in _SUPPORT_ARTICLE_HEADING_TAGS:
                break
            detail = _bounded_support_article_improvement_detail(next_text)
            if detail and detail not in details:
                details.append(detail)
            if len(details) >= _SUPPORT_ARTICLE_IMPROVEMENT_DETAIL_LIMIT:
                return details
        if details:
            return details
    return details


def _atom_title_bucket(title: Any) -> dict[str, str]:
    normalized = re.sub(r"\s+", " ", str(title or "")).strip().lower().replace("_", "-")
    for needle, bucket in _TITLE_BUCKET_RULES:
        if needle in normalized:
            return {"bucket": bucket, "confidence": "low"}
    if re.search(r"\bos builds?\b", normalized):
        return {"bucket": "OS Build Update", "confidence": "low"}
    return {"bucket": "Microsoft Support Update", "confidence": "low"}


def _msrc_month_id_from_atom_date(value: Any) -> str | None:
    parsed = _parse_source_timestamp(str(value or "") or None)
    if parsed is None:
        return None
    return f"{parsed.year}-{_MONTH_ABBREVIATIONS[parsed.month]}"


def _record_msrc_month_id(record: Mapping[str, Any]) -> str | None:
    """Resolve the MSRC CVRF month id for an enrichment record.

    Prefers source-derived published/updated dates. Two record types carry
    ``msrc_cvrf_month_fallback`` instead: the active baseline-update notice
    record when the discovery source provides no published/updated dates, and
    the release-history record built for the broad target, whose month comes
    from the Release Health availability date. Both resolve a month id without
    any discovery-source entry, so security classification keeps working while
    that source is unavailable.
    """
    month_id = _msrc_month_id_from_atom_date(record.get("published") or record.get("updated"))
    if month_id:
        return month_id
    fallback = record.get("msrc_cvrf_month_fallback")
    return str(fallback) if fallback else None


def _extract_support_article_facts(url: str, html_text: str) -> dict[str, Any]:
    parser = _SupportArticleTextExtractor()
    parser.feed(html_text)
    parser.close()
    title = parser.title
    text = parser.text
    searchable = _compact_article_text(" ".join(part for part in (title, text) if part))
    lower_searchable = searchable.lower()
    security_signals = tuple(
        phrase for phrase in _SECURITY_ARTICLE_PHRASES if phrase in lower_searchable
    )
    improvement_labels: list[str] = []
    for label in re.findall(r"\[([A-Za-z0-9][A-Za-z0-9 .+/#&-]{1,60})\]", searchable):
        compact_label = _compact_article_text(label)
        if compact_label and compact_label not in improvement_labels:
            improvement_labels.append(compact_label)
        if len(improvement_labels) >= 8:
            break
    improvement_details = _extract_support_article_improvement_details(parser.blocks)
    release_date = None
    month_pattern = "|".join(_MONTH_NAMES)
    match = re.search(rf"\b({month_pattern})\s+\d{{1,2}},\s+20\d{{2}}\b", searchable)
    if match:
        release_date = match.group(0)
    applies_to = _extract_support_article_applies_to(parser.blocks, searchable)
    applies_to_releases = (
        list(_support_article_releases_from_applies_to(applies_to) or ()) if applies_to else []
    )
    known_issue_status = None
    if "not currently aware of any issues" in lower_searchable:
        known_issue_status = "not_currently_aware"

    facts: dict[str, Any] = {
        "url": url,
        "title": title,
        "kb_article": _extract_kb(searchable),
        "builds": list(_extract_builds(searchable)[:8]),
        "release_date": release_date,
        "applies_to": applies_to,
        "applies_to_releases": applies_to_releases,
        "known_issue_status": known_issue_status,
        "improvement_labels": improvement_labels,
        "improvement_details": improvement_details,
        "is_security": True if security_signals else False,
        "security_evidence_source": "support_article" if security_signals else "none",
        "security_signals": list(security_signals),
    }
    return {key: value for key, value in facts.items() if value not in (None, "", [], ())}


def default_support_article_fetcher(url: str, timeout: float, max_bytes: int) -> str:
    safe_url = _safe_support_article_url(url)
    if safe_url is None:
        raise PolicyFetchError("Support article URL failed safety validation.")
    return sources.fetch_url(
        safe_url,
        timeout=timeout,
        max_bytes=max_bytes,
        final_url_validator=_safe_support_article_url,
    )


def _support_article_enrichment(
    url: str,
    *,
    fetcher: SupportArticleFetcher,
    timeout: float,
) -> dict[str, Any]:
    safe_url = _safe_support_article_url(url)
    if safe_url is None:
        return {
            "url": url,
            "status": "skipped",
            "reason": "invalid_support_article_url",
        }
    try:
        html_text = fetcher(safe_url, timeout, DEFAULT_MAX_SUPPORT_ARTICLE_BYTES)
    except PROGRAMMING_ERROR_TYPES:
        raise
    except Exception as exc:
        return {
            "url": safe_url,
            "status": "error",
            "error": str(exc),
        }
    try:
        facts = _extract_support_article_facts(safe_url, html_text)
    except PROGRAMMING_ERROR_TYPES:
        raise
    except Exception as exc:
        return {
            "url": safe_url,
            "status": "degraded",
            "error": str(exc),
        }
    status = "ok"
    reason = None
    if not facts.get("title") and not facts.get("kb_article") and not facts.get("builds"):
        status = "degraded"
        reason = "support_article_parse_incomplete"
    facts["status"] = status
    facts["bytes"] = len(html_text.encode("utf-8"))
    if reason:
        facts["reason"] = reason
    return facts


def _support_article_security_result(article: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(article, Mapping):
        return {
            "is_security": None,
            "cves": [],
            "severities": [],
            "products": [],
            "client_products": [],
            "evidence_source": "unavailable",
        }
    if article.get("is_security") is True:
        return {
            "is_security": True,
            "cves": [],
            "severities": [],
            "products": [],
            "client_products": [],
            "evidence_source": "support_article",
        }
    status = str(article.get("status") or "")
    if status in {"error", "skipped"}:
        return {
            "is_security": None,
            "cves": [],
            "severities": [],
            "products": [],
            "client_products": [],
            "evidence_source": "unavailable",
        }
    return {
        "is_security": False,
        "cves": [],
        "severities": [],
        "products": [],
        "client_products": [],
        "evidence_source": "none",
    }


def _support_article_record_url(record: Mapping[str, Any]) -> str | None:
    return _safe_support_article_url(str(record.get("support_url") or record.get("atom_feed_url") or "") or None)


_SUPPORT_ARTICLE_VALIDATION_STATUSES = {"ok", "degraded", "mismatch", "unavailable", "skipped"}

_SUPPORT_ARTICLE_VALIDATION_REASON_LIMIT = 6


def _support_article_canonical_url(value: Any) -> str | None:
    safe_url = _safe_support_article_url(str(value or "") or None)
    if safe_url is None:
        return None
    parsed = urlparse(safe_url)
    return parsed._replace(fragment="").geturl()


def _support_article_expected_facts(record: Mapping[str, Any]) -> dict[str, str]:
    expected: dict[str, str] = {}
    kb_article = _extract_kb(str(record.get("kb_article") or ""))
    build = str(record.get("build") or "").strip()
    release = str(record.get("release") or "").strip()
    if kb_article:
        expected["kb"] = kb_article
    if build:
        expected["build"] = build
    if release:
        expected["release"] = release
    return expected


def _support_article_releases_from_applies_to(value: Any) -> tuple[str, ...] | None:
    text = _compact_article_text(str(value or ""))
    if not text:
        return ()
    normalized = text.lower()
    if "windows" not in normalized:
        return None
    releases = tuple(
        dict.fromkeys(
            f"{match.group(1).upper()}H{match.group(2)}"
            for match in re.finditer(r"\b(\d{2})\s*h\s*([12])\b", text, flags=re.IGNORECASE)
        )
    )
    if releases:
        return releases
    if "windows 10" in normalized and "windows 11" not in normalized:
        return ()
    if "windows 11" in normalized:
        return None
    return ()


def _normalized_support_article_release_values(value: Any) -> tuple[str, ...]:
    releases: list[str] = []
    for item in _as_sequence(value):
        text = str(item or "").strip().upper()
        match = re.fullmatch(r"(\d{2})\s*H\s*([12])", text, flags=re.IGNORECASE)
        if match:
            releases.append(f"{match.group(1).upper()}H{match.group(2)}")
    return tuple(dict.fromkeys(releases))
