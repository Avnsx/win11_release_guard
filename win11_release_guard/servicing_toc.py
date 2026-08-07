"""Parse the public Windows 11 servicing table of contents."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

from .exceptions import PolicyParseError
from .update_text import _extract_builds, _extract_kb, _is_out_of_band, _is_preview

SERVICING_TOC_URL = "https://support.microsoft.com/en-us/servicing/os/windows-11/toc.json"
SERVICING_ARTICLE_BASE = "https://support.microsoft.com/en-us/servicing/os/windows-11/"

_LANE_TITLE_RE = re.compile(r"^Windows 11, version (\d\dH\d)$")
_TITLE_DATE_RE = re.compile(r"^(?P<month>[A-Z][a-z]+) (?P<day>\d{1,2}), (?P<year>\d{4})")
_HREF_DATE_RE = re.compile(r"^(?P<year>(?:19|20)\d{2})/(?P<month>0[1-9]|1[0-2])/")
_MONTH_NUMBERS = {
    "january": 1,
    "february": 2,
    "march": 3,
    "april": 4,
    "may": 5,
    "june": 6,
    "july": 7,
    "august": 8,
    "september": 9,
    "october": 10,
    "november": 11,
    "december": 12,
}
_MAX_TOC_DEPTH = 8
_MAX_HREF_LENGTH = 512


@dataclass(frozen=True)
class ServicingTocEntry:
    title: str
    release: str | None = None
    href: str | None = None
    url: str | None = None
    kb_article: str | None = None
    builds: tuple[str, ...] = ()
    preview: bool = False
    out_of_band: bool = False
    published: str | None = None


def _document(payload: Mapping[str, Any] | str) -> Mapping[str, Any]:
    if isinstance(payload, Mapping):
        return payload
    text = str(payload or "").lstrip("﻿").strip()
    if not text:
        return {}
    try:
        decoded = json.loads(text)
    except ValueError as exc:
        raise PolicyParseError(f"Servicing TOC is malformed: {exc}") from exc
    if not isinstance(decoded, Mapping):
        raise PolicyParseError("Servicing TOC is malformed: the top level value must be an object.")
    return decoded


def _child_nodes(value: Any) -> Sequence[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return ()


def _lane_release(title: str) -> str | None:
    match = _LANE_TITLE_RE.match(title)
    return match.group(1).upper() if match else None


def _servicing_entry_date(title: str, href: str) -> str | None:
    match = _TITLE_DATE_RE.match(title.strip())
    if match:
        month = _MONTH_NUMBERS.get(match.group("month").lower())
        if month:
            try:
                parsed = datetime(int(match.group("year")), month, int(match.group("day")))
            except ValueError:
                parsed = None
            if parsed is not None:
                return f"{parsed.year:04d}-{parsed.month:02d}-{parsed.day:02d}"
    href_match = _HREF_DATE_RE.match(str(href or "").lstrip("/"))
    if href_match:
        return f"{href_match.group('year')}-{href_match.group('month')}-01"
    return None


def _resolve_url(href: str) -> str | None:
    if len(href) > _MAX_HREF_LENGTH or "\\" in href or ":" in href or "//" in href:
        return None
    normalized = href.lstrip("/")
    if not normalized:
        return None
    if any(part in ("", ".", "..") for part in normalized.split("/")):
        return None
    return SERVICING_ARTICLE_BASE + normalized


def _entry_for(title: str, href: Any, release: str | None) -> ServicingTocEntry | None:
    href_text = str(href or "").strip()
    if not title or not href_text:
        return None
    if _lane_release(title) is not None:
        # A lane heading (e.g. "Windows 11, version 25H2") can itself carry an
        # href to its update-history landing page. That landing page is not a
        # servicing entry; it is skipped the same way an href-less lane node is.
        return None
    return ServicingTocEntry(
        title=title,
        release=release,
        href=href_text,
        url=_resolve_url(href_text),
        kb_article=_extract_kb(title),
        builds=_extract_builds(title),
        preview=_is_preview(title),
        out_of_band=_is_out_of_band(title),
        published=_servicing_entry_date(title, href_text),
    )


def _walk(
    nodes: Sequence[Any],
    release: str | None,
    depth: int,
    entries: list[ServicingTocEntry],
    seen: set[tuple[str, str, str]],
) -> None:
    if depth > _MAX_TOC_DEPTH:
        return
    for node in nodes:
        if not isinstance(node, Mapping):
            continue
        title = str(node.get("toc_title") or "").strip()
        child_release = _lane_release(title) or release
        entry = _entry_for(title, node.get("href"), child_release)
        if entry is not None:
            key = (entry.release or "", entry.href or "", entry.title)
            if key not in seen:
                seen.add(key)
                entries.append(entry)
        _walk(_child_nodes(node.get("children")), child_release, depth + 1, entries, seen)


def parse_servicing_toc(payload: Mapping[str, Any] | str) -> tuple[ServicingTocEntry, ...]:
    document = _document(payload)
    entries: list[ServicingTocEntry] = []
    seen: set[tuple[str, str, str]] = set()
    _walk(_child_nodes(document.get("items")), None, 0, entries, seen)
    return tuple(entries)


__all__ = [
    "SERVICING_ARTICLE_BASE",
    "SERVICING_TOC_URL",
    "ServicingTocEntry",
    "parse_servicing_toc",
]
