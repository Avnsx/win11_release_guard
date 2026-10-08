"""HTML table extraction and row helpers for the Release Health page."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Mapping
from .exceptions import PolicyParseError
from .models import EditionScope, ReleaseHistoryEntry, ReleasePolicyEntry, ServicingChannel


_FIELD_LABELS: Mapping[str, str] = {
    "version": "Version",
    "servicing_option": "Servicing option",
    "latest_build": "Latest build",
    "availability_date": "Availability date",
    "latest_revision_date": "Latest revision date",
    "build": "Build",
    "update_type": "Update type",
    "kb_article": "KB article",
}


_HEADER_ALIASES: Mapping[str, tuple[tuple[str, ...], ...]] = {
    "version": (("version",), ("release",)),
    "servicing_option": (
        ("servicing", "option"),
        ("servicing", "channel"),
        ("service", "option"),
        ("wartungsoption",),
        ("serviceoption",),
        ("wartungskanal",),
    ),
    "latest_build": (
        ("latest", "build"),
        ("latest", "os", "build"),
        ("neuester", "build"),
        ("aktuellster", "build"),
        ("aktuelle", "build"),
    ),
    "availability_date": (
        ("availability", "date"),
        ("available", "date"),
        ("release", "date"),
        ("verfugbarkeitsdatum",),
        ("veroffentlichungsdatum",),
        ("freigabedatum",),
    ),
    "latest_revision_date": (
        ("latest", "revision", "date"),
        ("latest", "revision"),
        ("latest", "revisioned"),
        ("neueste", "revision"),
        ("letzte", "revision"),
        ("revisionsdatum",),
    ),
    "build": (
        ("build",),
        ("os", "build"),
        ("betriebssystembuild",),
        ("betriebssystem", "build"),
    ),
    "update_type": (
        ("update", "type"),
        ("update", "typ"),
        ("updatetyp",),
        ("typ", "update"),
        ("release", "type"),
        ("type",),
    ),
    "kb_article": (
        ("kb", "article"),
        ("kb", "artikel"),
        ("kb",),
    ),
}


@dataclass(frozen=True)
class _Cell:
    text: str
    is_header: bool


@dataclass(frozen=True)
class _Table:
    headings: tuple[str, ...]
    rows: tuple[tuple[_Cell, ...], ...]


@dataclass(frozen=True)
class _CurrentVersionCandidate:
    entry: ReleasePolicyEntry
    table_index: int
    scope: tuple[ServicingChannel, tuple[EditionScope, ...]]
    matched_history_context: bool


@dataclass(frozen=True)
class _CurrentVersionSelection:
    entries: list[ReleasePolicyEntry]
    diagnostics: tuple[dict[str, Any], ...] = ()
    conflicts: tuple[dict[str, Any], ...] = ()


class _ReleaseHealthHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[_Table] = []
        self.headings: list[str] = []
        self.document_text_parts: list[str] = []

        self._in_table = False
        self._table_rows: list[tuple[_Cell, ...]] = []
        self._row_cells: list[_Cell] | None = None
        self._cell_parts: list[str] | None = None
        self._cell_is_header = False

        self._heading_tag: str | None = None
        self._heading_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag == "table":
            self._in_table = True
            self._table_rows = []
            return

        if self._in_table:
            if tag == "tr":
                self._row_cells = []
            elif tag in {"th", "td"}:
                self._cell_parts = []
                self._cell_is_header = tag == "th"
            return

        if tag in {"h1", "h2", "h3", "h4", "h5", "h6", "strong"}:
            self._heading_tag = tag
            self._heading_parts = []

    def handle_data(self, data: str) -> None:
        self.document_text_parts.append(data)
        if self._cell_parts is not None:
            self._cell_parts.append(data)
        elif self._heading_tag is not None:
            self._heading_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()

        if self._in_table:
            if tag in {"th", "td"} and self._cell_parts is not None:
                text = _normalize_text(" ".join(self._cell_parts))
                if self._row_cells is not None:
                    self._row_cells.append(_Cell(text=text, is_header=self._cell_is_header))
                self._cell_parts = None
                self._cell_is_header = False
            elif tag == "tr" and self._row_cells is not None:
                if any(cell.text for cell in self._row_cells):
                    self._table_rows.append(tuple(self._row_cells))
                self._row_cells = None
            elif tag == "table":
                self.tables.append(
                    _Table(
                        headings=tuple(self.headings[-40:]),
                        rows=tuple(self._table_rows),
                    )
                )
                self._in_table = False
                self._table_rows = []
            return

        if self._heading_tag == tag:
            text = _normalize_text(" ".join(self._heading_parts))
            if text:
                self.headings.append(text)
            self._heading_tag = None
            self._heading_parts = []


def _normalize_text(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").replace("\xa0", " ")).strip()


def _fold_text(value: str | None) -> str:
    text = _normalize_text(value).replace("ß", "ss")
    text = unicodedata.normalize("NFKD", text)
    text = "".join(char for char in text if not unicodedata.combining(char))
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _release_key(release: str | None) -> tuple[int, int]:
    if not release:
        return (-1, -1)
    match = re.fullmatch(r"(\d{2})H([12])", release.upper())
    if not match:
        return (-1, -1)
    return int(match.group(1)), int(match.group(2))


def _build_key(build: str | None) -> tuple[int, int]:
    if not build:
        return (-1, -1)
    parts = str(build).split(".")
    try:
        major = int(parts[0])
        revision = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        return (-1, -1)
    return major, revision


def _extract_release(text: str | None) -> str | None:
    match = re.search(r"\b(\d{2}H[12])\b", text or "", flags=re.IGNORECASE)
    return match.group(1).upper() if match else None


def _extract_build_family(build: str | None) -> int | None:
    match = re.search(r"\b(\d{5})(?:\.\d+)?\b", build or "")
    return int(match.group(1)) if match else None


def _field_aliases(field: str, extra_needles: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    if not extra_needles and field in _HEADER_ALIASES:
        return _HEADER_ALIASES[field]
    return ((field, *extra_needles),)


def _header_matches(header: str, field: str, *extra_needles: str) -> bool:
    folded = _fold_text(header)
    return any(
        all(_fold_text(needle) in folded for needle in alias)
        for alias in _field_aliases(field, extra_needles)
    )


def _headers_have(headers: list[str], field: str) -> bool:
    return any(_header_matches(header, field) for header in headers)


def _missing_fields(headers: list[str], required_fields: tuple[str, ...]) -> list[str]:
    return [field for field in required_fields if not _headers_have(headers, field)]


def _row_value(row: Mapping[str, str], *needles: str) -> str | None:
    if not needles:
        return None
    field, *extra = needles
    for key, value in row.items():
        if _header_matches(key, field, *extra):
            return value
    return None


def _table_diagnostics(tables: list[_Table], required_fields: tuple[str, ...]) -> str:
    if not tables:
        return "found 0 tables"
    diagnostics: list[str] = []
    for index, table in enumerate(tables[:8]):
        headers, _rows = _table_rows(table)
        heading = " / ".join(table.headings[-3:]) or "none"
        header_text = " | ".join(headers) or "none"
        missing = ", ".join(_FIELD_LABELS.get(field, field) for field in _missing_fields(headers, required_fields))
        diagnostics.append(
            f"table[{index}] headings={heading!r} headers={header_text!r} missing={missing or 'none'}"
        )
    if len(tables) > 8:
        diagnostics.append(f"{len(tables) - 8} additional tables not shown")
    return "; ".join(diagnostics)


def _dedupe_diagnostics(items: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str | None, str | None, str | None, str | None, str | None]] = set()
    for item in items:
        key = (
            str(item.get("severity")) if item.get("severity") is not None else None,
            str(item.get("kind")) if item.get("kind") is not None else None,
            str(item.get("release")) if item.get("release") is not None else None,
            str(item.get("build")) if item.get("build") is not None else None,
            str(item.get("kb_article")) if item.get("kb_article") is not None else None,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(dict(item))
    return deduped


def _missing_table_error(table_name: str, required_fields: tuple[str, ...], tables: list[_Table]) -> PolicyParseError:
    required = ", ".join(_FIELD_LABELS.get(field, field) for field in required_fields)
    return PolicyParseError(
        f"Could not parse Windows 11 {table_name}: missing table with required headers {required}. "
        f"Scanned {len(tables)} tables: {_table_diagnostics(tables, required_fields)}."
    )


def _table_rows(table: _Table) -> tuple[list[str], list[dict[str, str]]]:
    rows = [row for row in table.rows if row]
    if not rows:
        return [], []

    header_index = 0
    for index, row in enumerate(rows):
        if any(cell.is_header for cell in row):
            header_index = index
            break

    headers = [cell.text for cell in rows[header_index]]
    mapped_rows: list[dict[str, str]] = []
    for row in rows[header_index + 1 :]:
        values = [cell.text for cell in row]
        if not any(values):
            continue
        mapped_rows.append(
            {
                headers[index] if index < len(headers) else f"P{index}": value
                for index, value in enumerate(values)
            }
        )
    return headers, mapped_rows


def _nearest_version_heading(table: _Table) -> tuple[str | None, int | None]:
    for heading in reversed(table.headings):
        match = re.search(
            r"Version\s+(\d{2}H[12])\s+\((?:OS\s*-?\s*build|Betriebssystem\s*-?\s*build|Build)\s+(\d+)\)",
            heading,
            flags=re.IGNORECASE,
        )
        if match:
            return match.group(1).upper(), int(match.group(2))
    return None, None


def _table_context(table: _Table, headers: list[str]) -> str:
    return _fold_text(" | ".join((*table.headings, *headers)))


def _row_context(row: Mapping[str, str]) -> str:
    return _fold_text(" | ".join(str(value) for value in row.values()))


def _servicing_context_is_plausible(value: str | None) -> bool:
    folded = _fold_text(value)
    if not folded:
        return False
    needles = (
        "general availability",
        "availability channel",
        "servicing channel",
        "long term",
        "ltsc",
        "ltsb",
        "hotpatch",
        "hot patch",
        "allgemein",
        "verfugbar",
        "wartung",
        "service",
    )
    return any(needle in folded for needle in needles)


def _update_type_is_plausible(value: str | None) -> bool:
    folded = _fold_text(value)
    return bool(
        folded
        and (
            re.search(r"\b(?:oob|[a-d])\b", folded)
            or re.search(r"\b20\d{2}\s+\d{2}\b", folded)
            or "preview" in folded
            or "vorschau" in folded
        )
    )


def _classify_current_version_table(
    table: _Table,
    headers: list[str],
    row: Mapping[str, str],
) -> tuple[ServicingChannel, tuple[EditionScope, ...]]:
    blob = f"{_table_context(table, headers)} | {_row_context(row)}"
    if "hotpatch" in blob or "hot patch" in blob:
        return ServicingChannel.HOTPATCH, (EditionScope.ENTERPRISE_EDUCATION,)
    if "long-term" in blob or "long term" in blob or "ltsc" in blob or "ltsb" in blob:
        return (
            ServicingChannel.LTSC,
            (EditionScope.ENTERPRISE_LTSC, EditionScope.IOT_ENTERPRISE_LTSC),
        )
    return (
        ServicingChannel.GENERAL_AVAILABILITY,
        (EditionScope.HOME_PRO, EditionScope.ENTERPRISE_EDUCATION),
    )


def _history_contexts(release_history: list[ReleaseHistoryEntry]) -> set[tuple[str, int]]:
    return {(row.release, row.build_family) for row in release_history}


def _current_candidate_key(
    candidate: _CurrentVersionCandidate,
) -> tuple[str, int, ServicingChannel, tuple[EditionScope, ...]]:
    return (
        candidate.entry.version,
        candidate.entry.build_family,
        candidate.entry.servicing_channel,
        candidate.entry.edition_scopes,
    )


def _current_candidate_table_contexts(
    candidates: list[_CurrentVersionCandidate],
) -> dict[tuple[int, tuple[ServicingChannel, tuple[EditionScope, ...]]], set[tuple[str, int]]]:
    contexts: dict[tuple[int, tuple[ServicingChannel, tuple[EditionScope, ...]]], set[tuple[str, int]]] = {}
    for candidate in candidates:
        key = (candidate.table_index, candidate.scope)
        contexts.setdefault(key, set()).add((candidate.entry.version, candidate.entry.build_family))
    return contexts


def _candidate_is_superseded_by_broader_table(
    candidate: _CurrentVersionCandidate,
    table_contexts: Mapping[tuple[int, tuple[ServicingChannel, tuple[EditionScope, ...]]], set[tuple[str, int]]],
) -> bool:
    candidate_table_key = (candidate.table_index, candidate.scope)
    candidate_context = table_contexts.get(candidate_table_key, set())
    row_context = (candidate.entry.version, candidate.entry.build_family)
    if not candidate_context:
        return False
    for table_key, contexts in table_contexts.items():
        if table_key == candidate_table_key or table_key[1] != candidate.scope:
            continue
        if row_context in contexts and candidate_context < contexts:
            return True
    return False


def _current_conflict_diagnostic(
    *,
    key: tuple[str, int, ServicingChannel, tuple[EditionScope, ...]],
    candidates: list[_CurrentVersionCandidate],
) -> dict[str, Any]:
    builds = sorted({candidate.entry.latest_build for candidate in candidates if candidate.entry.latest_build})
    table_indexes = sorted({candidate.table_index for candidate in candidates})
    return {
        "severity": "warning",
        "kind": "current_versions_candidate_conflict",
        "release": key[0],
        "build_family": key[1],
        "builds": builds,
        "table_indexes": table_indexes,
        "message": (
            "Multiple Current Versions candidates describe the same release/build-family context "
            f"with different latest_build values: {', '.join(builds)}."
        ),
    }
