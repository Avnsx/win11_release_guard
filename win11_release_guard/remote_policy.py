from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Mapping

from .config import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    DEFAULT_POLICY_URL,
    DEFAULT_PUBLISHED_POLICY_URLS,
    DEFAULT_RELEASE_HEALTH_URL,
)
from .exceptions import PolicyError, PolicyFetchError, PolicyParseError
from . import http_client
from .json_utils import DEFAULT_MAX_POLICY_BYTES, StrictJSONError, strict_json_object
from .models import (
    EditionScope,
    QualityPolicy,
    ReleaseHistoryEntry,
    ReleasePolicy,
    ReleasePolicyEntry,
    ServicingChannel,
)
from .policy_schema import SUPPORTED_POLICY_SCHEMA_VERSION, is_source_diagnostic_id


HttpGet = Callable[..., Any]
_RELEASE_PATTERN = re.compile(r"^\d{2}H[12]$", re.IGNORECASE)
_BUILD_PATTERN = re.compile(r"^\d{5}\.\d+$")
_CURRENT_VERSION_REQUIRED_FIELDS = ("version", "servicing_option", "latest_build")
_RELEASE_HISTORY_REQUIRED_FIELDS = ("update_type", "build")
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


def _parse_current_versions(
    tables: list[_Table],
    release_history: list[ReleaseHistoryEntry],
) -> _CurrentVersionSelection:
    candidates: list[_CurrentVersionCandidate] = []
    history_contexts = _history_contexts(release_history)

    for table_index, table in enumerate(tables):
        headers, rows = _table_rows(table)
        if _missing_fields(headers, _CURRENT_VERSION_REQUIRED_FIELDS):
            continue

        for row in rows:
            release = _extract_release(_row_value(row, "version"))
            latest_build = _row_value(row, "latest_build")
            build_family = _extract_build_family(latest_build)
            servicing_option = _row_value(row, "servicing_option")
            if (
                not release
                or build_family is None
                or not latest_build
                or not _BUILD_PATTERN.fullmatch(latest_build)
                or not _servicing_context_is_plausible(servicing_option)
            ):
                continue

            servicing_channel, edition_scopes = _classify_current_version_table(table, headers, row)
            scope = (servicing_channel, edition_scopes)
            candidates.append(
                _CurrentVersionCandidate(
                    entry=ReleasePolicyEntry(
                        version=release,
                        build_family=build_family,
                        latest_build=latest_build,
                        servicing_option=servicing_option,
                        availability_date=_row_value(row, "availability_date"),
                        edition_scopes=edition_scopes,
                        servicing_channel=servicing_channel,
                        metadata={
                            "home_pro_end": (
                                _row_value(row, "home")
                                or _row_value(row, "end", "updates")
                            ),
                            "enterprise_education_end": _row_value(row, "enterprise")
                            or _row_value(row, "education"),
                            "ltsc_end": _row_value(row, "ltsc")
                            or _row_value(row, "long-term")
                            or _row_value(row, "iot"),
                            "latest_revision_date": _row_value(row, "latest_revision_date"),
                            "raw": dict(row),
                        },
                    ),
                    table_index=table_index,
                    scope=scope,
                    matched_history_context=(release, build_family) in history_contexts,
                )
            )

    if not candidates:
        return _CurrentVersionSelection(entries=[])

    table_contexts = _current_candidate_table_contexts(candidates)
    filtered: list[_CurrentVersionCandidate] = []
    diagnostics: list[dict[str, Any]] = []
    for candidate in candidates:
        if _candidate_is_superseded_by_broader_table(candidate, table_contexts):
            diagnostics.append(
                {
                    "severity": "notice",
                    "kind": "ignored_current_versions_subset_table",
                    "release": candidate.entry.version,
                    "build_family": candidate.entry.build_family,
                    "build": candidate.entry.latest_build,
                    "table_index": candidate.table_index,
                    "message": (
                        "Ignored a Current Versions candidate from a narrower table because another "
                        "same-scope table covers a broader matching Release History structure."
                    ),
                }
            )
            continue
        filtered.append(candidate)

    grouped: dict[tuple[str, int, ServicingChannel, tuple[EditionScope, ...]], list[_CurrentVersionCandidate]] = {}
    for candidate in filtered:
        grouped.setdefault(_current_candidate_key(candidate), []).append(candidate)

    current_versions: list[ReleasePolicyEntry] = []
    conflicts: list[dict[str, Any]] = []
    for key, group in grouped.items():
        pool = [candidate for candidate in group if candidate.matched_history_context] or group
        builds = {candidate.entry.latest_build for candidate in pool if candidate.entry.latest_build}
        if len(builds) > 1:
            diagnostic = _current_conflict_diagnostic(key=key, candidates=pool)
            diagnostics.append(diagnostic)
            conflicts.append(diagnostic)
        current_versions.append(pool[0].entry)

    return _CurrentVersionSelection(
        entries=current_versions,
        diagnostics=tuple(_dedupe_diagnostics(diagnostics)),
        conflicts=tuple(_dedupe_diagnostics(conflicts)),
    )


def _parse_release_history(tables: list[_Table]) -> list[ReleaseHistoryEntry]:
    release_history: list[ReleaseHistoryEntry] = []

    for table in tables:
        release, build_family = _nearest_version_heading(table)
        if not release or build_family is None:
            continue

        headers, rows = _table_rows(table)
        if _missing_fields(headers, _RELEASE_HISTORY_REQUIRED_FIELDS):
            continue

        for row in rows:
            build = _row_value(row, "build")
            if not build or not re.match(r"^\d+\.\d+$", build):
                continue

            update_type = _row_value(row, "update_type") or ""
            if not _update_type_is_plausible(update_type):
                continue
            update_type_match = re.search(r"\b(OOB|[A-D])\b", update_type.upper())
            update_type_letter = update_type_match.group(1) if update_type_match else None
            kb_article = (
                _row_value(row, "kb", "article")
                or _row_value(row, "kb")
            )

            release_history.append(
                ReleaseHistoryEntry(
                    release=release,
                    build_family=build_family,
                    build=build,
                    availability_date=_row_value(row, "availability_date"),
                    servicing_option=_row_value(row, "servicing_option"),
                    update_type=update_type,
                    update_type_letter=update_type_letter,
                    preview=update_type_letter == "D",
                    out_of_band=update_type_letter == "OOB",
                    kb_article=kb_article,
                    kb_url=_kb_url(kb_article),
                    catalog_url=_catalog_url(kb_article),
                    metadata={"raw": dict(row)},
                )
            )

    return release_history


def _detect_special_release_reasons(document_text: str) -> dict[str, str]:
    reasons: dict[str, str] = {}
    text = _normalize_text(document_text)

    sentences = re.split(r"(?<=[.!?])\s+", text)
    for sentence in sentences:
        sentence_l = _fold_text(sentence)
        if (
            "new devices" in sentence_l
            and "existing devices" in sentence_l
            and (
                "not designed as a feature update" in sentence_l
                or "not offered as an in-place update" in sentence_l
                or "not designed as a feature" in sentence_l
            )
        ):
            for release in re.findall(r"\b(\d{2}H[12])\b", sentence, flags=re.IGNORECASE):
                normalized_release = release.upper()
                if f"version {normalized_release.lower()}" in sentence_l:
                    reasons[normalized_release] = sentence

    for match in re.finditer(r"\b(\d{2}H[12])\b", text, flags=re.IGNORECASE):
        normalized_release = match.group(1).upper()
        if normalized_release in reasons:
            continue
        context = text[max(0, match.start() - 240) : min(len(text), match.end() + 420)]
        context_l = _fold_text(context)
        subject_window = text[max(0, match.start() - 80) : min(len(text), match.end() + 120)]
        subject_window_l = _fold_text(subject_window)
        release_subject = f"version {normalized_release.lower()}"
        mentions_release_as_subject = (
            f"windows 11 {release_subject}" in subject_window_l
            or f"windows 11 release {normalized_release.lower()}" in subject_window_l
        )
        has_new_devices = "new devices" in context_l or "neue gerate" in context_l
        has_existing_devices = "existing devices" in context_l or "bestehende gerate" in context_l
        has_not_feature_update = (
            "not designed as a feature update" in context_l
            or "not offered as an in place update" in context_l
            or "nicht als funktionsupdate" in context_l
            or "nicht als feature update" in context_l
            or "nicht als direktes update" in context_l
            or "nicht angeboten" in context_l
        )
        if mentions_release_as_subject and has_new_devices and has_existing_devices and has_not_feature_update:
            reasons[normalized_release] = _normalize_text(context)

    return reasons


def _with_special_metadata(entry: ReleasePolicyEntry, reason: str) -> ReleasePolicyEntry:
    metadata = dict(entry.metadata)
    metadata.update(
        {
            "special_release": True,
            "new_devices_only": True,
            "not_broad_target": True,
            "not_broad_target_existing_devices": True,
        }
    )
    return replace(
        entry,
        reason=reason,
        metadata=metadata,
    )


def _is_ga_entry(entry: ReleasePolicyEntry) -> bool:
    if entry.servicing_channel is ServicingChannel.GENERAL_AVAILABILITY:
        return True
    servicing = _fold_text(entry.servicing_option)
    return "general availability" in servicing or "allgemein" in servicing


def _is_supported_for_home_pro(entry: ReleasePolicyEntry) -> bool:
    home_pro_end = _fold_text(str(entry.metadata.get("home_pro_end") or ""))
    return "end of updates" not in home_pro_end and "ende der updates" not in home_pro_end


def _kb_url(kb_article: str | None) -> str | None:
    if not kb_article or kb_article.upper() == "N/A":
        return None
    match = re.search(r"KB(\d{6,8})", kb_article, flags=re.IGNORECASE)
    if not match:
        return None
    return f"https://support.microsoft.com/help/{match.group(1)}"


def _catalog_url(kb_article: str | None) -> str | None:
    if not kb_article or kb_article.upper() == "N/A":
        return None
    match = re.search(r"KB\d{6,8}", kb_article, flags=re.IGNORECASE)
    if not match:
        return None
    return f"https://www.catalog.update.microsoft.com/Search.aspx?q={match.group(0).upper()}"


def _select_broad_target(
    current_versions: list[ReleasePolicyEntry],
    special_versions: set[str],
) -> ReleasePolicyEntry:
    candidates = [
        entry
        for entry in current_versions
        if entry.version not in special_versions
        and _is_ga_entry(entry)
        and _is_supported_for_home_pro(entry)
    ]
    if not candidates:
        raise PolicyParseError(
            "Could not select broad_target_existing_devices: no supported Windows 11 GA target candidate found."
        )

    h2_candidates = [entry for entry in candidates if entry.version.endswith("H2")]
    if h2_candidates:
        candidates = h2_candidates

    return max(candidates, key=lambda entry: _release_key(entry.version))


def _validate_special_release_notes(
    current_versions: list[ReleasePolicyEntry],
    special_reasons: Mapping[str, str],
) -> None:
    current_release_versions = {entry.version for entry in current_versions}
    if "26H1" in current_release_versions and "26H1" not in special_reasons:
        raise PolicyParseError(
            "Suspicious Microsoft Release Health source shape: current_versions contains 26H1, "
            "but the parser did not find the 26H1 new-devices-only special release note."
        )


def _select_quality_baseline(
    release_history: list[ReleaseHistoryEntry],
    target_release: str,
    quality_policy: QualityPolicy = QualityPolicy.B_RELEASE_ONLY,
) -> ReleaseHistoryEntry | None:
    rows = [row for row in release_history if row.release == target_release.upper()]
    if not rows:
        return None

    if quality_policy is QualityPolicy.B_RELEASE_ONLY:
        filtered = [row for row in rows if row.update_type_letter == "B"]
    elif quality_policy is QualityPolicy.LATEST_NON_PREVIEW:
        filtered = [row for row in rows if not row.preview]
    else:
        filtered = rows

    if not filtered and quality_policy is QualityPolicy.B_RELEASE_ONLY:
        return None
    if not filtered:
        filtered = rows

    return max(
        filtered,
        key=lambda row: (
            row.availability_date or "",
            _build_key(row.build),
        ),
    )


def _conflict_matches_entry(conflict: Mapping[str, Any], entry: ReleasePolicyEntry) -> bool:
    try:
        build_family = int(conflict.get("build_family"))
    except (TypeError, ValueError):
        return False
    return str(conflict.get("release") or "").upper() == entry.version and build_family == entry.build_family


def _current_versions_with_quality_baselines(
    current_versions: list[ReleasePolicyEntry],
    release_history: list[ReleaseHistoryEntry],
) -> list[ReleasePolicyEntry]:
    enriched: list[ReleasePolicyEntry] = []
    for entry in current_versions:
        baseline = _select_quality_baseline(
            release_history,
            entry.version,
            QualityPolicy.B_RELEASE_ONLY,
        )
        if baseline is None:
            enriched.append(entry)
            continue
        enriched.append(
            replace(
                entry,
                baseline_build=baseline.build,
                required_baseline_build=baseline.build,
            )
        )
    return enriched


def _looks_like_json(text: str) -> bool:
    stripped = text.lstrip("\ufeff\r\n\t ")
    return stripped.startswith("{") or stripped.startswith("[")


def _looks_like_html(text: str) -> bool:
    stripped = text.lstrip("\ufeff\r\n\t ").lower()
    return stripped.startswith("<!doctype html") or stripped.startswith("<html") or "<html" in stripped[:500]


def _parse_iso_datetime(value: str, field: str) -> None:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyParseError(f"{field} must be an ISO 8601 timestamp.") from exc


def _require_mapping(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key)
    if not isinstance(value, Mapping):
        raise PolicyParseError(f"JSON policy is missing required object '{key}'.")
    return value


def _require_sequence(data: Mapping[str, Any], key: str) -> list[Any]:
    value = data.get(key)
    if not isinstance(value, list) or not value:
        raise PolicyParseError(f"JSON policy is missing required non-empty list '{key}'.")
    return value


def _normalize_published_urls(value: Any) -> dict[str, str]:
    if value in (None, {}):
        return dict(DEFAULT_PUBLISHED_POLICY_URLS)
    if not isinstance(value, Mapping):
        raise PolicyParseError("JSON policy field 'published_urls' must be an object.")
    normalized: dict[str, str] = {}
    for key, url in value.items():
        if not isinstance(url, str) or not url:
            raise PolicyParseError(f"published_urls.{key} must be a non-empty URL string.")
        normalized[str(key)] = url
    return normalized


def _source_url_is_listed(
    source_url: str | None,
    *,
    source_urls: list[Any],
    published_urls: Mapping[str, str],
) -> bool:
    if not source_url or not _is_url(source_url):
        return True
    upstream_urls = {str(url) for url in source_urls if isinstance(url, str)}
    public_urls = {str(url) for url in published_urls.values()}
    return source_url in upstream_urls or source_url in public_urls


def _validate_release(value: Any, field: str) -> str:
    release = str(value or "").upper()
    if not _RELEASE_PATTERN.fullmatch(release):
        raise PolicyParseError(f"{field} must be a release string like 25H2.")
    return release


def _validate_build_family(value: Any, field: str) -> int:
    try:
        build_family = int(value)
    except (TypeError, ValueError) as exc:
        raise PolicyParseError(f"{field} must be a build family integer.") from exc
    if build_family < 10000:
        raise PolicyParseError(f"{field} must be a Windows build family.")
    return build_family


def _validate_build(value: Any, field: str, *, required: bool = False) -> str | None:
    if value in (None, ""):
        if required:
            raise PolicyParseError(f"{field} is required.")
        return None
    build = str(value)
    if not _BUILD_PATTERN.fullmatch(build):
        raise PolicyParseError(f"{field} must be a full build string like 26200.8457.")
    return build


def _build_key(value: str) -> tuple[int, int]:
    major, minor = value.split(".", 1)
    return int(major), int(minor)


def _validate_latest_observed_build(
    latest_build: str | None,
    latest_observed_build: str | None,
    field: str,
) -> None:
    if latest_build is None or latest_observed_build is None:
        return
    if _build_key(latest_observed_build) < _build_key(latest_build):
        raise PolicyParseError(f"{field} must not be older than latest_build.")


def _entry_has_explicit_baseline(data: Mapping[str, Any], target: Mapping[str, Any]) -> bool:
    if _validate_build(target.get("baseline_build"), "broad_target_existing_devices.baseline_build"):
        return True
    if _validate_build(target.get("required_baseline_build"), "broad_target_existing_devices.required_baseline_build"):
        return True
    if _validate_build(data.get("baseline_build"), "baseline_build"):
        return True
    quality_baseline = data.get("quality_baseline")
    if isinstance(quality_baseline, Mapping):
        if _validate_build(quality_baseline.get("build"), "quality_baseline.build"):
            return True
    return bool(_validate_build(target.get("latest_build"), "broad_target_existing_devices.latest_build"))


def _optional_int(data: Mapping[str, Any], key: str) -> int | None:
    value = data.get(key)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise PolicyParseError(f"{key} must be an integer.") from exc


def _compatibility_warnings(data: Mapping[str, Any], allowed_keys: set[str]) -> list[str]:
    warnings: list[str] = []
    min_reader = _optional_int(data, "min_reader_schema_version")
    max_reader = _optional_int(data, "max_reader_schema_version")
    if min_reader is not None and min_reader > SUPPORTED_POLICY_SCHEMA_VERSION:
        raise PolicyParseError(
            f"Policy requires reader schema_version {min_reader}; "
            f"this reader supports {SUPPORTED_POLICY_SCHEMA_VERSION}."
        )
    if max_reader is not None and max_reader < SUPPORTED_POLICY_SCHEMA_VERSION:
        raise PolicyParseError(
            f"Policy max_reader_schema_version {max_reader} excludes this reader "
            f"schema_version {SUPPORTED_POLICY_SCHEMA_VERSION}."
        )
    if min_reader is not None and max_reader is not None and min_reader > max_reader:
        raise PolicyParseError("min_reader_schema_version must not exceed max_reader_schema_version.")
    api_version = data.get("api_version")
    if api_version is not None and (not isinstance(api_version, str) or not api_version):
        raise PolicyParseError("api_version must be a non-empty string.")
    compatibility = data.get("compatibility")
    if compatibility is not None and not isinstance(compatibility, Mapping):
        raise PolicyParseError("compatibility must be an object.")
    extensions = data.get("extensions")
    if extensions is not None and not isinstance(extensions, Mapping):
        raise PolicyParseError("extensions must be an object.")

    unknown_keys = sorted(
        str(key)
        for key in data.keys()
        if key not in allowed_keys and not str(key).startswith("x_")
    )
    warnings.extend(
        f"Policy compatibility warning: unknown top-level key {key!r} ignored by this reader."
        for key in unknown_keys
    )
    return warnings


def _validate_source_diagnostic_ids(data: Mapping[str, Any]) -> None:
    source_diagnostics = data.get("source_diagnostics")
    if source_diagnostics is None:
        return
    if not isinstance(source_diagnostics, Mapping):
        raise PolicyParseError("source_diagnostics must be an object.")

    events = source_diagnostics.get("events")
    if events is not None:
        if not isinstance(events, list):
            raise PolicyParseError("source_diagnostics.events must be a list.")
        seen_event_ids: set[str] = set()
        for index, event in enumerate(events):
            if not isinstance(event, Mapping):
                raise PolicyParseError(f"source_diagnostics.events[{index}] must be an object.")
            diagnostic_id = event.get("id")
            if diagnostic_id is not None and not is_source_diagnostic_id(diagnostic_id):
                raise PolicyParseError(
                    f"source_diagnostics.events[{index}].id must be a source diagnostic id."
                )
            if isinstance(diagnostic_id, str):
                if diagnostic_id in seen_event_ids:
                    raise PolicyParseError("source_diagnostics.events ids must be unique.")
                seen_event_ids.add(diagnostic_id)

    issue_status = source_diagnostics.get("issue_status")
    if issue_status is not None:
        if not isinstance(issue_status, Mapping):
            raise PolicyParseError("source_diagnostics.issue_status must be an object.")
        for diagnostic_id in issue_status:
            if not is_source_diagnostic_id(diagnostic_id):
                raise PolicyParseError("source_diagnostics.issue_status keys must be source diagnostic ids.")


def _normalize_json_policy_data(
    data: Mapping[str, Any],
    *,
    source_url: str | None = None,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    warnings = [str(warning) for warning in data.get("validation_warnings", [])]
    allowed_keys = {
        "schema_version",
        "generated_at_utc",
        "source",
        "source_urls",
        "published_urls",
        "generator_version",
        "source_fetch_status",
        "source_diagnostics",
        "quality_policy",
        "current_versions",
        "release_history",
        "supported_build_families",
        "broad_target_existing_devices",
        "excluded_for_existing_devices",
        "special_releases",
        "supported_releases",
        "quality_baselines",
        "quality_baseline",
        "baseline_build",
        "preview_builds",
        "out_of_band_builds",
        "known_notes",
        "validation_warnings",
        "metadata",
        "min_reader_schema_version",
        "max_reader_schema_version",
        "api_version",
        "compatibility",
        "extensions",
    }
    warnings.extend(_compatibility_warnings(data, allowed_keys))

    schema_version = data.get("schema_version")
    if schema_version is None:
        raise PolicyParseError("JSON policy is missing required field 'schema_version'.")
    try:
        schema_version_int = int(schema_version)
    except (TypeError, ValueError) as exc:
        raise PolicyParseError("schema_version must be an integer.") from exc
    if schema_version_int != SUPPORTED_POLICY_SCHEMA_VERSION:
        raise PolicyParseError(
            f"Unsupported policy schema_version {schema_version_int}; "
            f"supported version is {SUPPORTED_POLICY_SCHEMA_VERSION}."
        )

    generated_at = data.get("generated_at_utc")
    if not isinstance(generated_at, str) or not generated_at:
        raise PolicyParseError("JSON policy is missing required field 'generated_at_utc'.")
    _parse_iso_datetime(generated_at, "generated_at_utc")

    source_urls = data.get("source_urls")
    if not isinstance(source_urls, list) or not source_urls or not all(isinstance(url, str) and url for url in source_urls):
        raise PolicyParseError("JSON policy is missing required non-empty list 'source_urls'.")
    published_urls = _normalize_published_urls(data.get("published_urls"))
    if not _source_url_is_listed(
        source_url,
        source_urls=source_urls,
        published_urls=published_urls,
    ):
        warnings.append("Loaded policy URL is not listed in published_urls or source_urls.")
    _validate_source_diagnostic_ids(data)

    current_versions = _require_sequence(data, "current_versions")
    normalized_current_versions: list[Mapping[str, Any]] = []
    target_version_counts: dict[str, set[int]] = {}
    for index, item in enumerate(current_versions):
        if not isinstance(item, Mapping):
            raise PolicyParseError(f"current_versions[{index}] must be an object.")
        release = _validate_release(item.get("version"), f"current_versions[{index}].version")
        build_family = _validate_build_family(item.get("build_family"), f"current_versions[{index}].build_family")
        latest_build = _validate_build(item.get("latest_build"), f"current_versions[{index}].latest_build")
        latest_observed = _validate_build(
            item.get("latest_observed_build"),
            f"current_versions[{index}].latest_observed_build",
        )
        _validate_latest_observed_build(
            latest_build,
            latest_observed,
            f"current_versions[{index}].latest_observed_build",
        )
        baseline_build = _validate_build(item.get("baseline_build"), f"current_versions[{index}].baseline_build")
        required_baseline = _validate_build(
            item.get("required_baseline_build"),
            f"current_versions[{index}].required_baseline_build",
        )
        if baseline_build and required_baseline and required_baseline != baseline_build:
            raise PolicyParseError(f"current_versions[{index}].required_baseline_build must match baseline_build.")
        target_version_counts.setdefault(release, set()).add(build_family)
        normalized_current_versions.append(item)

    supported_build_families = data.get("supported_build_families")
    if not isinstance(supported_build_families, Mapping) or not supported_build_families:
        raise PolicyParseError("JSON policy is missing required object 'supported_build_families'.")
    normalized_supported: dict[str, str] = {}
    for raw_build_family, raw_release in supported_build_families.items():
        build_family = _validate_build_family(raw_build_family, "supported_build_families key")
        normalized_supported[str(build_family)] = _validate_release(
            raw_release,
            f"supported_build_families[{raw_build_family!r}]",
        )

    broad_target = _require_mapping(data, "broad_target_existing_devices")
    target_release = _validate_release(
        broad_target.get("version"),
        "broad_target_existing_devices.version",
    )
    target_build_family = _validate_build_family(
        broad_target.get("build_family"),
        "broad_target_existing_devices.build_family",
    )
    target_latest_build = _validate_build(broad_target.get("latest_build"), "broad_target_existing_devices.latest_build")
    target_latest_observed = _validate_build(
        broad_target.get("latest_observed_build"),
        "broad_target_existing_devices.latest_observed_build",
    )
    _validate_latest_observed_build(
        target_latest_build,
        target_latest_observed,
        "broad_target_existing_devices.latest_observed_build",
    )
    target_baseline_build = _validate_build(
        broad_target.get("baseline_build"),
        "broad_target_existing_devices.baseline_build",
    )
    target_required_baseline = _validate_build(
        broad_target.get("required_baseline_build"),
        "broad_target_existing_devices.required_baseline_build",
    )
    if target_baseline_build and target_required_baseline and target_required_baseline != target_baseline_build:
        raise PolicyParseError("broad_target_existing_devices.required_baseline_build must match baseline_build.")

    if str(target_build_family) not in normalized_supported:
        raise PolicyParseError("broad_target_existing_devices build family is missing from supported_build_families.")
    if not any(
        item.get("version", "").upper() == target_release
        and int(item.get("build_family")) == target_build_family
        for item in normalized_current_versions
    ):
        raise PolicyParseError("broad_target_existing_devices is missing from current_versions.")

    matching_families = target_version_counts.get(target_release, set())
    if len(matching_families) > 1 and not any("ambiguous" in warning.lower() for warning in warnings):
        raise PolicyParseError("Ambiguous target selection without explicit warning.")

    release_history = data.get("release_history")
    if isinstance(release_history, list) and release_history:
        for index, item in enumerate(release_history):
            if not isinstance(item, Mapping):
                raise PolicyParseError(f"release_history[{index}] must be an object.")
            _validate_release(item.get("release"), f"release_history[{index}].release")
            _validate_build_family(item.get("build_family"), f"release_history[{index}].build_family")
            _validate_build(item.get("build"), f"release_history[{index}].build", required=True)
    elif _entry_has_explicit_baseline(data, broad_target):
        warnings.append("release_history is missing; using explicit quality baseline fields.")
    else:
        raise PolicyParseError("JSON policy requires release_history or explicit quality baseline fields.")

    normalized = dict(data)
    normalized["schema_version"] = schema_version_int
    normalized["supported_build_families"] = normalized_supported
    normalized["source_urls"] = list(source_urls)
    normalized["published_urls"] = dict(published_urls)
    if source_url:
        source = dict(normalized.get("source") or {})
        source["policy_url"] = source_url
        normalized["source"] = source
    normalized["validation_warnings"] = list(dict.fromkeys(warnings))
    return normalized, tuple(normalized["validation_warnings"])


def _load_json_policy(
    text: str,
    *,
    source_url: str | None = None,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> ReleasePolicy:
    try:
        data = strict_json_object(text, label="JSON policy", max_bytes=max_bytes)
    except StrictJSONError as exc:
        raise PolicyParseError(f"Malformed JSON policy: {exc}") from exc

    normalized, warnings = _normalize_json_policy_data(data, source_url=source_url)
    try:
        policy = ReleasePolicy.from_dict(normalized)
    except (TypeError, ValueError, KeyError) as exc:
        raise PolicyParseError(f"JSON policy schema is invalid: {exc}") from exc

    return replace(policy, validation_warnings=warnings)


def _load_policy_text(
    text: str,
    *,
    content_type: str | None = None,
    source_url: str | None = None,
    allow_html_fallback: bool = False,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> ReleasePolicy:
    content_type_l = (content_type or "").lower()

    if "application/json" in content_type_l or _looks_like_json(text):
        return _load_json_policy(text, source_url=source_url, max_bytes=max_bytes)

    if "text/html" in content_type_l or _looks_like_html(text):
        if not allow_html_fallback:
            raise PolicyParseError("HTML policy source is not allowed in runtime mode.")
        policy = parse_windows11_release_health_html(text)
        if source_url:
            source = dict(policy.source)
            source["release_health_url"] = source_url
            source["policy_url"] = source_url
            policy = replace(policy, source=source)
        return policy

    raise PolicyParseError("Policy source is neither JSON nor HTML.")


def load_policy_text(
    text: str,
    *,
    source_url: str | None = None,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> ReleasePolicy:
    return _load_policy_text(text, source_url=source_url, max_bytes=max_bytes)


def load_policy_bytes(
    data: bytes,
    *,
    content_type: str | None = None,
    source_url: str | None = None,
    allow_html_fallback: bool = False,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> ReleasePolicy:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PolicyParseError("Policy bytes are not valid UTF-8.") from exc
    return _load_policy_text(
        text,
        content_type=content_type,
        source_url=source_url,
        allow_html_fallback=allow_html_fallback,
        max_bytes=max_bytes,
    )


def parse_windows11_release_health_html(html: str) -> ReleasePolicy:
    parser = _ReleaseHealthHtmlParser()
    parser.feed(html)
    parser.close()

    release_history = _parse_release_history(parser.tables)
    if not release_history:
        raise _missing_table_error(
            "release_history tables",
            _RELEASE_HISTORY_REQUIRED_FIELDS,
            parser.tables,
        )
    current_selection = _parse_current_versions(parser.tables, release_history)
    current_versions = current_selection.entries
    parser_diagnostics = list(current_selection.diagnostics)
    if not current_versions:
        raise _missing_table_error(
            "current_versions table",
            _CURRENT_VERSION_REQUIRED_FIELDS,
            parser.tables,
        )
    current_versions = _current_versions_with_quality_baselines(current_versions, release_history)

    special_reasons = _detect_special_release_reasons(" ".join(parser.document_text_parts))
    _validate_special_release_notes(current_versions, special_reasons)
    special_versions = set(special_reasons)
    special_entries = tuple(
        _with_special_metadata(entry, special_reasons[entry.version])
        for entry in current_versions
        if entry.version in special_versions
    )

    broad_target = _select_broad_target(current_versions, special_versions)
    if broad_target is None:
        raise PolicyParseError("Could not select broad_target_existing_devices from Release Health HTML.")
    for conflict in current_selection.conflicts:
        if _conflict_matches_entry(conflict, broad_target):
            raise PolicyParseError(
                "Conflicting Current Versions candidates make broad_target_existing_devices ambiguous: "
                f"{conflict.get('message')}"
            )
    baseline = _select_quality_baseline(
        release_history,
        broad_target.version,
        QualityPolicy.B_RELEASE_ONLY,
    )
    if baseline is None:
        raise PolicyParseError(
            "Could not select B-release required baseline for broad_target_existing_devices "
            f"{broad_target.version}/{broad_target.build_family} from Release Health release_history."
        )
    broad_target = replace(
        broad_target,
        baseline_build=baseline.build,
        required_baseline_build=baseline.build,
    )

    return ReleasePolicy(
        generated_at_utc=datetime.now(timezone.utc).isoformat(),
        source={
            "type": "microsoft_windows11_release_health_html",
            "release_health_url": DEFAULT_RELEASE_HEALTH_URL,
            "graph_enriched": False,
        },
        quality_policy=QualityPolicy.B_RELEASE_ONLY,
        broad_target_existing_devices=broad_target,
        current_versions=tuple(current_versions),
        release_history=tuple(release_history),
        special_releases=special_entries,
        supported_releases=tuple(current_versions),
        excluded_for_existing_devices=special_entries,
        source_diagnostics={
            "parser": {
                "events": parser_diagnostics,
            }
        },
        metadata={
            "parser": "stdlib_html_parser",
            "special_release_versions": sorted(special_versions),
            "parser_diagnostics": parser_diagnostics,
        },
    )


def _payload_too_large_message(label: str, max_bytes: int) -> str:
    return f"{label} is too large: exceeds safety cap of {max_bytes} bytes."


def _content_length_from_headers(headers: Any) -> int | None:
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


def _declared_content_length(response: Any) -> int | None:
    return _content_length_from_headers(getattr(response, "headers", None))


def _ensure_payload_size(data: bytes, *, max_bytes: int, label: str) -> None:
    if len(data) > max_bytes:
        raise PolicyFetchError(_payload_too_large_message(label, max_bytes))


def _read_limited_response(response: Any, *, max_bytes: int, label: str) -> bytes:
    declared_length = _declared_content_length(response)
    if declared_length is not None and declared_length > max_bytes:
        raise PolicyFetchError(_payload_too_large_message(label, max_bytes))
    try:
        data = response.read(max_bytes + 1)
    except TypeError as exc:
        raise PolicyFetchError(f"{label} reader does not support bounded reads.") from exc
    if isinstance(data, str):
        encoded = data.encode("utf-8")
        _ensure_payload_size(encoded, max_bytes=max_bytes, label=label)
        return encoded
    if isinstance(data, bytes):
        _ensure_payload_size(data, max_bytes=max_bytes, label=label)
        return data
    raise PolicyFetchError("Release policy fetcher returned an unsupported response type.")


def _default_http_get(url: str, timeout: float, *, max_bytes: int = DEFAULT_MAX_POLICY_BYTES) -> bytes:
    result = http_client.request(
        url,
        headers={"Accept": "application/json,text/html,application/xhtml+xml"},
        timeout=timeout,
        max_bytes=max_bytes,
        label="Release policy response",
    )
    return result.content


def _call_http_get(http_get: HttpGet, url: str, timeout: float) -> Any:
    try:
        return http_get(url, timeout=timeout)
    except TypeError:
        return http_get(url)


def _response_text(response: Any, *, max_bytes: int = DEFAULT_MAX_POLICY_BYTES) -> str:
    data, _content_type = _response_bytes(response, max_bytes=max_bytes)
    return data.decode("utf-8", errors="replace")


def _response_bytes(
    response: Any,
    *,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> tuple[bytes, str | None]:
    if hasattr(response, "raise_for_status"):
        response.raise_for_status()

    status_code = getattr(response, "status_code", None)
    if status_code is not None and int(status_code) >= 400:
        raise PolicyFetchError(f"Release policy fetch returned HTTP {status_code}.")

    label = "Release policy response"
    declared_length = _declared_content_length(response)
    if declared_length is not None and declared_length > max_bytes:
        raise PolicyFetchError(_payload_too_large_message(label, max_bytes))

    content_type = _response_content_type(response)

    if isinstance(response, str):
        data = response.encode("utf-8")
        _ensure_payload_size(data, max_bytes=max_bytes, label=label)
        return data, content_type
    if isinstance(response, bytes):
        _ensure_payload_size(response, max_bytes=max_bytes, label=label)
        return response, content_type

    text = getattr(response, "text", None)
    if isinstance(text, str):
        data = text.encode("utf-8")
        _ensure_payload_size(data, max_bytes=max_bytes, label=label)
        return data, content_type

    content = getattr(response, "content", None)
    if isinstance(content, bytes):
        _ensure_payload_size(content, max_bytes=max_bytes, label=label)
        return content, content_type

    if hasattr(response, "read"):
        return _read_limited_response(response, max_bytes=max_bytes, label=label), content_type

    raise PolicyFetchError("Release policy fetcher returned an unsupported response type.")


def _response_content_type(response: Any) -> str | None:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    if hasattr(headers, "get"):
        value = headers.get("content-type") or headers.get("Content-Type")
        if value:
            return str(value)
    if hasattr(headers, "items"):
        for key, value in headers.items():
            if str(key).lower() == "content-type":
                return str(value)
    return None


def _is_url(value: str) -> bool:
    return bool(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value))


def _content_type_from_path(path: str) -> str | None:
    suffix = Path(path).suffix.lower()
    if suffix == ".json":
        return "application/json"
    if suffix in {".html", ".htm"}:
        return "text/html"
    return None


def fetch_release_policy(
    url: str | None = DEFAULT_POLICY_URL,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    http_get: HttpGet | None = None,
    *,
    allow_html_fallback: bool = False,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> ReleasePolicy:
    if not url:
        raise PolicyFetchError("No release policy URL configured.")
    data, content_type = fetch_policy_bytes(
        url,
        timeout=timeout,
        http_get=http_get,
        max_bytes=max_bytes,
    )
    return load_policy_bytes(
        data,
        content_type=content_type,
        source_url=url,
        allow_html_fallback=allow_html_fallback,
        max_bytes=max_bytes,
    )


def fetch_policy_bytes(
    url: str,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    http_get: HttpGet | None = None,
    *,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> tuple[bytes, str | None]:
    try:
        if http_get is None and not _is_url(url):
            policy_path = Path(url)
            if policy_path.stat().st_size > max_bytes:
                raise PolicyFetchError(
                    _payload_too_large_message("Release policy file", max_bytes)
                )
            content_type = _content_type_from_path(url)
            return policy_path.read_bytes(), content_type
        response = (
            _call_http_get(http_get, url, timeout)
            if http_get
            else _default_http_get(url, timeout, max_bytes=max_bytes)
        )
        return _response_bytes(response, max_bytes=max_bytes)
    except PolicyFetchError:
        raise
    except Exception as exc:
        raise PolicyFetchError(f"Failed to fetch release policy from {url}: {exc}") from exc


def policy_from_dict(data: Mapping[str, Any]) -> ReleasePolicy:
    return ReleasePolicy.from_dict(data)


def policy_to_dict(policy: ReleasePolicy) -> dict[str, Any]:
    return policy.to_dict()


def require_broad_target(policy: ReleasePolicy) -> ReleasePolicyEntry:
    if policy.broad_target_existing_devices is None:
        raise PolicyError("Release policy does not define broad_target_existing_devices.")
    return policy.broad_target_existing_devices


__all__ = [
    "ReleaseHistoryEntry",
    "ReleasePolicy",
    "ReleasePolicyEntry",
    "fetch_release_policy",
    "fetch_policy_bytes",
    "load_policy_bytes",
    "load_policy_text",
    "parse_windows11_release_health_html",
    "policy_from_dict",
    "policy_to_dict",
    "require_broad_target",
]
