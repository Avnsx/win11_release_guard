from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Mapping

from .config import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    DEFAULT_POLICY_URL,
    DEFAULT_RELEASE_HEALTH_URL,
    DEFAULT_USER_AGENT,
)
from .exceptions import PolicyError, PolicyFetchError, PolicyParseError
from .models import (
    EditionScope,
    QualityPolicy,
    ReleaseHistoryEntry,
    ReleasePolicy,
    ReleasePolicyEntry,
    ServicingChannel,
)


HttpGet = Callable[..., Any]
SUPPORTED_POLICY_SCHEMA_VERSION = 1
_RELEASE_PATTERN = re.compile(r"^\d{2}H[12]$", re.IGNORECASE)
_BUILD_PATTERN = re.compile(r"^\d{5}\.\d+$")


@dataclass(frozen=True)
class _Cell:
    text: str
    is_header: bool


@dataclass(frozen=True)
class _Table:
    headings: tuple[str, ...]
    rows: tuple[tuple[_Cell, ...], ...]


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


def _row_value(row: Mapping[str, str], *needles: str) -> str | None:
    for key, value in row.items():
        key_l = key.lower()
        if all(needle.lower() in key_l for needle in needles):
            return value
    return None


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
            r"Version\s+(\d{2}H[12])\s+\(OS build\s+(\d+)\)",
            heading,
            flags=re.IGNORECASE,
        )
        if match:
            return match.group(1).upper(), int(match.group(2))
    return None, None


def _table_context(table: _Table, headers: list[str]) -> str:
    return " | ".join((*table.headings, *headers)).lower()


def _row_context(row: Mapping[str, str]) -> str:
    return " | ".join(str(value) for value in row.values()).lower()


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


def _parse_current_versions(tables: list[_Table]) -> list[ReleasePolicyEntry]:
    current_versions: list[ReleasePolicyEntry] = []
    seen: set[tuple[str, int, ServicingChannel, tuple[EditionScope, ...]]] = set()

    for table in tables:
        headers, rows = _table_rows(table)
        header_blob = " | ".join(headers).lower()
        if not (
            "version" in header_blob
            and "servicing option" in header_blob
            and "latest build" in header_blob
        ):
            continue

        for row in rows:
            release = _extract_release(_row_value(row, "version"))
            latest_build = _row_value(row, "latest", "build")
            build_family = _extract_build_family(latest_build)
            if not release or build_family is None:
                continue

            servicing_channel, edition_scopes = _classify_current_version_table(table, headers, row)
            key = (release, build_family, servicing_channel, edition_scopes)
            if key in seen:
                continue
            seen.add(key)

            current_versions.append(
                ReleasePolicyEntry(
                    version=release,
                    build_family=build_family,
                    latest_build=latest_build,
                    servicing_option=_row_value(row, "servicing", "option"),
                    availability_date=_row_value(row, "availability", "date"),
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
                        "raw": dict(row),
                    },
                )
            )

    return current_versions


def _parse_release_history(tables: list[_Table]) -> list[ReleaseHistoryEntry]:
    release_history: list[ReleaseHistoryEntry] = []

    for table in tables:
        release, build_family = _nearest_version_heading(table)
        if not release or build_family is None:
            continue

        headers, rows = _table_rows(table)
        header_blob = " | ".join(headers).lower()
        if "build" not in header_blob or "availability date" not in header_blob:
            continue

        for row in rows:
            build = _row_value(row, "build")
            if not build or not re.match(r"^\d+\.\d+$", build):
                continue

            update_type = _row_value(row, "update", "type") or ""
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
                    availability_date=_row_value(row, "availability", "date"),
                    servicing_option=_row_value(row, "servicing", "option"),
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
        sentence_l = sentence.lower()
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
    servicing = (entry.servicing_option or "").lower()
    return "general availability" in servicing or "allgemeine" in servicing


def _is_supported_for_home_pro(entry: ReleasePolicyEntry) -> bool:
    home_pro_end = str(entry.metadata.get("home_pro_end") or "")
    return "end of updates" not in home_pro_end.lower()


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
        raise PolicyParseError("No supported Windows 11 GA target candidate found.")

    h2_candidates = [entry for entry in candidates if entry.version.endswith("H2")]
    if h2_candidates:
        candidates = h2_candidates

    return max(candidates, key=lambda entry: _release_key(entry.version))


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

    if not filtered:
        filtered = rows

    return max(
        filtered,
        key=lambda row: (
            row.availability_date or "",
            _build_key(row.build),
        ),
    )


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


def _entry_has_explicit_baseline(data: Mapping[str, Any], target: Mapping[str, Any]) -> bool:
    if _validate_build(target.get("baseline_build"), "broad_target_existing_devices.baseline_build"):
        return True
    if _validate_build(data.get("baseline_build"), "baseline_build"):
        return True
    quality_baseline = data.get("quality_baseline")
    if isinstance(quality_baseline, Mapping):
        if _validate_build(quality_baseline.get("build"), "quality_baseline.build"):
            return True
    return bool(_validate_build(target.get("latest_build"), "broad_target_existing_devices.latest_build"))


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
        "generator_version",
        "source_fetch_status",
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
    }
    unknown_keys = sorted(str(key) for key in data.keys() - allowed_keys)
    if unknown_keys:
        raise PolicyParseError(f"JSON policy contains unknown top-level key(s): {', '.join(unknown_keys)}.")

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
    if source_url and _is_url(source_url) and source_url not in source_urls:
        warnings.append("Loaded policy URL is not listed in source_urls.")

    current_versions = _require_sequence(data, "current_versions")
    normalized_current_versions: list[Mapping[str, Any]] = []
    target_version_counts: dict[str, set[int]] = {}
    for index, item in enumerate(current_versions):
        if not isinstance(item, Mapping):
            raise PolicyParseError(f"current_versions[{index}] must be an object.")
        release = _validate_release(item.get("version"), f"current_versions[{index}].version")
        build_family = _validate_build_family(item.get("build_family"), f"current_versions[{index}].build_family")
        _validate_build(item.get("latest_build"), f"current_versions[{index}].latest_build")
        _validate_build(item.get("baseline_build"), f"current_versions[{index}].baseline_build")
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
    _validate_build(broad_target.get("latest_build"), "broad_target_existing_devices.latest_build")
    _validate_build(broad_target.get("baseline_build"), "broad_target_existing_devices.baseline_build")

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
    if source_url:
        source = dict(normalized.get("source") or {})
        source["policy_url"] = source_url
        normalized["source"] = source
    normalized["validation_warnings"] = list(dict.fromkeys(warnings))
    return normalized, tuple(normalized["validation_warnings"])


def _load_json_policy(text: str, *, source_url: str | None = None) -> ReleasePolicy:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyParseError(f"Malformed JSON policy: {exc}") from exc
    if not isinstance(data, Mapping):
        raise PolicyParseError("JSON policy top-level value must be an object.")

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
) -> ReleasePolicy:
    content_type_l = (content_type or "").lower()

    if "application/json" in content_type_l or _looks_like_json(text):
        return _load_json_policy(text, source_url=source_url)

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


def load_policy_text(text: str, *, source_url: str | None = None) -> ReleasePolicy:
    return _load_policy_text(text, source_url=source_url)


def load_policy_bytes(
    data: bytes,
    *,
    content_type: str | None = None,
    source_url: str | None = None,
    allow_html_fallback: bool = False,
) -> ReleasePolicy:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PolicyParseError(f"Policy bytes are not valid UTF-8: {exc}") from exc
    return _load_policy_text(
        text,
        content_type=content_type,
        source_url=source_url,
        allow_html_fallback=allow_html_fallback,
    )


def parse_windows11_release_health_html(html: str) -> ReleasePolicy:
    parser = _ReleaseHealthHtmlParser()
    parser.feed(html)
    parser.close()

    current_versions = _parse_current_versions(parser.tables)
    if not current_versions:
        raise PolicyParseError("Could not parse Windows 11 current-version table.")

    release_history = _parse_release_history(parser.tables)
    if not release_history:
        raise PolicyParseError("Could not parse Windows 11 release-history tables.")

    special_reasons = _detect_special_release_reasons(" ".join(parser.document_text_parts))
    special_versions = set(special_reasons)
    special_entries = tuple(
        _with_special_metadata(entry, special_reasons[entry.version])
        for entry in current_versions
        if entry.version in special_versions
    )

    broad_target = _select_broad_target(current_versions, special_versions)
    baseline = _select_quality_baseline(
        release_history,
        broad_target.version,
        QualityPolicy.B_RELEASE_ONLY,
    )
    if baseline is not None:
        broad_target = replace(broad_target, baseline_build=baseline.build)

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
        metadata={
            "parser": "stdlib_html_parser",
            "special_release_versions": sorted(special_versions),
        },
    )


def _default_http_get(url: str, timeout: float) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "application/json,text/html,application/xhtml+xml",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset, errors="replace")


def _call_http_get(http_get: HttpGet, url: str, timeout: float) -> Any:
    try:
        return http_get(url, timeout=timeout)
    except TypeError:
        return http_get(url)


def _response_text(response: Any) -> str:
    if hasattr(response, "raise_for_status"):
        response.raise_for_status()

    status_code = getattr(response, "status_code", None)
    if status_code is not None and int(status_code) >= 400:
        raise PolicyFetchError(f"Release policy fetch returned HTTP {status_code}.")

    if isinstance(response, str):
        return response
    if isinstance(response, bytes):
        return response.decode("utf-8", errors="replace")

    text = getattr(response, "text", None)
    if isinstance(text, str):
        return text

    content = getattr(response, "content", None)
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")

    if hasattr(response, "read"):
        data = response.read()
        if isinstance(data, str):
            return data
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")

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


def _response_bytes(response: Any) -> tuple[bytes, str | None]:
    if hasattr(response, "raise_for_status"):
        response.raise_for_status()

    status_code = getattr(response, "status_code", None)
    if status_code is not None and int(status_code) >= 400:
        raise PolicyFetchError(f"Release policy fetch returned HTTP {status_code}.")

    content_type = _response_content_type(response)

    if isinstance(response, str):
        return response.encode("utf-8"), content_type
    if isinstance(response, bytes):
        return response, content_type

    content = getattr(response, "content", None)
    if isinstance(content, bytes):
        return content, content_type

    text = getattr(response, "text", None)
    if isinstance(text, str):
        return text.encode("utf-8"), content_type

    if hasattr(response, "read"):
        data = response.read()
        if isinstance(data, str):
            return data.encode("utf-8"), content_type
        if isinstance(data, bytes):
            return data, content_type

    raise PolicyFetchError("Release policy fetcher returned an unsupported response type.")


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
) -> ReleasePolicy:
    if not url:
        raise PolicyFetchError("No release policy URL configured.")
    data, content_type = fetch_policy_bytes(url, timeout=timeout, http_get=http_get)
    return load_policy_bytes(
        data,
        content_type=content_type,
        source_url=url,
        allow_html_fallback=allow_html_fallback,
    )


def fetch_policy_bytes(
    url: str,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    http_get: HttpGet | None = None,
) -> tuple[bytes, str | None]:
    try:
        if http_get is None and not _is_url(url):
            content_type = _content_type_from_path(url)
            return Path(url).read_bytes(), content_type
        response = _call_http_get(http_get, url, timeout) if http_get else _default_http_get(url, timeout)
        return _response_bytes(response)
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
