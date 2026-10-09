"""Selecting current versions, release history, and the broad target from Release Health."""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Mapping
from .config import DEFAULT_RELEASE_HEALTH_URL
from .exceptions import PolicyParseError
from .broad_target_hold import BroadTargetHold, pending_b_release_diagnostic, prove_broad_target_hold, with_pending_b_release_metadata
from .models import EditionScope, QualityPolicy, ReleaseHistoryEntry, ReleasePolicy, ReleasePolicyEntry, ServicingChannel
from .release_health_tables import (
    _CurrentVersionCandidate,
    _CurrentVersionSelection,
    _ReleaseHealthHtmlParser,
    _Table,
    _build_key,
    _candidate_is_superseded_by_broader_table,
    _classify_current_version_table,
    _current_candidate_key,
    _current_candidate_table_contexts,
    _current_conflict_diagnostic,
    _dedupe_diagnostics,
    _extract_build_family,
    _extract_release,
    _fold_text,
    _history_contexts,
    _missing_fields,
    _missing_table_error,
    _nearest_version_heading,
    _normalize_text,
    _release_key,
    _row_value,
    _servicing_context_is_plausible,
    _table_rows,
    _update_type_is_plausible,
)


_BUILD_PATTERN = re.compile(r"^\d{5}\.\d+$")


_CURRENT_VERSION_REQUIRED_FIELDS = ("version", "servicing_option", "latest_build")


_RELEASE_HISTORY_REQUIRED_FIELDS = ("update_type", "build")


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


def _broad_target_hold(
    current_versions: list[ReleasePolicyEntry],
    special_versions: set[str],
    release_history: list[ReleaseHistoryEntry],
    pending: ReleasePolicyEntry,
) -> BroadTargetHold | None:
    remaining = [
        entry
        for entry in current_versions
        if (entry.version, entry.build_family) != (pending.version, pending.build_family)
    ]
    try:
        target = _select_broad_target(remaining, special_versions)
    except PolicyParseError:
        return None
    if _release_key(target.version) >= _release_key(pending.version):
        return None
    baseline = _select_quality_baseline(release_history, target.version, QualityPolicy.B_RELEASE_ONLY)
    if baseline is None:
        return None
    return prove_broad_target_hold(
        pending=pending,
        target=target,
        baseline=baseline,
        release_history=release_history,
    )


def _raise_on_conflicting_target(conflicts: tuple[dict[str, Any], ...], entry: ReleasePolicyEntry) -> None:
    for conflict in conflicts:
        if _conflict_matches_entry(conflict, entry):
            raise PolicyParseError(
                "Conflicting Current Versions candidates make broad_target_existing_devices ambiguous: "
                f"{conflict.get('message')}"
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
    _raise_on_conflicting_target(current_selection.conflicts, broad_target)
    baseline = _select_quality_baseline(
        release_history,
        broad_target.version,
        QualityPolicy.B_RELEASE_ONLY,
    )
    if baseline is None:
        hold = _broad_target_hold(current_versions, special_versions, release_history, broad_target)
        if hold is None:
            raise PolicyParseError(
                "Could not select B-release required baseline for broad_target_existing_devices "
                f"{broad_target.version}/{broad_target.build_family} from Release Health release_history."
            )
        _raise_on_conflicting_target(current_selection.conflicts, hold.target)
        current_versions = [
            with_pending_b_release_metadata(entry, hold)
            if (entry.version, entry.build_family) == (hold.pending.version, hold.pending.build_family)
            else entry
            for entry in current_versions
        ]
        parser_diagnostics.append(pending_b_release_diagnostic(hold))
        broad_target, baseline = hold.target, hold.baseline
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
