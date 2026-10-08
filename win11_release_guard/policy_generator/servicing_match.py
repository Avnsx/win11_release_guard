"""Matching servicing index entries to Release Health history."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Iterable
from ..models import QualityPolicy, ReleaseHistoryEntry, ReleasePolicyEntry
from ..update_text import _extract_kb
from .keys import _build_key, _history_sort_key, _release_key
from .sources import AtomFeedEntry
from .support_articles import _atom_entry_support_url, _atom_title_bucket, _kb_url
from .timestamps import _parse_source_timestamp


def _catalog_url(kb_article: str | None) -> str | None:
    kb = _extract_kb(kb_article)
    if not kb:
        return None
    return f"https://www.catalog.update.microsoft.com/Search.aspx?q={kb}"


def _atom_entry_preference_key(entry: AtomFeedEntry) -> tuple[float, float, str, str]:
    updated = _parse_source_timestamp(entry.updated)
    published = _parse_source_timestamp(entry.published)
    return (
        updated.timestamp() if updated is not None else float("-inf"),
        published.timestamp() if published is not None else float("-inf"),
        str(entry.entry_id or ""),
        str(entry.title or ""),
    )


def _preferred_atom_entry(entries: Iterable[AtomFeedEntry]) -> AtomFeedEntry | None:
    candidates = tuple(entries)
    if not candidates:
        return None
    return max(candidates, key=_atom_entry_preference_key)


def _release_matches(row: ReleaseHistoryEntry, entry: AtomFeedEntry) -> bool:
    return bool(entry.release) and str(entry.release).upper() == str(row.release or "").upper()


def _atom_entry_build_families(entry: AtomFeedEntry) -> set[int]:
    families = {_build_key(build)[0] for build in entry.builds}
    return {family for family in families if family >= 0}


def _is_contradictory_same_family_atom_entry(row: ReleaseHistoryEntry, entry: AtomFeedEntry) -> bool:
    """True if an explicit-build entry covers the row's build family but not its build."""
    return bool(
        entry.builds
        and row.build_family in _atom_entry_build_families(entry)
        and row.build not in entry.builds
    )


def _unambiguous_kb_only_atom_entries(
    row: ReleaseHistoryEntry,
    entries: tuple[AtomFeedEntry, ...],
) -> tuple[AtomFeedEntry, ...]:
    """Build-agnostic KB-only fallback, allowed only in narrow, safe cases.

    This runs after exact KB+build and build-only matching have failed. A KB can
    map to multiple builds, so build-specific Atom metadata must never attach to a
    row by KB alone. The balance here keeps legitimate article-level (build-
    agnostic) evidence while still refusing wrong-build attachment:

    - if any explicit-build entry covers the row's build family but excludes the
      row build, the situation is contradictory for this row family and no fallback
      is allowed (an explicit entry for a *different* family does not block it);
    - only build-agnostic entries (no parsed explicit builds) may fall back;
    - the candidate must have a safe canonical Atom support URL;
    - Preview/Out-of-band candidates never enrich a normal broad-target row;
    - the surviving candidates must be unambiguous (single safe URL and bucket).

    When anything is ambiguous, prefer no enrichment over wrong enrichment.
    """
    if not entries:
        return ()

    if any(_is_contradictory_same_family_atom_entry(row, entry) for entry in entries):
        return ()

    row_flags = (bool(row.preview), bool(row.out_of_band))
    candidates = [
        entry
        for entry in entries
        if not entry.builds
        and _atom_entry_support_url(entry)
        and (bool(entry.preview), bool(entry.out_of_band)) == row_flags
        and (not entry.release or _release_matches(row, entry))
    ]
    if not candidates:
        return ()

    safe_urls = {_atom_entry_support_url(entry) for entry in candidates}
    if len(safe_urls) > 1:
        return ()

    buckets = {_atom_title_bucket(entry.title).get("bucket") for entry in candidates}
    if len(buckets) > 1:
        return ()

    return tuple(candidates)


def _match_atom(row: ReleaseHistoryEntry, entries: tuple[AtomFeedEntry, ...]) -> AtomFeedEntry | None:
    row_kb = _extract_kb(row.kb_article)
    if row_kb:
        lane_matches = tuple(
            entry
            for entry in entries
            if entry.kb_article == row_kb
            and _release_matches(row, entry)
            and not _is_contradictory_same_family_atom_entry(row, entry)
        )
        match = _preferred_atom_entry(lane_matches)
        if match is not None:
            return match
        kb_and_build_matches = tuple(
            entry for entry in entries if entry.kb_article == row_kb and row.build in entry.builds
        )
        match = _preferred_atom_entry(kb_and_build_matches)
        if match is not None:
            return match

    build_matches = tuple(entry for entry in entries if row.build in entry.builds)
    match = _preferred_atom_entry(build_matches)
    if match is not None:
        return match

    if row_kb:
        kb_matches = tuple(entry for entry in entries if entry.kb_article == row_kb)
        return _preferred_atom_entry(_unambiguous_kb_only_atom_entries(row, kb_matches))
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
            atom_support_url = _atom_entry_support_url(atom_entry)
            metadata.update(
                {
                    "atom_enriched": True,
                    "atom_feed_title": atom_entry.title,
                    "atom_published": atom_entry.published,
                    "atom_updated": atom_entry.updated,
                }
            )
            if atom_support_url:
                metadata["atom_feed_url"] = atom_support_url
            for key, value in (
                ("atom_entry_id", atom_entry.entry_id),
                ("atom_support_article_id", atom_entry.support_article_id),
                ("diagnostic_id_hint", atom_entry.diagnostic_id_hint),
            ):
                if value:
                    metadata[key] = value

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
