"""Latest observed build evidence from the servicing index."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping
from ..models import ReleaseHistoryEntry, ReleasePolicyEntry
from ..update_text import _extract_kb
from .keys import _build_key, _release_key
from .sources import AtomFeedEntry
from .support_articles import _atom_entry_support_url, _safe_support_article_url
from .timestamps import _newest_timestamp, _source_timestamp_for_sort


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
    missing_by_key: dict[tuple[str, str | None], dict[str, Any]] = {}
    for entry in atom_entries:
        kb = _extract_kb(entry.kb_article)
        support_url = _atom_entry_support_url(entry)
        for build in entry.builds:
            family = _build_key(build)[0]
            if family < 0:
                continue
            if build in history_builds:
                continue
            if _build_key(build) <= newest_by_family.get(family, (-1, -1)):
                continue
            key = (build, kb)
            record = {
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
                "atom_entry_id": entry.entry_id,
                "atom_support_article_id": entry.support_article_id,
                "diagnostic_id_hint": entry.diagnostic_id_hint,
            }
            if support_url:
                record["atom_feed_url"] = support_url
                record["support_url"] = support_url
            current = missing_by_key.get(key)
            if current is None or _atom_drift_record_is_preferred(record, current):
                missing_by_key[key] = record
    return tuple(
        missing_by_key[key]
        for key in sorted(
            missing_by_key,
            key=lambda item: (_build_key(item[0]), item[1] or ""),
        )
    )


def _atom_observed_record_is_preferred(candidate: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    candidate_build = _build_key(str(candidate.get("build") or ""))
    current_build = _build_key(str(current.get("build") or ""))
    if candidate_build != current_build:
        return candidate_build > current_build
    return _atom_drift_record_is_preferred(candidate, current)


def _atom_support_href_missing_event(
    *,
    target: ReleasePolicyEntry,
    entry: AtomFeedEntry,
    build: str,
    kb_article: str,
) -> dict[str, Any]:
    support_url = _atom_entry_support_url(entry)
    event = {
        "severity": "warning",
        "kind": "atom_support_article_href_missing",
        "release": target.version,
        "build_family": target.build_family,
        "build": build,
        "kb_article": kb_article,
        "affects_broad_target": True,
        "affects_required_baseline": True,
        "message": (
            f"Servicing index reports {kb_article} build {build} for the broad target but does not provide "
            "a usable support.microsoft.com article href; latest observed build was not advanced from that evidence."
        ),
        "published": entry.published,
        "updated": entry.updated,
        "title": entry.title,
        "atom_entry_id": entry.entry_id,
        "atom_support_article_id": entry.support_article_id,
    }
    if support_url:
        event["atom_feed_url"] = support_url
        event["support_url"] = support_url
    return {key: value for key, value in event.items() if value not in (None, "")}


def _latest_observed_atom_support_record(
    target: ReleasePolicyEntry | None,
    atom_entries: tuple[AtomFeedEntry, ...],
    release_history: tuple[ReleaseHistoryEntry, ...],
) -> tuple[dict[str, Any] | None, tuple[dict[str, Any], ...]]:
    if target is None or not target.latest_build:
        return None, ()

    release_by_family = _history_release_by_family(release_history)
    target_latest_key = _build_key(target.latest_build)
    selected: dict[str, Any] | None = None
    missing_href_by_key: dict[tuple[str, str], dict[str, Any]] = {}

    for entry in atom_entries:
        if entry.preview or entry.out_of_band:
            continue
        kb_article = _extract_kb(entry.kb_article)
        if not kb_article:
            continue
        support_url = _safe_support_article_url(entry.link)
        for build in entry.builds:
            build_key = _build_key(build)
            family = build_key[0]
            if family != target.build_family:
                continue
            if release_by_family.get(family) != target.version:
                continue
            if build_key <= target_latest_key:
                continue
            if support_url is None:
                event = _atom_support_href_missing_event(
                    target=target,
                    entry=entry,
                    build=build,
                    kb_article=kb_article,
                )
                key = (build, kb_article)
                current = missing_href_by_key.get(key)
                if current is None or _atom_drift_record_is_preferred(event, current):
                    missing_href_by_key[key] = event
                continue

            record = {
                "build": build,
                "release": target.version,
                "build_family": family,
                "kb_article": kb_article,
                "latest_observed_source": "atom_support_article",
                "latest_observed_source_url": support_url,
                "latest_observed_kb_article": kb_article,
                "latest_observed_published": entry.published,
                "latest_observed_updated": entry.updated,
                "latest_observed_atom_entry_id": entry.entry_id,
                "latest_observed_atom_support_article_id": entry.support_article_id,
                "atom_entry_id": entry.entry_id,
                "atom_support_article_id": entry.support_article_id,
                "atom_feed_url": support_url,
                "support_url": support_url,
                "updated": entry.updated,
                "published": entry.published,
                "title": entry.title,
            }
            if entry.diagnostic_id_hint:
                record["diagnostic_id_hint"] = entry.diagnostic_id_hint
            record = {key: value for key, value in record.items() if value not in (None, "")}
            if selected is None or _atom_observed_record_is_preferred(record, selected):
                selected = record

    missing_events = tuple(
        missing_href_by_key[key]
        for key in sorted(missing_href_by_key, key=lambda item: (_build_key(item[0]), item[1]))
    )
    return selected, missing_events


def _entry_with_latest_observed_evidence(
    entry: ReleasePolicyEntry,
    record: Mapping[str, Any],
) -> ReleasePolicyEntry:
    build = str(record.get("build") or "")
    if not build:
        return entry
    metadata = dict(entry.metadata)
    for key in (
        "latest_observed_source",
        "latest_observed_source_url",
        "latest_observed_kb_article",
        "latest_observed_published",
        "latest_observed_updated",
        "latest_observed_atom_entry_id",
        "latest_observed_atom_support_article_id",
    ):
        value = record.get(key)
        if value not in (None, ""):
            metadata[key] = value
    return replace(entry, latest_observed_build=build, metadata=metadata)


def _atom_drift_record_is_preferred(candidate: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    candidate_updated = _source_timestamp_for_sort(str(candidate.get("updated") or "") or None)
    current_updated = _source_timestamp_for_sort(str(current.get("updated") or "") or None)
    if candidate_updated != current_updated:
        return candidate_updated > current_updated
    candidate_id = str(candidate.get("atom_entry_id") or "\uffff")
    current_id = str(current.get("atom_entry_id") or "\uffff")
    if candidate_id != current_id:
        return candidate_id < current_id
    return str(candidate.get("atom_feed_url") or candidate.get("title") or "") < str(
        current.get("atom_feed_url") or current.get("title") or ""
    )
