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
from typing import Any, Mapping
from urllib.parse import urlparse
from xml.etree import ElementTree

from .config import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    DEFAULT_PAGES_BASE_URL,
    DEFAULT_PUBLISHED_POLICY_URLS,
    DEFAULT_RELEASE_HEALTH_URL,
    DEFAULT_TRUSTED_POLICY_KEY_ID,
    DEFAULT_USER_AGENT,
)
from .exceptions import PolicyFetchError, PolicyParseError
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


@dataclass(frozen=True)
class SourceText:
    text: str
    status: Mapping[str, Any]


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
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


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


def _fetch_url(url: str, *, timeout: float) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/atom+xml,application/xml,text/xml",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset, errors="replace")


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
                    "build": build,
                    "build_family": family,
                    "kb_article": kb,
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

    warnings: list[str] = []
    if atom_newer:
        newest = atom_newer[0]
        warnings.append(
            "Source freshness warning: Atom feed has newer build/KB entries not present in Release Health "
            f"release_history, including {newest.get('kb_article') or 'unknown KB'} "
            f"build {newest.get('build')}."
        )
    if current_stale:
        stale = current_stale[0]
        warnings.append(
            "Source freshness warning: Current Versions latest_build appears older than Release History for "
            f"{stale['version']}/{stale['build_family']}: {stale.get('latest_build') or 'unknown'} < "
            f"{stale['newest_release_history_build']}."
        )
    if generated_after_hours is not None and generated_after_hours >= 24 and (atom_newer or current_stale):
        warnings.append(
            "Source freshness warning: policy was generated more than 24 hours after the newest source timestamp "
            "while source drift diagnostics remain unresolved."
        )
    if (
        generated_after_hours is not None
        and generated_after_hours >= 24
        and not atom_entries
        and atom_status.get("status") != "ok"
    ):
        warnings.append(
            "Source freshness warning: policy was generated more than 24 hours after the newest Release Health "
            "timestamp and Atom diagnostics are unavailable; preview/out-of-band enrichment may be incomplete."
        )

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
        baseline = quality_baselines.get(target.version, {}).get(QualityPolicy.B_RELEASE_ONLY.value)
        if isinstance(baseline, Mapping):
            build = baseline.get("build")
            if build:
                baseline_build = str(build)
                target = replace(
                    target,
                    baseline_build=baseline_build,
                    required_baseline_build=baseline_build,
                )

    metadata = dict(base_policy.metadata)
    metadata["signature_status"] = signature_status
    metadata["generator"] = GENERATOR_VERSION
    source_diagnostics = _source_diagnostics(
        current_versions=current_versions,
        release_history=release_history,
        atom_entries=atom_entries,
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
            warnings.append(f"Atom feed could not be parsed: {exc}")
    else:
        warnings.append("Atom feed missing; preview/out-of-band enrichment unavailable.")

    if atom_feed_xml and not atom_entries:
        warnings.append("Atom feed contained no usable entries.")

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
    if signing_key:
        signature = sign_policy_bytes(policy_bytes, signing_key, key_id=key_id)
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
                signature=signature,
            ),
        )
        written["index"] = index_file

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
            signature=signature,
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


def render_policy_index(
    policy: ReleasePolicy,
    *,
    policy_bytes: bytes | None = None,
    signature: Mapping[str, Any] | None = None,
) -> str:
    target = policy.broad_target_existing_devices
    policy_hash = _sha256_hex(policy_bytes)
    generated_human = _generated_at_human(policy.generated_at_utc)
    signature_algorithm = _signature_field(signature, "algorithm") or "unavailable"
    key_id = _signature_field(signature, "key_id") or "legacy default key"
    status = _status_text(policy)
    status_class = "ok" if status == "Policy current" else "warning"
    excluded_items = "\n".join(
        (
            "          <li>"
            f"<strong>{escape(entry.version)} excluded for existing devices</strong>"
            f"<span>{escape(_excluded_release_summary(entry))}</span>"
            "</li>"
        )
        for entry in policy.excluded_for_existing_devices
    ) or "          <li><strong>None</strong><span>No existing-device exclusions in this policy.</span></li>"
    source_items = "\n".join(
        f'          <li><span>{escape(_source_label(url))}</span><a href="{escape(url)}">{escape(url)}</a></li>'
        for url in policy.source_urls
    )
    warning_items = "\n".join(f"<li>{escape(warning)}</li>" for warning in policy.validation_warnings)
    warning_block = (
        f"      <section class=\"panel span-2\"><h2>Warnings</h2><ul class=\"warnings\">{warning_items}</ul></section>"
        if warning_items
        else ""
    )
    target_release = target.version if target else "unknown"
    target_family = str(target.build_family) if target else "unknown"
    target_latest_observed = target.latest_observed_build if target else None
    target_baseline = target.required_baseline_build if target else None
    return (
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"utf-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "  <title>win11_release_guard</title>\n"
        "  <style>\n"
        "    :root{color-scheme:light;--bg:#f6f8fb;--ink:#182230;--muted:#667085;--line:#d7dee8;--panel:#ffffff;--accent:#0f766e;--warn:#b45309;--code:#0b4a6f}\n"
        "    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Segoe UI,Arial,sans-serif;line-height:1.45}\n"
        "    main{max-width:1120px;margin:0 auto;padding:32px 20px}header{display:flex;justify-content:space-between;gap:20px;align-items:flex-start;margin-bottom:22px}\n"
        "    h1{font-size:32px;line-height:1.1;margin:0 0 6px}p{margin:0}.subtitle{font-size:16px;color:var(--muted)}\n"
        "    .badge{border:1px solid var(--line);border-radius:999px;padding:7px 12px;background:var(--panel);font-weight:700;white-space:nowrap}.badge.ok{color:var(--accent)}.badge.warning{color:var(--warn)}\n"
        "    .grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px;min-width:0}.span-2{grid-column:span 2}.span-4{grid-column:span 4}\n"
        "    h2{font-size:14px;text-transform:uppercase;letter-spacing:0;color:var(--muted);margin:0 0 12px}.metric{font-size:30px;font-weight:760;line-height:1}.label{display:block;color:var(--muted);font-size:13px;margin-top:6px}\n"
        "    .kv{display:grid;grid-template-columns:120px 1fr;gap:8px 12px;font-size:14px}.kv dt{color:var(--muted)}.kv dd{margin:0;font-weight:650;overflow-wrap:anywhere}.mono{font-family:Consolas,Menlo,monospace;color:var(--code)}\n"
        "    ul.clean{list-style:none;margin:0;padding:0;display:grid;gap:10px}ul.clean li{display:grid;gap:3px}ul.clean span{color:var(--muted);font-size:13px}a{color:#075985;text-decoration:none}a:hover{text-decoration:underline}\n"
        "    .sources li{grid-template-columns:minmax(170px,220px) 1fr;align-items:start}.links{display:flex;flex-wrap:wrap;gap:10px}.links a{border:1px solid var(--line);border-radius:6px;padding:8px 10px;background:#f8fafc;font-family:Consolas,Menlo,monospace;font-size:13px}\n"
        "    footer{margin-top:16px;color:var(--muted);font-size:13px}@media(max-width:760px){header{display:block}.badge{display:inline-block;margin-top:14px}.grid{grid-template-columns:1fr}.span-2,.span-4{grid-column:auto}.kv{grid-template-columns:1fr}.sources li{grid-template-columns:1fr}}\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <main>\n"
        "    <header>\n"
        "      <div><h1>win11_release_guard</h1><p class=\"subtitle\">Windows release policy feed</p></div>\n"
        f"      <div class=\"badge {status_class}\">{escape(status)}</div>\n"
        "    </header>\n"
        "    <section class=\"grid\">\n"
        "      <article class=\"panel\"><h2>Release</h2>"
        f"<div class=\"metric\">{escape(target_release)}</div><span class=\"label\">broad target</span></article>\n"
        "      <article class=\"panel\"><h2>Build family</h2>"
        f"<div class=\"metric\">{escape(target_family)}</div><span class=\"label\">Windows build line</span></article>\n"
        "      <article class=\"panel\"><h2>Latest observed</h2>"
        f"<div class=\"metric\">{escape(target_latest_observed or 'unknown')}</div><span class=\"label\">Microsoft current table</span></article>\n"
        "      <article class=\"panel\"><h2>Required baseline</h2>"
        f"<div class=\"metric\">{escape(target_baseline or 'unknown')}</div><span class=\"label\">{escape(policy.quality_policy.value)} floor</span></article>\n"
        "      <section class=\"panel span-2\"><h2>Excluded release</h2><ul class=\"clean\">"
        f"{excluded_items}</ul></section>\n"
        "      <section class=\"panel span-2\"><h2>Last updated</h2><dl class=\"kv\">"
        f"<dt>Berlin</dt><dd>{escape(generated_human)}</dd>"
        f"<dt>UTC</dt><dd><time datetime=\"{escape(policy.generated_at_utc)}\">{escape(policy.generated_at_utc)}</time></dd>"
        "</dl></section>\n"
        "      <section class=\"panel span-2\"><h2>Sources</h2><ul class=\"clean sources\">"
        f"{source_items}</ul></section>\n"
        "      <section class=\"panel span-2\"><h2>Signature</h2><dl class=\"kv\">"
        f"<dt>Algorithm</dt><dd>{escape(signature_algorithm)}</dd>"
        f"<dt>key_id</dt><dd class=\"mono\">{escape(key_id)}</dd>"
        f"<dt>Policy SHA-256</dt><dd class=\"mono\">{escape(_short_hash(policy_hash))}</dd>"
        "</dl></section>\n"
        f"{warning_block}\n"
        "      <section class=\"panel span-4\"><h2>Programmatic API</h2>"
        "<p class=\"subtitle\">Public JSON policy artifacts for automation and fleet dashboards.</p>"
        "<div class=\"links\">"
        "<a href=\"windows-release-policy.json\">/windows-release-policy.json</a>"
        "<a href=\"windows-release-policy.json.sig\">/windows-release-policy.json.sig</a>"
        "<a href=\"policy-manifest.json\">/policy-manifest.json</a>"
        "<a href=\"api/v1/policy.json\">/api/v1/policy.json</a>"
        "<a href=\"api/v1/manifest.json\">/api/v1/manifest.json</a>"
        "</div></section>\n"
        "    </section>\n"
        "    <footer>Programmatic JSON endpoint for automation and fleet dashboards.</footer>\n"
        "  </main>\n"
        "</body>\n"
        "</html>\n"
    )


def render_robots_txt() -> str:
    return ROBOTS_TXT


def render_sitemap_xml(policy: ReleasePolicy, *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    generated_at = escape(policy.generated_at_utc or _utc_now())
    urls = (
        f"{base_url}/",
        f"{base_url}/windows-release-policy.json",
        f"{base_url}/policy-manifest.json",
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
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    target = policy.broad_target_existing_devices
    policy_sha256 = _sha256_hex(policy_bytes)
    signature_sha256 = _sha256_hex(signature_bytes)
    status = _status_text(policy)
    manifest = {
        "schema_version": 1,
        "generated_at_utc": policy.generated_at_utc,
        "generated_at_human": _generated_at_human(policy.generated_at_utc),
        "timezone": PAGES_TIMEZONE,
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
        "signature_algorithm": _signature_field(signature, "algorithm"),
        "key_id": _signature_field(signature, "key_id"),
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
    "render_policy_index",
    "render_policy_manifest",
    "render_robots_txt",
    "render_sitemap_xml",
    "sign_policy_bytes",
    "write_policy_outputs",
]
