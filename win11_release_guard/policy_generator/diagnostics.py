"""Assembling the source_diagnostics block of the policy."""

from __future__ import annotations

from typing import Any, Mapping
from ..models import ReleaseHistoryEntry, ReleasePolicy, ReleasePolicyEntry
from .baseline_notice import _baseline_update_notice_event
from .diagnostic_ids import _source_diagnostic_events_with_ids
from .events import _dedupe_source_events, _source_event_counts
from .observed import (
    _atom_newer_than_history,
    _newest_atom_timestamp,
    _newest_current_version_revision_date,
    _newest_release_history_availability_date,
)
from .source_events import (
    _atom_newer_event,
    _current_version_latest_older_than_history,
    _current_versions_lag_event,
    _is_unresolved_source_drift_event,
    _newest_atom_build,
    _source_diagnostic_messages,
    _source_diagnostic_notices,
    _source_status,
)
from .sources import AtomFeedEntry
from .timestamps import _newest_timestamp, _parse_source_timestamp


def _source_diagnostics(
    *,
    current_versions: tuple[ReleasePolicyEntry, ...],
    release_history: tuple[ReleaseHistoryEntry, ...],
    atom_entries: tuple[AtomFeedEntry, ...],
    support_articles: Mapping[str, Mapping[str, Any]] | None = None,
    msrc_cvrf_statuses: Mapping[str, Mapping[str, Any]] | None = None,
    baseline_update_notice: Mapping[str, Any] | None = None,
    broad_target: ReleasePolicyEntry | None,
    parser_diagnostics: tuple[Mapping[str, Any], ...] = (),
    source_input_events: tuple[Mapping[str, Any], ...] = (),
    source_fetch_status: Mapping[str, Any],
    release_health_url: str,
    release_health_html: str,
    generated_at_utc: str,
    servicing_toc_url: str | None = None,
    servicing_toc_json: str | None = None,
    servicing_toc_entries: tuple[AtomFeedEntry, ...] = (),
    msrc_month_id_fallback_allowed: bool = False,
) -> dict[str, Any]:
    release_health_status = _source_status(
        source_fetch_status,
        "release_health_html",
        source_url=release_health_url,
        text=release_health_html,
        generated_at_utc=generated_at_utc,
    )
    servicing_status = _source_status(
        source_fetch_status,
        "servicing_toc",
        source_url=servicing_toc_url,
        text=servicing_toc_json,
        generated_at_utc=generated_at_utc,
    )
    newest_current_revision = _newest_current_version_revision_date(current_versions)
    newest_history_availability = _newest_release_history_availability_date(release_history)
    newest_atom_updated = _newest_atom_timestamp(atom_entries, "updated")
    newest_atom_published = _newest_atom_timestamp(atom_entries, "published")
    atom_newer = _atom_newer_than_history(atom_entries, release_history)
    effective_support_articles = support_articles or {}
    effective_msrc_cvrf_statuses = msrc_cvrf_statuses or {}
    current_stale = _current_version_latest_older_than_history(current_versions, release_history)
    baseline_notice_event = _baseline_update_notice_event(baseline_update_notice)
    events = _dedupe_source_events(
        [
            *(dict(item) for item in parser_diagnostics),
            *(dict(item) for item in source_input_events),
            *(dict(item) for item in ((baseline_notice_event,) if baseline_notice_event else ())),
            *(
                _atom_newer_event(
                    item,
                    broad_target,
                    support_articles=effective_support_articles,
                    msrc_month_id_fallback_allowed=msrc_month_id_fallback_allowed,
                )
                for item in atom_newer
            ),
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
        has_unresolved_drift = any(_is_unresolved_source_drift_event(event) for event in events)
        if has_unresolved_drift:
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
    events = _source_diagnostic_events_with_ids(_dedupe_source_events(events))
    parser_events = _source_diagnostic_events_with_ids(
        [dict(item) for item in parser_diagnostics if isinstance(item, Mapping)]
    )
    warnings = list(dict.fromkeys(_source_diagnostic_messages(events, minimum="warning")))
    notices = list(dict.fromkeys(_source_diagnostic_notices(events)))

    diagnostics: dict[str, Any] = {
        "release_health_html": {
            "source_url": release_health_status.get("url"),
            "fetched_at_utc": release_health_status.get("fetched_at_utc"),
            "bytes": release_health_status.get("bytes"),
            "status": release_health_status.get("status"),
            "newest_current_version_revision_date": newest_current_revision,
            "newest_release_history_availability_date": newest_history_availability,
        },
        "servicing_toc": {
            "source_url": servicing_status.get("url"),
            "fetched_at_utc": servicing_status.get("fetched_at_utc"),
            "bytes": servicing_status.get("bytes"),
            "status": servicing_status.get("status"),
            "newest_servicing_build": _newest_atom_build(servicing_toc_entries),
            "entry_count": len(servicing_toc_entries),
        },
        "drift": {
            "atom_newer_than_release_history": [dict(item) for item in atom_newer],
            "current_version_latest_older_than_release_history": [dict(item) for item in current_stale],
            "newest_source_timestamp": newest_source_timestamp,
            "generated_after_newest_source_hours": generated_after_hours,
        },
        "support_articles": {
            str(url): dict(article)
            for url, article in sorted(effective_support_articles.items())
        },
        "msrc_cvrf": {
            str(month_id): dict(status)
            for month_id, status in sorted(effective_msrc_cvrf_statuses.items())
        },
        "parser": {
            "events": parser_events,
        },
        "events": events,
        "event_counts": _source_event_counts(events),
        "notices": notices,
        "warnings": warnings,
    }
    if baseline_update_notice is not None:
        diagnostics["baseline_update_notice"] = dict(baseline_update_notice)
    return diagnostics


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
