"""Hold the broad target while a newer release waits for its first B release.

Microsoft publishes a new annual Windows 11 release during the fourth week of a
month with only an optional non-security preview (D) update, and the release
receives its first monthly security (B) update on the next Patch Tuesday. The
B-release-only quality policy cannot select a required baseline for it until
then, so the previous release stays the broad target in the meantime.

Patch Tuesday ships a B release for every supported version on the same day.
A release may therefore lack a B row only while no Patch Tuesday has passed
since it became available. When the held release has a B row dated on or after
the pending release's availability date, Release Health is inconsistent and
the caller must fail closed instead.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import date
from typing import Any, Iterable

from .models import ReleaseHistoryEntry, ReleasePolicyEntry

PENDING_B_RELEASE_KIND = "broad_target_pending_b_release"

_ISO_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


@dataclass(frozen=True)
class BroadTargetHold:
    pending: ReleasePolicyEntry
    target: ReleasePolicyEntry
    baseline: ReleaseHistoryEntry
    available_since: date


def _iso_date(value: str | None) -> date | None:
    text = str(value or "").strip()
    if not _ISO_DATE_RE.fullmatch(text):
        return None
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def _available_since(entry: ReleasePolicyEntry, release_history: Iterable[ReleaseHistoryEntry]) -> date | None:
    available = _iso_date(entry.availability_date)
    if available is not None:
        return available
    history_dates = [
        parsed
        for row in release_history
        if row.release == entry.version and row.build_family == entry.build_family
        for parsed in (_iso_date(row.availability_date),)
        if parsed is not None
    ]
    return min(history_dates) if history_dates else None


def prove_broad_target_hold(
    *,
    pending: ReleasePolicyEntry,
    target: ReleasePolicyEntry,
    baseline: ReleaseHistoryEntry,
    release_history: Iterable[ReleaseHistoryEntry],
) -> BroadTargetHold | None:
    """Return the hold when ``pending`` has provably not reached a Patch Tuesday yet."""

    available_since = _available_since(pending, release_history)
    newest_b_release = _iso_date(baseline.availability_date)
    if available_since is None or newest_b_release is None:
        return None
    if newest_b_release >= available_since:
        return None
    return BroadTargetHold(pending=pending, target=target, baseline=baseline, available_since=available_since)


def hold_reason(hold: BroadTargetHold) -> str:
    return (
        f"No B release for Windows 11 {hold.pending.version} yet, so the broad target stays on "
        f"{hold.target.version} (required baseline {hold.baseline.build}). "
        f"Release Health lists {hold.pending.version} as available since {hold.available_since.isoformat()}; "
        "it becomes the broad target with its first monthly security (B) release."
    )


def hold_user_message(hold: BroadTargetHold) -> str:
    return (
        f"{hold.target.version} stays the broad target with required baseline {hold.baseline.build} until "
        f"Windows 11 {hold.pending.version} receives its first monthly security (B) release on a Patch Tuesday. "
        f"Devices already on {hold.pending.version} report ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE until then."
    )


def with_pending_b_release_metadata(entry: ReleasePolicyEntry, hold: BroadTargetHold) -> ReleasePolicyEntry:
    metadata = dict(entry.metadata)
    metadata.update(
        {
            "not_broad_target": True,
            "not_broad_target_existing_devices": True,
            "pending_first_b_release": True,
            "broad_target_hold_reason": hold_reason(hold),
        }
    )
    return replace(entry, metadata=metadata)


def pending_b_release_diagnostic(hold: BroadTargetHold) -> dict[str, Any]:
    return {
        "severity": "notice",
        "kind": PENDING_B_RELEASE_KIND,
        "release": hold.pending.version,
        "build_family": hold.pending.build_family,
        "build": hold.pending.latest_build,
        "kb_article": None,
        "available_since": hold.available_since.isoformat(),
        "held_release": hold.target.version,
        "held_build_family": hold.target.build_family,
        "held_required_baseline_build": hold.baseline.build,
        "affects_broad_target": True,
        "affects_required_baseline": False,
        "message": hold_reason(hold),
        "user_message": hold_user_message(hold),
    }
