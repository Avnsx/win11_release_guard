"""Parsing and normalising source timestamps."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


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

def _datetime_utc_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def _source_timestamp_utc_z(value: Any) -> str | None:
    parsed = _parse_source_timestamp(str(value or "") or None)
    return _datetime_utc_z(parsed) if parsed else None

def _baseline_notice_official_date(value: str | None) -> datetime | None:
    """Parse a date-only Microsoft source value to a UTC-midnight datetime.

    Accepts zero-padded and non-zero-padded ``YYYY-M-D`` forms deterministically.
    Impossible calendar dates (for example ``2026-02-30`` or ``2026-13-01``) raise
    ``ValueError`` during construction and degrade to ``None`` instead of crashing
    policy generation. Only a calendar date is parsed; no time of day is invented.
    """
    match = re.fullmatch(r"(\d{4})-(\d{1,2})-(\d{1,2})", str(value or "").strip())
    if not match:
        return None
    try:
        return datetime(int(match[1]), int(match[2]), int(match[3]), tzinfo=timezone.utc)
    except ValueError:
        return None

def _source_timestamp_for_sort(value: str | None) -> datetime:
    return _parse_source_timestamp(value) or datetime.min.replace(tzinfo=timezone.utc)
