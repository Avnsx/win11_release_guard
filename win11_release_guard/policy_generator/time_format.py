"""Human-readable UTC and Europe/Berlin time strings."""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from typing import Any
from ..freshness import parse_iso_utc_datetime
from .clock import _parse_policy_datetime
from . import clock


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


_WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
_MONTHS = (
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
_DATE_ONLY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _long_date(day: datetime | date) -> str:
    """The dashboard's date format: "Friday, 9 October 2026"."""
    return f"{_WEEKDAYS[day.weekday()]}, {day.day} {_MONTHS[day.month - 1]} {day.year}"


def _berlin_local(utc_dt: datetime) -> tuple[datetime, str]:
    offset_hours, label = _berlin_offset_hours(utc_dt)
    return utc_dt.replace(tzinfo=None) + timedelta(hours=offset_hours), label


def _human_date(value: str | None) -> str | None:
    """A date-only ISO value as "Tuesday, 29 September 2026", without inventing a time of day."""
    text = str(value or "").strip()
    if not _DATE_ONLY_RE.fullmatch(text):
        return None
    try:
        return _long_date(date.fromisoformat(text))
    except ValueError:
        return None


def _generated_at_human(value: str | None) -> str:
    local_dt, label = _berlin_local(_parse_policy_datetime(value))
    return f"{_long_date(local_dt)}, {local_dt:%H:%M:%S} {label}"


def _generated_at_local_date(value: str | None) -> str:
    local_dt, _label = _berlin_local(_parse_policy_datetime(value))
    return _long_date(local_dt)


def _generated_at_local_time(value: str | None) -> str:
    local_dt, label = _berlin_local(_parse_policy_datetime(value))
    return f"{local_dt:%H:%M:%S} {label}"


def _utc_time_human(value: str | None) -> str:
    utc_dt = parse_iso_utc_datetime(value)
    if utc_dt is None:
        return "unavailable"
    return f"{_long_date(utc_dt)}, {utc_dt:%H:%M:%S} UTC"


def _dual_zone_time_human(value: Any) -> str | None:
    human_date = _human_date(value)
    if human_date is not None:
        return human_date
    utc_dt = parse_iso_utc_datetime(str(value or ""))
    if utc_dt is None:
        return None
    local_dt, label = _berlin_local(utc_dt)
    return f"{_long_date(local_dt)}, {local_dt:%H:%M:%S} {label} / {utc_dt:%H:%M:%S} UTC"


def _generated_age_days(value: str | None, *, reference: datetime | None = None) -> float:
    generated = _parse_policy_datetime(value)
    now = reference or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return round(max(0.0, (now.astimezone(timezone.utc) - generated).total_seconds() / 86400), 2)


def _age_unit_text(value: int, unit: str) -> str:
    return f"{value} {unit}" if value == 1 else f"{value} {unit}s"


def _dashboard_exact_age_text(seconds: int) -> str:
    seconds = max(0, int(seconds))
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    parts: list[str] = []
    if days:
        parts.append(_age_unit_text(days, "day"))
    if hours or days:
        parts.append(_age_unit_text(hours, "hour"))
    parts.append(_age_unit_text(minutes, "minute"))
    return ", ".join(parts)


def _dashboard_age_display(
    value: str | None,
    *,
    reference: datetime | None = None,
) -> tuple[str, str, str]:
    generated = parse_iso_utc_datetime(value)
    if generated is None:
        return "unknown", "age-wide", "Published feed age unknown"

    now = reference or parse_iso_utc_datetime(clock.utc_now()) or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    seconds = max(0, int((now.astimezone(timezone.utc) - generated).total_seconds()))
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    full = f"Published feed age {_dashboard_exact_age_text(seconds)}"
    if days >= 1:
        return f"{days}d {hours}h", "age-compact" if days >= 10 else "age-wide", full
    hour_value = seconds / 3600
    if hour_value >= 2:
        hours_text = f"{hour_value:.1f}"
        if hours_text.endswith(".0"):
            hours_text = hours_text[:-2]
        return f"{hours_text} hours", "age-wide" if hour_value >= 10 else "", full
    return _age_unit_text(minutes, "minute"), "age-wide" if minutes >= 100 else "", full
