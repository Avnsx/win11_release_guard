"""The single wall-clock seam for policy generation; tests freeze time by patching utc_now here."""

from __future__ import annotations

from datetime import datetime, timezone


_LAST_UTC_NOW_MS = 0


def utc_now() -> str:
    global _LAST_UTC_NOW_MS
    epoch_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    if epoch_ms <= _LAST_UTC_NOW_MS:
        epoch_ms = _LAST_UTC_NOW_MS + 1
    _LAST_UTC_NOW_MS = epoch_ms
    seconds, milliseconds = divmod(epoch_ms, 1000)
    return datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=milliseconds * 1000).isoformat(
        timespec="milliseconds"
    )


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
