"""Source event identity, de-duplication, and counting."""

from __future__ import annotations

from typing import Any, Mapping, Sequence
from .observed import _atom_drift_record_is_preferred


def _event_key(item: Mapping[str, Any]) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    return (
        str(item.get("severity")) if item.get("severity") is not None else None,
        str(item.get("kind")) if item.get("kind") is not None else None,
        str(item.get("release")) if item.get("release") is not None else None,
        str(item.get("build")) if item.get("build") is not None else None,
        str(item.get("kb_article")) if item.get("kb_article") is not None else None,
    )

def _dedupe_source_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str | None, str | None, str | None, str | None, str | None], dict[str, Any]] = {}
    order: list[tuple[str | None, str | None, str | None, str | None, str | None]] = []
    for event in events:
        key = _event_key(event)
        item = dict(event)
        current = by_key.get(key)
        if current is None:
            order.append(key)
            by_key[key] = item
            continue
        if _atom_drift_record_is_preferred(item, current):
            by_key[key] = item
    return [by_key[key] for key in order]

def _source_event_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"notice": 0, "warning": 0, "error": 0}
    for event in events:
        severity = str(event.get("severity") or "")
        if severity in counts:
            counts[severity] += 1
    return counts

def _human_join(items: Sequence[str]) -> str:
    values = [item for item in items if item]
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return ", ".join(values[:-1]) + f", and {values[-1]}"
