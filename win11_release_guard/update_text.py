"""Shared KB, build, preview, and out-of-band extraction for update titles."""

from __future__ import annotations

import re


def _extract_kb(text: str | None) -> str | None:
    match = re.search(r"\bKB\d{6,8}\b", text or "", flags=re.IGNORECASE)
    return match.group(0).upper() if match else None


def _extract_builds(text: str | None) -> tuple[str, ...]:
    return tuple(dict.fromkeys(re.findall(r"\b\d{5}\.\d+\b", text or "")))


def _is_preview(text: str) -> bool:
    return "preview" in text.lower()


def _is_out_of_band(text: str) -> bool:
    normalized = text.lower().replace("_", "-")
    return (
        "out-of-band" in normalized
        or "out of band" in normalized
        or re.search(r"\boob\b", normalized) is not None
    )


__all__ = ["_extract_builds", "_extract_kb", "_is_out_of_band", "_is_preview"]
