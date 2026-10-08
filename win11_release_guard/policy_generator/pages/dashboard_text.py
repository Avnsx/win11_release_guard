"""Plain-text labels used by dashboard rendering."""

from __future__ import annotations

import re
from typing import Any, Mapping
from urllib.parse import urlparse
from ...models import ReleasePolicy, ReleasePolicyEntry
from ..constants import CURATED_EXCLUDED_RELEASE_SUMMARIES


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
    has_servicing_path = any(
        left == "servicing" and right == "os"
        for left, right in zip(path_segments, path_segments[1:])
    )
    if host == "support.microsoft.com" and has_servicing_path:
        return "Microsoft servicing index"
    return url

def _status_text(policy: ReleasePolicy) -> str:
    return "Warning state" if policy.validation_warnings else "Policy current"

def _latest_observed_source_label(entry: ReleasePolicyEntry | None) -> str:
    if entry and str(entry.metadata.get("latest_observed_source") or "") == "atom_support_article":
        return "Microsoft Support article"
    return "Microsoft Current Versions table"

def _latest_observed_evidence_metadata(entry: ReleasePolicyEntry | None) -> dict[str, Any]:
    if entry is None:
        return {}
    return {
        key: entry.metadata[key]
        for key in (
            "latest_observed_source",
            "latest_observed_source_url",
            "latest_observed_kb_article",
            "latest_observed_published",
            "latest_observed_updated",
            "latest_observed_atom_entry_id",
            "latest_observed_atom_support_article_id",
        )
        if key in entry.metadata and entry.metadata[key] not in (None, "")
    }

def _source_event_counts_for_policy(policy: ReleasePolicy) -> dict[str, int]:
    source_diagnostics = policy.source_diagnostics if isinstance(policy.source_diagnostics, Mapping) else {}
    raw_counts = source_diagnostics.get("event_counts") if isinstance(source_diagnostics, Mapping) else {}
    counts = {"notice": 0, "warning": 0, "error": 0}
    if isinstance(raw_counts, Mapping):
        for key in counts:
            try:
                counts[key] = max(0, int(raw_counts.get(key) or 0))
            except (TypeError, ValueError):
                counts[key] = 0
    return counts

def _source_diagnostics_for_policy(policy: ReleasePolicy) -> Mapping[str, Any]:
    source_diagnostics = policy.source_diagnostics if isinstance(policy.source_diagnostics, Mapping) else {}
    return source_diagnostics
