"""Source drift and enrichment diagnostic events."""

from __future__ import annotations

import re
from typing import Any, Mapping
from ..models import ReleaseHistoryEntry, ReleasePolicyEntry
from ..update_text import _extract_kb
from ..wu_offer_probe import WindowsUpdateOffer
from .constants import (
    WINDOWS_UPDATE_PROBE_CORROBORATION_KIND,
    WINDOWS_UPDATE_PROBE_OFFER_LIMIT,
    WINDOWS_UPDATE_PROBE_UNAVAILABLE_KIND,
    _WINDOWS_UPDATE_PROBE_BUILD_RE,
    _WINDOWS_UPDATE_PROBE_KB_RE,
)
from .diagnostic_ids import _short_diagnostic_text
from .events import _human_join
from .keys import _build_key
from .msrc_cvrf import _as_sequence
from .observed import _history_build_maps
from .sources import AtomFeedEntry, WindowsUpdateProbe
from .support_articles import (
    _MONTH_NAMES,
    _SUPPORT_ARTICLE_VALIDATION_REASON_LIMIT,
    _atom_title_bucket,
    _record_msrc_month_id,
    _support_article_expected_facts,
)
from .support_validation import _support_article_validation_for_record
from .timestamps import _parse_source_timestamp


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

def _month_year_from_article_date(value: Any) -> str | None:
    match = re.fullmatch(r"([A-Za-z]+)\s+\d{1,2},\s+(20\d{2})", str(value or "").strip())
    if not match:
        return None
    return f"{match.group(1)} {match.group(2)}"

def _month_year_from_timestamp(value: Any) -> str | None:
    parsed = _parse_source_timestamp(str(value or "") or None)
    if parsed is None:
        return None
    return f"{_MONTH_NAMES[parsed.month - 1]} {parsed.year}"

def _support_article_notice_summary(event: Mapping[str, Any], article: Mapping[str, Any]) -> str | None:
    status = str(article.get("status") or "")
    validation_status = str(
        event.get("support_article_validation_status")
        or article.get("support_article_validation_status")
        or ""
    )
    if validation_status in {"mismatch", "unavailable", "skipped"}:
        return None
    if status not in {"ok", "degraded", "not_fetched"} and event.get("is_security") is not True:
        return None
    kb_article = str(event.get("kb_article") or article.get("kb_article") or "unknown KB")
    release = str(event.get("release") or "").strip()
    build = str(event.get("build") or "").strip()
    date_label = _month_year_from_article_date(article.get("release_date")) or _month_year_from_timestamp(
        event.get("published")
    )
    patch_type = "security update" if event.get("is_security") is True else "Windows update"
    release_text = f"Windows 11 {release}" if release else "Windows 11"
    build_text = f" build {build}" if build else ""
    kb_text = kb_article or "this KB"
    if event.get("affects_required_baseline"):
        intro = (
            f"Microsoft published {kb_text} for {release_text}{build_text}. This looks like the next "
            "stable broad-fleet baseline candidate, but this policy waits for Release Health baseline "
            "rules before requiring it"
        )
    else:
        intro = (
            f"Microsoft published {kb_text} for {release_text}{build_text}. This is official "
            "release-specific update evidence, but it is not the selected broad-fleet baseline in this policy"
        )
    if date_label:
        intro += f" ({patch_type}, {date_label})"
    else:
        intro += f" ({patch_type})"
    if release and build:
        movement = ""
    elif build:
        movement = f"; it reports build {build}"
    else:
        movement = "; Microsoft Support has public notes"
    summary = intro + movement
    labels = [str(label) for label in article.get("improvement_labels") or ()][:4]
    if labels:
        summary += f"; public notes mention {_human_join(labels)}"
    if validation_status == "degraded":
        reasons = [
            str(item)
            for item in _as_sequence(
                event.get("support_article_validation_reasons")
                or article.get("support_article_validation_reasons")
            )
            if str(item or "").strip()
        ][: _SUPPORT_ARTICLE_VALIDATION_REASON_LIMIT]
        if reasons:
            summary += f"; support article validation degraded: {', '.join(reasons)}"
    return summary + "."

def _event_with_support_article(
    event: dict[str, Any],
    article: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(article, Mapping):
        return event
    validation = _support_article_validation_for_record(event, article)
    event.update(validation)
    validation_status = str(validation.get("support_article_validation_status") or "")
    expected = _support_article_expected_facts(event)
    expected_kb = expected.get("kb")
    expected_build = expected.get("build")
    article_kb = _extract_kb(str(article.get("kb_article") or ""))
    article_builds = tuple(str(item) for item in _as_sequence(article.get("builds")) if str(item or "").strip())
    article_security_source = str(article.get("security_evidence_source") or "")
    for source_key, event_key in (
        ("status", "support_article_status"),
        ("url", "support_article_url"),
        ("title", "support_article_title"),
        ("kb_article", "support_article_kb_article"),
        ("builds", "support_article_builds"),
        ("release_date", "support_article_release_date"),
        ("applies_to", "support_article_applies_to"),
        ("applies_to_releases", "support_article_applies_to_releases"),
        ("known_issue_status", "support_article_known_issue_status"),
        ("improvement_labels", "support_article_improvement_labels"),
        ("is_security", "is_security"),
        ("security_evidence_source", "security_evidence_source"),
        ("security_severities", "security_severities"),
        ("security_products", "security_products"),
        ("security_signals", "security_signals"),
        ("msrc_cvrf_month_id", "msrc_cvrf_month_id"),
        ("msrc_cvrf_status", "msrc_cvrf_status"),
        ("msrc_cvrf_url", "msrc_cvrf_url"),
        ("msrc_cvrf_error", "msrc_cvrf_error"),
        ("reason", "support_article_reason"),
        ("error", "support_article_error"),
    ):
        value = article.get(source_key)
        if source_key in {
            "title",
            "release_date",
            "known_issue_status",
            "improvement_labels",
        } and validation_status not in {"ok", "degraded"}:
            continue
        if source_key == "kb_article" and expected_kb and article_kb != expected_kb:
            continue
        if source_key == "builds" and expected_build and expected_build not in article_builds:
            continue
        if source_key == "security_signals" and validation_status != "ok":
            continue
        if (
            source_key
            in {
                "is_security",
                "security_evidence_source",
                "security_severities",
                "security_products",
            }
            and validation_status != "ok"
            and article_security_source != "msrc_cvrf"
        ):
            continue
        if source_key == "is_security" and source_key in article:
            event[event_key] = value
            continue
        if value not in (None, "", [], ()):
            event[event_key] = value
    if validation_status != "ok" and article_security_source != "msrc_cvrf":
        event["is_security"] = None
        event["security_evidence_source"] = "unavailable"
    article_for_summary = dict(article)
    article_for_summary.update(validation)
    summary = _support_article_notice_summary(event, article_for_summary)
    if summary:
        event["notice_summary"] = summary
        event["user_message"] = summary
    return event

def _atom_newer_event(
    item: Mapping[str, Any],
    target: ReleasePolicyEntry | None,
    *,
    support_articles: Mapping[str, Mapping[str, Any]] | None = None,
    msrc_month_id_fallback_allowed: bool = False,
) -> dict[str, Any]:
    release = str(item.get("release") or "") or None
    build_family = item.get("build_family")
    kb_article = item.get("kb_article")
    has_kb_article = bool(_extract_kb(str(kb_article))) if kb_article else False
    affects_broad_target = bool(
        target is not None
        and release == target.version
        and build_family == target.build_family
    )
    affects_required_baseline = (
        affects_broad_target
        and has_kb_article
        and not bool(item.get("preview") or item.get("out_of_band"))
    )
    severity = "warning" if affects_required_baseline else "notice"
    build = str(item.get("build") or "")
    if severity == "warning":
        message = (
            "Servicing index shows a newer non-preview build for the broad target that is not present "
            f"in Release Health release_history: {kb_article or 'unknown KB'} build {build}."
        )
    else:
        message = (
            "Servicing index has newer Preview/OOB or non-baseline update information not present in "
            f"Release Health release_history: {kb_article or 'unknown KB'} build {build}."
        )
    event = {
        "severity": severity,
        "kind": "atom_newer_than_release_history",
        "release": release,
        "build_family": build_family,
        "build": build or None,
        "kb_article": kb_article,
        "affects_broad_target": affects_broad_target,
        "affects_required_baseline": affects_required_baseline,
        "message": message,
    }
    bucket = _atom_title_bucket(item.get("title"))
    event["kb_update_bucket"] = bucket["bucket"]
    event["kb_update_bucket_confidence"] = bucket["confidence"]
    for key in (
        "atom_entry_id",
        "atom_support_article_id",
        "atom_feed_url",
        "support_url",
        "diagnostic_id_hint",
        "published",
        "updated",
        "title",
    ):
        value = item.get(key)
        if value not in (None, ""):
            event[key] = value
    source_url = item.get("support_url") or item.get("atom_feed_url")
    if source_url not in (None, ""):
        event["source_url"] = source_url
    if support_articles and source_url not in (None, ""):
        event = _event_with_support_article(event, support_articles.get(str(source_url)))
    if msrc_month_id_fallback_allowed and "msrc_cvrf_month_id" not in event:
        # Only reached when no support-article or MSRC CVRF fetcher was configured for this
        # run at all (see msrc_month_id_fallback_allowed at the call site) — e.g. tests and
        # other offline callers of generate_policy(). When real fetchers are configured,
        # this never fires, so records that _records_for_support_article_enrichment
        # deliberately excludes (preview/out-of-band, non-target release/build_family) keep
        # carrying no msrc_cvrf_month_id, exactly as before.
        month_id = _record_msrc_month_id(item)
        if month_id:
            event["msrc_cvrf_month_id"] = month_id
    return event

def _is_unresolved_source_drift_event(event: Mapping[str, Any]) -> bool:
    return (
        str(event.get("severity") or "") in {"warning", "error"}
        and str(event.get("kind") or "")
        in {"atom_newer_than_release_history", "current_versions_lag_release_history"}
    )

def _current_versions_lag_event(item: Mapping[str, Any], target: ReleasePolicyEntry | None) -> dict[str, Any]:
    release = str(item.get("version") or "") or None
    build_family = item.get("build_family")
    build = item.get("newest_release_history_build")
    affects_broad_target = bool(
        target is not None
        and release == target.version
        and build_family == target.build_family
    )
    return {
        "severity": "warning",
        "kind": "current_versions_lag_release_history",
        "release": release,
        "build_family": build_family,
        "build": build,
        "kb_article": None,
        "affects_broad_target": affects_broad_target,
        "affects_required_baseline": False,
        "message": (
            "Current Versions latest_build appears older than Release History for "
            f"{release}/{build_family}: {item.get('latest_build') or 'unknown'} < {build}."
        ),
    }

def _source_diagnostic_messages(events: list[dict[str, Any]], *, minimum: str = "warning") -> list[str]:
    severities = {"notice": 0, "warning": 1, "error": 2}
    threshold = severities[minimum]
    return [
        str(event["message"])
        for event in events
        if severities.get(str(event.get("severity") or ""), -1) >= threshold
        and event.get("message")
    ]

def _source_diagnostic_notices(events: list[dict[str, Any]]) -> list[str]:
    return [
        str(event["message"])
        for event in events
        if event.get("severity") == "notice" and event.get("message")
    ]

def _source_input_event(kind: str, message: str, *, severity: str = "warning") -> dict[str, Any]:
    return {
        "severity": severity,
        "kind": kind,
        "release": None,
        "build_family": None,
        "build": None,
        "kb_article": None,
        "affects_broad_target": False,
        "affects_required_baseline": False,
        "message": message,
    }

def _windows_update_offer_label(offer: WindowsUpdateOffer) -> str:
    build = str(offer.build or "").strip()
    kb_article = str(offer.kb_article or "").strip()
    if not _WINDOWS_UPDATE_PROBE_BUILD_RE.match(build):
        build = ""
    if not _WINDOWS_UPDATE_PROBE_KB_RE.match(kb_article):
        kb_article = ""
    if build and kb_article:
        return f"{build} ({kb_article})"
    return build or kb_article

def _windows_update_probe_events(probe: WindowsUpdateProbe | None) -> list[dict[str, Any]]:
    if probe is None:
        return []
    try:
        offers = tuple(probe())
    except Exception as exc:  # Corroborating evidence must never block generation.
        detail = _short_diagnostic_text(exc, max_length=90) or "no detail reported"
        return [
            _source_input_event(
                WINDOWS_UPDATE_PROBE_UNAVAILABLE_KIND,
                f"Windows Update offer probe reported no corroborating evidence: {detail}",
                severity="notice",
            )
        ]
    labels = [
        label
        for label in (_windows_update_offer_label(offer) for offer in offers[:WINDOWS_UPDATE_PROBE_OFFER_LIMIT])
        if label
    ]
    if not labels:
        return [
            _source_input_event(
                WINDOWS_UPDATE_PROBE_UNAVAILABLE_KIND,
                "Windows Update offer probe reported no corroborating evidence: "
                "the offer snapshot carried no build or KB article.",
                severity="notice",
            )
        ]
    return [
        _source_input_event(
            WINDOWS_UPDATE_PROBE_CORROBORATION_KIND,
            f"Windows Update offers corroborate the document sources: {_human_join(labels)}.",
            severity="notice",
        )
    ]

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
