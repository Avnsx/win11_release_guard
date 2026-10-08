"""Validating Support article enrichment against history records."""

from __future__ import annotations

from typing import Any, Mapping
from ..models import ReleaseHistoryEntry, ReleasePolicyEntry
from ..update_text import _extract_kb
from .events import _dedupe_source_events
from .keys import _history_sort_key
from .msrc_cvrf import _as_sequence
from .observed import _atom_newer_than_history, _atom_observed_record_is_preferred
from .sources import AtomFeedEntry
from .support_articles import (
    SupportArticleFetcher,
    _SUPPORT_ARTICLE_VALIDATION_REASON_LIMIT,
    _compact_article_text,
    _msrc_month_id_from_atom_date,
    _normalized_support_article_release_values,
    _safe_support_article_url,
    _support_article_canonical_url,
    _support_article_enrichment,
    _support_article_expected_facts,
    _support_article_record_url,
    _support_article_releases_from_applies_to,
)
from .timestamps import _baseline_notice_official_date, _datetime_utc_z


def _support_article_applies_to_compatibility(
    value: Any,
    *,
    release: str | None,
    build_family: Any = None,
    applies_to_releases: Any = None,
) -> str:
    del build_family
    text = _compact_article_text(str(value or ""))
    explicit_releases = _normalized_support_article_release_values(applies_to_releases)
    if not text and not explicit_releases:
        return "unknown"
    normalized = text.lower()
    if text and "windows" not in normalized and not explicit_releases:
        return "unknown"
    if text and "windows 10" in normalized and "windows 11" not in normalized:
        return "incompatible"
    releases = explicit_releases or _support_article_releases_from_applies_to(text)
    expected_release = str(release or "").strip().upper()
    if expected_release and releases:
        return "compatible" if expected_release in releases else "incompatible"
    if text and "windows 11" in normalized:
        return "unknown"
    return "incompatible"

def _support_article_validation_for_record(
    record: Mapping[str, Any],
    article: Mapping[str, Any] | None,
) -> dict[str, Any]:
    expected = _support_article_expected_facts(record)
    validation: dict[str, Any] = {
        "support_article_expected_kb": expected.get("kb"),
        "support_article_expected_build": expected.get("build"),
        "support_article_expected_release": expected.get("release"),
    }
    if not isinstance(article, Mapping):
        validation["support_article_validation_status"] = "unavailable"
        validation["support_article_validation_reasons"] = ["not_fetched"]
        return {key: value for key, value in validation.items() if value not in (None, "", [], ())}

    status = str(article.get("status") or "")
    mismatch_reasons: list[str] = []
    degraded_reasons: list[str] = []

    if status == "skipped":
        degraded_reasons.append(str(article.get("reason") or "skipped"))
    elif status in {"error", "unavailable", "not_fetched"}:
        degraded_reasons.append(str(article.get("reason") or article.get("error") or status or "unavailable"))
    elif status == "degraded":
        degraded_reasons.append(str(article.get("reason") or article.get("error") or "support_article_degraded"))

    expected_url = _support_article_canonical_url(_support_article_record_url(record))
    actual_url = _support_article_canonical_url(article.get("url"))
    if expected_url and actual_url and expected_url != actual_url:
        mismatch_reasons.append("url_mismatch")
    elif expected_url and not actual_url:
        degraded_reasons.append("url_unavailable")

    expected_kb = expected.get("kb")
    article_kb = _extract_kb(str(article.get("kb_article") or ""))
    if expected_kb:
        if article_kb and article_kb != expected_kb:
            mismatch_reasons.append("kb_mismatch")
        elif not article_kb and status == "ok":
            degraded_reasons.append("kb_missing")

    expected_build = expected.get("build")
    article_builds = tuple(str(item) for item in _as_sequence(article.get("builds")) if str(item or "").strip())
    if expected_build:
        if article_builds and expected_build not in article_builds:
            mismatch_reasons.append("build_missing")
        elif not article_builds and status == "ok":
            degraded_reasons.append("builds_missing")

    expected_release = expected.get("release")
    applies_to = article.get("applies_to")
    if expected_release:
        applies_compatibility = _support_article_applies_to_compatibility(
            applies_to,
            release=expected_release,
            build_family=record.get("build_family"),
            applies_to_releases=article.get("applies_to_releases"),
        )
        if applies_compatibility == "incompatible":
            mismatch_reasons.append("applies_to_mismatch")
        elif applies_compatibility == "unknown" and status == "ok":
            degraded_reasons.append("applies_to_missing" if applies_to in (None, "") else "applies_to_unknown")

    if mismatch_reasons:
        validation_status = "mismatch"
        reasons = mismatch_reasons + degraded_reasons
    elif status == "skipped":
        validation_status = "skipped"
        reasons = degraded_reasons or ["skipped"]
    elif status in {"error", "unavailable", "not_fetched"}:
        validation_status = "unavailable"
        reasons = degraded_reasons or ["unavailable"]
    elif degraded_reasons or status == "degraded":
        validation_status = "degraded"
        reasons = degraded_reasons or ["support_article_degraded"]
    else:
        validation_status = "ok"
        reasons = []

    validation["support_article_validation_status"] = validation_status
    if reasons:
        validation["support_article_validation_reasons"] = list(dict.fromkeys(reasons))[
            :_SUPPORT_ARTICLE_VALIDATION_REASON_LIMIT
        ]
    return {key: value for key, value in validation.items() if value not in (None, "", [], ())}

def _release_history_enrichment_record(
    target: ReleasePolicyEntry | None,
    release_history: tuple[ReleaseHistoryEntry, ...],
) -> dict[str, Any] | None:
    if target is None:
        return None
    candidates = [
        row
        for row in release_history
        if row.release == target.version
        and row.build_family == target.build_family
        and not row.preview
        and not row.out_of_band
        and (row.update_type_letter or "B") == "B"
        and _extract_kb(row.kb_article)
    ]
    if not candidates:
        return None
    row = max(candidates, key=_history_sort_key)
    metadata = row.metadata if isinstance(row.metadata, Mapping) else {}
    support_url = _safe_support_article_url(str(metadata.get("atom_feed_url") or "") or None)
    record: dict[str, Any] = {
        "release": row.release,
        "build_family": row.build_family,
        "build": row.build,
        "kb_article": _extract_kb(row.kb_article),
        "update_type": row.update_type,
        "update_type_letter": row.update_type_letter,
        "availability_date": row.availability_date,
        "release_history_record": True,
        "preview": row.preview,
        "out_of_band": row.out_of_band,
    }
    if support_url:
        record["support_url"] = support_url
        record["atom_feed_url"] = support_url
    official_date = _baseline_notice_official_date(row.availability_date)
    if official_date is not None:
        month_id = _msrc_month_id_from_atom_date(_datetime_utc_z(official_date))
        if month_id:
            record["msrc_cvrf_month_fallback"] = month_id
    return {key: value for key, value in record.items() if value not in (None, "", [], ())}

def _records_for_support_article_enrichment(
    *,
    target: ReleasePolicyEntry | None,
    atom_entries: tuple[AtomFeedEntry, ...],
    release_history: tuple[ReleaseHistoryEntry, ...],
    observed_record: Mapping[str, Any] | None,
    baseline_update_record: Mapping[str, Any] | None = None,
    release_history_record: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], ...]:
    if target is None:
        return ()
    records_by_url: dict[str, dict[str, Any]] = {}
    urlless_records: list[dict[str, Any]] = []
    if observed_record is not None:
        url = _support_article_record_url(observed_record)
        if url:
            records_by_url[url] = dict(observed_record)
    if baseline_update_record is not None:
        url = _support_article_record_url(baseline_update_record)
        if url:
            if url not in records_by_url:
                records_by_url[url] = dict(baseline_update_record)
        elif baseline_update_record.get("msrc_cvrf_month_fallback"):
            # Atom feed lag: the baseline record has no support URL, but the
            # Release Health baseline month still lets MSRC CVRF classify the
            # baseline KB. Keep it in the enrichment set (with no URL, so no
            # support article is fetched) so MSRC payload fetching, the KB join,
            # and the MSRC warning event can all see its month id.
            urlless_records.append(dict(baseline_update_record))

    for record in _atom_newer_than_history(atom_entries, release_history):
        url = _support_article_record_url(record)
        if not url:
            continue
        if record.get("preview") or record.get("out_of_band"):
            continue
        if record.get("release") != target.version or record.get("build_family") != target.build_family:
            continue
        if not _extract_kb(str(record.get("kb_article") or "")):
            continue
        current = records_by_url.get(url)
        if current is None or _atom_observed_record_is_preferred(record, current):
            records_by_url[url] = dict(record)
    if release_history_record is not None:
        record = dict(release_history_record)
        build = str(record.get("build") or "")
        url = _support_article_record_url(record)
        already_known = any(
            str(existing.get("build") or "") == build
            for existing in (*records_by_url.values(), *urlless_records)
        )
        if not already_known:
            if url:
                records_by_url.setdefault(url, record)
            elif record.get("msrc_cvrf_month_fallback"):
                urlless_records.append(record)

    return (*(records_by_url[url] for url in sorted(records_by_url)), *urlless_records)

def _support_article_enrichments(
    records: tuple[Mapping[str, Any], ...],
    *,
    fetcher: SupportArticleFetcher | None,
    timeout: float,
) -> dict[str, dict[str, Any]]:
    if fetcher is None:
        return {}
    enrichments: dict[str, dict[str, Any]] = {}
    for record in records:
        url = _support_article_record_url(record)
        if not url or url in enrichments:
            continue
        enrichment = _support_article_enrichment(
            url,
            fetcher=fetcher,
            timeout=timeout,
        )
        enrichment.update(_support_article_validation_for_record(record, enrichment))
        enrichments[url] = enrichment
    return enrichments

def _support_article_enrichment_event(
    record: Mapping[str, Any],
    enrichment: Mapping[str, Any],
    target: ReleasePolicyEntry | None,
) -> dict[str, Any] | None:
    status = str(enrichment.get("status") or "")
    validation_status = str(enrichment.get("support_article_validation_status") or "")
    validation_reasons = [
        str(item)
        for item in _as_sequence(enrichment.get("support_article_validation_reasons"))
        if str(item or "").strip()
    ][: _SUPPORT_ARTICLE_VALIDATION_REASON_LIMIT]
    if status == "not_fetched" and validation_status not in {"mismatch", "degraded", "unavailable", "skipped"}:
        return None
    if status == "ok" and validation_status in {"", "ok"}:
        return None
    release = str(record.get("release") or "") or None
    build_family = record.get("build_family")
    build = str(record.get("build") or "") or None
    kb_article = _extract_kb(str(record.get("kb_article") or "")) or None
    affects_broad_target = bool(
        target is not None
        and release == target.version
        and build_family == target.build_family
    )
    if validation_status == "mismatch":
        kind = "support_article_enrichment_mismatch"
    elif validation_status == "degraded" or status == "degraded":
        kind = "support_article_enrichment_degraded"
    else:
        kind = "support_article_enrichment_unavailable"
    url = str(enrichment.get("url") or record.get("support_url") or record.get("atom_feed_url") or "")
    effective_status = validation_status or status or "unavailable"
    message = (
        f"Support article enrichment for {kb_article or 'unknown KB'} build {build or 'unknown'} "
        f"is {effective_status} at {url or 'unknown URL'}."
    )
    if validation_reasons:
        message += f" Validation reasons: {', '.join(validation_reasons)}."
    if enrichment.get("error"):
        message += f" {enrichment['error']}"
    event = {
        "severity": "warning" if affects_broad_target else "notice",
        "kind": kind,
        "release": release,
        "build_family": build_family,
        "build": build,
        "kb_article": kb_article,
        "affects_broad_target": affects_broad_target,
        "affects_required_baseline": False,
        "message": message,
        "source_url": url or None,
        "support_article_status": status or "unavailable",
        "support_article_error": enrichment.get("error"),
        "support_article_reason": enrichment.get("reason"),
        "support_article_validation_status": validation_status or None,
        "support_article_validation_reasons": validation_reasons,
        "support_article_expected_kb": enrichment.get("support_article_expected_kb"),
        "support_article_expected_build": enrichment.get("support_article_expected_build"),
        "support_article_expected_release": enrichment.get("support_article_expected_release"),
        "atom_entry_id": record.get("atom_entry_id"),
        "atom_support_article_id": record.get("atom_support_article_id"),
        "atom_feed_url": record.get("atom_feed_url"),
    }
    return {key: value for key, value in event.items() if value not in (None, "")}

def _support_article_enrichment_events(
    records: tuple[Mapping[str, Any], ...],
    enrichments: Mapping[str, Mapping[str, Any]],
    target: ReleasePolicyEntry | None,
) -> tuple[dict[str, Any], ...]:
    events: list[dict[str, Any]] = []
    for record in records:
        url = _support_article_record_url(record)
        if not url:
            # A baseline record with no support URL never attempted a fetch, so
            # there is nothing to surface; skip it silently as before.
            continue
        enrichment = enrichments.get(url)
        if not isinstance(enrichment, Mapping):
            continue
        if record.get("baseline_update_notice"):
            # Baseline records normally stay quiet because the baseline notice
            # carries its own dashboard event. But a real support-article fetch
            # failure (status other than "ok") for a baseline record that HAS a
            # source_url must no longer be silently swallowed.
            if str(enrichment.get("status") or "") == "ok":
                continue
        event = _support_article_enrichment_event(record, enrichment, target)
        if event is not None:
            events.append(event)
    return tuple(_dedupe_source_events(events))
