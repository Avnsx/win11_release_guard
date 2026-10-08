"""The dashboard-only baseline-update notice."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any, Mapping
from ..models import ReleaseHistoryEntry, ReleasePolicyEntry
from ..update_text import _extract_kb
from .events import _human_join
from .keys import _history_sort_key
from .msrc_cvrf import _as_sequence
from .security_events import _security_result_for_record
from .support_articles import (
    _SUPPORT_ARTICLE_IMPROVEMENT_DETAIL_LIMIT,
    _SUPPORT_ARTICLE_IMPROVEMENT_DETAIL_MAX_LENGTH,
    _SUPPORT_ARTICLE_VALIDATION_REASON_LIMIT,
    _msrc_month_id_from_atom_date,
    _safe_support_article_url,
)
from .timestamps import (
    _baseline_notice_official_date,
    _datetime_utc_z,
    _parse_source_timestamp,
    _source_timestamp_utc_z,
)


_BASELINE_UPDATE_NOTICE_SCHEMA = "win11_release_guard.baseline_update_notice.v1"

_BASELINE_UPDATE_NOTICE_WINDOW_DAYS = 14

def _baseline_notice_source_url(row: ReleaseHistoryEntry) -> str | None:
    metadata_url = row.metadata.get("atom_feed_url") if isinstance(row.metadata, Mapping) else None
    return _safe_support_article_url(str(metadata_url or "") or None)

def _required_baseline_history_row(
    target: ReleasePolicyEntry | None,
    release_history: tuple[ReleaseHistoryEntry, ...],
) -> ReleaseHistoryEntry | None:
    if target is None or not target.required_baseline_build:
        return None
    candidates = [
        row
        for row in release_history
        if row.release == target.version
        and row.build_family == target.build_family
        and row.build == target.required_baseline_build
        and row.update_type_letter == "B"
        and not row.preview
        and not row.out_of_band
    ]
    if not candidates:
        return None
    return max(candidates, key=_history_sort_key)

def _baseline_update_notice_record(
    target: ReleasePolicyEntry | None,
    row: ReleaseHistoryEntry | None,
) -> dict[str, Any] | None:
    if (
        target is None
        or row is None
        or not target.required_baseline_build
        or target.required_baseline_build != target.latest_observed_build
    ):
        return None
    source_url = _baseline_notice_source_url(row)
    metadata = row.metadata if isinstance(row.metadata, Mapping) else {}
    published = metadata.get("atom_published")
    updated = metadata.get("atom_updated")
    record = {
        "release": row.release,
        "build_family": row.build_family,
        "build": row.build,
        "kb_article": row.kb_article,
        "update_type": row.update_type,
        "update_type_letter": row.update_type_letter,
        "quality_policy": target.quality_policy.value,
        "availability_date": row.availability_date,
        "support_url": source_url,
        "atom_feed_url": source_url,
        "source_url": source_url,
        "published": published,
        "updated": updated,
        "atom_entry_id": metadata.get("atom_entry_id"),
        "atom_support_article_id": metadata.get("atom_support_article_id"),
        "diagnostic_id_hint": metadata.get("diagnostic_id_hint"),
        "baseline_update_notice": True,
        "preview": row.preview,
        "out_of_band": row.out_of_band,
    }
    # MSRC month fallback: when the servicing index has no entry attached to
    # the new baseline KB, there is no published/updated date to derive an
    # MSRC month from. Fall back to the Release Health baseline month (the
    # same official_release_date the notice reports) so MSRC CVRF can still
    # classify the baseline KB. Only the baseline record ever carries this.
    if not published and not updated:
        official_date = _baseline_notice_official_date(row.availability_date)
        if official_date is not None:
            record["msrc_cvrf_month_fallback"] = _msrc_month_id_from_atom_date(
                _datetime_utc_z(official_date)
            )
    return {key: value for key, value in record.items() if value not in (None, "", [], ())}

def _baseline_notice_visibility_window(
    row: ReleaseHistoryEntry,
) -> tuple[str, str, str, str] | None:
    visible_from = _baseline_notice_official_date(row.availability_date)
    if visible_from is None:
        return None
    official_date = f"{visible_from.year:04d}-{visible_from.month:02d}-{visible_from.day:02d}"
    visible_until = visible_from + timedelta(days=_BASELINE_UPDATE_NOTICE_WINDOW_DAYS)
    return official_date, "date", _datetime_utc_z(visible_from), _datetime_utc_z(visible_until)

def _baseline_notice_is_active(
    row: ReleaseHistoryEntry | None,
    *,
    generated_at_utc: str,
) -> bool:
    if row is None:
        return False
    visibility = _baseline_notice_visibility_window(row)
    if visibility is None:
        return False
    _, _, visible_from_utc, visible_until_utc = visibility
    generated_dt = _parse_source_timestamp(generated_at_utc)
    visible_from_dt = _parse_source_timestamp(visible_from_utc)
    visible_until_dt = _parse_source_timestamp(visible_until_utc)
    return bool(
        generated_dt
        and visible_from_dt
        and visible_until_dt
        and visible_from_dt <= generated_dt < visible_until_dt
    )

def _baseline_notice_security_evidence_status(
    is_security: Any,
    evidence_source: str,
) -> str:
    if is_security is True and evidence_source in {"msrc_cvrf", "support_article"}:
        return "trusted"
    if is_security is False:
        return "not_security"
    return "unknown"

def _security_evidence_display_label(*, is_security: Any, evidence_source: Any) -> str | None:
    source = str(evidence_source or "").strip().lower()
    if is_security is True:
        if source == "msrc_cvrf":
            return "Security confirmed by MSRC"
        if source == "support_article":
            return "Security confirmed by Microsoft Support"
        return "Security confirmed"
    if is_security is False:
        return "Non-security according to trusted evidence"
    return None

def _baseline_notice_security_sentence(is_security: Any, evidence_source: Any) -> str:
    """Source-aware, human-facing security sentence for the baseline summary.

    MSRC wording is used only for exact MSRC CVRF evidence; validated Support
    article evidence is attributed to Microsoft Support; unavailable/unknown/none
    evidence (or ``is_security`` None) yields neutral wording; ``is_security``
    False yields clear, non-alarmist wording. No raw enum/status tokens
    (``msrc_cvrf``, ``support_article``, ``not_security``, ...) are emitted.
    """
    if is_security is True:
        source = str(evidence_source or "").strip().lower()
        if source == "msrc_cvrf":
            return "MSRC confirms it as a security update."
        if source == "support_article":
            return "Microsoft Support notes it includes the security update."
        return "Checked evidence classifies it as a security update."
    if is_security is False:
        return "Checked evidence does not classify it as a security update."
    return "Security classification is unavailable from the checked enrichment source."

def _baseline_notice_summary(
    *,
    release: str,
    build: str,
    kb_article: str | None,
    update_type: str | None,
    official_release_date: str,
    is_security: Any,
    security_evidence_source: Any = None,
) -> str:
    kb_text = kb_article or "the selected KB"
    update_text = update_type or "B-release"
    # Build complete sentences and join with a single space so the visible copy
    # never produces punctuation artifacts such as "B.;" and never leaks raw
    # status enums into human-facing text.
    sentences = (
        f"New required baseline: Windows 11 {release} build {build} now matches Microsoft "
        f"evidence and the signed fleet baseline.",
        f"For broad-fleet {release} devices, this likely marks the stable rollout floor for "
        f"{kb_text} / {update_text}.",
        f"Release Health lists the baseline date as {official_release_date}.",
        _baseline_notice_security_sentence(is_security, security_evidence_source),
    )
    return " ".join(sentence for sentence in sentences if sentence)

def _baseline_notice_update_summary(article: Mapping[str, Any], validation_status: str) -> str | None:
    if validation_status not in {"ok", "degraded"}:
        return None
    details: list[str] = []
    for item in _as_sequence(article.get("improvement_details")):
        text = re.sub(r"\s+", " ", str(item or "")).strip()
        if not text or len(text) > _SUPPORT_ARTICLE_IMPROVEMENT_DETAIL_MAX_LENGTH + 1 or text in details:
            continue
        details.append(text)
        if len(details) >= _SUPPORT_ARTICLE_IMPROVEMENT_DETAIL_LIMIT:
            break
    if details:
        return "Update highlights: " + " ".join(details)
    labels: list[str] = []
    for item in _as_sequence(article.get("improvement_labels")):
        text = re.sub(r"\s+", " ", str(item or "")).strip()
        if not text or len(text) > 80 or text in labels:
            continue
        labels.append(text)
        if len(labels) >= 4:
            break
    if not labels:
        return None
    return f"Update highlights: public notes mention {_human_join(labels)}."

def _baseline_update_notice_payload(
    *,
    target: ReleasePolicyEntry | None,
    row: ReleaseHistoryEntry | None,
    baseline_record: Mapping[str, Any] | None,
    support_articles: Mapping[str, Mapping[str, Any]],
    msrc_payloads: Mapping[str, Mapping[str, Any]],
    msrc_statuses: Mapping[str, Mapping[str, Any]],
    generated_at_utc: str,
) -> dict[str, Any] | None:
    if target is None or row is None or baseline_record is None:
        return None
    visibility = _baseline_notice_visibility_window(row)
    if visibility is None:
        return None
    official_release_date, official_release_precision, visible_from_utc, visible_until_utc = visibility
    generated_dt = _parse_source_timestamp(generated_at_utc)
    visible_from_dt = _parse_source_timestamp(visible_from_utc)
    visible_until_dt = _parse_source_timestamp(visible_until_utc)
    active = bool(
        generated_dt
        and visible_from_dt
        and visible_until_dt
        and visible_from_dt <= generated_dt < visible_until_dt
    )
    source_url = str(baseline_record.get("support_url") or baseline_record.get("atom_feed_url") or "") or None
    article = support_articles.get(source_url or "") if source_url else None
    if not isinstance(article, Mapping):
        article = {}
    if not source_url and baseline_record.get("msrc_cvrf_month_fallback"):
        # Atom feed lag: no Atom-linked Support article exists (support validation
        # stays "unavailable"), but the Release Health baseline month lets MSRC
        # CVRF classify the baseline KB with an exact KB-token join. No support
        # article is fetched or synthesized.
        fallback_security = _security_result_for_record(
            baseline_record,
            None,
            msrc_payloads=msrc_payloads,
            msrc_statuses=msrc_statuses,
        )
        is_security = fallback_security.get("is_security")
        security_evidence_source = str(fallback_security.get("evidence_source") or "unavailable")
    else:
        is_security = article.get("is_security") if "is_security" in article else None
        security_evidence_source = str(article.get("security_evidence_source") or "unavailable")
    security_evidence_status = _baseline_notice_security_evidence_status(
        is_security,
        security_evidence_source,
    )
    validation_status = str(article.get("support_article_validation_status") or "unavailable")
    validation_reasons = [
        str(item)
        for item in _as_sequence(article.get("support_article_validation_reasons"))
        if str(item or "").strip()
    ][: _SUPPORT_ARTICLE_VALIDATION_REASON_LIMIT]
    update_summary = _baseline_notice_update_summary(article, validation_status)
    improvement_labels = [
        str(item).strip()
        for item in _as_sequence(article.get("improvement_labels"))
        if str(item or "").strip()
    ][:4] if update_summary else []
    improvement_details = [
        str(item).strip()
        for item in _as_sequence(article.get("improvement_details"))
        if str(item or "").strip()
    ][: _SUPPORT_ARTICLE_IMPROVEMENT_DETAIL_LIMIT] if update_summary else []
    first_spotted = _source_timestamp_utc_z(baseline_record.get("published"))
    updated = _source_timestamp_utc_z(baseline_record.get("updated"))
    release_health_revision = str(target.metadata.get("latest_revision_date") or "") or None
    kb_article = _extract_kb(str(row.kb_article or ""))
    summary = _baseline_notice_summary(
        release=target.version,
        build=row.build,
        kb_article=kb_article,
        update_type=row.update_type,
        official_release_date=official_release_date,
        is_security=is_security,
        security_evidence_source=security_evidence_source,
    )
    security_detail = _security_evidence_display_label(
        is_security=is_security,
        evidence_source=security_evidence_source,
    )
    technical_summary = (
        f"Release Health selected {row.update_type or 'unknown update type'} for Windows 11 "
        f"{target.version} build {row.build}; support validation {validation_status}."
    )
    if security_detail:
        technical_summary += f" {security_detail}."
    payload: dict[str, Any] = {
        "schema": _BASELINE_UPDATE_NOTICE_SCHEMA,
        "active": active,
        "release": target.version,
        "build_family": target.build_family,
        "build": row.build,
        "kb_article": kb_article,
        "update_type": row.update_type,
        "quality_policy": target.quality_policy.value,
        "summary": summary,
        "update_summary": update_summary,
        "technical_summary": technical_summary,
        "source_url": source_url,
        "atom_entry_id": baseline_record.get("atom_entry_id"),
        "atom_support_article_id": baseline_record.get("atom_support_article_id"),
        "first_spotted_atom_published_utc": first_spotted,
        "support_article_updated_utc": updated,
        "official_release_date": official_release_date,
        "official_release_precision": official_release_precision,
        "release_health_latest_revision_date": release_health_revision,
        "visible_from_utc": visible_from_utc,
        "visible_until_utc": visible_until_utc,
        "policy_generated_at_utc": generated_at_utc,
        "is_security": is_security,
        "security_evidence_source": security_evidence_source,
        "security_evidence_status": security_evidence_status,
        "support_article_validation_status": validation_status,
        "support_article_validation_reasons": validation_reasons,
        "support_article_improvement_labels": improvement_labels,
        "support_article_improvement_details": improvement_details,
    }
    return {key: value for key, value in payload.items() if value not in (None, "", [], {})}

def _baseline_update_notice_event(notice: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(notice, Mapping) or notice.get("active") is not True:
        return None
    event: dict[str, Any] = {
        "severity": "notice",
        "kind": "required_baseline_matched_latest_observed",
        "release": notice.get("release"),
        "build_family": notice.get("build_family"),
        "build": notice.get("build"),
        "kb_article": notice.get("kb_article"),
        "affects_broad_target": True,
        "affects_required_baseline": True,
        "message": notice.get("technical_summary") or notice.get("summary"),
        "user_message": notice.get("summary"),
        "source_url": notice.get("source_url"),
        "atom_entry_id": notice.get("atom_entry_id"),
        "atom_support_article_id": notice.get("atom_support_article_id"),
        "published": notice.get("first_spotted_atom_published_utc"),
        "updated": notice.get("support_article_updated_utc"),
        "support_article_url": notice.get("source_url"),
        "support_article_validation_status": notice.get("support_article_validation_status"),
        "support_article_validation_reasons": notice.get("support_article_validation_reasons"),
        "security_evidence_source": notice.get("security_evidence_source"),
        "is_security": notice.get("is_security"),
    }
    return {key: value for key, value in event.items() if value not in (None, "", [], {})}
