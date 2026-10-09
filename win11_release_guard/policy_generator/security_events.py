"""Security classification from MSRC and Support evidence."""

from __future__ import annotations

from typing import Any, Mapping
from ..models import ReleasePolicyEntry
from .constants import DEFAULT_MAX_MSRC_CVRF_BYTES, PROGRAMMING_ERROR_TYPES
from .events import _dedupe_source_events
from .msrc_cvrf import MsrcCvrfFetcher, _cvrf_kb_join, _msrc_cvrf_url
from .support_articles import _record_msrc_month_id, _support_article_record_url, _support_article_security_result
from .support_validation import _support_article_validation_for_record


def _msrc_cvrf_payloads(
    records: tuple[Mapping[str, Any], ...],
    *,
    fetcher: MsrcCvrfFetcher | None,
    timeout: float,
) -> tuple[dict[str, Mapping[str, Any]], dict[str, dict[str, Any]]]:
    if fetcher is None:
        return {}, {}
    month_ids = sorted(
        {
            month_id
            for record in records
            if (month_id := _record_msrc_month_id(record))
        }
    )
    payloads: dict[str, Mapping[str, Any]] = {}
    statuses: dict[str, dict[str, Any]] = {}
    for month_id in month_ids:
        url = _msrc_cvrf_url(month_id)
        try:
            payload = fetcher(url, timeout, DEFAULT_MAX_MSRC_CVRF_BYTES)
        except PROGRAMMING_ERROR_TYPES:
            raise
        except Exception as exc:
            statuses[month_id] = {
                "status": "error",
                "url": url,
                "error": str(exc),
            }
            continue
        if not isinstance(payload, Mapping):
            statuses[month_id] = {
                "status": "degraded",
                "url": url,
                "error": "MSRC CVRF response must be a JSON object.",
            }
            continue
        payloads[month_id] = payload
        statuses[month_id] = {
            "status": "ok",
            "url": url,
        }
    return payloads, statuses


def _security_result_for_record(
    record: Mapping[str, Any],
    article: Mapping[str, Any] | None,
    *,
    msrc_payloads: Mapping[str, Mapping[str, Any]],
    msrc_statuses: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    month_id = _record_msrc_month_id(record)
    msrc_status = msrc_statuses.get(str(month_id or ""))
    if month_id and msrc_status and msrc_status.get("status") == "ok":
        cvrf_result = _cvrf_kb_join(msrc_payloads.get(month_id, {}), str(record.get("kb_article") or ""))
        if cvrf_result["is_security"] is True:
            return {
                **cvrf_result,
                "msrc_cvrf_month_id": month_id,
                "msrc_cvrf_status": "ok",
                "msrc_cvrf_url": msrc_status.get("url"),
            }
        support_result = _support_article_security_result(article)
        if support_result["is_security"] is True:
            return {
                **support_result,
                "msrc_cvrf_month_id": month_id,
                "msrc_cvrf_status": "ok",
                "msrc_cvrf_url": msrc_status.get("url"),
            }
        return {
            **cvrf_result,
            "msrc_cvrf_month_id": month_id,
            "msrc_cvrf_status": "ok",
            "msrc_cvrf_url": msrc_status.get("url"),
        }

    support_result = _support_article_security_result(article)
    if support_result["is_security"] is True:
        result = dict(support_result)
    elif msrc_status:
        result = {
            "is_security": None,
            "cves": [],
            "severities": [],
            "products": [],
            "evidence_source": "unavailable",
        }
    else:
        result = support_result
    if month_id and msrc_status:
        result.update(
            {
                "msrc_cvrf_month_id": month_id,
                "msrc_cvrf_status": str(msrc_status.get("status") or "unavailable"),
                "msrc_cvrf_url": msrc_status.get("url"),
            }
        )
        if msrc_status.get("error"):
            result["msrc_cvrf_error"] = msrc_status.get("error")
    return result


def _support_articles_with_security(
    records: tuple[Mapping[str, Any], ...],
    support_articles: Mapping[str, Mapping[str, Any]],
    *,
    msrc_payloads: Mapping[str, Mapping[str, Any]],
    msrc_statuses: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    enriched = {str(url): dict(article) for url, article in support_articles.items()}
    for record in records:
        url = _support_article_record_url(record)
        if not url:
            continue
        article = dict(enriched.get(url) or {"url": url, "status": "not_fetched"})
        article.update(_support_article_validation_for_record(record, article))
        article_for_security = (
            article if article.get("support_article_validation_status") == "ok" else None
        )
        security = _security_result_for_record(
            record,
            article_for_security,
            msrc_payloads=msrc_payloads,
            msrc_statuses=msrc_statuses,
        )
        article["is_security"] = security.get("is_security")
        article["security_evidence_source"] = security.get("evidence_source")
        if security.get("severities"):
            article["security_severities"] = security["severities"]
        if security.get("products"):
            article["security_products"] = security["products"]
        for key in ("msrc_cvrf_month_id", "msrc_cvrf_status", "msrc_cvrf_url", "msrc_cvrf_error"):
            value = security.get(key)
            if value not in (None, ""):
                article[key] = value
        if article.get("support_article_validation_status") != "ok":
            article.pop("security_signals", None)
        cleaned = {key: value for key, value in article.items() if value not in (None, "", [], ())}
        if "is_security" in article:
            cleaned["is_security"] = article["is_security"]
        enriched[url] = cleaned
    return enriched


def _msrc_cvrf_events(
    records: tuple[Mapping[str, Any], ...],
    statuses: Mapping[str, Mapping[str, Any]],
    target: ReleasePolicyEntry | None,
) -> tuple[dict[str, Any], ...]:
    events: list[dict[str, Any]] = []
    affected_months = {
        month_id
        for record in records
        if (
            target is not None
            and record.get("release") == target.version
            and record.get("build_family") == target.build_family
            and (month_id := _record_msrc_month_id(record))
        )
    }
    for month_id in sorted(affected_months):
        status = statuses.get(month_id)
        if not status or status.get("status") == "ok":
            continue
        events.append(
            {
                "severity": "warning",
                "kind": "msrc_cvrf_enrichment_unavailable",
                "release": target.version if target else None,
                "build_family": target.build_family if target else None,
                "build": None,
                "kb_article": None,
                "affects_broad_target": bool(target),
                "affects_required_baseline": False,
                "message": f"MSRC CVRF enrichment for {month_id} is {status.get('status')}; security classification may use support article evidence only.",
                "msrc_cvrf_month_id": month_id,
                "msrc_cvrf_status": status.get("status"),
                "msrc_cvrf_url": status.get("url"),
                "msrc_cvrf_error": status.get("error"),
            }
        )
    return tuple(_dedupe_source_events(events))
