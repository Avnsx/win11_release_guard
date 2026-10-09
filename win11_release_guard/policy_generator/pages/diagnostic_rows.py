"""Dashboard rows for Source Diagnostic events."""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence
from ...config import DEFAULT_POLICY_STRICT_STALE_AGE_DAYS, DEFAULT_POLICY_WARNING_AGE_DAYS
from ...models import ReleasePolicy
from ..constants import GITHUB_ISSUES_BASE_URL, MSRC_UPDATE_GUIDE_URL, _SOURCE_DIAGNOSTIC_SEVERITY_PRIORITY
from .dashboard_text import _excluded_release_summary, _source_diagnostics_for_policy
from ..diagnostic_ids import (
    _is_source_diagnostic_id,
    _short_diagnostic_text,
    _source_diagnostic_display_title,
    _source_diagnostic_event_severity,
    _source_diagnostic_event_tags,
    _source_diagnostic_events_with_ids,
    _source_diagnostic_hash_id_for_event,
    _source_diagnostic_id,
    _source_diagnostic_id_hint_for_event,
    _source_diagnostic_id_text,
    _source_diagnostic_source_label,
)
from ..support_articles import _safe_support_article_url
from ..time_format import _dual_zone_time_human


def _source_diagnostic_row_from_event(event: Mapping[str, Any]) -> dict[str, Any]:
    kind = event.get("kind")
    severity = _source_diagnostic_event_severity(event.get("severity"))
    title = _source_diagnostic_display_title(event)
    message = _short_diagnostic_text(event.get("message") or event.get("title") or title)
    source = _source_diagnostic_source_label(kind)
    tags = _source_diagnostic_event_tags(event)
    diagnostic_id = _source_diagnostic_id_text(event.get("id"))
    if not _is_source_diagnostic_id(diagnostic_id):
        diagnostic_id = _source_diagnostic_id_hint_for_event(event)
    if diagnostic_id is None:
        diagnostic_id = _source_diagnostic_hash_id_for_event(event)
    row: dict[str, Any] = {
        "id": diagnostic_id,
        "severity": severity,
        "title": title,
        "source": source,
        "message": message,
        "user_message": _short_diagnostic_text(
            event.get("user_message") or event.get("notice_summary"),
            max_length=360,
        ),
        "tags": tags,
        "issue_sync_event": severity in {"warning", "error"},
    }
    for key in (
        "kb_update_bucket",
        "kb_update_bucket_confidence",
        "security_evidence_source",
        "support_article_url",
        "support_article_validation_status",
        "support_article_validation_reasons",
        "support_article_expected_kb",
        "support_article_expected_build",
        "support_article_expected_release",
        "support_article_applies_to_releases",
        "source_url",
        "msrc_cvrf_url",
        "msrc_cvrf_month_id",
        "kind",
        "affects_required_baseline",
        "affects_broad_target",
        "atom_entry_id",
        "atom_support_article_id",
    ):
        value = event.get(key)
        if value not in (None, "", (), [], {}):
            row[key] = value
    if isinstance(event.get("is_security"), bool):
        row["is_security"] = event["is_security"]
    return row


def _source_diagnostic_row_from_text(severity: str, message: Any, *, source: str, title: str) -> dict[str, Any]:
    normalized_severity = _source_diagnostic_event_severity(severity)
    normalized_message = _short_diagnostic_text(message)
    return {
        "id": _source_diagnostic_id(
            severity=normalized_severity,
            source=source,
            title=title,
            message=normalized_message,
            tags=(),
            allow_message_fallback=True,
        ),
        "severity": normalized_severity,
        "title": title,
        "source": source,
        "message": normalized_message,
        "tags": (),
    }


def _raw_diagnostic_messages(source_diagnostics: Mapping[str, Any], key: str) -> tuple[str, ...]:
    values = source_diagnostics.get(key)
    if not isinstance(values, list):
        return ()
    return tuple(str(item) for item in values if str(item or "").strip())


def _freshness_diagnostic_row(generated_age_days: float) -> dict[str, Any] | None:
    if generated_age_days >= DEFAULT_POLICY_STRICT_STALE_AGE_DAYS:
        return _source_diagnostic_row_from_text(
            "error",
            (
                "Published policy feed is stale at render time. Do not treat this data as "
                "production-current until automation refresh succeeds."
            ),
            source="Policy feed currency",
            title="Policy feed stale",
        )
    if generated_age_days >= DEFAULT_POLICY_WARNING_AGE_DAYS:
        return _source_diagnostic_row_from_text(
            "warning",
            (
                "Published policy feed refresh is due at render time. Verify automation health "
                "before treating this data as production-current."
            ),
            source="Policy feed currency",
            title="Policy feed refresh due",
        )
    return None


def _source_diagnostic_rows(policy: ReleasePolicy, *, generated_age_days: float) -> tuple[dict[str, Any], ...]:
    source_diagnostics = _source_diagnostics_for_policy(policy)
    raw_events = source_diagnostics.get("events")
    rows: list[dict[str, Any]] = []
    if isinstance(raw_events, list):
        event_items = [dict(event) for event in raw_events if isinstance(event, Mapping)]
        rows.extend(
            _source_diagnostic_row_from_event(event)
            for event in _source_diagnostic_events_with_ids(event_items)
        )

    if not rows:
        for message in _raw_diagnostic_messages(source_diagnostics, "errors"):
            rows.append(_source_diagnostic_row_from_text("error", message, source="Source", title="Source error"))
        for message in _raw_diagnostic_messages(source_diagnostics, "warnings"):
            rows.append(_source_diagnostic_row_from_text("warning", message, source="Source", title="Source warning"))
        for message in _raw_diagnostic_messages(source_diagnostics, "notices"):
            rows.append(_source_diagnostic_row_from_text("notice", message, source="Source", title="Source notice"))
        for message in policy.validation_warnings:
            rows.append(
                _source_diagnostic_row_from_text(
                    "warning",
                    message,
                    source="Policy",
                    title="Policy warning",
                )
            )

    has_freshness_row = any(
        str(row.get("source") or "") in {"Freshness", "Policy feed currency"} for row in rows
    )
    freshness_row = _freshness_diagnostic_row(generated_age_days)
    if freshness_row is not None and not has_freshness_row:
        rows.append(freshness_row)

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        key = (str(row.get("severity") or ""), str(row.get("title") or ""), str(row.get("message") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return tuple(deduped)


def _excluded_release_diagnostic_rows(policy: ReleasePolicy) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in policy.excluded_for_existing_devices:
        version = str(entry.version or "").strip().upper()
        if not version or version in seen:
            continue
        seen.add(version)
        severity = "notice"
        title = f"{version} excluded for existing devices"
        source = "Release policy"
        message = _excluded_release_summary(entry)
        tags = (
            f"Release {version}",
            "Existing devices",
            "Not broad target",
        )
        rows.append(
            {
                "id": _source_diagnostic_id(
                    severity=severity,
                    source=source,
                    title=title,
                    message=message,
                    tags=tags,
                    release=version,
                    affects_broad_target=False,
                ),
                "severity": severity,
                "title": title,
                "source": source,
                "message": message,
                "tags": tags,
            }
        )
    return tuple(rows)


_UPDATE_KIND_LABELS = {
    "B": "monthly security update",
    "D": "optional preview",
    "OOB": "out-of-band update",
}


def _latest_update_article(policy: ReleasePolicy, build: str) -> tuple[str, str | None]:
    """KB number and validated Microsoft support article URL for a release-history build."""
    record = next((row for row in policy.release_history if row.build == build), None)
    if record is None:
        return "", None
    return str(record.kb_article or "").strip(), _safe_support_article_url(record.kb_url)


def _latest_update_diagnostic_rows(policy: ReleasePolicy) -> tuple[dict[str, Any], ...]:
    """One dashboard notice per Release Health version: its latest update date and build."""
    rows: list[dict[str, Any]] = []
    for entry in policy.current_versions:
        version = str(entry.version or "").strip().upper()
        build = str(entry.latest_build or "").strip()
        date = str(entry.metadata.get("latest_revision_date") or "").strip()
        if not version or not build or not date:
            continue
        name = f"Windows 11 {version}"
        if entry.servicing_channel.value == "ltsc":
            name += " LTSC"
        raw = entry.metadata.get("raw")
        update = str(raw.get("Latest update") or "").strip() if isinstance(raw, Mapping) else ""
        kind = _UPDATE_KIND_LABELS.get(update.rsplit(" ", 1)[-1].upper(), "")
        detail = f" ({update}, {kind})" if kind else (f" ({update})" if update else "")
        kb_article, article_url = _latest_update_article(policy, build)
        row = {
            "severity": "notice",
            "title": f"{name} latest update",
            "source": "Release Health",
            "message": f"{name} received its latest update on {date}: build {build}{detail}.",
            "tags": tuple(
                tag for tag in (f"Release {version}", f"Build {build}", update, kb_article) if tag
            ),
        }
        row_id = _source_diagnostic_id(**row, release=version, affects_broad_target=False)
        rows.append(
            {"id": row_id, **row, **({"update_details_url": article_url} if article_url else {})}
        )
    return tuple(rows)


def _display_source_event_counts(rows: tuple[Mapping[str, Any], ...]) -> dict[str, int]:
    display_counts = {"notice": 0, "warning": 0, "error": 0}
    for row in rows:
        severity = _source_diagnostic_event_severity(row.get("severity"))
        display_counts[severity] += 1
    return display_counts


def _source_diagnostic_text(value: Any, *, fallback: str = "") -> str:
    if value in (None, ""):
        return fallback
    try:
        text = str(value)
    except Exception:
        return fallback
    text = re.sub(r"\s+", " ", text).strip()
    return text or fallback


def _source_diagnostic_display_text(value: Any, *, fallback: str = "") -> str:
    text = _source_diagnostic_text(value, fallback=fallback)
    if not text:
        return text

    def replace_iso(match: re.Match[str]) -> str:
        return _dual_zone_time_human(match.group(0)) or match.group(0)

    iso_pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
    text = re.sub(
        rf"\bat\s+({iso_pattern})\b",
        lambda match: f"on {_dual_zone_time_human(match.group(1)) or match.group(1)}",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        rf"\b{iso_pattern}\b",
        replace_iso,
        text,
    )
    # Date-only values (Release Health dates) keep their date-only precision.
    return re.sub(
        r"(?<![\w/=.-])\d{4}-\d{2}-\d{2}(?![\w-])",
        replace_iso,
        text,
    )


def _source_diagnostic_attr_text(value: Any) -> str:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return ", ".join(
            item
            for item in (_source_diagnostic_text(part) for part in value)
            if item
        )
    return _source_diagnostic_text(value)


def _source_diagnostic_issue_number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _source_diagnostic_issue_state(value: Any) -> str:
    text = _source_diagnostic_text(value).lower()
    return text if text in {"open", "closed"} else "tracked"


def _canonical_source_diagnostic_issue_url(number: int) -> str:
    return f"{GITHUB_ISSUES_BASE_URL}/{number}"


def _source_diagnostic_issue_record(
    diagnostic_id: str,
    value: Any,
) -> tuple[str, dict[str, Any]] | None:
    if not _is_source_diagnostic_id(diagnostic_id) or not isinstance(value, Mapping):
        return None
    number = _source_diagnostic_issue_number(value.get("number") or value.get("issue_number"))
    if number is None:
        return None
    canonical_url = _canonical_source_diagnostic_issue_url(number)
    supplied_url = _source_diagnostic_text(value.get("url") or value.get("html_url"))
    if supplied_url and supplied_url != canonical_url:
        return None
    state = _source_diagnostic_issue_state(value.get("state") or value.get("status"))
    return diagnostic_id, {
        "number": number,
        "state": state,
        "url": canonical_url,
    }


def _source_diagnostic_issue_records(source_diagnostics: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    raw = source_diagnostics.get("issue_status")
    records: list[tuple[str, Any]] = []
    if isinstance(raw, Mapping):
        records.extend((str(key), value) for key, value in raw.items())
    elif isinstance(raw, list):
        for item in raw:
            if not isinstance(item, Mapping):
                continue
            diagnostic_id = _source_diagnostic_text(
                item.get("diagnostic_id") or item.get("source_diagnostic_id") or item.get("id")
            )
            records.append((diagnostic_id, item))
    issue_records: dict[str, dict[str, Any]] = {}
    for diagnostic_id, value in records:
        record = _source_diagnostic_issue_record(diagnostic_id, value)
        if record is None:
            continue
        key, metadata = record
        issue_records[key] = metadata
    return issue_records


def _source_diagnostic_issue_is_closed(issue: Mapping[str, Any] | None) -> bool:
    return isinstance(issue, Mapping) and _source_diagnostic_issue_state(issue.get("state")) == "closed"


def _source_diagnostic_rows_without_closed_issue_tickets(
    rows: Sequence[dict[str, Any]],
    issue_records: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    visible: list[dict[str, Any]] = []
    for row in rows:
        if row.get("issue_sync_event") is True:
            issue = issue_records.get(_source_diagnostic_row_id(row))
            if _source_diagnostic_issue_is_closed(issue):
                continue
        visible.append(row)
    return tuple(visible)


def _source_diagnostic_counts_without_closed_issue_tickets(
    counts: Mapping[str, int],
    rows: Sequence[dict[str, Any]],
    issue_records: Mapping[str, Mapping[str, Any]],
) -> dict[str, int]:
    adjusted = {
        severity: max(0, int(counts.get(severity, 0)))
        for severity in ("notice", "warning", "error")
    }
    for row in rows:
        if row.get("issue_sync_event") is not True:
            continue
        issue = issue_records.get(_source_diagnostic_row_id(row))
        if not _source_diagnostic_issue_is_closed(issue):
            continue
        severity = _source_diagnostic_event_severity(row.get("severity"))
        adjusted[severity] = max(0, adjusted[severity] - 1)
    return adjusted


def _source_diagnostic_rows_by_priority(rows: Sequence[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
    indexed_rows = tuple(enumerate(rows))
    return tuple(
        row
        for _index, row in sorted(
            indexed_rows,
            key=lambda item: (
                _SOURCE_DIAGNOSTIC_SEVERITY_PRIORITY[_source_diagnostic_event_severity(item[1].get("severity"))],
                item[0],
            ),
        )
    )


def _source_diagnostic_source_class(source: Any) -> str:
    text = _source_diagnostic_text(source, fallback="source").lower()
    if "atom" in text or "feed" in text or "servicing index" in text:
        return "src-atom-feed"
    if "release policy" in text:
        return "src-release-policy"
    if "release health" in text:
        return "src-release-health"
    if "source diagnostics" in text:
        return "src-diagnostics"
    if "freshness" in text or "currency" in text:
        return "src-freshness"
    if "signature" in text:
        return "src-signature"
    if "parser" in text:
        return "src-parser"
    if "policy" in text:
        return "src-policy"
    return "src-source"


def _source_diagnostic_support_url(row: Mapping[str, Any]) -> str | None:
    for key in ("support_article_url", "source_url", "support_url", "atom_feed_url"):
        safe_url = _safe_support_article_url(str(row.get(key) or "") or None)
        if safe_url:
            return safe_url
    return None


def _source_diagnostic_security_url(row: Mapping[str, Any]) -> str | None:
    if str(row.get("security_evidence_source") or "").strip().lower() == "msrc_cvrf":
        return MSRC_UPDATE_GUIDE_URL
    return None


def _source_diagnostic_read_more_url(row: Mapping[str, Any]) -> str | None:
    update_details_url = _safe_support_article_url(str(row.get("update_details_url") or "") or None)
    if update_details_url:
        return update_details_url
    support_url = _source_diagnostic_support_url(row)
    is_security = row.get("is_security") is True
    important_baseline = bool(row.get("affects_required_baseline")) or str(row.get("kind") or "") == (
        "required_baseline_matched_latest_observed"
    )
    if support_url and (is_security or important_baseline):
        return support_url
    if is_security:
        return _source_diagnostic_security_url(row)
    return None


def _source_diagnostic_row_id(row: Mapping[str, Any]) -> str:
    existing_id = _source_diagnostic_id_hint_for_event(row)
    if existing_id is not None:
        return existing_id
    severity = _source_diagnostic_event_severity(row.get("severity"))
    title = _source_diagnostic_text(row.get("title"), fallback="Source diagnostic")
    source = _source_diagnostic_text(row.get("source"), fallback="Source")
    message = _source_diagnostic_text(row.get("message"))
    return _source_diagnostic_id(
        severity=severity,
        source=source,
        title=title,
        message=message,
        tags=row.get("tags"),
        kind=row.get("kind"),
        release=row.get("release"),
        build_family=row.get("build_family"),
        build=row.get("build"),
        kb_article=row.get("kb_article"),
        affects_broad_target=row.get("affects_broad_target"),
        affects_required_baseline=row.get("affects_required_baseline"),
        source_url=row.get("source_url") or row.get("url") or row.get("atom_feed_url"),
    )
