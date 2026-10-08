"""The Source Diagnostics dashboard panel."""

from __future__ import annotations

from html import escape
from typing import Any, Mapping
from ...config import DEFAULT_PAGES_BASE_URL
from ...models import ReleasePolicy
from .components import (
    _dashboard_info_topic_html,
    _epoch_copy_icon_html,
    _github_icon_html,
    _ui_icon_html,
)
from .dashboard_parts import _render_source_tiles
from .dashboard_text import _source_diagnostics_for_policy
from ..diagnostic_ids import _source_diagnostic_event_severity, _source_diagnostic_id
from .diagnostic_rows import (
    _canonical_source_diagnostic_issue_url,
    _display_source_event_counts,
    _excluded_release_diagnostic_rows,
    _source_diagnostic_attr_text,
    _source_diagnostic_counts_without_closed_issue_tickets,
    _source_diagnostic_display_text,
    _source_diagnostic_issue_number,
    _source_diagnostic_issue_records,
    _source_diagnostic_issue_state,
    _source_diagnostic_read_more_url,
    _source_diagnostic_row_from_text,
    _source_diagnostic_row_id,
    _source_diagnostic_rows,
    _source_diagnostic_rows_by_priority,
    _source_diagnostic_rows_without_closed_issue_tickets,
    _source_diagnostic_security_url,
    _source_diagnostic_source_class,
    _source_diagnostic_support_url,
    _source_diagnostic_text,
)


def _source_diagnostic_tag_items_html(tags: Any, *, row: Mapping[str, Any] | None = None) -> str:
    del row
    if tags in (None, ""):
        return ""
    if isinstance(tags, Mapping):
        raw_items = (
            f"{_source_diagnostic_text(key, fallback='field')}: {_source_diagnostic_text(value, fallback='unavailable')}"
            for key, value in tags.items()
        )
    elif isinstance(tags, (str, bytes)):
        raw_items = (tags,)
    else:
        try:
            raw_items = iter(tags)
        except TypeError:
            raw_items = (tags,)
    rendered: list[str] = []
    for tag in raw_items:
        text = _source_diagnostic_text(tag)
        if not text:
            continue
        class_attr = ' class="security-evidence"' if text.startswith("Security confirmed") else ""
        rendered.append(f"<span{class_attr}>{escape(text)}</span>")
    return "".join(rendered)

def _source_diagnostic_issue_link_html(issue: Mapping[str, Any] | None) -> str:
    if not isinstance(issue, Mapping):
        return ""
    number = _source_diagnostic_issue_number(issue.get("number"))
    if number is None:
        return ""
    url = _source_diagnostic_text(issue.get("url"))
    canonical_url = _canonical_source_diagnostic_issue_url(number)
    if url != canonical_url:
        return ""
    state = _source_diagnostic_issue_state(issue.get("state"))
    issue_text = f"#Ticket {number}"
    return (
        f"<a class=\"diag-ticket-link\" href=\"{escape(canonical_url, quote=True)}\" "
        f"aria-label=\"GitHub issue {int(number)} status {escape(state, quote=True)}\">"
        f"{_ui_icon_html('link', class_name='ui-icon diag-ticket-link-icon')}"
        f"<span>{escape(issue_text)}</span>{_github_icon_html()}</a>"
    )

def _placeholder_rows_for_unexplained_counts(
    counts: Mapping[str, int],
    rows: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    rows_by_severity = {"notice": 0, "warning": 0, "error": 0}
    for row in rows:
        rows_by_severity[_source_diagnostic_event_severity(row.get("severity"))] += 1
    placeholders: list[dict[str, Any]] = []
    for severity, title in (
        ("error", "Error diagnostics reported"),
        ("warning", "Warning diagnostics reported"),
        ("notice", "Notice diagnostics reported"),
    ):
        missing = max(0, int(counts.get(severity, 0)) - rows_by_severity[severity])
        if missing:
            label = "entry" if missing == 1 else "entries"
            placeholders.append(
                _source_diagnostic_row_from_text(
                    severity,
                    f"{missing} {severity} diagnostic {label} reported without structured row details.",
                    source="Source",
                    title=title,
                )
            )
    return tuple(placeholders)

def _source_diagnostic_row_data_attrs(row: Mapping[str, Any]) -> str:
    attrs: list[str] = []
    for key, attr in (
        ("user_message", "data-user-message"),
        ("kb_update_bucket", "data-kb-update-bucket"),
        ("kb_update_bucket_confidence", "data-kb-update-bucket-confidence"),
        ("security_evidence_source", "data-security-evidence-source"),
        ("msrc_cvrf_url", "data-msrc-cvrf-url"),
        ("msrc_cvrf_month_id", "data-msrc-cvrf-month-id"),
        ("support_article_validation_status", "data-support-article-validation-status"),
        ("support_article_validation_reasons", "data-support-article-validation-reasons"),
        ("support_article_expected_kb", "data-support-article-expected-kb"),
        ("support_article_expected_build", "data-support-article-expected-build"),
        ("support_article_expected_release", "data-support-article-expected-release"),
        ("support_article_applies_to_releases", "data-support-article-applies-to-releases"),
        ("atom_entry_id", "data-atom-entry-id"),
        ("atom_support_article_id", "data-atom-support-article-id"),
    ):
        raw_value = row.get(key)
        if key == "user_message":
            value = _source_diagnostic_display_text(raw_value)
        else:
            value = _source_diagnostic_attr_text(raw_value)
        if value:
            attrs.append(f' {attr}="{escape(value, quote=True)}"')
    support_url = _source_diagnostic_support_url(row)
    if support_url:
        attrs.append(f' data-support-article-url="{escape(support_url, quote=True)}"')
        attrs.append(f' data-source-url="{escape(support_url, quote=True)}"')
    read_more_url = _source_diagnostic_read_more_url(row)
    if read_more_url:
        attrs.append(f' data-read-more-url="{escape(read_more_url, quote=True)}"')
    security_url = _source_diagnostic_security_url(row)
    if security_url:
        attrs.append(f' data-security-url="{escape(security_url, quote=True)}"')
    is_security = row.get("is_security")
    if isinstance(is_security, bool):
        attrs.append(f' data-is-security="{str(is_security).lower()}"')
    return "".join(attrs)

def _source_diagnostic_read_more_html(row: Mapping[str, Any]) -> str:
    read_more_url = _source_diagnostic_read_more_url(row)
    if not read_more_url:
        return ""
    return (
        f' <a class="diag-read-more-inline" href="{escape(read_more_url, quote=True)}" '
        'rel="noopener noreferrer">Read more</a>'
    )

def _render_source_diagnostic_row(
    row: Mapping[str, Any],
    *,
    issue_metadata: Mapping[str, Any] | None = None,
) -> str:
    if not isinstance(row, Mapping):
        row = {}
    severity = _source_diagnostic_event_severity(row.get("severity"))
    title = _source_diagnostic_text(row.get("title"), fallback="Source diagnostic")
    source = _source_diagnostic_text(row.get("source"), fallback="Source")
    source_class = _source_diagnostic_source_class(source)
    message = _source_diagnostic_display_text(row.get("message"))
    user_message = _source_diagnostic_display_text(row.get("user_message") or row.get("notice_summary"))
    read_more_html = _source_diagnostic_read_more_html(row)
    user_message_html = (
        f"<p class=\"diag-user-message\">{escape(user_message)}{read_more_html}</p>"
        if user_message
        else ""
    )
    technical_link_html = "" if user_message else read_more_html
    technical_message_html = f"<p class=\"diag-technical-message\">{escape(message)}{technical_link_html}</p>"
    tag_items = _source_diagnostic_tag_items_html(row.get("tags"), row=row)
    diagnostic_id = _source_diagnostic_row_id(row)
    data_attrs = _source_diagnostic_row_data_attrs(row)
    issue_link = _source_diagnostic_issue_link_html(issue_metadata)
    return (
        f"<article class=\"diag-row {severity}\" data-diagnostic-severity=\"{severity}\" "
        f"data-diagnostic-id=\"{escape(diagnostic_id, quote=True)}\"{data_attrs}>"
        "<span class=\"diag-stripe\" aria-hidden=\"true\"></span>"
        f"{_source_diagnostic_icon_html(row)}"
        f"{issue_link}"
        "<div>"
        "<div class=\"diag-row-head\">"
        f"<span class=\"severity-badge {severity}\">{escape(severity.capitalize())}</span>"
        f"<strong>{escape(title)}</strong>"
        f"<span class=\"source-chip {source_class}\">{escape(source)}</span>"
        "</div>"
        f"{user_message_html}"
        f"{technical_message_html}"
        f"<div class=\"diag-tags\">{tag_items}</div>"
        "</div>"
        "</article>"
    )

def _diagnostic_filter_button_html(severity: str, count: int, label: str, icon_name: str) -> str:
    escaped_severity = escape(severity, quote=True)
    escaped_label = escape(label, quote=True)
    return (
        f"<button type=\"button\" class=\"diag-tile {escaped_severity}\" "
        f"data-diagnostic-filter=\"{escaped_severity}\" "
        f"data-diagnostic-severity=\"{escaped_severity}\" "
        "aria-pressed=\"false\" aria-controls=\"source-diagnostics-feed\" "
        f"aria-label=\"Show {escaped_severity} source diagnostics ({int(count)})\">"
        f"<strong>{int(count)}</strong><span>{escaped_label}</span>"
        f"{_ui_icon_html(icon_name, class_name='ui-icon diag-tile-icon')}</button>"
    )

def _source_diagnostics_copy_button_html() -> str:
    return (
        '<button type="button" class="epoch-copy diag-export-copy" '
        'data-diagnostics-copy="visible-json" '
        'aria-label="Copy visible Source Diagnostics as JSON" '
        'title="Copy visible Source Diagnostics JSON">'
        f"{_epoch_copy_icon_html()}"
        "</button>"
    )

def _source_diagnostic_icon_html(row: Mapping[str, Any]) -> str:
    severity = _source_diagnostic_event_severity(row.get("severity"))
    if severity in {"warning", "error"}:
        icon = severity
    else:
        title = _source_diagnostic_text(row.get("title")).lower()
        source = _source_diagnostic_text(row.get("source")).lower()
        if title == "no source issues reported":
            icon = "megaphone"
        elif "atom" in title or "feed" in title or "atom" in source or "feed" in source:
            icon = "document"
        elif "release policy" in source or "excluded" in title:
            icon = "info"
        else:
            icon = "megaphone"
    return (
        f"<span class=\"diag-row-icon {severity}\" aria-hidden=\"true\">"
        f"{_ui_icon_html(icon, class_name='ui-icon')}</span>"
    )

def _clear_source_diagnostic_row() -> dict[str, Any]:
    severity = "notice"
    title = "No source issues reported"
    source = "Source diagnostics"
    message = "Release Health, servicing index, parser, and freshness checks have no warning or error events."
    tags = ("No warnings", "No errors")
    return {
        "id": _source_diagnostic_id(
            severity=severity,
            source=source,
            title=title,
            message=message,
            tags=tags,
        ),
        "severity": severity,
        "title": title,
        "source": source,
        "message": message,
        "tags": tags,
    }

def _source_diagnostic_issue_sync_notice_html(source_diagnostics: Mapping[str, Any]) -> str:
    raw = source_diagnostics.get("issue_sync")
    if not isinstance(raw, Mapping):
        return ""
    status = _source_diagnostic_text(raw.get("status")).lower()
    if status not in {"degraded", "unavailable"}:
        return ""
    label = "Issue sync unavailable" if status == "unavailable" else "Issue sync degraded"
    message = _source_diagnostic_text(
        raw.get("message"),
        fallback="GitHub Issues status metadata is currently unavailable; diagnostic ticket links may be missing.",
    )
    reason = _source_diagnostic_text(raw.get("reason"))
    reason_html = f"<span>{escape(reason)}</span>" if reason else ""
    return (
        f"<p class=\"diag-issue-sync-status {escape(status, quote=True)}\" "
        f"data-issue-sync-status=\"{escape(status, quote=True)}\" role=\"status\">"
        f"{_ui_icon_html('warning', class_name='ui-icon diag-issue-sync-icon')}"
        f"<strong>{escape(label)}</strong><span>{escape(message)}</span>{reason_html}</p>"
    )

def _render_source_diagnostics_panel(
    policy: ReleasePolicy,
    counts: Mapping[str, int],
    *,
    generated_age_days: float,
    generated_at_utc: str,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    source_diagnostics = _source_diagnostics_for_policy(policy)
    issue_records = _source_diagnostic_issue_records(source_diagnostics)
    issue_sync_notice = _source_diagnostic_issue_sync_notice_html(source_diagnostics)
    def render_row(row: Mapping[str, Any]) -> str:
        issue_metadata = None
        if row.get("issue_sync_event") is True:
            issue_metadata = issue_records.get(_source_diagnostic_row_id(row))
        return _render_source_diagnostic_row(row, issue_metadata=issue_metadata)

    base_rows = _source_diagnostic_rows(policy, generated_age_days=generated_age_days)
    excluded_rows = _excluded_release_diagnostic_rows(policy)
    counted_rows = (*base_rows, *excluded_rows)
    visible_counted_rows = _source_diagnostic_rows_without_closed_issue_tickets(counted_rows, issue_records)
    adjusted_counts = _source_diagnostic_counts_without_closed_issue_tickets(counts, counted_rows, issue_records)
    rows = _source_diagnostic_rows_by_priority(
        (*visible_counted_rows, *_placeholder_rows_for_unexplained_counts(adjusted_counts, visible_counted_rows))
    )
    rendered_rows: tuple[Mapping[str, Any], ...]
    if not rows:
        clear_row = _clear_source_diagnostic_row()
        rendered_rows = (clear_row,)
        rendered_clear_row = render_row(clear_row)
        details = f"<div class=\"diag-events diag-events-empty\">{rendered_clear_row}</div>"
    else:
        has_warning_or_error = any(
            _source_diagnostic_event_severity(row.get("severity")) in {"warning", "error"}
            for row in rows
        )
        lead_row: Mapping[str, Any] | None = None
        if not has_warning_or_error:
            lead_row = _clear_source_diagnostic_row()
        rendered_rows = (lead_row, *rows) if lead_row is not None else rows
        visible_rows = rows[:5]
        hidden_rows = rows[5:]
        rendered_visible = (
            (render_row(lead_row) if lead_row is not None else "")
            + "".join(render_row(row) for row in visible_rows)
        )
        overflow = ""
        if hidden_rows:
            rendered_hidden = "".join(render_row(row) for row in hidden_rows)
            overflow = (
                f"<details class=\"diag-more\"><summary>+{len(hidden_rows)} more</summary>"
                f"<div class=\"diag-events\">{rendered_hidden}</div></details>"
            )
        details = f"<div class=\"diag-events\">{rendered_visible}</div>{overflow}"
    display_counts = _display_source_event_counts(rendered_rows)
    count_tiles = (
        "<div class=\"diag-summary\" aria-label=\"Source diagnostic counts\">"
        f"{_diagnostic_filter_button_html('notice', display_counts['notice'], 'Notices', 'megaphone')}"
        f"{_diagnostic_filter_button_html('warning', display_counts['warning'], 'Warnings', 'warning')}"
        f"{_diagnostic_filter_button_html('error', display_counts['error'], 'Errors', 'error')}"
        "</div>"
    )
    total_rows = sum(display_counts.values())
    return (
        "<section class=\"panel span-7 source-diagnostics\" data-diagnostic-filter-root "
        "data-diagnostics-expanded=\"false\">"
        "<div class=\"panel-head\"><h2><span>Source diagnostics</span>"
        f"{_dashboard_info_topic_html('source-diagnostics', base_url=base_url)}</h2>"
        "<div class=\"panel-actions\">"
        "<button type=\"button\" class=\"panel-action diag-filter-reset\" "
        "data-diagnostic-filter=\"all\" aria-controls=\"source-diagnostics-feed\" "
        "aria-pressed=\"true\">View all</button>"
        "<button type=\"button\" class=\"panel-action diag-expand-toggle\" "
        "data-diagnostics-expand-toggle=\"true\" aria-controls=\"source-diagnostics-feed\" "
        "aria-expanded=\"false\" aria-label=\"Expand Source Diagnostics view\">Expand View</button>"
        "</div></div>"
        f"{count_tiles}{issue_sync_notice}"
        "<div class=\"diag-feed-bar\">"
        "<p id=\"source-diagnostics-filter-status\" class=\"diag-filter-status\" aria-live=\"polite\">"
        f"Showing all {total_rows} source diagnostic rows.</p>{_source_diagnostics_copy_button_html()}</div>"
        "<div id=\"source-diagnostics-feed\" class=\"diag-feed\" role=\"region\" aria-label=\"Source diagnostic event feed\">"
        "<div id=\"source-diagnostics-empty\" class=\"diag-filter-empty\" hidden>"
        "This category currently contains no entries.</div>"
        f"{details}</div>{_render_source_tiles(policy, generated_at_utc=generated_at_utc)}</section>\n"
    )
