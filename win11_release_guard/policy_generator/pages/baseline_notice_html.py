"""Dashboard rendering of the baseline-update notice."""

from __future__ import annotations

from html import escape
from typing import Any, Mapping
from ...models import ReleasePolicy
from ..baseline_notice import _security_evidence_display_label
from .components import _ui_icon_html
from ..constants import MSRC_UPDATE_GUIDE_URL
from .dashboard_text import _source_diagnostics_for_policy
from .diagnostic_rows import _source_diagnostic_text
from ..msrc_cvrf import _as_sequence
from ..support_articles import _SUPPORT_ARTICLE_IMPROVEMENT_DETAIL_LIMIT, _safe_support_article_url
from ..time_format import _dual_zone_time_human


def _baseline_update_notice_for_policy(policy: ReleasePolicy) -> Mapping[str, Any] | None:
    source_diagnostics = _source_diagnostics_for_policy(policy)
    notice = source_diagnostics.get("baseline_update_notice")
    if isinstance(notice, Mapping) and notice.get("active") is True:
        return notice
    return None


def _baseline_update_security_label(notice: Mapping[str, Any]) -> str:
    return _security_evidence_display_label(
        is_security=notice.get("is_security"),
        evidence_source=notice.get("security_evidence_source"),
    ) or "Security evidence unknown"


def _baseline_update_security_url(notice: Mapping[str, Any]) -> str | None:
    if str(notice.get("security_evidence_source") or "").strip().lower() == "msrc_cvrf":
        return MSRC_UPDATE_GUIDE_URL
    return None


def _baseline_update_chip_html(
    label: str,
    value: Any,
    *,
    extra_class: str = "",
    href: str | None = None,
) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    class_attr = "baseline-chip" + (f" {extra_class}" if extra_class else "")
    content = f"{label} {text}".strip()
    if href:
        return (
            f'<a class="{escape(class_attr, quote=True)}" href="{escape(href, quote=True)}" '
            f'rel="noopener noreferrer">{escape(content)}</a>'
        )
    return f'<span class="{escape(class_attr, quote=True)}">{escape(content)}</span>'


def _baseline_read_more_html(source_url: str | None) -> str:
    if not source_url:
        return ""
    return (
        f' <a class="baseline-read-more" href="{escape(source_url, quote=True)}" '
        'rel="noopener noreferrer">Read more</a>'
    )


def _baseline_review_html(notice: Mapping[str, Any], source_url: str | None) -> str:
    read_more_html = _baseline_read_more_html(source_url)
    details = [
        _source_diagnostic_text(item)
        for item in _as_sequence(notice.get("support_article_improvement_details"))
    ]
    details = [item for item in details if item][:_SUPPORT_ARTICLE_IMPROVEMENT_DETAIL_LIMIT]
    if details:
        items_html = "".join(f"<li>{escape(item)}</li>" for item in details)
        return (
            '<div class="baseline-review">'
            '<span class="baseline-review-label">Update highlights:</span>'
            f'<ul class="baseline-review-list">{items_html}</ul>'
            f'{read_more_html}'
            '</div>'
        )
    update_summary = _source_diagnostic_text(notice.get("update_summary"))
    if not update_summary:
        return ""
    review_text = update_summary.removeprefix("Update highlights:").strip()
    return (
        '<p class="baseline-review">'
        '<span class="baseline-review-label">Update highlights:</span>'
        f' {escape(review_text)}{read_more_html}</p>'
    )


def _render_baseline_update_notice(policy: ReleasePolicy) -> str:
    notice = _baseline_update_notice_for_policy(policy)
    if notice is None:
        return ""
    release = str(notice.get("release") or "unknown").strip()
    build_family = str(notice.get("build_family") or "unknown").strip()
    build = str(notice.get("build") or "unknown").strip()
    kb_article = str(notice.get("kb_article") or "").strip()
    update_type = str(notice.get("update_type") or "").strip()
    security_label = _baseline_update_security_label(notice)
    summary = _source_diagnostic_text(notice.get("summary"))
    if not summary:
        summary_bits = [
            (
                f"Windows 11 {release} build {build} now matches both latest observed Microsoft evidence "
                "and the signed required baseline."
            )
        ]
        if kb_article and update_type:
            summary_bits.append(f"{kb_article} is the {update_type} baseline source.")
        elif kb_article:
            summary_bits.append(f"{kb_article} is the baseline source.")
        if security_label:
            summary_bits.append(f"{security_label}.")
        summary = _source_diagnostic_text(" ".join(summary_bits))
    official_date = str(notice.get("official_release_date") or "").strip()
    precision = str(notice.get("official_release_precision") or "").strip().lower()
    official_label = ""
    if official_date:
        precision_text = " (Release Health date-only)" if precision == "date" else ""
        official_label = f"{official_date}{precision_text}"
    visible_until = str(notice.get("visible_until_utc") or "").strip()
    source_url = _safe_support_article_url(str(notice.get("source_url") or "") or None)
    security_url = _baseline_update_security_url(notice)
    data_attrs = [
        f'data-baseline-notice-build="{escape(build, quote=True)}"',
        f'data-baseline-notice-kb="{escape(kb_article, quote=True)}"',
        f'data-baseline-notice-visible-until="{escape(visible_until, quote=True)}"',
    ]
    if source_url:
        data_attrs.append(f'data-baseline-notice-source-url="{escape(source_url, quote=True)}"')
    if security_url:
        data_attrs.append(f'data-baseline-notice-security-url="{escape(security_url, quote=True)}"')
    chips = [
        _baseline_update_chip_html("Release", release),
        _baseline_update_chip_html("Family", build_family),
        _baseline_update_chip_html("Build", build),
        _baseline_update_chip_html("", kb_article),
        _baseline_update_chip_html("Update", update_type),
        _baseline_update_chip_html("", security_label, extra_class="security"),
        _baseline_update_chip_html("Official baseline date:", official_label, extra_class="official-date"),
    ]
    chip_html = "".join(item for item in chips if item)
    timeline_bits: list[str] = []
    atom_first_seen = _dual_zone_time_human(notice.get("first_spotted_atom_published_utc")) or str(
        notice.get("first_spotted_atom_published_utc") or ""
    ).strip()
    if atom_first_seen:
        timeline_bits.append(f"Atom first spotted {atom_first_seen}")
    support_updated = _dual_zone_time_human(notice.get("support_article_updated_utc")) or str(
        notice.get("support_article_updated_utc") or ""
    ).strip()
    if support_updated:
        timeline_bits.append(f"Support updated {support_updated}")
    if official_label:
        timeline_bits.append(f"Release Health baseline date {official_label}")
    timeline_html = (
        f'<p class="baseline-timeline">{"; ".join(escape(item) for item in timeline_bits)}.</p>'
        if timeline_bits
        else ""
    )
    read_more_html = _baseline_read_more_html(source_url)
    update_summary_html = _baseline_review_html(notice, source_url)
    summary_link = "" if update_summary_html else read_more_html
    return (
        f'      <section class="panel span-12 baseline-update-notice" role="status" aria-live="polite" '
        f'data-baseline-notice="active" {" ".join(data_attrs)}>'
        f'<div class="baseline-notice-icon" aria-hidden="true">{_ui_icon_html("shield-check", class_name="ui-icon")}</div>'
        '<div class="baseline-notice-body">'
        '<div class="baseline-notice-head">'
        '<span class="baseline-notice-pill">Notice</span>'
        f'<h2 class="baseline-title">New required baseline: {escape(release)} build {escape(build)}</h2>'
        '</div>'
        f'<p class="baseline-summary">{escape(summary)}{summary_link}</p>'
        f'{update_summary_html}'
        f'{timeline_html}'
        f'<div class="baseline-chip-list" aria-label="Baseline notice metadata">{chip_html}</div>'
        '</div></section>'
    )
