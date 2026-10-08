"""The policy dashboard page (index.html)."""

from __future__ import annotations

from .assets import render_asset

import json
import os
from datetime import datetime
from html import escape
from typing import Any, Mapping
from ...config import DEFAULT_PAGES_BASE_URL, DEFAULT_POLICY_STRICT_STALE_AGE_DAYS, DEFAULT_POLICY_WARNING_AGE_DAYS
from ...freshness import freshness_policy_metadata, freshness_thresholds
from ...models import ReleasePolicy
from ...policy_schema import GENERATOR_VERSION
from ..artifacts import _public_verification_metadata, _sha256_hex
from .baseline_notice_html import _render_baseline_update_notice
from .components import (
    _dashboard_info_topic_html,
    _footer_html,
    _github_icon_html,
    _time_with_epoch_copy_html,
    _ui_icon_html,
)
from ..constants import (
    GITHUB_RELEASES_BASE_URL,
    GITHUB_REPOSITORY_URL,
    PYPI_PROJECT_URL,
    WIKI_FAVICON_DATA_URL,
    _RELEASE_VERSION_PATTERN,
)
from .dashboard_parts import _hash_html
from .dashboard_text import _latest_observed_source_label, _source_event_counts_for_policy
from ..diagnostic_ids import _signature_field, _signature_trust_class
from .diagnostic_panel import _render_source_diagnostics_panel
from ..time_format import (
    _dashboard_age_display,
    _generated_age_days,
    _generated_at_human,
    _generated_at_local_date,
    _generated_at_local_time,
)
from .wiki_page import _seo_meta_html
from .wiki_sources import _pages_root_url, _pages_wiki_url, _pypi_download_image_url
from .. import clock


def _program_version_from_generator(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return "unknown"
    return text.rsplit("/", 1)[-1] if "/" in text else text

def _program_release_url(version: str | None) -> str | None:
    text = str(version or "").strip()
    if not _RELEASE_VERSION_PATTERN.fullmatch(text):
        return None
    return f"{GITHUB_RELEASES_BASE_URL}/v{text}"

def _program_title_version_html(version: str | None) -> str:
    text = str(version or "").strip() or "unknown"
    url = _program_release_url(text)
    escaped_text = escape(text)
    label = f"Program Version {escaped_text}"
    if url is None:
        return (
            '<span class="title-version-link">'
            f'<span class="title-version-label">Program Version</span> {escaped_text}'
            "</span>"
        )
    escaped_url = escape(url, quote=True)
    return (
        f'<a class="title-version-link mono" href="{escaped_url}" '
        f'aria-label="{escape(label, quote=True)} release">'
        '<span class="title-version-label">Program Version</span> '
        f"{escaped_text}</a>"
    )

def _pypi_download_link_html(*, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    image_url = _pypi_download_image_url(base_url=base_url)
    return (
        f'<a class="pypi-download-link" href="{escape(PYPI_PROJECT_URL, quote=True)}" '
        'aria-label="Download win11_release_guard from PyPI" data-nav-label="PyPI">'
        f'<img src="{escape(image_url, quote=True)}" alt="Download from PyPI" width="96" height="96">'
        "</a>"
    )

def _header_nav_html(*, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    dashboard_icon = (
        '<svg viewBox="0 0 48 48" aria-hidden="true" focusable="false">'
        '<path d="M20,4H6A2,2,0,0,0,4,6V20a2,2,0,0,0,2,2H20a2,2,0,0,0,2-2V6A2,2,0,0,0,20,4Z"/>'
        '<path d="M42,4H28a2,2,0,0,0-2,2V20a2,2,0,0,0,2,2H42a2,2,0,0,0,2-2V6A2,2,0,0,0,42,4Z"/>'
        '<path d="M20,26H6a2,2,0,0,0-2,2V42a2,2,0,0,0,2,2H20a2,2,0,0,0,2-2V28A2,2,0,0,0,20,26Z"/>'
        '<path d="M42,26H28a2,2,0,0,0-2,2V42a2,2,0,0,0,2,2H42a2,2,0,0,0,2-2V28A2,2,0,0,0,42,26Z"/>'
        "</svg>"
    )
    issue_icon = (
        '<svg viewBox="0 0 512 512" aria-hidden="true" focusable="false">'
        '<path d="M421.073 221.719c-.578 11.719-9.469 26.188-23.797 40.094v183.25c-.016 4.719-1.875 8.719-5.016 11.844-3.156 3.063-7.25 4.875-12.063 4.906H81.558c-4.781-.031-8.891-1.844-12.047-4.906-3.141-3.125-4.984-7.125-5-11.844V152.219c.016-4.703 1.859-8.719 5-11.844 3.156-3.063 7.266-4.875 12.047-4.906h158.609c12.828-16.844 27.781-34.094 44.719-49.906.078-.094.141-.188.219-.281H81.558c-18.75-.016-35.984 7.531-48.25 19.594-12.328 12.063-20.016 28.938-20 47.344v292.844c-.016 18.406 7.672 35.313 20 47.344C45.573 504.469 62.808 512 81.558 512h298.641c18.781 0 36.016-7.531 48.281-19.594 12.297-12.031 20-28.938 19.984-47.344V203.469c0 0-.125-.156-.328-.313-7.766 6.657-16.813 13-27.063 18.563z"/>'
        '<path d="M498.058 0s-15.688 23.438-118.156 58.109C275.417 93.469 211.104 237.313 211.104 237.313c-15.484 29.469-76.688 151.906-76.688 151.906-16.859 31.625 14.031 50.313 32.156 17.656 34.734-62.688 57.156-119.969 109.969-121.594 77.047-2.375 129.734-69.656 113.156-66.531-21.813 9.5-69.906.719-41.578-3.656 68-5.453 109.906-56.563 96.25-60.031-24.109 9.281-46.594.469-51-2.188C513.386 138.281 498.058 0 498.058 0z"/>'
        "</svg>"
    )
    wiki_icon = (
        '<svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">'
        '<path d="M5 0C3.343 0 2 1.343 2 3v10c0 1.657 1.343 3 3 3h9v-2H4v-2h10V0H5z"/>'
        "</svg>"
    )
    items = (
        ("Repository", GITHUB_REPOSITORY_URL, _github_icon_html()),
        ("Dashboard", _pages_root_url(base_url=base_url), dashboard_icon),
        ("Write a Issue Ticket", "https://github.com/Avnsx/win11_release_guard/issues/new", issue_icon),
        ("Wiki", _pages_wiki_url(base_url=base_url), wiki_icon),
    )
    links = "".join(
        (
            f'<li><a href="{escape(href, quote=True)}" aria-label="{escape(label, quote=True)}" '
            f'data-nav-label="{escape(label, quote=True)}">'
            f"{icon}<span class=\"sr-only\">{escape(label)}</span></a></li>"
        )
        for label, href, icon in items
    )
    return (
        '<nav class="header-nav" aria-label="Header navigation">'
        '<span class="nav-hover-label" aria-hidden="true">Dashboard</span>'
        f'<ul class="nav-inner">{links}</ul>'
        "</nav>"
    )

def _render_endpoint_links() -> str:
    endpoints = (
        (
            "Signed policy JSON",
            "windows-release-policy.json",
            "Primary signed policy document used by automation and fleet dashboards.",
            "document",
        ),
        (
            "Detached signature",
            "windows-release-policy.json.sig",
            "Ed25519 signature that lets clients verify the policy before trusting it.",
            "key",
        ),
        (
            "Policy manifest",
            "policy-manifest.json",
            "Compact metadata for hashes, freshness thresholds, source state, and API aliases.",
            "database",
        ),
        (
            "API v1 policy alias",
            "api/v1/policy.json",
            "Backward-compatible policy endpoint for stable reader integrations.",
            "api",
        ),
        (
            "API v1 manifest alias",
            "api/v1/manifest.json",
            "Backward-compatible manifest endpoint for stable reader integrations.",
            "api",
        ),
    )
    return "".join(
        (
            f'<a class="api-endpoint-row" href="{escape(endpoint, quote=True)}">'
            f"{_ui_icon_html(icon, class_name='ui-icon api-row-icon')}"
            f"<span><strong>{escape(title)}</strong><em>{escape(description)}</em></span>"
            f"<code>/{escape(endpoint)}</code></a>"
        )
        for title, endpoint, description, icon in endpoints
    )

def _safe_json_script_payload(data: Mapping[str, Any]) -> str:
    return (
        json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )

def render_policy_index(
    policy: ReleasePolicy,
    *,
    policy_bytes: bytes | None = None,
    signature: Mapping[str, Any] | None = None,
    verification_metadata: Mapping[str, Any] | None = None,
    base_url: str = DEFAULT_PAGES_BASE_URL,
    generated_age_reference: datetime | None = None,
) -> str:
    target = policy.broad_target_existing_devices
    policy_hash = _sha256_hex(policy_bytes)
    generated_at_utc = policy.generated_at_utc or clock.utc_now()
    generated_human = _generated_at_human(generated_at_utc)
    generated_local_date = _generated_at_local_date(generated_at_utc)
    generated_local_time = _generated_at_local_time(generated_at_utc)
    generated_age_days = _generated_age_days(generated_at_utc, reference=generated_age_reference)
    generated_age_text, generated_age_size, generated_age_label = _dashboard_age_display(
        generated_at_utc,
        reference=generated_age_reference,
    )
    generated_age_class = "freshness-metric" + (f" {generated_age_size}" if generated_age_size else "")
    verification = verification_metadata if verification_metadata is not None else _public_verification_metadata(signature)
    signature_attached = verification is not None
    raw_signature_status = str(policy.metadata.get("signature_status") or "unavailable")
    if signature_attached:
        signature_algorithm = _signature_field(verification, "algorithm") or "unavailable"
        key_id = _signature_field(verification, "key_id") or "legacy default key"
        signature_status = raw_signature_status
        trust_indicator = "Signed policy trust"
    else:
        signature_algorithm = "not attached"
        key_id = "not attached"
        signature_status = "unsigned local preview" if raw_signature_status == "unsigned" else raw_signature_status
        trust_indicator = "Unsigned local preview" if signature_status == "unsigned local preview" else "Signature metadata"
    trust_class = _signature_trust_class(
        signature_attached=signature_attached,
        signature_status=signature_status,
    )
    source_event_counts = _source_event_counts_for_policy(policy)
    source_diagnostics_panel = _render_source_diagnostics_panel(
        policy,
        source_event_counts,
        generated_age_days=generated_age_days,
        generated_at_utc=generated_at_utc,
        base_url=base_url,
    )
    program_version = _program_version_from_generator(GENERATOR_VERSION)
    workflow_run = os.environ.get("GITHUB_RUN_ID") or "not available in local render"
    endpoint_links = _render_endpoint_links()
    freshness_data = {
        "generated_at_utc": generated_at_utc,
        **freshness_thresholds(generated_at_utc),
        "freshness_policy": freshness_policy_metadata(),
    }
    baseline_notice_block = _render_baseline_update_notice(policy)
    warning_items = "\n".join(f"<li>{escape(warning)}</li>" for warning in policy.validation_warnings)
    warning_block = (
        f"      <section class=\"panel span-12 dashboard-warning-panel\"><h2>Warnings</h2><ul class=\"warnings\">{warning_items}</ul></section>"
        if warning_items
        else ""
    )
    dashboard_grid_classes = ["grid", "dashboard-grid"]
    if baseline_notice_block:
        dashboard_grid_classes.append("has-baseline-notice")
    if warning_items:
        dashboard_grid_classes.append("has-validation-warnings")
    dashboard_grid_class = " ".join(dashboard_grid_classes)
    target_release = target.version if target else "unknown"
    target_family = str(target.build_family) if target else "unknown"
    target_latest_observed = target.latest_observed_build if target else None
    target_latest_observed_source = _latest_observed_source_label(target)
    target_baseline = target.required_baseline_build if target else None
    dashboard_url = _pages_root_url(base_url=base_url)
    dashboard_description = (
        "Windows 11 Release Guard dashboard for Windows 11 release compliance, signed public policy feed "
        f"freshness, {target_release} target status, source diagnostics, and fleet administration checks."
    )
    dashboard_seo_meta = _seo_meta_html(
        title="Windows 11 Release Guard",
        description=dashboard_description,
        canonical_url=dashboard_url,
    )
    return render_asset(
        "dashboard.html",
        wiki_favicon_data_url=f'{WIKI_FAVICON_DATA_URL}',
        dashboard_seo_meta=f'{dashboard_seo_meta}',
        ui_icon_html_shield_class_name_ui_icon_eyebrow_i=f"{_ui_icon_html('shield', class_name='ui-icon eyebrow-icon')}",
        header_nav_html_base_url_base_url=f'{_header_nav_html(base_url=base_url)}',
        pypi_download_link_html_base_url_base_url=f'{_pypi_download_link_html(base_url=base_url)}',
        program_title_version_html_program_version=f'{_program_title_version_html(program_version)}',
        ui_icon_html_target_class_name_ui_icon_kpi_icon=f"{_ui_icon_html('target', class_name='ui-icon kpi-icon')}",
        escape_target_release=f'{escape(target_release)}',
        ui_icon_html_chip_class_name_ui_icon_kpi_icon=f"{_ui_icon_html('chip', class_name='ui-icon kpi-icon')}",
        escape_target_family=f'{escape(target_family)}',
        ui_icon_html_eye_class_name_ui_icon_kpi_icon=f"{_ui_icon_html('eye', class_name='ui-icon kpi-icon')}",
        dashboard_info_topic_html_latest_observed_base_u=f"{_dashboard_info_topic_html('latest-observed', base_url=base_url)}",
        escape_target_latest_observed_or_unknown=f"{escape(target_latest_observed or 'unknown')}",
        escape_target_latest_observed_source=f'{escape(target_latest_observed_source)}',
        ui_icon_html_shield_check_class_name_ui_icon_kpi=f"{_ui_icon_html('shield-check', class_name='ui-icon kpi-icon')}",
        dashboard_info_topic_html_required_baseline_base=f"{_dashboard_info_topic_html('required-baseline', base_url=base_url)}",
        escape_target_baseline_or_unknown=f"{escape(target_baseline or 'unknown')}",
        escape_policy_quality_policy_value=f'{escape(policy.quality_policy.value)}',
        dashboard_grid_class=f'{dashboard_grid_class}',
        baseline_notice_block=f'{baseline_notice_block}',
        warning_block=f'{warning_block}',
        dashboard_info_topic_html_policy_feed_currency_b=f"{_dashboard_info_topic_html('policy-feed-currency', base_url=base_url)}",
        ui_icon_html_check_class_name_ui_icon_freshness_=f"{_ui_icon_html('check', class_name='ui-icon freshness-ring-icon')}",
        escape_generated_age_class_quote_true=f'{escape(generated_age_class, quote=True)}',
        escape_generated_age_label_quote_true=f'{escape(generated_age_label, quote=True)}',
        escape_generated_age_label_quote_true_2=f'{escape(generated_age_label, quote=True)}',
        escape_generated_age_text=f'{escape(generated_age_text)}',
        ui_icon_html_check_class_name_ui_icon_freshness__2=f"{_ui_icon_html('check', class_name='ui-icon freshness-callout-icon')}",
        ui_icon_html_calendar_class_name_ui_icon=f"{_ui_icon_html('calendar', class_name='ui-icon')}",
        default_policy_warning_age_days=f'{DEFAULT_POLICY_WARNING_AGE_DAYS}',
        ui_icon_html_clock_class_name_ui_icon=f"{_ui_icon_html('clock', class_name='ui-icon')}",
        default_policy_strict_stale_age_days=f'{DEFAULT_POLICY_STRICT_STALE_AGE_DAYS}',
        ui_icon_html_pin_class_name_ui_icon_freshness_me=f"{_ui_icon_html('pin', class_name='ui-icon freshness-meta-icon')}",
        ui_icon_html_calendar_class_name_ui_icon_freshne=f"{_ui_icon_html('calendar', class_name='ui-icon freshness-meta-icon')}",
        escape_generated_local_date=f'{escape(generated_local_date)}',
        ui_icon_html_clock_class_name_ui_icon_freshness_=f"{_ui_icon_html('clock', class_name='ui-icon freshness-meta-icon')}",
        escape_generated_local_time=f'{escape(generated_local_time)}',
        escape_generated_human=f'{escape(generated_human)}',
        time_with_epoch_copy_html_generated_at_utc_label=f"{_time_with_epoch_copy_html(generated_at_utc, label='policy generated UTC')}",
        generated_age_days=f'{generated_age_days:g}',
        escape_workflow_run=f'{escape(workflow_run)}',
        source_diagnostics_panel=f'{source_diagnostics_panel}',
        trust_class=f'{trust_class}',
        ui_icon_html_key_class_name_ui_icon_panel_headin=f"{_ui_icon_html('key', class_name='ui-icon panel-heading-icon')}",
        dashboard_info_topic_html_signature_base_url_bas=f"{_dashboard_info_topic_html('signature', base_url=base_url)}",
        trust_class_2=f'{trust_class}',
        escape_trust_indicator=f'{escape(trust_indicator)}',
        trust_class_3=f'{trust_class}',
        escape_signature_status=f'{escape(signature_status)}',
        escape_signature_algorithm=f'{escape(signature_algorithm)}',
        escape_key_id=f'{escape(key_id)}',
        hash_html_policy_hash=f'{_hash_html(policy_hash)}',
        escape_signature_status_2=f'{escape(signature_status)}',
        ui_icon_html_api_class_name_ui_icon_panel_headin=f"{_ui_icon_html('api', class_name='ui-icon panel-heading-icon')}",
        dashboard_info_topic_html_programmatic_api_base_=f"{_dashboard_info_topic_html('programmatic-api', base_url=base_url)}",
        endpoint_links=f'{endpoint_links}',
        footer_html=f'{_footer_html()}',
        safe_json_script_payload_freshness_data=f'{_safe_json_script_payload(freshness_data)}',
        default_policy_warning_age_days_2=f'{DEFAULT_POLICY_WARNING_AGE_DAYS}',
        default_policy_warning_age_days_3=f'{DEFAULT_POLICY_WARNING_AGE_DAYS}',
    )
