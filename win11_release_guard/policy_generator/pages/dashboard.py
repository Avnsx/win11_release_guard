"""The policy dashboard page (index.html)."""

from __future__ import annotations

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
    return (
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"utf-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "  <title>Windows 11 Release Guard</title>\n"
        f"  <link rel=\"icon\" href=\"{WIKI_FAVICON_DATA_URL}\">\n"
        f"{dashboard_seo_meta}"
        "  <style>\n"
        "    :root{color-scheme:light;--bg:#f4f8fd;--ink:#172033;--muted:#667085;--soft:#f8fbff;--line:#d8e3f0;--panel:#ffffff;--blue:#0078d4;--blue-strong:#0067c0;--blue-soft:#e8f3ff;--ok:#107c10;--ok-soft:#eaf7ed;--warn:#b45309;--warn-soft:#fff4df;--err:#b42318;--err-soft:#fff0ed;--unknown:#64748b;--unknown-soft:#f1f5f9;--code:#063f63;--shadow:0 18px 55px rgba(31,79,143,.12)}\n"
        "    *{box-sizing:border-box}html{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}html,body{max-width:100%;overflow-x:hidden}body{position:relative;isolation:isolate;margin:0;min-height:100vh;background:radial-gradient(circle at 14% 9%,#8ee4ff 0,#39b9ff 15%,rgba(57,185,255,0) 34%),radial-gradient(circle at 78% -10%,#78d6ff 0,#168df0 22%,rgba(22,141,240,0) 43%),radial-gradient(circle at 72% 78%,#0036bd 0,#005bd8 27%,rgba(0,91,216,0) 48%),linear-gradient(145deg,#34c8ff 0%,#0587ee 33%,#0058d4 61%,#002b99 100%);color:var(--ink);font-family:Segoe UI,Arial,sans-serif;line-height:1.45}body:before,body:after{content:'';position:fixed;pointer-events:none;z-index:0}body:before{width:115vw;height:84vh;left:-17vw;top:-18vh;border-radius:0 0 58% 52%;background:radial-gradient(ellipse at 32% 35%,rgba(255,255,255,.72),rgba(185,232,255,.38) 28%,rgba(0,120,212,0) 58%);transform:rotate(-8deg);filter:blur(2px)}body:after{width:92vw;height:76vh;right:-26vw;bottom:-29vh;border:2px solid rgba(255,255,255,.32);border-left-color:rgba(151,220,255,.48);border-radius:50%;box-shadow:-120px -82px 0 -26px rgba(255,255,255,.18),-230px -122px 0 -72px rgba(0,120,212,.34);transform:rotate(-18deg)}\n"
        "    main{position:relative;z-index:1;width:calc(100% - 80px);max-width:1580px;margin:40px auto;padding:34px;border:1px solid rgba(255,255,255,.65);border-radius:32px;background:linear-gradient(180deg,rgba(255,255,255,.86),rgba(239,248,255,.74));box-shadow:0 42px 110px rgba(0,35,126,.34),inset 0 1px 0 rgba(255,255,255,.82);backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px)}.masthead{margin-bottom:28px;padding:0 2px 10px;border:0;border-radius:0;background:transparent;box-shadow:none;backdrop-filter:none}\n"
        "    .brand{display:flex;gap:32px;align-items:center;min-width:0}.brand>div:last-child{min-width:0;flex:1}.brand-layout{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:28px;align-items:center}.brand-copy{min-width:0}.header-actions{position:relative;z-index:2;display:flex;flex-direction:column;align-items:flex-end;justify-content:center;gap:14px;min-width:0;opacity:1;visibility:visible}.header-top-actions{position:relative;z-index:2;display:flex;align-items:center;justify-content:flex-end;gap:12px;max-width:100%;flex-wrap:wrap;opacity:1;visibility:visible}.pypi-download-link{display:inline-flex;align-items:center;justify-content:center;width:96px;height:96px;line-height:0;text-decoration:none;filter:drop-shadow(0 14px 22px rgba(0,79,168,.18));opacity:1;visibility:visible;flex:0 0 auto}.pypi-download-link:hover{text-decoration:none;filter:drop-shadow(0 16px 26px rgba(0,79,168,.24))}.pypi-download-link:focus-visible{outline:3px solid rgba(0,120,212,.3);outline-offset:4px;border-radius:20px}.pypi-download-link img{display:block;width:96px;height:96px;object-fit:contain;border-radius:18px}.winmark{width:132px;height:132px;display:grid;grid-template-columns:1fr 1fr;gap:8px;flex:0 0 auto;filter:drop-shadow(0 18px 28px rgba(0,88,212,.22))}.winmark span{background:linear-gradient(145deg,#3fb8ff 0%,#0a84ff 42%,#0055ef 100%);border-radius:9px;box-shadow:inset 0 1px 0 rgba(255,255,255,.38),0 8px 18px rgba(0,78,184,.18)}\n"
        "    .title-line h1{font-size:clamp(34px,4rem,64px);line-height:1.04;margin:0 0 10px;font-weight:760;overflow-wrap:anywhere;color:#071632;letter-spacing:0}.subtitle-line{display:flex;align-items:baseline;gap:16px;min-width:0}.title-version-link{display:inline-flex;align-items:center;gap:8px;margin-left:auto;position:relative;z-index:2;border:1px solid rgba(142,188,236,.82);border-radius:999px;background:linear-gradient(180deg,rgba(255,255,255,.96),rgba(239,248,255,.9));box-shadow:0 14px 30px rgba(0,79,168,.12),inset 0 1px 0 rgba(255,255,255,.9);padding:13px 20px;font-size:16px;font-weight:700;color:#0b5bd3;white-space:nowrap;flex:0 0 auto;opacity:1;visibility:visible}.title-version-link:after{content:'';width:7px;height:7px;border-radius:999px;background:#0b5bd3;box-shadow:0 0 0 4px rgba(11,91,211,.1)}.title-version-label{color:#233152;font-family:Segoe UI,Arial,sans-serif;font-weight:500}p{margin:0}.subtitle{font-size:23px;color:#263858;overflow-wrap:anywhere;min-width:0}.eyebrow{display:inline-flex;align-items:center;gap:8px;margin-bottom:8px;color:#004de6;font-size:20px;font-weight:740;text-transform:uppercase;letter-spacing:0}.eyebrow-icon{width:22px;height:22px;color:#0057e7}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}\n"
        "    .header-nav{--item-size:42px;--nav-gap:5px;--enter-nav:0;--label-x:21px;--label-y:0px;position:relative;z-index:2;isolation:isolate;opacity:1;visibility:visible;flex:0 0 auto}.header-nav ul{list-style:none;margin:0;padding:0}.header-nav .nav-inner{position:relative;z-index:1;display:flex;gap:var(--nav-gap);white-space:nowrap;border:1px solid rgba(142,188,236,.82);border-radius:999px;background:linear-gradient(180deg,rgba(255,255,255,.95),rgba(238,247,255,.88));box-shadow:0 14px 30px rgba(0,79,168,.13),inset 0 1px 0 rgba(255,255,255,.9);padding:4px;opacity:1;visibility:visible}.header-nav .nav-inner li{display:flex}.header-nav .nav-inner a{width:var(--item-size);height:38px;display:grid;place-items:center;border-radius:999px;color:#5e6b86;text-decoration:none;transition:color .16s ease,background-color .16s ease,transform .16s ease;opacity:1;visibility:visible}.header-nav .nav-inner a:hover,.header-nav .nav-inner a:focus-visible{color:var(--blue-strong);background:linear-gradient(180deg,#ffffff,#eaf5ff);text-decoration:none;transform:translateY(-1px)}.header-nav .nav-inner a:focus-visible{outline:3px solid rgba(0,120,212,.24);outline-offset:3px}.header-nav svg{width:21px;height:21px;display:block;fill:currentColor}.nav-hover-label{position:absolute;left:0;bottom:calc(100% + 6px);max-width:180px;opacity:var(--enter-nav);pointer-events:none;white-space:nowrap;border:1px solid rgba(184,207,234,.95);border-radius:999px;background:rgba(239,246,255,.96);box-shadow:0 9px 18px rgba(31,79,143,.12);color:#075985;font-size:11px;font-weight:600;line-height:1;padding:7px 10px;transform:translate(calc(var(--label-x) - 50%),calc((1 - var(--enter-nav)) * 4px + var(--label-y)));transition:opacity .15s ease,transform .2s ease}.header-nav:not(:hover):not(:focus-within){--enter-nav:0}\n"
        "    .grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:16px}.kpi-grid{gap:20px;margin-bottom:22px}.dashboard-grid{align-items:stretch}.panel{background:linear-gradient(180deg,rgba(255,255,255,.94),rgba(248,252,255,.9));border:1px solid var(--line);border-radius:8px;padding:14px;min-width:0;box-shadow:0 10px 30px rgba(31,79,143,.08)}.panel *{min-width:0}.panel p,.panel span,.panel dd,.panel strong{overflow-wrap:anywhere}.panel.status-card{display:grid;gap:18px;padding:22px;border-radius:18px;background:linear-gradient(180deg,rgba(255,255,255,.96),rgba(247,252,255,.9));border-color:#c6d9ee;box-shadow:0 18px 38px rgba(31,79,143,.12),inset 0 1px 0 rgba(255,255,255,.88)}.span-3{grid-column:span 3}.span-4{grid-column:span 4}.span-5{grid-column:span 5}.span-6{grid-column:span 6}.span-7{grid-column:span 7}.span-8{grid-column:span 8}.span-12{grid-column:span 12}\n"
        "    .ui-icon{display:block;flex:0 0 auto}.kpi-card{position:relative;display:grid;align-content:start;gap:14px;min-height:188px;padding:24px;border-color:rgba(167,204,242,.82);border-radius:18px;background:linear-gradient(180deg,rgba(255,255,255,.92),rgba(246,251,255,.78));box-shadow:0 18px 38px rgba(31,79,143,.11),inset 0 1px 0 rgba(255,255,255,.92);overflow:visible}.kpi-card:before{content:'';position:absolute;inset:0 0 auto;height:1px;background:rgba(255,255,255,.96)}.kpi-card>*{position:relative}.kpi-head{display:flex;align-items:center;gap:14px;margin-bottom:8px}.kpi-head h2{margin:0;color:#4b5d78;font-size:13px;font-weight:740;line-height:1.15;text-transform:uppercase;letter-spacing:0}.icon-bubble{display:inline-grid;place-items:center;width:54px;height:54px;border:1px solid #c9e3ff;border-radius:999px;background:linear-gradient(135deg,#e5f3ff,#f7fbff);color:var(--blue-strong);box-shadow:inset 0 1px 0 rgba(255,255,255,.92),0 10px 22px rgba(31,79,143,.1)}.kpi-icon{width:27px;height:27px}.kpi-target .icon-bubble{color:#005bd3;background:linear-gradient(135deg,#dff0ff,#f8fcff)}.kpi-family .icon-bubble,.kpi-observed .icon-bubble,.kpi-baseline .icon-bubble{color:#0b69d1}.status-pill{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:5px 11px;font-size:13px;font-weight:650;line-height:1;color:var(--unknown);background:var(--unknown-soft);white-space:nowrap}.kpi-head .status-pill{margin-left:auto}.status-pill.current{color:var(--ok);border-color:#a9ddb7;background:linear-gradient(180deg,var(--ok-soft),#f7fff8)}\n"
        "    h2{font-size:12px;font-weight:720;text-transform:uppercase;letter-spacing:0;color:var(--muted);margin:0 0 12px}.metric{font-size:31px;font-weight:680;line-height:1;color:#102a43}.kpi-card .metric{font-size:54px;font-weight:720;letter-spacing:0;color:#071632}.metric.blue,.kpi-card .metric.blue{color:#005bd3}.label{display:block;color:var(--muted);font-size:13px;margin-top:6px}.kpi-card .label{font-size:17px;color:#50627e;margin-top:0;line-height:1.25}.mono{font-family:Consolas,Menlo,monospace;color:var(--code);overflow-wrap:anywhere;word-break:break-word}.panel-heading-icon{width:16px;height:16px;color:var(--blue-strong)}.kpi-head h2,.freshness-head h2,.source-diagnostics>.panel-head h2,.signature-head h2,.programmatic-api>h2{display:inline-flex;align-items:center;gap:6px;min-width:0}.dashboard-info-link{position:relative;z-index:4;display:inline-grid;place-items:center;width:17px;height:17px;flex:0 0 auto;border:1px solid rgba(142,188,236,.95);border-radius:999px;background:linear-gradient(180deg,#fff,#eaf5ff);box-shadow:inset 0 1px 0 rgba(255,255,255,.92),0 5px 12px rgba(31,79,143,.1);color:#0067c0;text-decoration:none;line-height:0}.dashboard-info-link:hover,.dashboard-info-link:focus-visible{border-color:#7bb8f0;background:#fff;text-decoration:none;color:#005bd3}.dashboard-info-link:focus-visible{outline:3px solid rgba(0,120,212,.26);outline-offset:2px}.dashboard-info-icon{width:11px;height:11px;stroke-width:2.2}.dashboard-info-link:after{content:attr(data-help);position:absolute;left:50%;top:calc(100% + 9px);width:max-content;max-width:min(280px,70vw);white-space:normal;text-align:left;border:1px solid rgba(174,203,235,.96);border-radius:10px;background:rgba(255,255,255,.98);box-shadow:0 14px 30px rgba(31,79,143,.16),inset 0 1px 0 rgba(255,255,255,.92);padding:9px 10px;color:#233152;font-size:12px;font-weight:600;line-height:1.35;text-transform:none;letter-spacing:0;opacity:0;pointer-events:none;transform:translate(-50%,-2px);transition:opacity .14s ease,transform .14s ease}.dashboard-info-link:before{content:'';position:absolute;left:50%;top:calc(100% + 4px);width:9px;height:9px;border-left:1px solid rgba(174,203,235,.96);border-top:1px solid rgba(174,203,235,.96);background:#fff;opacity:0;pointer-events:none;transform:translate(-50%,-2px) rotate(45deg);transition:opacity .14s ease,transform .14s ease}.dashboard-info-link:hover:after,.dashboard-info-link:focus-visible:after,.dashboard-info-link:hover:before,.dashboard-info-link:focus-visible:before{opacity:1;transform:translate(-50%,0) rotate(0deg)}.dashboard-info-link:hover:before,.dashboard-info-link:focus-visible:before{transform:translate(-50%,0) rotate(45deg)}\n"
        "    .baseline-update-notice{position:relative;overflow:hidden;display:grid;grid-template-columns:auto minmax(0,1fr);gap:16px;align-items:start;border-color:rgba(88,166,255,.82);border-radius:18px;background:linear-gradient(135deg,rgba(255,255,255,.98),rgba(232,243,255,.94) 58%,rgba(217,236,255,.9));box-shadow:0 20px 42px rgba(0,91,216,.14),inset 0 1px 0 rgba(255,255,255,.94);padding:18px 20px}.baseline-update-notice:before{content:'';position:absolute;inset:0 0 auto;height:3px;background:linear-gradient(90deg,#0078d4,#5ab7ff,#cfe9ff)}.baseline-notice-icon{position:relative;display:grid;place-items:center;width:48px;height:48px;border:1px solid #9cccf6;border-radius:16px;background:linear-gradient(180deg,#fff,#e7f3ff);color:#005bd3;box-shadow:inset 0 1px 0 rgba(255,255,255,.92),0 10px 22px rgba(0,91,216,.12)}.baseline-notice-icon .ui-icon{width:27px;height:27px}.baseline-notice-body{position:relative;display:grid;gap:9px}.baseline-notice-head{display:flex;flex-wrap:wrap;align-items:center;gap:9px 12px}.baseline-notice-pill{display:inline-flex;align-items:center;border:1px solid #9cccf6;border-radius:999px;background:linear-gradient(180deg,#fff,#eaf5ff);padding:4px 10px;color:#005bd3;font-size:12px;font-weight:760;line-height:1}.baseline-title{margin:0;color:#071632;font-size:21px;font-weight:760;line-height:1.2;text-transform:none}.baseline-update-notice p{margin:0;color:#263858;font-size:14px;line-height:1.42}.baseline-review{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:8px 10px;align-items:start;border-left:3px solid #0a84ff;border-radius:12px;background:rgba(255,255,255,.58);box-shadow:inset 0 1px 0 rgba(255,255,255,.74);padding:8px 10px;color:#17345f!important}.baseline-review-label{display:inline-flex;align-items:center;width:max-content;border:1px solid #9cccf6;border-radius:999px;background:#fff;padding:2px 7px;color:#005bd3;font-size:12px;font-weight:760;line-height:1.1}.baseline-review-list{margin:0;padding:0;display:grid;grid-template-columns:repeat(2,minmax(180px,1fr));gap:5px 14px;list-style:none;color:#17345f;font-size:13px;line-height:1.35}.baseline-review-list li{position:relative;min-width:0;padding-left:13px}.baseline-review-list li:before{content:'';position:absolute;left:0;top:.58em;width:5px;height:5px;border-radius:999px;background:#0a84ff;box-shadow:0 0 0 3px rgba(10,132,255,.12)}.baseline-timeline{color:#475569!important;font-size:13px!important}.baseline-read-more,.diag-read-more-inline{display:inline-flex;align-items:center;margin-left:6px;color:#005bd3;font-size:12px;font-weight:750;text-decoration:none;white-space:nowrap}.baseline-review>.baseline-read-more{margin-left:0;margin-top:2px}.baseline-read-more:after,.diag-read-more-inline:after{content:'>';padding-left:5px;font-weight:760}.baseline-read-more:hover,.baseline-read-more:focus-visible,.diag-read-more-inline:hover,.diag-read-more-inline:focus-visible{color:#004a9f;text-decoration:underline;text-underline-offset:3px}.baseline-read-more:focus-visible,.diag-read-more-inline:focus-visible{outline:3px solid rgba(0,120,212,.24);outline-offset:2px;border-radius:6px}.baseline-chip-list{display:flex;flex-wrap:wrap;gap:7px}.baseline-chip{display:inline-flex;align-items:center;max-width:100%;border:1px solid #bfdbfe;border-radius:999px;background:rgba(255,255,255,.78);box-shadow:inset 0 1px 0 rgba(255,255,255,.9);padding:5px 9px;color:#16427c;font-size:12px;font-weight:650;line-height:1.2;text-decoration:none}.baseline-chip.security{border-color:#93c5fd;background:linear-gradient(180deg,#fff,#e8f3ff);color:#005bd3}.baseline-chip.official-date{color:#334155}.baseline-update-notice[hidden]{display:none!important}\n"
        "    .dashboard-info-link:after{display:none}.dashboard-info-tooltip{position:absolute;top:calc(100% + 11px);left:50%;z-index:6;width:max-content;max-width:min(280px,72vw);white-space:normal;text-align:left;border:1px solid rgba(174,203,235,.96);border-radius:10px;background:rgba(255,255,255,.98);box-shadow:0 14px 30px rgba(31,79,143,.16),inset 0 1px 0 rgba(255,255,255,.92);padding:9px 10px;color:#233152;font-size:12px;font-weight:600;line-height:1.35;text-transform:none;letter-spacing:0;opacity:0;pointer-events:none;transform:translate(-50%,-2px);transition:opacity .14s ease,transform .14s ease}.dashboard-info-tooltip span{display:block}.dashboard-info-tooltip-action{margin-top:7px;color:#0067c0;font-weight:760}.dashboard-info-link:hover .dashboard-info-tooltip,.dashboard-info-link:focus-visible .dashboard-info-tooltip{opacity:1;transform:translate(-50%,0)}\n"
        "    .kv{display:grid;grid-template-columns:minmax(126px,160px) 1fr;gap:9px 14px;font-size:14px}.kv dt{color:var(--muted)}.kv dd{margin:0;font-weight:600;overflow-wrap:anywhere}.kv dd span{display:block;margin-top:2px;color:var(--muted);font-size:12px;font-weight:500}.compact-kv{grid-template-columns:1fr;gap:4px}.compact-kv dt{font-size:12px}.compact-kv dd{margin:0 0 8px}.metadata{border-top:1px solid var(--line);padding-top:12px}.refresh{border-left:3px solid var(--blue);background:linear-gradient(90deg,var(--blue-soft),rgba(255,255,255,0));padding-left:12px}.time-copy{display:inline-flex!important;align-items:center;gap:6px;max-width:100%;min-width:0;color:inherit;font-size:inherit}.time-copy time{overflow-wrap:anywhere}.time-copy.unavailable{color:var(--muted);font-size:13px}.epoch-copy{display:inline-grid;place-items:center;width:24px;height:24px;min-width:24px;border:1px solid var(--line);border-radius:6px;background:rgba(255,255,255,.86);color:#64748b;cursor:pointer;padding:0;box-shadow:0 1px 1px rgba(15,23,42,.04)}.epoch-copy:hover{border-color:#9cccf6;color:var(--blue-strong);background:#fff}.epoch-copy:focus-visible{outline:3px solid rgba(0,120,212,.28);outline-offset:2px}.epoch-copy[data-copy-state=\"copied\"]{border-color:#b9e6c4;color:var(--ok);background:var(--ok-soft)}.epoch-copy[data-copy-state=\"failed\"]{border-color:#f6b7ad;color:var(--err);background:var(--err-soft)}.epoch-copy svg{width:14px;height:14px;display:block;pointer-events:none}\n"
        "    .panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.freshness-head h2{margin:0;color:#0f1f3d}.freshness-state{display:inline-flex;align-items:center;border-radius:999px;border:1px solid var(--line);padding:6px 12px;font-size:13px;font-weight:650;line-height:1;color:var(--unknown);background:var(--unknown-soft);white-space:nowrap}.freshness-state.current{color:var(--ok);background:var(--ok-soft);border-color:#b9e6c4}.freshness-state.refresh-due{color:var(--warn);background:var(--warn-soft);border-color:#f6d493}.freshness-state.stale{color:var(--err);background:var(--err-soft);border-color:#f6b7ad}.freshness-state.unknown{color:var(--unknown);background:var(--unknown-soft);border-color:var(--line)}.freshness-layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(176px,190px);gap:14px;align-items:center}.freshness-primary{display:grid;gap:16px}.freshness-hero{display:flex;align-items:center;gap:16px}.freshness-ring{display:inline-grid;place-items:center;width:120px;height:120px;flex:0 0 auto;border:3px solid var(--ok);border-radius:999px;background:radial-gradient(circle,#f8fff9 0,#e9f8ec 72%,#def4e4 100%);color:var(--ok);box-shadow:0 18px 34px rgba(16,124,16,.18),0 0 0 14px rgba(16,124,16,.08),inset 0 1px 0 rgba(255,255,255,.9)}.freshness-ring.refresh-due{border-color:var(--warn);color:var(--warn);background:linear-gradient(180deg,var(--warn-soft),#fffaf0);box-shadow:0 18px 34px rgba(180,83,9,.14),0 0 0 14px rgba(180,83,9,.08)}.freshness-ring.stale{border-color:var(--err);color:var(--err);background:linear-gradient(180deg,var(--err-soft),#fff8f6);box-shadow:0 18px 34px rgba(180,35,24,.14),0 0 0 14px rgba(180,35,24,.08)}.freshness-ring.unknown{border-color:#b8c5d6;color:var(--unknown);background:linear-gradient(180deg,var(--unknown-soft),#fbfdff);box-shadow:0 18px 34px rgba(100,116,139,.12),0 0 0 14px rgba(100,116,139,.06)}.freshness-ring-icon{width:64px;height:64px}.freshness-metric{font-size:46px;font-weight:720;line-height:1;color:#071632;letter-spacing:0;white-space:nowrap}.freshness-detail{color:#334155;font-size:14px}.freshness-callout{display:flex;align-items:center;gap:10px;margin:0;border:1px solid #cfe5d4;border-radius:12px;background:linear-gradient(180deg,rgba(255,255,255,.9),rgba(247,255,249,.84));padding:12px 14px;box-shadow:inset 0 1px 0 rgba(255,255,255,.86)}.freshness-callout.refresh-due{border-color:#f6d493;background:linear-gradient(180deg,var(--warn-soft),#fffaf0)}.freshness-callout.stale{border-color:#f6b7ad;background:linear-gradient(180deg,var(--err-soft),#fff8f6)}.freshness-callout.unknown{border-color:var(--line);background:linear-gradient(180deg,var(--unknown-soft),#fbfdff)}.freshness-callout-icon{width:22px;height:22px;flex:0 0 auto;color:var(--ok)}.freshness-callout.refresh-due .freshness-callout-icon{color:var(--warn)}.freshness-callout.stale .freshness-callout-icon{color:var(--err)}.freshness-callout.unknown .freshness-callout-icon{color:var(--unknown)}.thresholds{display:grid;grid-template-columns:1fr;gap:10px}.threshold-card{display:grid;grid-template-columns:auto minmax(0,1fr);gap:10px;align-items:center;border:1px solid var(--line);border-radius:12px;background:linear-gradient(180deg,#f8fbff,#f2f7ff);padding:11px}.threshold-icon{display:inline-grid;place-items:center;width:34px;height:34px;border:1px solid #c9e3ff;border-radius:10px;background:#fff;color:var(--blue-strong)}.threshold-icon svg{width:20px;height:20px}.thresholds strong{display:block;font-size:17px;font-weight:640}.thresholds span{display:block;color:var(--muted);font-size:12px}.freshness-meta-strip{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border-top:1px solid var(--line);padding-top:16px}.freshness-meta-item{display:flex;align-items:center;justify-content:center;gap:10px;color:#24344f;font-size:15px;line-height:1.2;min-width:0;white-space:nowrap}.freshness-meta-item+.freshness-meta-item{border-left:1px solid var(--line)}.freshness-meta-icon{width:25px;height:25px;flex:0 0 auto;color:#005bd3}.freshness-metadata{border:0;padding-top:0}.freshness-metadata dl{margin:0}.freshness-metadata dt{font-size:12px}.freshness-metadata dd{font-size:13px}\n"
        "    ul.clean{list-style:none;margin:0;padding:0;display:grid;gap:10px}ul.clean li{display:grid;gap:3px}ul.clean span{color:var(--muted);font-size:13px}a{color:#075985;text-decoration:none;overflow-wrap:anywhere;word-break:break-word}a:hover{text-decoration:underline}a:focus-visible,summary:focus-visible{outline:3px solid rgba(0,120,212,.28);outline-offset:3px;border-radius:6px}.version-link{display:inline-flex;align-items:center;gap:6px;color:#0067c0;font-weight:600}.version-link:after{content:'\\2197';font-family:Segoe UI,Arial,sans-serif;font-size:12px}.hash{display:inline-block;max-width:100%}\n"
        "    .trust-indicator{--trust-ring:rgba(16,124,16,.18);display:inline-flex;align-items:center;gap:8px;width:max-content;overflow:hidden;border:1px solid #a9ddb7;border-radius:999px;background:linear-gradient(180deg,var(--ok-soft),#f7fff8);color:var(--ok);padding:5px 10px;font-size:12px;font-weight:620;white-space:nowrap;box-shadow:inset 0 1px 0 rgba(255,255,255,.82)}.trust-indicator:before{content:'';width:9px;height:9px;border-radius:999px;background:currentColor;box-shadow:0 0 0 4px var(--trust-ring);transform-origin:center;animation:trustPulse 2.2s cubic-bezier(.4,0,.2,1) infinite;will-change:transform}@keyframes trustPulse{0%,100%{transform:scale(1)}45%{transform:scale(1.48)}72%{transform:scale(1.12)}}.trust-indicator.warning{color:var(--warn);background:linear-gradient(180deg,var(--warn-soft),#fffaf0);border-color:#f6d493;--trust-ring:rgba(180,83,9,.2)}.trust-indicator.error{color:var(--err);background:linear-gradient(180deg,var(--err-soft),#fff8f6);border-color:#f6b7ad;--trust-ring:rgba(180,35,24,.2)}.signature-panel{position:relative;overflow:hidden;display:flex;flex-direction:column;gap:14px;padding:18px;background:linear-gradient(180deg,rgba(255,255,255,.98),rgba(247,251,255,.94));border-color:#c9d9ec}.signature-panel:before{content:'';position:absolute;inset:0 0 auto;height:3px;background:linear-gradient(90deg,var(--ok),rgba(0,120,212,.28));opacity:.5}.signature-panel.warning{border-color:#f6d493;background:linear-gradient(180deg,#fffaf1,#fffdf7)}.signature-panel.warning:before{background:linear-gradient(90deg,var(--warn),rgba(180,83,9,.22))}.signature-panel.error{border-color:#f6b7ad;background:linear-gradient(180deg,#fff7f5,#fffdfc)}.signature-panel.error:before{background:linear-gradient(90deg,var(--err),rgba(180,35,24,.22))}.signature-panel>*{position:relative}.signature-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.signature-head h2,.programmatic-api h2{display:flex;align-items:center;gap:7px}.signature-head h2{margin:0;color:#475569;font-weight:720}.signature-status-card{display:grid;gap:4px;border:1px solid #a9ddb7;border-radius:10px;background:linear-gradient(135deg,#f0fbf3,#fbfffc);padding:13px 14px;box-shadow:inset 0 1px 0 rgba(255,255,255,.8)}.signature-status-card.warning{border-color:#f6d493;background:linear-gradient(135deg,var(--warn-soft),#fffaf0)}.signature-status-card.error{border-color:#f6b7ad;background:linear-gradient(135deg,var(--err-soft),#fff8f6)}.signature-status-card span{color:var(--muted);font-size:12px}.signature-status-card strong{color:#0f172a;font-size:16px;font-weight:650;line-height:1.25}.signature-status-card.error strong{color:var(--err)}.signature-kv{display:grid;gap:9px;margin:0}.signature-kv div{display:grid;grid-template-columns:minmax(104px,30%) minmax(0,1fr);gap:12px;align-items:center;border:1px solid #d5e2f0;border-radius:8px;background:linear-gradient(180deg,#fbfdff,#f5f8fc);padding:10px 12px;box-shadow:inset 0 1px 0 rgba(255,255,255,.7);transition:transform .16s ease,border-color .16s ease,background-color .16s ease}.signature-kv div:hover{border-color:#b8c9dd;background:#fff;box-shadow:0 7px 16px rgba(31,79,143,.07);transform:translateY(-1px)}.signature-kv dt{color:var(--muted);font-size:12px}.signature-kv dd{margin:0;color:#172033;font-weight:600;line-height:1.25;overflow-wrap:anywhere}.signature-kv .mono{font-size:13px;font-weight:600}.source-health{border-top:1px solid var(--line);padding-top:10px;display:grid;gap:8px}.source-health h3{margin:0;color:var(--muted);font-size:11px;font-weight:720;text-transform:uppercase;letter-spacing:0}.source-health-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.source-tile{border:1px solid var(--line);border-radius:8px;padding:10px;min-width:0;background:var(--soft)}.source-tile.ok{border-color:#b9e6c4;background:linear-gradient(180deg,var(--ok-soft),#f8fff9)}.source-tile.warning{border-color:#f6d493;background:linear-gradient(180deg,var(--warn-soft),#fffaf0)}.source-tile.error{border-color:#f6b7ad;background:linear-gradient(180deg,var(--err-soft),#fff8f6)}.source-tile.unknown{border-color:var(--line);background:linear-gradient(180deg,var(--unknown-soft),#fbfdff)}.source-tile-head{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between}.source-name{display:inline-flex;align-items:center;gap:7px;min-width:0}.source-name strong{font-weight:700}.source-icon{width:17px;height:17px;color:var(--blue-strong)}.source-status{border:1px solid var(--line);border-radius:999px;background:#fff;color:#475569;padding:2px 7px;font-size:11px;font-weight:600}.source-status.ok{color:var(--ok);border-color:#b9e6c4;background:#fff}.source-status.warning{color:var(--warn);border-color:#f6d493;background:#fff}.source-status.error{color:var(--err);border-color:#f6b7ad;background:#fff}.source-status.unknown{color:var(--unknown);background:#fff}.source-tile a{display:block;margin:8px 0 10px;font-size:13px}.source-tile>span{display:block;margin-top:4px;color:var(--muted);font-size:13px}.mini-kv{display:grid;grid-template-columns:80px minmax(0,1fr);gap:5px 10px;margin:0;font-size:12px}.mini-kv dt{color:var(--muted)}.mini-kv dd{margin:0;font-weight:600;overflow-wrap:anywhere}\n"
        "    .source-diagnostics{display:flex;flex-direction:column;gap:10px;min-height:0;align-self:start}.diag-summary{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;flex:0 0 auto}.diag-tile{appearance:none;width:100%;display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:center;column-gap:8px;min-height:48px;border:1px solid var(--line);border-radius:8px;background:linear-gradient(180deg,#fbfdff,#f2f7ff);padding:8px 10px;color:inherit;font:inherit;text-align:left;cursor:pointer}.diag-tile:hover{border-color:#9cccf6;background:#fff}.diag-tile:focus-visible{outline:3px solid rgba(0,120,212,.28);outline-offset:2px}.diag-tile[aria-pressed=\"true\"]{box-shadow:inset 0 0 0 2px rgba(0,120,212,.18)}.diag-tile strong{display:block;font-size:22px;font-weight:650;line-height:1}.diag-tile span{color:var(--muted);font-size:12px}.diag-tile-icon{width:19px;height:19px;justify-self:end}.diag-tile.notice{border-color:#bfdbfe;background:linear-gradient(180deg,var(--blue-soft),#f8fbff)}.diag-tile.notice strong,.diag-tile.notice .diag-tile-icon{color:var(--blue)}.diag-tile.notice span{color:var(--blue-strong);font-weight:600}.diag-tile.warning{border-color:#f6d493;background:linear-gradient(180deg,var(--warn-soft),#fffaf0)}.diag-tile.warning strong,.diag-tile.warning .diag-tile-icon{color:var(--warn)}.diag-tile.warning span{color:var(--warn);font-weight:600}.diag-tile.error{border-color:#f6b7ad;background:linear-gradient(180deg,var(--err-soft),#fff8f6)}.diag-tile.error strong,.diag-tile.error .diag-tile-icon{color:var(--err)}.diag-tile.error span{color:var(--err);font-weight:600}.diag-filter-status{margin:-2px 0 0;color:var(--muted);font-size:12px;line-height:1.3}.diag-issue-sync-status{display:flex;align-items:flex-start;gap:7px;margin:0;border:1px solid #f6d493;border-radius:10px;background:linear-gradient(180deg,var(--warn-soft),#fffaf0);padding:8px 10px;color:var(--warn);font-size:12px;line-height:1.3}.diag-issue-sync-status strong{flex:0 0 auto}.diag-issue-sync-status span{color:#7c4a03}.diag-issue-sync-icon{flex:0 0 auto;width:16px;height:16px}.diag-filter-empty{border:1px dashed var(--line);border-radius:12px;background:#fff;padding:14px;color:#475569;font-size:13px}.diag-filter-empty[hidden],.diag-row[hidden],.diag-more[hidden]{display:none!important}.diag-feed{margin-top:2px;height:340px;min-height:340px;max-height:340px;overflow-y:scroll;overscroll-behavior:contain;scrollbar-gutter:stable;border:1px solid #d8dee8;border-radius:8px;background:linear-gradient(180deg,#f6f7f9,#eef1f5);padding:14px 11px 24px 14px;box-shadow:inset 0 1px 2px rgba(15,23,42,.06);scrollbar-width:thin;scrollbar-color:#a8b0bc #eef1f5}.diag-feed::-webkit-scrollbar{width:10px}.diag-feed::-webkit-scrollbar-track{background:#eef1f5;border-radius:999px}.diag-feed::-webkit-scrollbar-thumb{background:#a8b0bc;border-radius:999px;border:2px solid #eef1f5}.diag-events{display:grid;gap:10px;padding:2px 2px 24px}.diag-events-empty .diag-row{background:linear-gradient(90deg,#ffffff,#f8fafc)}.diag-row{display:grid;grid-template-columns:4px 34px minmax(0,1fr);gap:8px;align-items:start;border:1px solid var(--line);border-radius:8px;background:#fbfdff;padding:8px}.diag-row.warning{border-color:#f6d493;background:linear-gradient(90deg,#fffaf0,#ffffff)}.diag-row.error{border-color:#f6b7ad;background:linear-gradient(90deg,#fff8f6,#ffffff)}.diag-row p{margin:3px 0 0;color:#475569;font-size:13px;line-height:1.35}.diag-stripe{display:block;align-self:stretch;border-radius:999px;background:var(--blue)}.diag-row-icon{width:20px;height:20px;margin-top:2px;justify-self:center;color:var(--blue-strong)}.diag-row-icon.warning{color:var(--warn)}.diag-row-icon.error{color:var(--err)}.diag-row.warning .diag-stripe{background:var(--warn)}.diag-row.error .diag-stripe{background:var(--err)}.diag-row-head{display:flex;flex-wrap:wrap;gap:5px;align-items:center}.diag-row-head strong{font-size:13px;font-weight:640}.severity-badge,.source-chip,.diag-tags span,.diag-tags a{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:2px 7px;font-size:11px;font-weight:600;background:#fff;color:#475569}.severity-badge.notice{color:var(--blue-strong);background:var(--blue-soft);border-color:#bfdbfe}.severity-badge.warning{color:var(--warn);background:var(--warn-soft);border-color:#f6d493}.severity-badge.error{color:var(--err);background:var(--err-soft);border-color:#f6b7ad}.source-chip{font-weight:600}.diag-tags{display:flex;flex-wrap:wrap;gap:5px;margin-top:5px}.diag-tags:empty{display:none}.diag-more{border:1px solid var(--line);border-radius:8px;background:var(--soft);padding:8px}.diag-more summary{cursor:pointer;color:#075985;font-size:13px;font-weight:600}.diag-more .diag-events{margin-top:8px}\n"
        "    .diag-row{position:relative}.diag-ticket-link{position:absolute;right:10px;top:10px;z-index:2;display:inline-flex;align-items:center;gap:5px;max-width:calc(100% - 20px);border:1px solid rgba(197,216,236,.95);border-radius:999px;background:rgba(255,255,255,.96);box-shadow:0 8px 18px rgba(31,79,143,.12),inset 0 1px 0 rgba(255,255,255,.9);padding:4px 8px;color:#075985;font-size:11px;font-weight:700;line-height:1;text-decoration:none;opacity:0;pointer-events:none;transform:translateY(-2px);transition:opacity .14s ease,transform .14s ease}.diag-ticket-link:hover{text-decoration:none}.diag-row:hover .diag-ticket-link,.diag-row:focus-within .diag-ticket-link{opacity:1;pointer-events:auto;transform:translateY(0)}.diag-ticket-link-icon{width:12px;height:12px}.diag-ticket-link .github-icon{width:12px;height:12px}\n"
        "    .programmatic-api{display:flex;flex-direction:column;justify-content:flex-start}.api-endpoints{display:grid;gap:9px}.api-endpoint-row{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:10px;align-items:center;border:1px solid var(--line);border-radius:8px;background:linear-gradient(180deg,#f8fafc,#f3f6fa);padding:10px 11px;color:inherit;text-decoration:none}.api-row-icon{width:18px;height:18px;color:var(--blue-strong)}.api-endpoint-row:hover{border-color:#b8c9dd;background:#ffffff;text-decoration:none}.api-endpoint-row:focus-visible{outline:3px solid rgba(0,120,212,.28);outline-offset:3px}.api-endpoint-row strong{display:block;color:#172033;font-size:13px;font-weight:640;line-height:1.25}.api-endpoint-row em{display:block;margin-top:2px;color:var(--muted);font-size:12px;font-style:italic;font-weight:500;line-height:1.35}.api-endpoint-row code{font-family:Consolas,Menlo,monospace;font-size:12px;color:var(--code);white-space:normal;text-align:right;overflow-wrap:anywhere}.api-note{margin-bottom:12px}.warnings{margin:0;padding-left:18px;color:var(--warn)}footer{position:relative;display:grid;gap:8px;justify-items:center;margin-top:34px;padding:20px 12px 4px;color:var(--muted);font-size:12px;line-height:1.45;text-align:center;background:linear-gradient(180deg,rgba(255,255,255,0),rgba(255,255,255,.42));border-radius:14px 14px 0 0}footer:before{content:'';width:min(640px,100%);height:1px;margin-bottom:8px;background:linear-gradient(90deg,rgba(194,213,235,0),rgba(148,163,184,.55),rgba(194,213,235,0));box-shadow:0 -12px 28px rgba(31,79,143,.08)}.footer-note{max-width:900px;margin:0}.footer-disclaimer,.footer-owner{color:#64748b}.footer-source{display:flex;flex-wrap:wrap;align-items:center;justify-content:center;gap:4px 6px;margin-top:2px}.footer-github{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.82);padding:2px 8px;color:#075985;font-weight:600;white-space:nowrap;box-shadow:0 3px 10px rgba(31,79,143,.06)}.footer-license-basic{color:#075985;font-weight:600;text-decoration:none}.footer-license-basic:hover,.footer-license-basic:focus-visible{text-decoration:underline}.github-icon{width:13px;height:13px;display:block;flex:0 0 auto}@media(prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;transition:none!important;animation:none!important}.signature-kv div:hover{transform:none!important}}\n"
        "    @media(max-width:1400px){main{margin:28px auto;padding:28px;border-radius:28px}.brand{gap:24px}.winmark{width:104px;height:104px;gap:7px}.title-line h1{font-size:48px}.subtitle{font-size:19px}.eyebrow{font-size:16px}.title-version-link{padding:11px 16px;font-size:14px}.kpi-card .metric{font-size:40px}.freshness-layout{grid-template-columns:1fr}.freshness-ring{width:104px;height:104px}.freshness-ring-icon{width:56px;height:56px}.freshness-metric{font-size:40px}.thresholds{grid-template-columns:repeat(2,minmax(0,1fr))}}\n"
        "    @media(min-width:901px){#live-freshness-panel{grid-column:1/span 5;grid-row:1/span 2}.source-diagnostics{grid-column:6/span 7;grid-row:1/span 2}.signature-panel{grid-column:1/span 5;grid-row:3}.programmatic-api{grid-column:6/span 7;grid-row:3}.dashboard-grid.has-baseline-notice .baseline-update-notice{grid-column:1/-1;grid-row:1}.dashboard-grid.has-baseline-notice #live-freshness-panel{grid-row:2/span 2}.dashboard-grid.has-baseline-notice .source-diagnostics{grid-row:2/span 2}.dashboard-grid.has-baseline-notice .signature-panel{grid-row:4}.dashboard-grid.has-baseline-notice .programmatic-api{grid-row:4}.dashboard-grid.has-validation-warnings .dashboard-warning-panel{grid-column:1/-1;grid-row:1}.dashboard-grid.has-validation-warnings #live-freshness-panel{grid-row:2/span 2}.dashboard-grid.has-validation-warnings .source-diagnostics{grid-row:2/span 2}.dashboard-grid.has-validation-warnings .signature-panel{grid-row:4}.dashboard-grid.has-validation-warnings .programmatic-api{grid-row:4}.dashboard-grid.has-baseline-notice.has-validation-warnings .dashboard-warning-panel{grid-row:2}.dashboard-grid.has-baseline-notice.has-validation-warnings #live-freshness-panel{grid-row:3/span 2}.dashboard-grid.has-baseline-notice.has-validation-warnings .source-diagnostics{grid-row:3/span 2}.dashboard-grid.has-baseline-notice.has-validation-warnings .signature-panel{grid-row:5}.dashboard-grid.has-baseline-notice.has-validation-warnings .programmatic-api{grid-row:5}}\n"
        "    @media(max-width:900px){main{width:calc(100% - 24px);margin:18px auto;padding:24px;border-radius:24px}.grid{grid-template-columns:repeat(6,minmax(0,1fr))}.span-3,.span-4{grid-column:span 3}.span-5,.span-6,.span-7,.span-8,.span-12{grid-column:span 6}.source-health-grid{grid-template-columns:1fr}.brand-layout{grid-template-columns:1fr}.header-actions{align-items:flex-start}.header-nav{--item-size:37px}.nav-hover-label{display:none}.title-version-link{margin-left:0}.masthead{margin-bottom:20px}}\n"
        "    @media(min-width:741px) and (max-width:900px){.signature-panel{grid-column:span 3}.programmatic-api{grid-column:span 3}.api-endpoint-row{grid-template-columns:auto 1fr}.api-endpoint-row code{grid-column:2;text-align:left}}\n"
        "    @media(max-width:740px){.signature-panel,.programmatic-api{grid-column:1/-1}.signature-head{display:grid}.signature-kv div{grid-template-columns:1fr}.api-endpoint-row{grid-template-columns:auto 1fr}.api-endpoint-row code{grid-column:2;text-align:left}}\n"
        "    @media(max-width:640px){main{width:calc(100% - 16px);margin:10px auto;padding:16px 12px;border-radius:20px}.masthead{padding:0 0 12px}.brand{display:grid;grid-template-columns:58px minmax(0,1fr);gap:14px;align-items:start}.brand-layout{grid-template-columns:1fr;gap:12px}.header-actions{align-items:flex-start;gap:12px}.header-top-actions{justify-content:flex-start;gap:10px}.pypi-download-link{width:74px;height:74px}.pypi-download-link img{width:74px;height:74px;border-radius:15px}.winmark{width:58px;height:58px;gap:4px}.winmark span{border-radius:5px}.title-line h1{font-size:34px}.subtitle-line{flex-wrap:wrap;gap:5px 12px}.eyebrow{font-size:12px}.eyebrow-icon{width:15px;height:15px}.header-nav{--item-size:35px;max-width:100%}.header-nav .nav-inner{width:max-content;max-width:100%;gap:3px;padding:3px}.header-nav .nav-inner a{height:32px}.header-nav svg{width:19px;height:19px}.title-version-link{font-size:12px;margin-left:0;padding:8px 11px}.subtitle{font-size:14px;max-width:240px}.grid{grid-template-columns:1fr;gap:12px}.span-3,.span-4,.span-5,.span-6,.span-7,.span-8,.span-12{grid-column:auto}.kpi-card .metric{font-size:34px}.freshness-hero{align-items:flex-start}.freshness-ring{width:84px;height:84px}.freshness-ring-icon{width:46px;height:46px}.freshness-metric{font-size:34px}.freshness-callout{align-items:flex-start}.freshness-meta-strip{grid-template-columns:1fr;gap:10px}.freshness-meta-item{justify-content:flex-start}.freshness-meta-item+.freshness-meta-item{border-left:0}.kv{grid-template-columns:1fr}.diag-summary,.thresholds{grid-template-columns:1fr}.diag-feed{height:300px;min-height:300px;max-height:300px}footer{margin-top:28px;padding-top:18px}}\n"
        "    .freshness-panel{gap:24px;padding:26px;overflow:hidden}.freshness-panel .panel-head{align-items:center;padding-bottom:2px}.freshness-layout{grid-template-columns:minmax(0,1fr) minmax(182px,198px);gap:22px;align-items:stretch}.freshness-primary{gap:18px;align-content:start}.freshness-hero{display:grid;grid-template-columns:minmax(90px,112px) minmax(0,1fr);gap:20px;align-items:center}.freshness-ring{position:relative;justify-self:center;width:min(112px,100%);height:auto;aspect-ratio:1;border:0;background:radial-gradient(circle at 34% 24%,#ffffff 0 14%,#ecfff0 38%,#c8f2d5 100%);box-shadow:0 18px 34px rgba(16,124,16,.18),0 0 0 12px rgba(16,124,16,.08),inset 0 1px 0 rgba(255,255,255,.9)}.freshness-ring:after{content:'';position:absolute;inset:10px;border:2px solid currentColor;border-radius:999px;opacity:.95}.freshness-ring.refresh-due{background:radial-gradient(circle at 34% 24%,#fff 0 14%,#fff8e8 42%,#fde7bd 100%);box-shadow:0 18px 34px rgba(180,83,9,.15),0 0 0 12px rgba(180,83,9,.08),inset 0 1px 0 rgba(255,255,255,.9)}.freshness-ring.stale{background:radial-gradient(circle at 34% 24%,#fff 0 14%,#fff0ed 42%,#ffd3cc 100%);box-shadow:0 18px 34px rgba(180,35,24,.15),0 0 0 12px rgba(180,35,24,.08),inset 0 1px 0 rgba(255,255,255,.9)}.freshness-ring.unknown{background:radial-gradient(circle at 34% 24%,#fff 0 14%,#f3f7fb 42%,#dce5ef 100%);box-shadow:0 18px 34px rgba(100,116,139,.13),0 0 0 12px rgba(100,116,139,.06),inset 0 1px 0 rgba(255,255,255,.9)}.freshness-ring-icon{position:relative;z-index:1;width:52px;height:52px;stroke-width:2.4;transform:translateY(-1px);filter:drop-shadow(0 4px 6px rgba(16,124,16,.16))}.freshness-age-copy{display:grid;gap:5px;align-content:center;min-width:0}.freshness-age-label{margin-top:0}.freshness-metric{font-size:clamp(34px,3.4vw,44px);line-height:1.02;max-width:100%;white-space:nowrap;overflow-wrap:normal;word-break:normal}.freshness-metric.age-wide{font-size:clamp(31px,3vw,38px)}.freshness-metric.age-compact{font-size:clamp(29px,2.8vw,36px);letter-spacing:0}.freshness-callout{gap:12px;padding:13px 15px;border-radius:14px;line-height:1.4}.freshness-callout-icon{box-sizing:content-box;width:18px;height:18px;min-width:18px;padding:5px;border:1px solid #b9e6c4;border-radius:999px;background:linear-gradient(180deg,#f8fff9,#e7f8eb);color:var(--ok)}.freshness-callout.refresh-due .freshness-callout-icon{border-color:#f6d493;background:linear-gradient(180deg,#fffaf0,#ffefd1);color:var(--warn)}.freshness-callout.stale .freshness-callout-icon{border-color:#f6b7ad;background:linear-gradient(180deg,#fff8f6,#ffe0db);color:var(--err)}.freshness-callout.unknown .freshness-callout-icon{border-color:#cbd5e1;background:linear-gradient(180deg,#fff,#f1f5f9);color:var(--unknown)}.thresholds{gap:12px;align-content:start}.threshold-card{min-height:66px;gap:12px;padding:13px 14px;border-radius:14px}.threshold-icon{width:40px;height:40px;border-radius:12px;background:linear-gradient(180deg,#fff,#eaf5ff);box-shadow:inset 0 1px 0 rgba(255,255,255,.88)}.threshold-icon svg{display:block;width:22px;height:22px;margin:auto}.threshold-card:nth-child(2) .threshold-icon{border-color:#fed7aa;background:linear-gradient(180deg,#fff,#fff3e4);color:#c85700}.freshness-meta-strip{margin-top:2px;padding-top:18px}.freshness-meta-item{gap:11px;min-height:42px}.freshness-meta-icon{box-sizing:content-box;width:20px;height:20px;padding:5px;border:1px solid #bfdbfe;border-radius:999px;background:linear-gradient(180deg,#f8fbff,#eaf5ff);box-shadow:inset 0 1px 0 rgba(255,255,255,.9);color:#005bd3}.freshness-metadata{margin-top:-4px}\n"
        "    @media(max-width:1400px){.freshness-panel{padding:24px}.freshness-layout{grid-template-columns:1fr;gap:22px}.freshness-hero{grid-template-columns:minmax(90px,112px) minmax(0,1fr);gap:22px}.freshness-ring{width:min(112px,100%)}.freshness-ring-icon{width:52px;height:52px}.freshness-metric{font-size:clamp(34px,5vw,44px)}.freshness-metric.age-wide{font-size:clamp(31px,4.4vw,38px)}.freshness-metric.age-compact{font-size:clamp(29px,4vw,36px)}}\n"
        "    @media(max-width:640px){.freshness-panel{padding:20px 16px;gap:20px}.freshness-panel .panel-head{gap:10px}.freshness-layout{gap:18px}.freshness-hero{grid-template-columns:82px minmax(0,1fr);gap:16px;align-items:center}.freshness-ring{width:82px}.freshness-ring:after{inset:7px}.freshness-ring-icon{width:40px;height:40px}.freshness-metric{font-size:30px}.freshness-metric.age-wide,.freshness-metric.age-compact{font-size:28px}.freshness-callout{padding:12px;align-items:flex-start}.threshold-card{min-height:62px}.freshness-meta-strip{padding-top:14px}.freshness-meta-item{min-height:34px}.freshness-meta-icon{width:18px;height:18px;padding:4px}.freshness-metadata{margin-top:-2px}}\n"
        "    @media(max-width:360px){.freshness-panel .panel-head{align-items:flex-start;flex-direction:column}.freshness-state{align-self:flex-start}.freshness-hero{grid-template-columns:1fr}.freshness-ring{justify-self:start;width:76px}.freshness-metric{font-size:28px}.freshness-metric.age-wide,.freshness-metric.age-compact{font-size:26px}}\n"
        "    .signature-panel,.programmatic-api{border-radius:18px;border-color:rgba(174,203,235,.86);background:linear-gradient(180deg,rgba(255,255,255,.94),rgba(246,251,255,.86));box-shadow:0 18px 38px rgba(31,79,143,.11),inset 0 1px 0 rgba(255,255,255,.9)}.signature-panel{gap:16px;padding:22px}.signature-panel:after{content:'';position:absolute;right:-58px;top:-62px;width:166px;height:166px;border-radius:999px;background:radial-gradient(circle,rgba(0,120,212,.14),rgba(0,120,212,.06) 44%,rgba(0,120,212,0) 70%);box-shadow:inset 0 0 0 1px rgba(0,120,212,.1);pointer-events:none}.signature-panel.warning:after{background:radial-gradient(circle,rgba(180,83,9,.14),rgba(180,83,9,.05) 46%,rgba(180,83,9,0) 70%)}.signature-panel.error:after{background:radial-gradient(circle,rgba(180,35,24,.14),rgba(180,35,24,.05) 46%,rgba(180,35,24,0) 70%)}.signature-head{align-items:center}.signature-head h2,.programmatic-api h2{margin:0;color:#334155;font-weight:740;gap:9px}.signature-head .panel-heading-icon,.programmatic-api .panel-heading-icon{box-sizing:content-box;width:18px;height:18px;padding:7px;border:1px solid #c9e3ff;border-radius:12px;background:linear-gradient(180deg,#fff,#eaf5ff);color:#005bd3;box-shadow:inset 0 1px 0 rgba(255,255,255,.9)}.signature-status-card{gap:5px;border-radius:14px;padding:15px 16px;background:linear-gradient(135deg,rgba(240,251,243,.98),rgba(255,255,255,.86));box-shadow:inset 0 1px 0 rgba(255,255,255,.9),0 8px 18px rgba(16,124,16,.06)}.signature-status-card strong{font-size:17px}.signature-kv{gap:10px}.signature-kv div{grid-template-columns:minmax(116px,32%) minmax(0,1fr);gap:14px;border-color:rgba(197,216,236,.88);border-radius:13px;background:linear-gradient(180deg,rgba(255,255,255,.88),rgba(246,250,255,.82));padding:13px 14px;box-shadow:inset 0 1px 0 rgba(255,255,255,.86);transition:border-color .16s ease,background-color .16s ease,box-shadow .16s ease}.signature-kv div:hover{border-color:#aecded;background:rgba(255,255,255,.96);box-shadow:0 8px 18px rgba(31,79,143,.08),inset 0 1px 0 rgba(255,255,255,.92);transform:none}.signature-kv dt{font-size:12px;font-weight:650;text-transform:uppercase;color:#65758e}.signature-kv dd{font-size:14px;color:#102033}.programmatic-api{gap:14px;padding:22px}.programmatic-api .api-note{margin:0;color:#334967;font-size:20px;line-height:1.3}.api-endpoints{gap:10px}.api-endpoint-row{grid-template-columns:auto minmax(0,1fr) max-content;gap:12px;border-color:rgba(197,216,236,.9);border-radius:13px;background:linear-gradient(180deg,rgba(255,255,255,.9),rgba(245,249,255,.84));padding:12px 13px;box-shadow:inset 0 1px 0 rgba(255,255,255,.86);transition:border-color .16s ease,background-color .16s ease,box-shadow .16s ease}.api-row-icon{box-sizing:content-box;width:18px;height:18px;padding:6px;border:1px solid #c9e3ff;border-radius:10px;background:linear-gradient(180deg,#fff,#eaf5ff);color:#005bd3}.api-endpoint-row:hover{border-color:#aecded;background:rgba(255,255,255,.96);box-shadow:0 8px 18px rgba(31,79,143,.08);text-decoration:none}.api-endpoint-row strong{font-size:13px;font-weight:700}.api-endpoint-row em{font-size:12px;color:#65758e}.api-endpoint-row code{justify-self:end;display:inline-flex;align-items:center;max-width:100%;border:1px solid #c9e3ff;border-radius:999px;background:linear-gradient(180deg,#fff,#edf6ff);padding:5px 9px;color:#064b7a;font-size:12px;line-height:1.2;white-space:nowrap;overflow-wrap:normal}.source-health{margin-top:2px;padding-top:14px;gap:10px;border-top-color:rgba(174,203,235,.78)}.source-health h3{color:#5b6d86;font-size:12px}.source-health-grid{gap:12px}.source-tile{position:relative;overflow:hidden;border-color:rgba(185,230,196,.95);border-radius:14px;background:linear-gradient(180deg,rgba(241,253,244,.96),rgba(250,255,251,.88));padding:14px;box-shadow:inset 0 1px 0 rgba(255,255,255,.9),0 8px 20px rgba(16,124,16,.06)}.source-tile:before{content:'';position:absolute;inset:0 0 auto;height:2px;background:linear-gradient(90deg,var(--ok),rgba(0,120,212,.24));opacity:.45}.source-tile.warning:before{background:linear-gradient(90deg,var(--warn),rgba(180,83,9,.2))}.source-tile.error:before{background:linear-gradient(90deg,var(--err),rgba(180,35,24,.2))}.source-tile.unknown:before{background:linear-gradient(90deg,var(--unknown),rgba(100,116,139,.18))}.source-tile-head,.source-tile>a,.source-tile>.mini-kv{position:relative}.source-name{gap:9px}.source-name strong{color:#172033;font-size:16px}.source-icon{box-sizing:content-box;width:16px;height:16px;padding:5px;border:1px solid #b9e6c4;border-radius:10px;background:linear-gradient(180deg,#fff,#ecfff0);color:var(--ok)}.source-tile.warning .source-icon{border-color:#f6d493;background:linear-gradient(180deg,#fff,#fff4df);color:var(--warn)}.source-tile.error .source-icon{border-color:#f6b7ad;background:linear-gradient(180deg,#fff,#fff0ed);color:var(--err)}.source-tile.unknown .source-icon{border-color:#cbd5e1;background:linear-gradient(180deg,#fff,#f1f5f9);color:var(--unknown)}.source-status{padding:3px 8px;background:rgba(255,255,255,.88);box-shadow:inset 0 1px 0 rgba(255,255,255,.8)}.source-tile a{margin:10px 0 12px;color:#075985;font-size:13px}.mini-kv{grid-template-columns:82px minmax(0,1fr);gap:7px 11px}.mini-kv dt{font-weight:650;color:#65758e}.mini-kv dd{color:#1f2f49}.mini-kv .time-copy{gap:7px}.mini-kv .epoch-copy{background:#fff}.dashboard-warning-panel{display:grid;grid-template-columns:max-content minmax(0,1fr);align-items:start;column-gap:14px;padding:15px 18px;border-color:#f6d493;background:linear-gradient(180deg,rgba(255,250,240,.96),rgba(255,246,226,.84));box-shadow:0 14px 28px rgba(180,83,9,.08),inset 0 1px 0 rgba(255,255,255,.88)}.dashboard-warning-panel h2{margin:3px 0 0;color:#8a4b00}.warnings{margin:0;border-radius:14px;background:rgba(255,250,240,.7);padding:10px 12px 10px 26px;color:#9a3f00}.warnings li+li{margin-top:5px}footer{margin-top:36px;padding:18px 12px 2px;background:transparent;border-radius:0;color:#6b7a90;box-shadow:none}footer:before{width:min(760px,100%);margin-bottom:6px;background:linear-gradient(90deg,rgba(194,213,235,0),rgba(148,163,184,.44),rgba(194,213,235,0));box-shadow:none}.footer-note{max-width:920px}.footer-source{margin-top:4px;gap:5px 7px}.footer-github{border-color:rgba(197,216,236,.8);background:rgba(255,255,255,.54);box-shadow:none;color:#1d5f8f}.footer-license-basic{color:#1d5f8f}@media(max-width:1199px) and (min-width:901px){main{width:calc(100% - 44px);padding:28px}.kpi-card{padding:20px}.source-health-grid{grid-template-columns:1fr}.api-endpoint-row{grid-template-columns:auto minmax(0,1fr)}.api-endpoint-row code{grid-column:2;justify-self:start;white-space:normal}.programmatic-api .api-note{font-size:18px}}@media(max-width:900px){.dashboard-grid{align-items:start}.span-5,.span-6,.span-7,.span-8,.span-12,#live-freshness-panel,.source-diagnostics,.signature-panel,.programmatic-api{grid-column:1/-1;grid-row:auto}.dashboard-warning-panel{grid-template-columns:1fr;row-gap:8px}.signature-panel,.programmatic-api{padding:20px}.source-health-grid{grid-template-columns:1fr}.api-endpoint-row{grid-template-columns:auto minmax(0,1fr)}.api-endpoint-row code{grid-column:2;justify-self:start;white-space:normal}.signature-kv div{grid-template-columns:minmax(110px,30%) minmax(0,1fr)}}@media(max-width:640px){body:before{width:150vw;left:-42vw}body:after{width:130vw;right:-62vw}.brand{grid-template-columns:52px minmax(0,1fr)}.winmark{width:52px;height:52px}.title-line h1{font-size:30px;line-height:1.08}.subtitle{font-size:14px;max-width:100%}.dashboard-warning-panel{padding:14px}.signature-panel,.programmatic-api{padding:18px 14px;border-radius:16px}.signature-head{align-items:flex-start;display:grid}.trust-indicator{justify-self:start}.signature-kv div{grid-template-columns:1fr;gap:5px;padding:12px}.programmatic-api .api-note{font-size:16px}.api-endpoint-row{grid-template-columns:auto minmax(0,1fr);align-items:start}.api-row-icon{margin-top:1px}.api-endpoint-row code{grid-column:1/-1;justify-self:start;white-space:normal}.source-tile{padding:13px}.source-tile-head{align-items:flex-start}.source-name strong{font-size:15px}.mini-kv{grid-template-columns:1fr;gap:4px}footer{margin-top:26px;padding:16px 4px 0}.footer-source{display:grid;justify-items:center}.footer-github{white-space:normal}}@media(max-width:360px){.title-line h1{font-size:27px}.api-endpoint-row{padding:11px}.source-name{align-items:flex-start}.footer-note{font-size:11px}}\n"
        "    @media(max-width:1500px){.freshness-panel .freshness-layout{grid-template-columns:1fr;gap:22px}.freshness-panel .thresholds{grid-template-columns:repeat(2,minmax(0,1fr))}}\n"
        "    @media(max-width:640px){main{width:calc(100% - 20px);padding:14px 10px}.kpi-head{flex-wrap:wrap;align-items:flex-start}.kpi-head .status-pill{margin-left:0}.subtitle{max-width:250px;overflow-wrap:break-word;word-break:normal}.freshness-panel .panel-head{align-items:flex-start;flex-direction:column}.freshness-state{align-self:flex-start}.diag-feed{overflow-x:hidden}.diag-row{grid-template-columns:4px 28px minmax(0,1fr);gap:7px}.diag-row-icon{width:18px;height:18px}.diag-row-head,.diag-row p,.diag-tags{min-width:0}.severity-badge,.source-chip,.diag-tags span,.diag-tags a{max-width:100%}.source-tile a{overflow-wrap:anywhere}.time-copy{flex-wrap:wrap}.freshness-panel .thresholds{grid-template-columns:1fr}}\n"
        "    .panel-head{display:flex;align-items:center;justify-content:space-between;gap:14px}.panel-head h2{margin:0;color:#172033}.panel-actions{display:flex;flex-wrap:wrap;align-items:center;justify-content:flex-end;gap:8px}.panel-action{appearance:none;display:inline-flex;align-items:center;justify-content:center;border:1px solid rgba(197,216,236,.9);border-radius:999px;background:rgba(255,255,255,.72);box-shadow:inset 0 1px 0 rgba(255,255,255,.9);padding:7px 13px;color:#0b4fb3;font-family:inherit;font-size:13px;font-weight:650;line-height:1;text-decoration:none;white-space:nowrap;cursor:pointer}.panel-action:hover{border-color:#9cccf6;background:#fff;text-decoration:none}.panel-action:focus-visible{outline:3px solid rgba(0,120,212,.28);outline-offset:2px}.panel-action[aria-pressed=\"true\"]{border-color:#9cccf6;background:#fff}.source-diagnostics{gap:14px;padding:22px;border-radius:18px;border-color:rgba(174,203,235,.86);background:linear-gradient(180deg,rgba(255,255,255,.94),rgba(246,251,255,.86));box-shadow:0 18px 38px rgba(31,79,143,.11),inset 0 1px 0 rgba(255,255,255,.9)}.source-diagnostics>.panel-head{flex:0 0 auto}.diag-feed-bar{display:flex;align-items:center;justify-content:space-between;gap:8px;margin:-4px 0 -8px;min-height:22px}.diag-feed-bar .diag-filter-status{flex:1 1 auto;margin:0}.diag-export-copy{align-self:center;width:22px;height:22px;min-width:22px;margin-right:1px;border-color:transparent;border-radius:5px;background:transparent;box-shadow:none;color:#64748b}.diag-export-copy:hover{border-color:transparent;background:transparent;box-shadow:none;color:var(--blue-strong)}.diag-export-copy[data-copy-state=\"copied\"]{border-color:transparent;background:transparent;color:var(--ok)}.diag-export-copy[data-copy-state=\"failed\"]{border-color:transparent;background:transparent;color:var(--err)}.diag-export-copy svg{width:16px;height:16px}.diag-summary{gap:10px}.diag-tile{grid-template-columns:auto minmax(0,1fr) auto;min-height:64px;border-radius:13px;padding:12px 14px;box-shadow:inset 0 1px 0 rgba(255,255,255,.88)}.diag-tile strong{font-size:25px;font-weight:720}.diag-tile span{font-size:13px}.diag-tile-icon{box-sizing:content-box;width:23px;height:23px;padding:8px;border-radius:999px;background:rgba(255,255,255,.72);box-shadow:inset 0 1px 0 rgba(255,255,255,.9)}.diag-tile.notice .diag-tile-icon{border:1px solid #bfdbfe;background:linear-gradient(180deg,#fff,#eaf5ff)}.diag-tile.warning .diag-tile-icon{border:1px solid #fed7aa;background:linear-gradient(180deg,#fff,#fff3e4)}.diag-tile.error .diag-tile-icon{border:1px solid #fecaca;background:linear-gradient(180deg,#fff,#fff0ed)}.diag-feed{height:340px;min-height:340px;max-height:340px;border-color:rgba(197,216,236,.95);border-radius:14px;background:linear-gradient(180deg,rgba(255,255,255,.76),rgba(238,247,255,.68));padding:14px;box-shadow:inset 0 1px 2px rgba(31,79,143,.05);scrollbar-color:#8eb7df rgba(232,243,255,.68)}.diag-feed::-webkit-scrollbar{width:8px}.diag-feed::-webkit-scrollbar-track{background:rgba(232,243,255,.64);border-radius:999px}.diag-feed::-webkit-scrollbar-thumb{background:#8eb7df;border:2px solid rgba(232,243,255,.84);border-radius:999px}.diag-events{gap:10px;padding:2px 4px 12px 2px}.diag-row{grid-template-columns:5px 50px minmax(0,1fr);gap:12px;border-color:rgba(197,216,236,.95);border-radius:14px;background:linear-gradient(180deg,rgba(255,255,255,.96),rgba(250,253,255,.88));padding:12px;box-shadow:inset 0 1px 0 rgba(255,255,255,.9)}.diag-row.warning{background:linear-gradient(90deg,#fffaf0,#fff)}.diag-row.error{background:linear-gradient(90deg,#fff8f6,#fff)}.diag-row>div{min-width:0}.diag-stripe{width:5px}.diag-row-icon{display:grid;place-items:center;justify-self:center;align-self:start;width:42px;height:46px;margin-top:0;border:1px solid #bfdbfe;border-radius:14px;background:linear-gradient(180deg,#fff,#eaf5ff);color:var(--blue-strong);box-shadow:inset 0 1px 0 rgba(255,255,255,.9)}.diag-row-icon.warning{border-color:#fed7aa;background:linear-gradient(180deg,#fff,#fff3e4);color:var(--warn)}.diag-row-icon.error{border-color:#fecaca;background:linear-gradient(180deg,#fff,#fff0ed);color:var(--err)}.diag-row-icon .ui-icon{width:25px;height:25px}.diag-row-head{gap:6px}.diag-row-head strong{font-size:14px}.diag-row p{font-size:13px;color:#40516a;overflow-wrap:anywhere}.diag-row .diag-user-message{margin-top:6px;color:#1f2f49;font-weight:650}.diag-row .diag-technical-message{margin-top:5px}.source-chip.src-diagnostics{color:#005bd3;background:var(--blue-soft);border-color:#bfdbfe}.source-chip.src-atom-feed{color:#005bd3;background:linear-gradient(180deg,#eef7ff,#f8fbff);border-color:#bfdbfe}.source-chip.src-release-policy,.source-chip.src-policy{color:#1d4ed8;background:linear-gradient(180deg,#edf4ff,#f8fbff);border-color:#c7d2fe}.source-chip.src-release-health{color:var(--ok);background:var(--ok-soft);border-color:#b9e6c4}.source-chip.src-freshness{color:#075985;background:#e0f2fe;border-color:#bae6fd}.source-chip.src-parser{color:var(--warn);background:var(--warn-soft);border-color:#fed7aa}.source-chip.src-signature{color:#5b21b6;background:#f3e8ff;border-color:#d8b4fe}.source-chip.src-source{color:#475569;background:#f8fafc;border-color:#cbd5e1}.diag-tags span{overflow-wrap:anywhere}.source-diagnostics #source-health{margin-top:0;padding-top:12px;border-top-color:rgba(174,203,235,.72)}\n"
        "    @media(max-width:640px){.baseline-update-notice{grid-template-columns:1fr;padding:16px 14px}.baseline-notice-icon{width:42px;height:42px;border-radius:14px}.baseline-notice-icon .ui-icon{width:24px;height:24px}.baseline-title{font-size:18px}.baseline-review{grid-template-columns:1fr}.baseline-review-list{grid-template-columns:1fr}.baseline-chip-list{gap:6px}.baseline-chip{border-radius:10px}.dashboard-info-tooltip{max-width:min(260px,82vw)}.source-diagnostics{padding:18px 14px;gap:12px}.source-diagnostics>.panel-head{align-items:flex-start;flex-direction:column}.panel-action{padding:6px 11px}.diag-summary{grid-template-columns:1fr}.diag-feed{height:320px;min-height:320px;max-height:320px;padding:12px}.diag-row{grid-template-columns:5px 40px minmax(0,1fr);gap:9px;padding:10px}.diag-row-icon{width:36px;height:40px}.diag-row-icon .ui-icon{width:21px;height:21px}.diag-row-head strong{font-size:13px}}\n"
        "    .diag-row{grid-template-columns:5px 38px minmax(0,1fr)}.diag-row-icon{width:32px;height:34px;margin-top:1px;border:0;border-radius:0;background:transparent;box-shadow:none}.diag-row-icon.warning,.diag-row-icon.error{border-color:transparent;background:transparent}.diag-row-icon .ui-icon{width:28px;height:28px;stroke-width:2}.diag-row-head{align-items:center;column-gap:7px;row-gap:4px}.diag-row-head .source-chip{font-size:10px;line-height:1.05;padding:2px 7px;font-weight:650;color:#047f9e;background:linear-gradient(180deg,#ecfeff,#f8fdff);border-color:#a5f3fc;box-shadow:inset 0 1px 0 rgba(255,255,255,.88);transform:translateY(-.5px)}.diag-row-head .source-chip.src-diagnostics,.diag-row-head .source-chip.src-atom-feed,.diag-row-head .source-chip.src-release-policy,.diag-row-head .source-chip.src-policy{color:#047f9e;background:linear-gradient(180deg,#ecfeff,#f8fdff);border-color:#a5f3fc}\n"
        "    @media(max-width:640px){.diag-row{grid-template-columns:5px 34px minmax(0,1fr)}.diag-row-icon{width:28px;height:30px;margin-top:0}.diag-row-icon .ui-icon{width:24px;height:24px}.diag-row-head .source-chip{font-size:10px;padding:2px 6px}}\n"
        "    .source-diagnostics[data-diagnostics-expanded=\"true\"]{align-self:stretch}.source-diagnostics[data-diagnostics-expanded=\"true\"] .diag-feed{height:min(700px,64vh);min-height:520px;max-height:none;flex:1 1 auto}.source-diagnostics[data-diagnostics-expanded=\"true\"] .diag-more[open]{border-color:rgba(142,188,236,.9);background:linear-gradient(180deg,rgba(255,255,255,.9),rgba(239,248,255,.74))}@media(min-width:901px){.dashboard-grid.diagnostics-expanded .source-diagnostics{grid-row:1/span 3;align-self:stretch}.dashboard-grid.has-validation-warnings.diagnostics-expanded .source-diagnostics{grid-row:2/span 3}.dashboard-grid.has-baseline-notice.diagnostics-expanded .source-diagnostics{grid-row:2/span 3}.dashboard-grid.has-baseline-notice.has-validation-warnings.diagnostics-expanded .source-diagnostics{grid-row:3/span 3}.dashboard-grid.diagnostics-expanded .programmatic-api{display:none!important}.dashboard-grid.diagnostics-expanded .source-diagnostics .diag-feed{height:clamp(680px,82vh,900px);min-height:680px;max-height:none;flex:1 1 auto}}@media(max-width:900px){.dashboard-grid.diagnostics-expanded .programmatic-api{display:none!important}.dashboard-grid.diagnostics-expanded .source-diagnostics .diag-feed{height:clamp(440px,68vh,720px);min-height:440px;max-height:none}}@media(max-width:640px){.dashboard-grid.diagnostics-expanded .source-diagnostics .diag-feed{height:clamp(380px,66vh,620px);min-height:380px}}\n"
        "    .icon-bubble{width:62px;height:62px;border-color:#bfdcff;background:linear-gradient(135deg,#dceeff,#f8fcff);box-shadow:inset 0 1px 0 rgba(255,255,255,.94),0 12px 24px rgba(31,79,143,.13)}.kpi-icon{width:31px;height:31px;stroke-width:2}.kpi-target .kpi-icon{width:34px;height:34px}.kpi-head{gap:16px}.kpi-target .icon-bubble{background:linear-gradient(135deg,#d9edff,#f8fcff);color:#005be5}.kpi-family .icon-bubble,.kpi-observed .icon-bubble,.kpi-baseline .icon-bubble{color:#075fe0}\n"
        "    @media(max-width:640px){.icon-bubble{width:54px;height:54px}.kpi-icon{width:28px;height:28px}.kpi-target .kpi-icon{width:30px;height:30px}.kpi-head{gap:13px}}\n"
        "    .threshold-card{grid-template-columns:46px minmax(0,1fr);align-items:stretch}.threshold-icon{position:relative;align-self:center;justify-self:center;display:block;line-height:0;transform:none}.threshold-icon svg{position:absolute;left:50%;top:50%;display:block;margin:0;transform:translate(-50%,calc(-50% + 2px));transform-box:fill-box;transform-origin:center}.threshold-card>div{align-self:center;display:grid;gap:3px;line-height:1.15}.thresholds strong{line-height:1.08}.thresholds span{line-height:1.22}\n"
        "    @media(max-width:640px){.threshold-card{grid-template-columns:44px minmax(0,1fr)}.threshold-icon svg{transform:translate(-50%,calc(-50% + 1px))}.threshold-card>div{gap:2px}}\n"
        "    .panel :where(p,dd,dt,strong,em,code,a,.metric,.label){max-width:100%;min-width:0;overflow-wrap:anywhere;word-break:break-word}.kpi-card{container-type:inline-size}.kpi-card .metric{display:block;max-width:100%;white-space:normal;overflow-wrap:anywhere;word-break:break-word;text-wrap:balance;font-size:clamp(32px,3vw,50px);line-height:.98}.kpi-observed .metric,.kpi-baseline .metric{font-size:clamp(31px,2.65vw,46px)}.kpi-card .label{white-space:normal}.api-endpoint-row code{white-space:normal;overflow-wrap:anywhere;word-break:break-word}.freshness-metric{max-width:100%;overflow-wrap:anywhere}.source-tile-head,.signature-head,.panel-head{min-width:0}.source-name,.api-endpoint-row span,.signature-kv dd{min-width:0;max-width:100%}@supports(font-size:1cqw){.kpi-card .metric{font-size:clamp(32px,13cqw,50px)}.kpi-observed .metric,.kpi-baseline .metric{font-size:clamp(31px,11.8cqw,46px)}}\n"
        "    @media(max-width:900px){.kpi-card .metric{font-size:clamp(32px,8vw,46px)}.kpi-observed .metric,.kpi-baseline .metric{font-size:clamp(31px,7vw,44px)}}\n"
        "    @media(max-width:640px){.kpi-card .metric,.kpi-observed .metric,.kpi-baseline .metric{font-size:clamp(30px,10vw,38px);line-height:1.02}.kpi-card{min-height:0}}\n"
        "    .kpi-card,.freshness-panel,.source-diagnostics,.signature-panel,.programmatic-api{border-color:rgba(150,197,246,.78);box-shadow:0 20px 44px rgba(14,74,150,.13),inset 0 1px 0 rgba(255,255,255,.92)}.kpi-card,.panel.status-card,.source-diagnostics,.signature-panel,.programmatic-api{background:linear-gradient(180deg,rgba(255,255,255,.95),rgba(246,251,255,.86))}.panel h2,.kpi-head h2{color:#1c3156}.metric,.freshness-metric{color:#071632}.panel-action,.status-pill,.source-chip,.diag-tags span,.diag-tags a{box-shadow:inset 0 1px 0 rgba(255,255,255,.88)}.diag-tags span.security-evidence{border-color:#93c5fd;background:linear-gradient(180deg,#fff,#e8f3ff);color:#005bd3;font-weight:700}\n"
        "    .freshness-panel{container-type:inline-size;align-content:start;grid-auto-rows:max-content}.freshness-panel .freshness-layout{grid-template-columns:1fr;gap:clamp(24px,3vw,34px)}.freshness-panel .freshness-hero{grid-template-columns:minmax(104px,120px) minmax(0,1fr);gap:clamp(28px,3vw,40px);max-width:100%}.freshness-age-copy{gap:8px;padding-inline-start:2px}.freshness-metric{white-space:normal;overflow-wrap:normal;word-break:normal;text-wrap:balance}.freshness-callout{margin-top:clamp(14px,2vw,22px)}@supports(margin-top:1cqw){.freshness-callout{margin-top:clamp(14px,3cqw,24px)}}.freshness-panel .thresholds{grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.freshness-panel .threshold-card{column-gap:14px}.freshness-metric.age-wide{font-size:clamp(32px,3.15vw,40px)}@media(max-width:1500px){.freshness-panel .freshness-layout{gap:28px}.freshness-panel .freshness-hero{grid-template-columns:minmax(96px,112px) minmax(0,1fr);gap:28px}}@media(max-width:640px){.freshness-panel .freshness-layout{gap:22px}.freshness-panel .freshness-hero{grid-template-columns:82px minmax(0,1fr);gap:20px}.freshness-age-copy{gap:6px;padding-inline-start:0}.freshness-panel .thresholds{grid-template-columns:1fr;gap:12px}}@media(max-width:360px){.freshness-panel .freshness-hero{grid-template-columns:1fr}.freshness-ring{justify-self:start;width:76px}.freshness-metric{font-size:28px}.freshness-metric.age-wide,.freshness-metric.age-compact{font-size:26px}}\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <main>\n"
        "    <header class=\"masthead\">\n"
        f"      <div class=\"brand\"><div class=\"winmark\" aria-hidden=\"true\"><span></span><span></span><span></span><span></span></div><div class=\"brand-layout\"><div class=\"brand-copy\"><span class=\"eyebrow\">{_ui_icon_html('shield', class_name='ui-icon eyebrow-icon')}<span>Signed public policy feed</span></span><div class=\"title-line\"><h1>Windows 11 Release Guard</h1></div><div class=\"subtitle-line\"><p class=\"subtitle\">Broad-fleet Windows 11 release and quality baseline dashboard.</p></div></div><div class=\"header-actions\"><div class=\"header-top-actions\">"
        f"{_header_nav_html(base_url=base_url)}"
        f"{_pypi_download_link_html(base_url=base_url)}"
        "</div>"
        f"{_program_title_version_html(program_version)}"
        "</div></div></div>\n"
        "    </header>\n"
        "    <section class=\"grid kpi-grid\" id=\"policy-summary\" aria-label=\"Policy summary\">\n"
        "      <article class=\"panel span-3 kpi-card kpi-target\"><div class=\"kpi-head\">"
        f"<span class=\"icon-bubble\">{_ui_icon_html('target', class_name='ui-icon kpi-icon')}</span><h2>Broad target</h2><span class=\"status-pill current\">Current</span></div>"
        f"<div class=\"metric blue\">{escape(target_release)}</div><span class=\"label\">existing Windows 11 devices</span></article>\n"
        "      <article class=\"panel span-3 kpi-card kpi-family\"><div class=\"kpi-head\">"
        f"<span class=\"icon-bubble\">{_ui_icon_html('chip', class_name='ui-icon kpi-icon')}</span><h2>Build family</h2></div>"
        f"<div class=\"metric\">{escape(target_family)}</div><span class=\"label\">Windows build line</span></article>\n"
        "      <article class=\"panel span-3 kpi-card kpi-observed\"><div class=\"kpi-head\">"
        f"<span class=\"icon-bubble\">{_ui_icon_html('eye', class_name='ui-icon kpi-icon')}</span><h2><span>Latest observed</span>{_dashboard_info_topic_html('latest-observed', base_url=base_url)}</h2></div>"
        f"<div class=\"metric\">{escape(target_latest_observed or 'unknown')}</div><span class=\"label\">{escape(target_latest_observed_source)}</span></article>\n"
        "      <article class=\"panel span-3 kpi-card kpi-baseline\"><div class=\"kpi-head\">"
        f"<span class=\"icon-bubble\">{_ui_icon_html('shield-check', class_name='ui-icon kpi-icon')}</span><h2><span>Required baseline</span>{_dashboard_info_topic_html('required-baseline', base_url=base_url)}</h2></div>"
        f"<div class=\"metric\">{escape(target_baseline or 'unknown')}</div><span class=\"label\">{escape(policy.quality_policy.value)} floor</span></article>\n"
        "    </section>\n"
        f"    <section class=\"{dashboard_grid_class}\" aria-label=\"Policy operations dashboard\">\n"
        f"{baseline_notice_block}\n"
        f"{warning_block}\n"
        "      <section class=\"panel span-5 status-card freshness-panel\" id=\"live-freshness-panel\" aria-label=\"Policy feed currency\">"
        f"<div class=\"panel-head freshness-head\"><h2><span>Policy Feed Currency</span>{_dashboard_info_topic_html('policy-feed-currency', base_url=base_url)}</h2><span id=\"live-freshness-state\" class=\"freshness-state unknown\" aria-live=\"polite\" aria-label=\"Published policy feed currency: Unknown\">Unknown</span></div>"
        "<div class=\"freshness-layout\"><div class=\"freshness-primary\"><div class=\"freshness-hero\">"
        f"<span class=\"freshness-ring unknown\" aria-hidden=\"true\">{_ui_icon_html('check', class_name='ui-icon freshness-ring-icon')}</span>"
        "<div class=\"freshness-age-copy\">"
        f"<div id=\"live-generated-age\" class=\"{escape(generated_age_class, quote=True)}\" aria-live=\"polite\" title=\"{escape(generated_age_label, quote=True)}\" aria-label=\"{escape(generated_age_label, quote=True)}\">{escape(generated_age_text)}</div>"
        "<span class=\"label freshness-age-label\">Published feed age</span></div></div>"
        "<p id=\"live-freshness-detail\" class=\"freshness-detail freshness-callout unknown\">"
        f"{_ui_icon_html('check', class_name='ui-icon freshness-callout-icon')}"
        "<span class=\"freshness-callout-text\">Render-time fallback. Browser recalculates published policy feed age from the GitHub Actions generated timestamp when JavaScript is available.</span></p></div>"
        "<div class=\"thresholds\">"
        f"<div class=\"threshold-card\"><span class=\"threshold-icon\">{_ui_icon_html('calendar', class_name='ui-icon')}</span><div><strong>{DEFAULT_POLICY_WARNING_AGE_DAYS} days</strong><span>refresh-due threshold</span></div></div>"
        f"<div class=\"threshold-card\"><span class=\"threshold-icon\">{_ui_icon_html('clock', class_name='ui-icon')}</span><div><strong>{DEFAULT_POLICY_STRICT_STALE_AGE_DAYS} days</strong><span>stale threshold</span></div></div>"
        "</div></div>"
        "<div class=\"freshness-meta-strip\" aria-label=\"Policy generation metadata\">"
        f"<div class=\"freshness-meta-item\">{_ui_icon_html('pin', class_name='ui-icon freshness-meta-icon')}<span>Berlin, Germany</span></div>"
        f"<div class=\"freshness-meta-item\">{_ui_icon_html('calendar', class_name='ui-icon freshness-meta-icon')}<span>{escape(generated_local_date)}</span></div>"
        f"<div class=\"freshness-meta-item\">{_ui_icon_html('clock', class_name='ui-icon freshness-meta-icon')}<span>{escape(generated_local_time)}</span></div></div>"
        "<div class=\"freshness-metadata\"><dl class=\"kv metadata\">"
        f"<dt>Berlin, Germany:</dt><dd class=\"refresh\">{escape(generated_human)}<span>GitHub workflow static feed generation</span></dd>"
        f"<dt>Time (UTC):</dt><dd>{_time_with_epoch_copy_html(generated_at_utc, label='policy generated UTC')}</dd>"
        f"<dt>Published feed age:</dt><dd>{generated_age_days:g} days at render-time fallback</dd>"
        f"<dt>Workflow refresh:</dt><dd>{escape(workflow_run)}<span>last automatic publish run, when generated in GitHub Actions</span></dd>"
        "<noscript><dt>Browser update:</dt><dd>JavaScript disabled; published feed age cannot recalculate in the browser.</dd></noscript>"
        "</dl></div></section>\n"
        f"{source_diagnostics_panel}"
        f"      <section class=\"panel span-5 signature-panel{trust_class}\"><div class=\"signature-head\"><h2>{_ui_icon_html('key', class_name='ui-icon panel-heading-icon')}<span>Signature</span>{_dashboard_info_topic_html('signature', base_url=base_url)}</h2><span class=\"trust-indicator{trust_class}\">{escape(trust_indicator)}</span></div>"
        f"<div class=\"signature-status-card{trust_class}\"><span>Document trust state</span><strong>{escape(signature_status)}</strong><span>Detached signature metadata for the published policy artifact.</span></div>"
        "<dl class=\"signature-kv\">"
        f"<div><dt>Algorithm</dt><dd>{escape(signature_algorithm)}</dd></div>"
        f"<div><dt>key_id</dt><dd class=\"mono\">{escape(key_id)}</dd></div>"
        f"<div><dt>Policy SHA-256</dt><dd>{_hash_html(policy_hash)}</dd></div>"
        f"<div><dt>Signature status</dt><dd>{escape(signature_status)}</dd></div>"
        "</dl></section>\n"
        f"      <section class=\"panel span-7 programmatic-api\"><h2>{_ui_icon_html('api', class_name='ui-icon panel-heading-icon')}<span>Programmatic API</span>{_dashboard_info_topic_html('programmatic-api', base_url=base_url)}</h2>"
        "<p class=\"subtitle api-note\">Public JSON policy artifacts for fleet dashboards and scripts.</p>"
        "<div class=\"api-endpoints\">"
        f"{endpoint_links}"
        "</div></section>\n"
        "    </section>\n"
        f"    {_footer_html()}\n"
        "  </main>\n"
        f"  <script type=\"application/json\" id=\"policy-freshness-data\">{_safe_json_script_payload(freshness_data)}</script>\n"
        "  <script>\n"
        "    (function(){\n"
        "      var dataNode=document.getElementById('policy-freshness-data');\n"
        "      var panelNode=document.getElementById('live-freshness-panel');\n"
        "      var stateNode=document.getElementById('live-freshness-state');\n"
        "      var ageNode=document.getElementById('live-generated-age');\n"
        "      var detailNode=document.getElementById('live-freshness-detail');\n"
        "      var ringNode=panelNode ? panelNode.querySelector('.freshness-ring') : null;\n"
        "      var detailTextNode=detailNode ? detailNode.querySelector('.freshness-callout-text') : null;\n"
        "      var uiActive=true;\n"
        "      var uiFrames=[];\n"
        "      var uiTimers=[];\n"
        "      function reportUiError(scope,error){\n"
        "        try{\n"
        "          var root=document.documentElement;\n"
        "          var label=String(scope||'unknown');\n"
        "          if(root){\n"
        "            if(root.dataset){root.dataset.uiLastError=label;}\n"
        "            root.setAttribute('data-ui-last-error',label);\n"
        "            var count=Number(root.getAttribute('data-ui-error-count')||'0');\n"
        "            if(!Number.isFinite(count)||count<0){count=0;}\n"
        "            root.setAttribute('data-ui-error-count',String(count+1));\n"
        "          }\n"
        "        }catch(_markerError){}\n"
        "        try{if(window.console&&console.warn){console.warn('Windows 11 Release Guard UI '+label+' failed');}}catch(_consoleError){}\n"
        "      }\n"
        "      function reportMissingNode(scope,name){reportUiError(scope+' missing '+name,new Error('missing '+name));}\n"
        "      function guard(scope,fn){try{return fn();}catch(error){reportUiError(scope,error);return undefined;}}\n"
        "      function safeSetTimeout(fn,delay){\n"
        "        if(!uiActive){return 0;}\n"
        "        try{\n"
        "          var id=window.setTimeout(function(){if(uiActive){guard('timer callback',fn);}},delay);\n"
        "          uiTimers.push(['timeout',id]);\n"
        "          return id;\n"
        "        }catch(error){reportUiError('timer setup',error);return 0;}\n"
        "      }\n"
        "      function safeSetInterval(fn,delay){\n"
        "        if(!uiActive){return 0;}\n"
        "        try{\n"
        "          var id=window.setInterval(function(){if(uiActive){guard('interval callback',fn);}},delay);\n"
        "          uiTimers.push(['interval',id]);\n"
        "          return id;\n"
        "        }catch(error){reportUiError('interval setup',error);return 0;}\n"
        "      }\n"
        "      function safeRequestFrame(fn){\n"
        "        if(!uiActive){return 0;}\n"
        "        if(!window.requestAnimationFrame){return safeSetTimeout(fn,16);}\n"
        "        try{\n"
        "          var id=window.requestAnimationFrame(function(){if(uiActive){guard('animation frame',fn);}});\n"
        "          uiFrames.push(id);\n"
        "          return id;\n"
        "        }catch(error){reportUiError('animation frame request',error);return safeSetTimeout(fn,16);}\n"
        "      }\n"
        "      function safeCancelFrame(id){\n"
        "        if(!id){return;}\n"
        "        try{if(window.cancelAnimationFrame){window.cancelAnimationFrame(id);}else{window.clearTimeout(id);}}\n"
        "        catch(error){reportUiError('animation cancel',error);}\n"
        "      }\n"
        "      function shutdownUi(){\n"
        "        if(!uiActive){return;}\n"
        "        uiActive=false;\n"
        "        uiFrames.forEach(safeCancelFrame);\n"
        "        uiFrames=[];\n"
        "        uiTimers.forEach(function(entry){try{if(entry[0]==='interval'){window.clearInterval(entry[1]);}else{window.clearTimeout(entry[1]);}}catch(error){reportUiError('timer cancel',error);}});\n"
        "        uiTimers=[];\n"
        "      }\n"
        "      window.addEventListener('pagehide',function(){guard('shutdown',shutdownUi);},{once:true});\n"
        "      window.addEventListener('beforeunload',function(){guard('shutdown',shutdownUi);},{once:true});\n"
        "      function setText(node,value,scope){if(uiActive&&node&&node.isConnected){node.textContent=value;return;}if(uiActive&&scope){reportMissingNode(scope,'text target');}}\n"
        "      function setState(state,label,detail,detailLabel){\n"
        "        if(!uiActive){return;}\n"
        "        if(panelNode&&panelNode.isConnected){panelNode.setAttribute('data-freshness-state',state);}else{reportMissingNode('freshness state','panel');}\n"
        "        if(ringNode&&ringNode.isConnected){ringNode.className='freshness-ring '+state;}else{reportMissingNode('freshness state','ring');}\n"
        "        if(detailNode&&detailNode.isConnected){detailNode.className='freshness-detail freshness-callout '+state;detailNode.setAttribute('aria-label',detailLabel||detail);}else{reportMissingNode('freshness state','detail');}\n"
        "        if(stateNode&&stateNode.isConnected){stateNode.className='freshness-state '+state;stateNode.textContent=label;stateNode.setAttribute('aria-label','Published policy feed currency: '+label);}else{reportMissingNode('freshness state','label');}\n"
        "        var detailTarget=(detailTextNode&&detailTextNode.isConnected) ? detailTextNode : detailNode;\n"
        "        setText(detailTarget,detail,'freshness detail');\n"
        "      }\n"
        "      function plural(value,unit){return value+' '+unit+(value===1?'':'s');}\n"
        "      function exactAge(seconds){\n"
        "        var days=Math.floor(seconds/86400);\n"
        "        var hours=Math.floor((seconds%86400)/3600);\n"
        "        var minutes=Math.floor((seconds%3600)/60);\n"
        "        var parts=[];\n"
        "        if(days){parts.push(plural(days,'day'));}\n"
        "        if(hours||days){parts.push(plural(hours,'hour'));}\n"
        "        parts.push(plural(minutes,'minute'));\n"
        "        return parts.join(', ');\n"
        "      }\n"
        "      function formatAge(seconds){\n"
        "        seconds=Number(seconds);\n"
        "        if(!Number.isFinite(seconds)||seconds<0){return {text:'unknown',size:'age-wide',full:'Published feed age unknown'};}\n"
        "        seconds=Math.max(0,Math.floor(seconds));\n"
        "        var days=Math.floor(seconds/86400);\n"
        "        var hours=Math.floor((seconds%86400)/3600);\n"
        "        var minutes=Math.floor((seconds%3600)/60);\n"
        "        var full='Published feed age '+exactAge(seconds);\n"
        "        if(days>=1){return {text:days+'d '+hours+'h',size:days>=10?'age-compact':'age-wide',full:full};}\n"
        "        var hourValue=seconds/3600;\n"
        "        if(hourValue>=2){return {text:hourValue.toFixed(1).replace(/\\.0$/,'')+' hours',size:hourValue>=10?'age-wide':'',full:full};}\n"
        "        return {text:plural(minutes,'minute'),size:minutes>=100?'age-wide':'',full:full};\n"
        "      }\n"
        "      function setAgeDisplay(age){\n"
        "        if(!uiActive){return;}\n"
        "        if(!ageNode||!ageNode.isConnected){reportMissingNode('freshness age','metric');return;}\n"
        "        ageNode.textContent=age.text;\n"
        "        ageNode.className='freshness-metric'+(age.size?' '+age.size:'');\n"
        "        ageNode.setAttribute('title',age.full);\n"
        "        ageNode.setAttribute('aria-label',age.full);\n"
        "      }\n"
        "      function fallbackCopy(text){\n"
        "        if(!uiActive){return Promise.reject(new Error('ui inactive'));}\n"
        "        if(!document.body){reportMissingNode('copy fallback','body');return Promise.reject(new Error('copy unavailable'));}\n"
        "        var area=document.createElement('textarea');\n"
        "        area.value=text;area.setAttribute('readonly','');\n"
        "        area.style.position='fixed';area.style.left='-9999px';\n"
        "        var ok=false;\n"
        "        try{document.body.appendChild(area);area.select();ok=Boolean(document.execCommand&&document.execCommand('copy'));}catch(_error){ok=false;}finally{if(area.parentNode){area.parentNode.removeChild(area);}}\n"
        "        return ok ? Promise.resolve() : Promise.reject(new Error('copy failed'));\n"
        "      }\n"
        "      function copyText(text){\n"
        "        if(!uiActive){return Promise.reject(new Error('ui inactive'));}\n"
        "        try{if(navigator.clipboard&&navigator.clipboard.writeText){return navigator.clipboard.writeText(text);}}catch(_error){return fallbackCopy(text);}\n"
        "        return fallbackCopy(text);\n"
        "      }\n"
        "      function markCopyButton(button,state,title){\n"
        "        if(!uiActive){return;}\n"
        "        if(!button||!button.isConnected){reportMissingNode('copy button','button');return;}\n"
        "        button.setAttribute('data-copy-state',state);\n"
        "        button.setAttribute('title',title);\n"
        "        safeSetTimeout(function(){if(button&&button.isConnected){button.removeAttribute('data-copy-state');button.setAttribute('title',button.getAttribute('data-default-title')||'Copy epoch millisecond timestamp');}},1600);\n"
        "      }\n"
        "      Array.prototype.forEach.call(document.querySelectorAll('.epoch-copy[data-epoch]'),function(button){\n"
        "        button.setAttribute('data-default-title',button.getAttribute('title')||'Copy epoch millisecond timestamp');\n"
        "        button.addEventListener('click',function(){guard('copy epoch',function(){\n"
        "          if(!uiActive||!button.isConnected){return;}\n"
        "          var epoch=button.getAttribute('data-epoch')||'';\n"
        "          if(!/^\\d+$/.test(epoch)){markCopyButton(button,'failed','Epoch millisecond timestamp unavailable');return;}\n"
        "          copyText(epoch).then(function(){markCopyButton(button,'copied','Copied epoch millisecond timestamp '+epoch);}).catch(function(){markCopyButton(button,'failed','Could not copy epoch millisecond timestamp');});\n"
        "        });});\n"
        "      });\n"
        "      function initBaselineUpdateNotice(){\n"
        "        var notice=document.querySelector('[data-baseline-notice=\"active\"]');\n"
        "        if(!notice){return;}\n"
        "        if(!notice.isConnected){reportMissingNode('baseline update notice timer','notice');return;}\n"
        "        var until=notice.getAttribute('data-baseline-notice-visible-until')||'';\n"
        "        if(!until){reportMissingNode('baseline update notice timer','expiry marker');return;}\n"
        "        var expiry=Date.parse(until);\n"
        "        if(!Number.isFinite(expiry)){return;}\n"
        "        function updateBaselineNoticeVisibility(){\n"
        "          if(!uiActive||!notice.isConnected){return;}\n"
        "          var remaining=expiry-Date.now();\n"
        "          if(remaining<=0){\n"
        "            notice.hidden=true;\n"
        "            notice.setAttribute('aria-hidden','true');\n"
        "            var grid=notice.closest ? notice.closest('.dashboard-grid') : null;\n"
        "            if(grid&&grid.isConnected){grid.classList.remove('has-baseline-notice');}\n"
        "            else{reportMissingNode('baseline update notice timer','dashboard grid');}\n"
        "            return;\n"
        "          }\n"
        "          safeSetTimeout(updateBaselineNoticeVisibility,Math.min(Math.max(remaining+1000,1000),3600000));\n"
        "        }\n"
        "        updateBaselineNoticeVisibility();\n"
        "      }\n"
        "      guard('baseline update notice timer',initBaselineUpdateNotice);\n"
        "      function initDiagnosticFilters(){\n"
        "        var root=document.querySelector('[data-diagnostic-filter-root]');\n"
        "        if(!root||!root.isConnected){reportMissingNode('source diagnostics filter','root');return;}\n"
        "        var feed=document.getElementById('source-diagnostics-feed');\n"
        "        if(!feed||!feed.isConnected){reportMissingNode('source diagnostics filter','feed');return;}\n"
        "        var controls=root.querySelectorAll('[data-diagnostic-filter]');\n"
        "        var rows=root.querySelectorAll('.diag-row[data-diagnostic-severity]');\n"
        "        if(!controls.length){reportMissingNode('source diagnostics filter','controls');return;}\n"
        "        if(!rows.length){reportMissingNode('source diagnostics filter','rows');return;}\n"
        "        var status=document.getElementById('source-diagnostics-filter-status');\n"
        "        var empty=document.getElementById('source-diagnostics-empty');\n"
        "        var moreBlocks=root.querySelectorAll('.diag-more');\n"
        "        var labels={notice:'notice',warning:'warning',error:'error'};\n"
        "        var grid=root.closest ? root.closest('.dashboard-grid') : null;\n"
        "        var programmatic=grid ? grid.querySelector('.programmatic-api') : document.querySelector('.programmatic-api');\n"
        "        var expandToggle=root.querySelector('[data-diagnostics-expand-toggle=\"true\"]');\n"
        "        var exportCopy=root.querySelector('[data-diagnostics-copy=\"visible-json\"]');\n"
        "        var diagnosticsExpanded=false;\n"
        "        if(!expandToggle||!expandToggle.isConnected){reportMissingNode('source diagnostics expansion','expand toggle');}\n"
        "        if(!exportCopy||!exportCopy.isConnected){reportMissingNode('source diagnostics export copy','button');}\n"
        "        function rowWord(count){return count===1?'row':'rows';}\n"
        "        function normalizedFilter(value){return labels[value] ? value : '';}\n"
        "        function compactText(node){return node ? (node.textContent||'').replace(/\\s+/g,' ').trim() : '';}\n"
        "        function elementDisplayed(element){\n"
        "          if(!element||!element.isConnected){return false;}\n"
        "          var current=element;\n"
        "          while(current&&current!==root){\n"
        "            if(current.hidden){return false;}\n"
        "            if(current.tagName&&current.tagName.toLowerCase()==='details'&&!current.open){return false;}\n"
        "            current=current.parentElement;\n"
        "          }\n"
        "          return true;\n"
        "        }\n"
        "        function dashboardDiagnosticCounts(){\n"
        "          var counts={notice:0,warning:0,error:0};\n"
        "          Array.prototype.forEach.call(root.querySelectorAll('.diag-tile[data-diagnostic-severity]'),function(tile){\n"
        "            if(!tile||!tile.isConnected){return;}\n"
        "            var severity=normalizedFilter(tile.getAttribute('data-diagnostic-severity')||'');\n"
        "            var value=Number(compactText(tile.querySelector('strong')));\n"
        "            if(severity&&Number.isFinite(value)){counts[severity]=value;}\n"
        "          });\n"
        "          return counts;\n"
        "        }\n"
        "        function visibleDiagnosticEntries(){\n"
        "          var entries=[];\n"
        "          Array.prototype.forEach.call(rows,function(row,index){\n"
        "            if(!elementDisplayed(row)){return;}\n"
        "            var severity=normalizedFilter(row.getAttribute('data-diagnostic-severity')||'')||'notice';\n"
        "            var tags=[];\n"
        "            Array.prototype.forEach.call(row.querySelectorAll('.diag-tags span,.diag-tags a'),function(tag){var text=compactText(tag);if(text){tags.push(text);}});\n"
        "            var issueLink=row.querySelector('.diag-ticket-link[href]');\n"
        "            var entry={\n"
        "              severity:severity,\n"
        "              diagnostic_id:row.getAttribute('data-diagnostic-id')||'',\n"
        "              title:compactText(row.querySelector('.diag-row-head strong'))||'Source diagnostic',\n"
        "              source:compactText(row.querySelector('.source-chip'))||'Source',\n"
        "              message:compactText(row.querySelector('.diag-technical-message'))||compactText(row.querySelector('p')),\n"
        "              tags:tags,\n"
        "              issue_url:issueLink ? (issueLink.getAttribute('href')||null) : null,\n"
        "              display_index:index+1\n"
        "            };\n"
        "            function addAttr(attr,key){var value=row.getAttribute(attr)||'';if(value){entry[key]=value;}}\n"
        "            function addListAttr(attr,key){var value=row.getAttribute(attr)||'';if(value){entry[key]=value.split(',').map(function(item){return item.trim();}).filter(Boolean);}}\n"
        "            addAttr('data-user-message','user_message');\n"
        "            addAttr('data-kb-update-bucket','kb_update_bucket');\n"
        "            addAttr('data-kb-update-bucket-confidence','kb_update_bucket_confidence');\n"
        "            addAttr('data-security-evidence-source','security_evidence_source');\n"
        "            addAttr('data-support-article-url','support_article_url');\n"
        "            addAttr('data-source-url','source_url');\n"
        "            addAttr('data-msrc-cvrf-url','msrc_cvrf_url');\n"
        "            addAttr('data-read-more-url','read_more_url');\n"
        "            addAttr('data-security-url','security_url');\n"
        "            addAttr('data-support-article-validation-status','support_article_validation_status');\n"
        "            addListAttr('data-support-article-validation-reasons','support_article_validation_reasons');\n"
        "            addAttr('data-support-article-expected-kb','support_article_expected_kb');\n"
        "            addAttr('data-support-article-expected-build','support_article_expected_build');\n"
        "            addAttr('data-support-article-expected-release','support_article_expected_release');\n"
        "            addListAttr('data-support-article-applies-to-releases','support_article_applies_to_releases');\n"
        "            addAttr('data-atom-entry-id','atom_entry_id');\n"
        "            addAttr('data-atom-support-article-id','atom_support_article_id');\n"
        "            var isSecurity=row.getAttribute('data-is-security');\n"
        "            if(isSecurity==='true'){entry.is_security=true;}else if(isSecurity==='false'){entry.is_security=false;}\n"
        "            entries.push(entry);\n"
        "          });\n"
        "          return entries;\n"
        "        }\n"
        "        function sourceDiagnosticsExportPayload(){\n"
        "          var entries=visibleDiagnosticEntries();\n"
        "          var visibleCounts={notice:0,warning:0,error:0};\n"
        "          entries.forEach(function(entry){if(labels[entry.severity]){visibleCounts[entry.severity]+=1;}});\n"
        "          return {\n"
        "            export_schema:'win11_release_guard.source_diagnostics.visible.v1',\n"
        "            product:'win11_release_guard',\n"
        "            exported_at_utc:new Date().toISOString(),\n"
        "            page_url:String(window.location.href||''),\n"
        "            active_filter:root.getAttribute('data-active-diagnostic-filter')||'all',\n"
        "            status_text:status&&status.isConnected ? compactText(status) : '',\n"
        "            dashboard_counts_by_severity:dashboardDiagnosticCounts(),\n"
        "            visible_counts_by_severity:visibleCounts,\n"
        "            visible_count:entries.length,\n"
        "            context_note:'DOM export of currently visible Source Diagnostics rows for technical triage. These rows describe source, parser, drift, freshness, or dashboard-derived context and do not override signed policy verdicts.',\n"
        "            entries:entries\n"
        "          };\n"
        "        }\n"
        "        function setDiagnosticsExpanded(expanded){\n"
        "          if(!uiActive||!root.isConnected){reportMissingNode('source diagnostics expansion','root');return;}\n"
        "          diagnosticsExpanded=Boolean(expanded);\n"
        "          root.setAttribute('data-diagnostics-expanded',diagnosticsExpanded?'true':'false');\n"
        "          if(grid&&grid.isConnected){grid.classList.toggle('diagnostics-expanded',diagnosticsExpanded);}else{reportMissingNode('source diagnostics expansion','dashboard grid');}\n"
        "          if(programmatic&&programmatic.isConnected){programmatic.hidden=diagnosticsExpanded;programmatic.setAttribute('aria-hidden',String(diagnosticsExpanded));}else{reportMissingNode('source diagnostics expansion','programmatic api');}\n"
        "          if(expandToggle&&expandToggle.isConnected){expandToggle.setAttribute('aria-expanded',String(diagnosticsExpanded));expandToggle.setAttribute('aria-label',diagnosticsExpanded?'Collapse Source Diagnostics view':'Expand Source Diagnostics view');expandToggle.textContent=diagnosticsExpanded?'Collapse View':'Expand View';}\n"
        "          Array.prototype.forEach.call(moreBlocks,function(block){if(block&&block.isConnected&&!block.hidden){block.open=diagnosticsExpanded||block.open;}});\n"
        "        }\n"
        "        function setFilterStatus(severity,shown){\n"
        "          if(!status||!status.isConnected){reportMissingNode('source diagnostics filter','status');return;}\n"
        "          if(!severity){status.textContent='Showing all '+rows.length+' source diagnostic '+rowWord(rows.length)+'.';return;}\n"
        "          if(shown){status.textContent='Showing '+shown+' '+labels[severity]+' diagnostic '+rowWord(shown)+'.';return;}\n"
        "          status.textContent='No '+labels[severity]+' diagnostic rows are currently reported.';\n"
        "        }\n"
        "        function setEmptyState(severity,shown){\n"
        "          if(!empty||!empty.isConnected){reportMissingNode('source diagnostics filter','empty state');return;}\n"
        "          if(severity&&shown===0){empty.hidden=false;empty.textContent='This category currently contains no entries.';return;}\n"
        "          empty.hidden=true;\n"
        "        }\n"
        "        function updateOverflow(severity){\n"
        "          Array.prototype.forEach.call(moreBlocks,function(block){\n"
        "            if(!block||!block.isConnected){return;}\n"
        "            var hasVisible=false;\n"
        "            Array.prototype.forEach.call(block.querySelectorAll('.diag-row[data-diagnostic-severity]'),function(row){if(!row.hidden){hasVisible=true;}});\n"
        "            if(severity){block.hidden=!hasVisible;if(hasVisible){block.open=true;}return;}\n"
        "            block.hidden=false;block.open=diagnosticsExpanded;\n"
        "          });\n"
        "        }\n"
        "        function setPressedState(severity){\n"
        "          Array.prototype.forEach.call(controls,function(control){\n"
        "            if(!control||!control.isConnected){return;}\n"
        "            var value=control.getAttribute('data-diagnostic-filter')||'';\n"
        "            control.setAttribute('aria-pressed',severity ? String(value===severity) : String(value==='all'));\n"
        "          });\n"
        "        }\n"
        "        function applyFilter(value){\n"
        "          if(!uiActive||!root.isConnected||!feed.isConnected){return;}\n"
        "          var severity=normalizedFilter(value);\n"
        "          root.setAttribute('data-active-diagnostic-filter',severity||'all');\n"
        "          var shown=0;\n"
        "          Array.prototype.forEach.call(rows,function(row){\n"
        "            if(!row||!row.isConnected){return;}\n"
        "            var match=!severity||row.getAttribute('data-diagnostic-severity')===severity;\n"
        "            row.hidden=!match;\n"
        "            row.classList.toggle('is-filtered-out',!match);\n"
        "            if(match){shown+=1;}\n"
        "          });\n"
        "          updateOverflow(severity);\n"
        "          setEmptyState(severity,shown);\n"
        "          setFilterStatus(severity,shown);\n"
        "          setPressedState(severity);\n"
        "        }\n"
        "        Array.prototype.forEach.call(controls,function(control){\n"
        "          control.addEventListener('click',function(event){guard('source diagnostics filter',function(){\n"
        "            if(event&&event.preventDefault){event.preventDefault();}\n"
        "            if(!uiActive||!control.isConnected){return;}\n"
        "            applyFilter(control.getAttribute('data-diagnostic-filter')||'all');\n"
        "          });});\n"
        "        });\n"
        "        if(expandToggle&&expandToggle.isConnected){expandToggle.addEventListener('click',function(event){guard('source diagnostics expansion',function(){\n"
        "          if(event&&event.preventDefault){event.preventDefault();}\n"
        "          if(!uiActive||!expandToggle.isConnected){return;}\n"
        "          setDiagnosticsExpanded(!diagnosticsExpanded);\n"
        "          updateOverflow(normalizedFilter(root.getAttribute('data-active-diagnostic-filter')||''));\n"
        "        });});}\n"
        "        if(exportCopy&&exportCopy.isConnected){\n"
        "          exportCopy.setAttribute('data-default-title',exportCopy.getAttribute('title')||'Copy visible Source Diagnostics JSON');\n"
        "          exportCopy.addEventListener('click',function(event){guard('source diagnostics export copy',function(){\n"
        "            if(event&&event.preventDefault){event.preventDefault();}\n"
        "            if(!uiActive||!exportCopy.isConnected){return;}\n"
        "            var payload=sourceDiagnosticsExportPayload();\n"
        "            copyText(JSON.stringify(payload,null,2)).then(function(){markCopyButton(exportCopy,'copied','Copied visible Source Diagnostics JSON');}).catch(function(){markCopyButton(exportCopy,'failed','Could not copy Source Diagnostics JSON');});\n"
        "          });});\n"
        "        }\n"
        "        applyFilter('all');\n"
        "      }\n"
        "      guard('source diagnostics filter init',initDiagnosticFilters);\n"
        "      function initHeaderNav(){\n"
        "        var nav=document.querySelector('.header-nav');\n"
        "        if(!nav){reportMissingNode('header nav','nav');return;}\n"
        "        var items=nav.querySelectorAll('.nav-inner a');\n"
        "        if(!items.length){reportMissingNode('header nav','items');return;}\n"
        "        var frame=0;\n"
        "        var label=nav.querySelector('.nav-hover-label');\n"
        "        function setItem(item,x,y){\n"
        "          if(!uiActive||!nav.isConnected||!item||!item.isConnected){return;}\n"
        "          var navRect=nav.getBoundingClientRect();\n"
        "          var rect=item.getBoundingClientRect();\n"
        "          var text=item.getAttribute('data-nav-label')||item.getAttribute('aria-label')||'';\n"
        "          nav.style.setProperty('--enter-nav','1');\n"
        "          nav.style.setProperty('--label-x',String((rect.left-navRect.left)+(rect.width/2)+(x*5))+'px');\n"
        "          nav.style.setProperty('--label-y',String(y*3)+'px');\n"
        "          if(label&&label.isConnected&&text){label.textContent=text;}\n"
        "        }\n"
        "        function queue(item,event){\n"
        "          if(!uiActive||!item||!item.isConnected||!event){return;}\n"
        "          if(frame){safeCancelFrame(frame);}\n"
        "          frame=safeRequestFrame(function(){\n"
        "            frame=0;\n"
        "            if(!uiActive||!item.isConnected){return;}\n"
        "            var rect=item.getBoundingClientRect();\n"
        "            var x=((event.clientX-rect.left)-(rect.width/2))/rect.width;\n"
        "            var y=((event.clientY-rect.top)-(rect.height/2))/rect.height;\n"
        "            setItem(item,Math.max(-.5,Math.min(.5,x)),Math.max(-.5,Math.min(.5,y)));\n"
        "          });\n"
        "        }\n"
        "        Array.prototype.forEach.call(items,function(item,index){\n"
        "          item.addEventListener('pointermove',function(event){guard('header nav pointer',function(){queue(item,event);});},{passive:true});\n"
        "          item.addEventListener('focus',function(){guard('header nav focus',function(){setItem(item,0,0);});});\n"
        "        });\n"
        "        nav.addEventListener('pointerleave',function(){guard('header nav leave',function(){if(nav.isConnected){nav.style.setProperty('--enter-nav','0');}else{reportMissingNode('header nav','nav');}});});\n"
        "        nav.addEventListener('focusout',function(){guard('header nav focusout',function(){safeSetTimeout(function(){if(uiActive&&nav.isConnected&&!nav.contains(document.activeElement)){nav.style.setProperty('--enter-nav','0');}},0);});});\n"
        "      }\n"
        "      guard('header nav init',initHeaderNav);\n"
        "      function update(){\n"
        "        if(!uiActive){return;}\n"
        "        var data;\n"
        "        if(!dataNode||!dataNode.isConnected){reportMissingNode('freshness update','data');data={};}\n"
        "        else{try{data=JSON.parse(dataNode.textContent||'{}');}catch(error){data={};reportUiError('freshness data parse',error);}}\n"
        "        var generated=Number(data.generated_at_epoch_s);\n"
        "        if(!Number.isFinite(generated)||generated<=0){setAgeDisplay(formatAge(NaN));setState('unknown','Unknown','Policy feed timestamp is unavailable or invalid.');return;}\n"
        "        var now=Math.floor(Date.now()/1000);\n"
        "        if(!Number.isFinite(now)){setAgeDisplay(formatAge(NaN));setState('unknown','Unknown','Browser time is unavailable, so feed age cannot be calculated.');return;}\n"
        "        if(generated-now>300){setAgeDisplay(formatAge(0));setState('unknown','Clock Check','Browser clock is behind the policy timestamp; feed age is clamped to zero.');return;}\n"
        "        var ageSeconds=Math.max(0,now-generated);\n"
        "        var warningSeconds=Number(data.warning_age_seconds);\n"
        "        if(!Number.isFinite(warningSeconds)||warningSeconds<=0){warningSeconds=1209600;reportUiError('freshness warning threshold',new Error('invalid warning threshold'));}\n"
        "        var staleSeconds=Number(data.strict_stale_age_seconds);\n"
        "        if(!Number.isFinite(staleSeconds)||staleSeconds<=0){staleSeconds=3888000;reportUiError('freshness stale threshold',new Error('invalid stale threshold'));}\n"
        "        setAgeDisplay(formatAge(ageSeconds));\n"
        "        if(ageSeconds>=staleSeconds){setState('stale','Stale','Feed is stale. Refresh automation before trusting it.','Published policy feed is stale. Do not treat this data as production-current until automation refresh succeeds.');return;}\n"
        "        if(ageSeconds>=warningSeconds){setState('refresh-due','Refresh Due','Refresh is due. Verify automation health before production use.','Published policy feed refresh is due. Verify automation health before treating this data as production-current.');return;}\n"
        f"        setState('current','Current','Within the {DEFAULT_POLICY_WARNING_AGE_DAYS}-day maintenance threshold.','Published policy feed is within the {DEFAULT_POLICY_WARNING_AGE_DAYS}-day maintenance threshold.');\n"
        "      }\n"
        "      guard('freshness update',update);\n"
        "      safeSetInterval(function(){guard('freshness update',update);},60000);\n"
        "    }());\n"
        "  </script>\n"
        "</body>\n"
        "</html>\n"
    )
