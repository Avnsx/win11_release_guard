"""Shared HTML components for the Pages site."""

from __future__ import annotations

import re
from html import escape
from ...config import DEFAULT_PAGES_BASE_URL
from ...freshness import epoch_milliseconds_from_iso, parse_iso_utc_datetime
from ..constants import GITHUB_LICENSE_URL, GITHUB_REPOSITORY_URL
from ..time_format import _utc_time_human
from .wiki_sources import _heading_slug_base, _pages_wiki_url


def _site_brand_icon_html(class_name: str = "site-brand-icon") -> str:
    safe_class = re.sub(r"[^A-Za-z0-9_-]+", "-", str(class_name or "site-brand-icon")).strip("-")
    if not safe_class:
        safe_class = "site-brand-icon"
    return (
        f'<svg class="{safe_class}" viewBox="0 0 32 32" aria-hidden="true" focusable="false">'
        '<rect width="32" height="32" rx="8" fill="#0f6cbd"/>'
        '<path fill="#fff" d="M8 8.5h6.5v6.5H8zm7.5 0H22v6.5h-6.5zM8 16h6.5v6.5H8zm7.5 0H22v6.5h-6.5z"/>'
        "</svg>"
    )

def _epoch_copy_icon_html() -> str:
    return (
        '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">'
        '<path d="M8 7.5A2.5 2.5 0 0 1 10.5 5h6A2.5 2.5 0 0 1 19 7.5v6A2.5 2.5 0 0 1 16.5 16h-6A2.5 2.5 0 0 1 8 13.5z" '
        'fill="none" stroke="currentColor" stroke-width="1.8"/>'
        '<path d="M5 10.5A2.5 2.5 0 0 1 7.5 8H8v5.5A2.5 2.5 0 0 0 10.5 16H16v.5A2.5 2.5 0 0 1 13.5 19h-6A2.5 2.5 0 0 1 5 16.5z" '
        'fill="none" stroke="currentColor" stroke-width="1.8"/>'
        "</svg>"
    )

def _ui_icon_html(name: str, *, class_name: str = "ui-icon") -> str:
    icons = {
        "shield": '<path d="M12 3 19 6v5c0 4.1-2.6 7.6-7 9-4.4-1.4-7-4.9-7-9V6l7-3z"/>',
        "shield-check": (
            '<path d="M12 3 19 6v5c0 4.1-2.6 7.6-7 9-4.4-1.4-7-4.9-7-9V6l7-3z"/>'
            '<path d="m9 12 2 2 4-5"/>'
        ),
        "target": (
            '<circle cx="11" cy="13" r="7.5"/><circle cx="11" cy="13" r="3.5"/>'
            '<path d="M11 13 20 4"/><path d="M16.5 4H20v3.5"/><path d="M18.8 5.2 21 3"/>'
        ),
        "chip": (
            '<rect x="6" y="6" width="12" height="12" rx="2"/>'
            '<rect x="10" y="10" width="4" height="4" rx="1"/>'
            '<path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>'
        ),
        "eye": (
            '<path d="M3 12s3.5-6 9-6 9 6 9 6-3.5 6-9 6-9-6-9-6z"/>'
            '<circle cx="12" cy="12" r="2.5"/>'
        ),
        "calendar": '<rect x="4" y="5" width="16" height="17" rx="2"/><path d="M8 3v4M16 3v4M4 10h16"/>',
        "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        "pin": '<path d="M12 21s7-5.6 7-12a7 7 0 0 0-14 0c0 6.4 7 12 7 12z"/><circle cx="12" cy="9" r="2.5"/>',
        "check": '<path d="m5 13 4 4L19 7"/>',
        "megaphone": '<path d="M4 13h3l9 4V5L7 9H4v4z"/><path d="m7 13 1 5M18 9l3-2M18 13l3 2"/>',
        "warning": '<path d="M12 4 21 20H3L12 4z"/><path d="M12 9v5M12 17h.01"/>',
        "error": '<circle cx="12" cy="12" r="9"/><path d="m8 8 8 8M16 8l-8 8"/>',
        "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 7h.01"/>',
        "document": '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5M10 13h6M10 17h4"/>',
        "key": '<circle cx="8" cy="12" r="3"/><path d="M11 12h10M17 12v3M20 12v2"/>',
        "api": '<path d="M8 8 4 12l4 4M16 8l4 4-4 4M14 5l-4 14"/>',
        "link": '<path d="M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1"/>',
        "database": '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/>',
    }
    body = icons.get(str(name or "").strip().lower(), icons["info"])
    return (
        f'<svg class="{escape(class_name, quote=True)}" viewBox="0 0 24 24" '
        'aria-hidden="true" focusable="false" fill="none" stroke="currentColor" '
        f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{body}</svg>'
    )

def _github_icon_html() -> str:
    return (
        '<svg class="github-icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false">'
        '<path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38'
        ' 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52'
        '-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2'
        '-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82'
        '.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08'
        ' 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48'
        ' 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/>'
        "</svg>"
    )

def _footer_html() -> str:
    return (
        "<footer>"
        '<p class="footer-note footer-disclaimer">Independent Windows release-policy dashboard. Not affiliated with Microsoft.</p>'
        '<p class="footer-note footer-owner">&copy; 2026 Mikail (&quot;Avnsx&quot;) C. Maintained as an open-source project.</p>'
        '<p class="footer-note footer-source">'
        "<span>Source code and documentation are available on</span>"
        f'<a class="footer-github" href="{escape(GITHUB_REPOSITORY_URL, quote=True)}">'
        f"{_github_icon_html()}<span>GitHub</span></a>"
        "<span>and provided under the</span>"
        f'<a class="footer-license-basic" href="{escape(GITHUB_LICENSE_URL, quote=True)}">GPL-3.0 license</a></p>'
        "</footer>"
    )

def _time_with_epoch_copy_html(value: str | None, *, label: str) -> str:
    utc_dt = parse_iso_utc_datetime(value)
    epoch_ms = epoch_milliseconds_from_iso(value)
    if utc_dt is None or epoch_ms is None:
        return '<span class="time-copy unavailable">unavailable</span>'
    iso_value = utc_dt.isoformat()
    display = _utc_time_human(iso_value)
    escaped_epoch = escape(str(epoch_ms), quote=True)
    escaped_label = escape(label, quote=True)
    return (
        '<span class="time-copy">'
        f'<time datetime="{escape(iso_value, quote=True)}">{escape(display)}</time>'
        '<button type="button" class="epoch-copy" '
        f'data-epoch="{escaped_epoch}" '
        f'aria-label="Copy {escaped_label} epoch millisecond timestamp {escaped_epoch}" '
        f'title="Copy epoch millisecond timestamp {escaped_epoch}">'
        f"{_epoch_copy_icon_html()}"
        "</button></span>"
    )

def _dashboard_wiki_help_href(page_slug: str, fragment: str, *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    return f"{_pages_wiki_url(base_url=base_url)}{page_slug.strip('/')}/#{_heading_slug_base(fragment)}"

def _dashboard_info_link_html(
    *,
    href: str,
    label: str,
    help_text: str,
) -> str:
    return (
        f'<a class="dashboard-info-link" href="{escape(href, quote=True)}" '
        f'aria-label="{escape(label, quote=True)}">'
        f"{_ui_icon_html('info', class_name='ui-icon dashboard-info-icon')}"
        f'<span class="dashboard-info-tooltip" aria-hidden="true">'
        f"<span>{escape(help_text)}</span>"
        '<span class="dashboard-info-tooltip-action">Click to navigate to related wiki page</span>'
        "</span>"
        f'<span class="sr-only">{escape(label)}</span></a>'
    )

def _dashboard_info_topic_html(topic: str, *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    targets = {
        "latest-observed": (
            "Policy-Feed-and-Trust-Model",
            "Baseline And Preview Semantics",
            "Newest Windows build found in Microsoft source data. It is informational and does not decide compliance by itself.",
            "Learn more about latest observed build semantics",
        ),
        "required-baseline": (
            "Policy-Feed-and-Trust-Model",
            "Baseline And Preview Semantics",
            "Minimum signed build this policy currently requires for existing Windows 11 fleet devices.",
            "Learn more about required baseline semantics",
        ),
        "policy-feed-currency": (
            "Anti-Static-Freshness",
            "Dashboard Behavior",
            "Shows when the current parsed policy results were last compiled. Workflow timing is traceable in publish-policy.yml.",
            "Learn more about policy feed currency",
        ),
        "source-diagnostics": (
            "Source-Diagnostics",
            "Diagnostic Sources",
            "Source diagnostics show parser, drift, and upstream feed events so operators can distinguish informational notices from publish-blocking errors.",
            "Learn more about source diagnostics",
        ),
        "signature": (
            "Policy-Feed-and-Trust-Model",
            "Trust Rules",
            "The public policy feed is accepted only after detached Ed25519 verification with a committed trusted public key.",
            "Learn more about signature trust",
        ),
        "programmatic-api": (
            "GitHub-Pages-Dashboard",
            "Dashboard Sections",
            "The API links expose the canonical signed policy, signature, manifest, and stable /api/v1 aliases for automation.",
            "Learn more about the programmatic API",
        ),
    }
    page_slug, fragment, help_text, label = targets[topic]
    href = _dashboard_wiki_help_href(page_slug, fragment, base_url=base_url)
    return _dashboard_info_link_html(href=href, label=label, help_text=help_text)
