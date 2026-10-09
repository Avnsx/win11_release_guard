"""Dashboard source tiles and hash rendering."""

from __future__ import annotations

from html import escape
from typing import Any, Mapping
from ...models import ReleasePolicy
from ..artifacts import _short_hash
from .components import _time_with_epoch_copy_html, _ui_icon_html
from .dashboard_text import _source_diagnostics_for_policy, _source_label


def _format_bytes(value: Any) -> str:
    try:
        size = int(value)
    except (TypeError, ValueError):
        return "unavailable"
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KiB"
    return f"{size / (1024 * 1024):.1f} MiB"


def _hash_html(value: str | None) -> str:
    short = _short_hash(value)
    title = f' title="{escape(value, quote=True)}"' if value else ""
    return f'<span class="mono hash"{title}>{escape(short)}</span>'


def _source_status_for_url(policy: ReleasePolicy, url: str, *, generated_at_utc: str) -> Mapping[str, Any]:
    label = _source_label(url)
    if label == "Microsoft Release Health":
        source = _source_diagnostics_for_policy(policy).get("release_health_html")
    elif label == "Microsoft Atom feed":
        source = _source_diagnostics_for_policy(policy).get("atom_feed")
    elif label == "Microsoft servicing index":
        source = _source_diagnostics_for_policy(policy).get("servicing_toc")
    else:
        source = None
    if not isinstance(source, Mapping):
        return {
            "status": "recorded",
            "fetched_at_utc": generated_at_utc,
            "bytes": None,
        }
    return source


def _source_status_class(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"ok", "success", "valid", "healthy", "current"}:
        return "ok"
    if any(token in text for token in ("warn", "degraded", "aging", "partial", "stale")):
        return "warning"
    if any(token in text for token in ("error", "err", "fail", "invalid", "blocked", "unavailable")):
        return "error"
    return "unknown"


def _render_source_tiles(policy: ReleasePolicy, *, generated_at_utc: str) -> str:
    if not policy.source_urls:
        return (
            "<div id=\"source-health\" class=\"source-health\" aria-label=\"Policy source status\">"
            "<h3>Source health</h3><div class=\"source-health-grid\">"
            "<div class=\"source-tile unknown\"><div class=\"source-tile-head\">"
            f"<span class=\"source-name\">{_ui_icon_html('database', class_name='ui-icon source-icon')}<strong>None recorded</strong></span>"
            "<span class=\"source-status unknown\">unknown</span></div>"
            "<span>No source URLs are present in this policy.</span></div>"
            "</div></div>"
        )
    items: list[str] = []
    for url in policy.source_urls:
        label = _source_label(url)
        source_icon = "database" if label == "Microsoft Release Health" else "document"
        status = _source_status_for_url(policy, url, generated_at_utc=generated_at_utc)
        fetched_at = str(status.get("fetched_at_utc") or "")
        fetched_at_html = _time_with_epoch_copy_html(fetched_at, label=f"{label} UTC")
        status_text = str(status.get("status") or "unknown")
        status_class = _source_status_class(status_text)
        bytes_text = _format_bytes(status.get("bytes"))
        escaped_url = escape(url, quote=True)
        items.append(
            f"<div class=\"source-tile {status_class}\">"
            "<div class=\"source-tile-head\">"
            f"<span class=\"source-name\">{_ui_icon_html(source_icon, class_name='ui-icon source-icon')}<strong>{escape(label)}</strong></span>"
            f"<span class=\"source-status {status_class}\">{escape(status_text)}</span>"
            "</div>"
            f"<a href=\"{escaped_url}\" title=\"{escaped_url}\">{escape(url)}</a>"
            "<dl class=\"mini-kv\">"
            f"<dt>Fetched:</dt><dd>{fetched_at_html}</dd>"
            f"<dt>Bytes:</dt><dd>{escape(bytes_text)}</dd>"
            "</dl>"
            "</div>"
        )
    return (
        "<div id=\"source-health\" class=\"source-health\" aria-label=\"Policy source status\">"
        "<h3>Source health</h3>"
        f"<div class=\"source-health-grid\">{''.join(items)}</div></div>"
    )
