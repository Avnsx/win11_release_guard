"""Rendering wiki Markdown to HTML."""

from __future__ import annotations

import re
from html import escape
from typing import Mapping, Sequence
from ...config import DEFAULT_PAGES_BASE_URL
from ..constants import _LIST_ITEM_RE, _MARKDOWN_HEADING_RE, _TABLE_SEPARATOR_RE
from .wiki_model import WikiHeading, WikiPageSource
from .wiki_sources import (
    _heading_slug_base,
    _plain_wiki_inline_text,
    _resolve_wiki_target,
    _unique_heading_slug,
    _unique_slug,
    _wiki_lookup_key,
)


def _is_allowed_absolute_url(target: str) -> bool:
    lower = target.casefold()
    return lower.startswith(("https://", "http://", "mailto:"))

def _has_url_scheme(target: str) -> bool:
    return bool(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", target))

def _render_broken_wiki_link(label: str, target: str, broken_links: list[str]) -> str:
    clean_target = target.strip()
    if clean_target:
        broken_links.append(clean_target)
    return (
        f'<span class="broken-link" data-broken-link="{escape(clean_target)}">'
        f"{escape(label.strip() or clean_target or 'broken link')}</span>"
    )

def _render_wiki_link(
    value: str,
    pages: Mapping[str, WikiPageSource],
    broken_links: list[str],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    if "|" in value:
        label, target = value.split("|", 1)
    else:
        label = target = value
    href, missing = _resolve_wiki_target(target, pages, base_url=base_url)
    if missing:
        return _render_broken_wiki_link(label, missing, broken_links)
    return f'<a href="{escape(href or "#")}">{escape(label.strip() or target.strip())}</a>'

def _render_markdown_link(
    label: str,
    target: str,
    pages: Mapping[str, WikiPageSource],
    broken_links: list[str],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    clean_target = target.strip()
    clean_label = label.strip() or clean_target
    if not clean_target:
        return escape(clean_label)
    if clean_target.startswith("#"):
        href = f"#{_heading_slug_base(clean_target[1:])}"
        return f'<a href="{escape(href)}">{escape(clean_label)}</a>'
    if _is_allowed_absolute_url(clean_target):
        rel = ' rel="noopener noreferrer"' if clean_target.casefold().startswith(("http://", "https://")) else ""
        return f'<a href="{escape(clean_target)}"{rel}>{escape(clean_label)}</a>'
    if _has_url_scheme(clean_target):
        return _render_broken_wiki_link(clean_label, clean_target, broken_links)
    if clean_target.startswith("/") and not clean_target.startswith("//"):
        href = f"{base_url.rstrip('/')}{clean_target}"
        return f'<a href="{escape(href)}">{escape(clean_label)}</a>'
    if clean_target.startswith(("./", "../")):
        return f'<a href="{escape(clean_target)}">{escape(clean_label)}</a>'
    if "/" in clean_target and not clean_target.startswith("//"):
        return f'<a href="{escape(clean_target)}">{escape(clean_label)}</a>'
    href, missing = _resolve_wiki_target(clean_target, pages, base_url=base_url)
    if missing:
        return _render_broken_wiki_link(clean_label, missing, broken_links)
    return f'<a href="{escape(href or "#")}">{escape(clean_label)}</a>'

def _render_markdown_image(alt: str, target: str) -> str:
    clean_target = target.strip()
    if not _is_allowed_absolute_url(clean_target):
        return escape(alt.strip())
    return (
        f'<img src="{escape(clean_target)}" alt="{escape(alt.strip())}" '
        'loading="lazy" decoding="async">'
    )

def _is_image_only_html(value: str) -> bool:
    stripped = value.strip()
    return stripped.startswith("<img ") and stripped.endswith(">") and stripped.count("<img ") == 1

_WIKI_MAX_SECTION_ICONS = 3

_WIKI_PAGE_ICON_BY_SLUG = {
    "home": "windows",
    "quick-start": "start",
    "faq": "help",
    "cli-and-rmm-usage": "terminal",
    "configuration": "config",
    "architecture": "architecture",
    "local-windows-detection": "device",
    "policy-feed-and-trust-model": "shield",
    "source-diagnostics": "diagnostics",
    "github-pages-dashboard": "dashboard",
    "anti-static-freshness": "freshness",
    "build-test-and-release": "build",
    "safe-exports-and-clean-archives": "archive",
    "release-v0.3.4": "release",
    "release-v0.3.3": "release",
    "release-v0.3.2": "release",
    "release-v0.3.1": "release",
    "tagged-release-lane": "tag",
    "troubleshooting": "troubleshooting",
    "agent-chokepoints": "guardrail",
    "changelog": "changelog",
}

_WIKI_HEADING_ICON_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("start", ("quick start", "pick your path", "install", "run", "start here")),
    ("terminal", ("cli", "rmm", "command", "commands", "usage")),
    ("config", ("configuration", "settings", "environment", "variables")),
    ("architecture", ("architecture", "signal map", "model", "core concepts")),
    ("shield", ("policy", "trust", "signed", "signature", "security")),
    ("diagnostics", ("diagnostic", "source health", "warning", "warnings", "errors")),
    ("dashboard", ("dashboard", "pages", "api")),
    ("freshness", ("freshness", "static", "generated time")),
    ("build", ("build", "test", "verify")),
    ("archive", ("archive", "archives", "export", "exports", "clean")),
    ("release", ("release", "releases", "version", "versions", "unreleased", "tagged")),
    ("help", ("faq", "troubleshooting", "question")),
)

def _wiki_icon_kind_for_page(page_slug: str | None) -> str:
    normalized = (page_slug or "home").strip("/").casefold()
    if normalized.startswith("changelog/"):
        return "changelog"
    return _WIKI_PAGE_ICON_BY_SLUG.get(normalized, "document")

def _wiki_icon_kind_for_heading(
    *,
    level: int,
    heading_text: str,
    page_slug: str | None,
    section_icon_count: int,
) -> str | None:
    if level == 1:
        return _wiki_icon_kind_for_page(page_slug)
    if level != 2 or section_icon_count >= _WIKI_MAX_SECTION_ICONS:
        return None
    lookup = _plain_wiki_inline_text(heading_text).casefold()
    for icon_kind, needles in _WIKI_HEADING_ICON_RULES:
        if any(needle in lookup for needle in needles):
            return icon_kind
    return None

def _wiki_icon_html(kind: str) -> str:
    icons = {
        "archive": (
            '<path class="wiki-icon-line" d="M9 11.5h14v11.2a2.3 2.3 0 0 1-2.3 2.3H11.3A2.3 2.3 0 0 1 9 22.7z"/>'
            '<path class="wiki-icon-line" d="M8 9h16l-1.4-3H9.4zM13 15h6M13 19h4"/>'
        ),
        "architecture": (
            '<path class="wiki-icon-line" d="M10 10h5v5h-5zM18 8h5v5h-5zM17 19h5v5h-5zM12.5 15v3.2h7M15 11h3"/>'
            '<circle class="wiki-icon-fill" cx="12.5" cy="18.2" r="1.3"/>'
        ),
        "build": (
            '<path class="wiki-icon-line" d="m11.2 18.8 7.4-7.4M17 7.1l4.9 4.9M9.2 20.8 7 23l-2-2 2.2-2.2"/>'
            '<path class="wiki-icon-line" d="M18.7 6.3 21 4l4 4-2.3 2.3"/>'
        ),
        "changelog": (
            '<path class="wiki-icon-line" d="M10 8.5h12a2 2 0 0 1 2 2v13H10zM10 12.5H7.8a2 2 0 0 0-2 2V24a2 2 0 0 0 2 2H22"/>'
            '<path class="wiki-icon-line" d="M13 14h6M13 18h7M13 22h4"/>'
        ),
        "config": (
            '<path class="wiki-icon-line" d="M8 10h14M8 16h14M8 22h14"/>'
            '<circle class="wiki-icon-fill" cx="13" cy="10" r="2.1"/><circle class="wiki-icon-fill" cx="18" cy="16" r="2.1"/><circle class="wiki-icon-fill" cx="11" cy="22" r="2.1"/>'
        ),
        "dashboard": (
            '<path class="wiki-icon-line" d="M8 9.5h7v5.5H8zM17 9.5h7v9h-7zM8 17h7v7H8zM17 21h7v3h-7z"/>'
        ),
        "device": (
            '<path class="wiki-icon-line" d="M8 9h16v10H8zM13 23h6M16 19v4"/>'
            '<path class="wiki-icon-line" d="M11 12h4v4h-4zM18 12h3M18 15h3"/>'
        ),
        "diagnostics": (
            '<path class="wiki-icon-line" d="M7 19h4l2.2-7 3.4 10 2.1-6H24"/>'
            '<path class="wiki-icon-line" d="M8 9h14M8 12h8"/>'
        ),
        "document": (
            '<path class="wiki-icon-line" d="M10 6.5h8l4 4V25H10zM18 6.5v4h4M13 15h6M13 19h6M13 23h3"/>'
        ),
        "freshness": (
            '<circle class="wiki-icon-line" cx="16" cy="16" r="8"/>'
            '<path class="wiki-icon-line" d="M16 11v5l3.4 2M8.6 11.3 7.2 7.8h3.8"/>'
        ),
        "guardrail": (
            '<path class="wiki-icon-line" d="M9 9v16M23 9v16M9 12h14M9 18h14M7 25h20"/>'
            '<path class="wiki-icon-line" d="M13 8.5 16 6l3 2.5"/>'
        ),
        "help": (
            '<path class="wiki-icon-line" d="M10 10.5a6 6 0 0 1 12 0c0 5-6 4.2-6 8"/>'
            '<circle class="wiki-icon-fill" cx="16" cy="23" r="1.4"/>'
        ),
        "release": (
            '<path class="wiki-icon-line" d="M8 8h9l7 7-9 9-7-7z"/>'
            '<circle class="wiki-icon-fill" cx="13" cy="13" r="1.6"/>'
            '<path class="wiki-icon-line" d="m14.5 19 2 2 4-5"/>'
        ),
        "shield": (
            '<path class="wiki-icon-line" d="M16 5.5 23 8.6v5.2c0 5.1-3.2 9.1-7 10.7-3.8-1.6-7-5.6-7-10.7V8.6z"/>'
            '<path class="wiki-icon-line" d="m12.6 15.7 2.5 2.5 4.5-5.5"/>'
        ),
        "start": (
            '<path class="wiki-icon-line" d="M10 8.5v15l13-7.5z"/>'
            '<path class="wiki-icon-line" d="M7 8.5v15"/>'
        ),
        "tag": (
            '<path class="wiki-icon-line" d="M8 8h8.5L24 15.5 16.5 23 8 14.5z"/>'
            '<circle class="wiki-icon-fill" cx="12.5" cy="12.5" r="1.5"/>'
            '<path class="wiki-icon-line" d="M17 16.5h4"/>'
        ),
        "terminal": (
            '<path class="wiki-icon-line" d="M7.5 8.5h17v15h-17zM7.5 12h17"/>'
            '<path class="wiki-icon-line" d="m11 16 2.5 2-2.5 2M16 20h4"/>'
        ),
        "troubleshooting": (
            '<path class="wiki-icon-line" d="m10 22 7.5-7.5M18.6 7.2a4.7 4.7 0 0 0-5.7 5.7L7.3 18.5a2.2 2.2 0 0 0 3.1 3.1l5.6-5.6a4.7 4.7 0 0 0 5.7-5.7l-3 3-2.1-2.1z"/>'
        ),
        "windows": (
            '<path class="wiki-icon-fill" d="M8 8.5h6.8v6.8H8zM16.2 8.5H23v6.8h-6.8zM8 16.7h6.8v6.8H8zM16.2 16.7H23v6.8h-6.8z"/>'
        ),
    }
    clean_kind = str(kind or "document").strip().casefold()
    body = icons.get(clean_kind, icons["document"])
    safe_kind = re.sub(r"[^a-z0-9_-]+", "-", clean_kind).strip("-") or "document"
    return (
        f'<svg class="wiki-heading-icon wiki-icon-{safe_kind}" viewBox="0 0 32 32" aria-hidden="true" '
        'focusable="false"><rect class="wiki-icon-tile" x="3.5" y="3.5" width="25" height="25" rx="7"/>'
        f"{body}</svg>"
    )

def _render_wiki_heading_html(level: int, slug: str, inline_heading: str, icon_kind: str | None) -> str:
    safe_slug = escape(slug, quote=True)
    if not icon_kind:
        return f'<h{level} id="{safe_slug}">{inline_heading}</h{level}>'
    return (
        f'<h{level} id="{safe_slug}" class="wiki-heading-with-icon">'
        f'{_wiki_icon_html(icon_kind)}<span class="wiki-heading-text">{inline_heading}</span></h{level}>'
    )

def _render_wiki_inline(
    text: str,
    pages: Mapping[str, WikiPageSource],
    broken_links: list[str],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    parts: list[str] = []
    index = 0
    while index < len(text):
        if text.startswith("![", index):
            label_end = text.find("](", index + 2)
            target_end = text.find(")", label_end + 2) if label_end != -1 else -1
            if label_end != -1 and target_end != -1:
                parts.append(_render_markdown_image(text[index + 2 : label_end], text[label_end + 2 : target_end]))
                index = target_end + 1
                continue
        if text.startswith("[[", index):
            end = text.find("]]", index + 2)
            if end != -1:
                parts.append(_render_wiki_link(text[index + 2 : end], pages, broken_links, base_url=base_url))
                index = end + 2
                continue
        if text.startswith("[", index):
            label_end = text.find("](", index + 1)
            target_end = text.find(")", label_end + 2) if label_end != -1 else -1
            if label_end != -1 and target_end != -1:
                parts.append(
                    _render_markdown_link(
                        text[index + 1 : label_end],
                        text[label_end + 2 : target_end],
                        pages,
                        broken_links,
                        base_url=base_url,
                    )
                )
                index = target_end + 1
                continue
        if text.startswith("**", index):
            end = text.find("**", index + 2)
            if end != -1:
                inner = _render_wiki_inline(text[index + 2 : end], pages, broken_links, base_url=base_url)
                parts.append(f"<strong>{inner}</strong>")
                index = end + 2
                continue
        if text.startswith("`", index):
            end = text.find("`", index + 1)
            if end != -1:
                parts.append(f"<code>{escape(text[index + 1 : end])}</code>")
                index = end + 1
                continue
        next_special = len(text)
        for marker in ("![", "[[", "[", "**", "`"):
            marker_index = text.find(marker, index + 1)
            if marker_index != -1:
                next_special = min(next_special, marker_index)
        parts.append(escape(text[index:next_special]))
        index = next_special
    return "".join(parts)

def _split_markdown_table_row(line: str) -> list[str]:
    cells: list[str] = []
    current: list[str] = []
    escaped_pipe = False
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    for char in stripped:
        if char == "|" and not escaped_pipe:
            cells.append("".join(current).strip())
            current = []
            continue
        if char == "\\" and not escaped_pipe:
            escaped_pipe = True
            continue
        if escaped_pipe:
            current.append(char)
            escaped_pipe = False
            continue
        current.append(char)
    cells.append("".join(current).strip())
    return cells

def _is_table_start(lines: Sequence[str], index: int) -> bool:
    if index + 1 >= len(lines):
        return False
    return "|" in lines[index] and bool(_TABLE_SEPARATOR_RE.match(lines[index + 1]))

def _render_wiki_table(
    rows: Sequence[str],
    pages: Mapping[str, WikiPageSource],
    broken_links: list[str],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    header = _split_markdown_table_row(rows[0])
    body_rows = rows[2:]
    thead = "".join(
        f"<th>{_render_wiki_inline(cell, pages, broken_links, base_url=base_url)}</th>" for cell in header
    )
    tbody_lines: list[str] = []
    for row in body_rows:
        cells = _split_markdown_table_row(row)
        tbody_lines.append(
            "<tr>"
            + "".join(f"<td>{_render_wiki_inline(cell, pages, broken_links, base_url=base_url)}</td>" for cell in cells)
            + "</tr>"
        )
    return f"<table><thead><tr>{thead}</tr></thead><tbody>{''.join(tbody_lines)}</tbody></table>"

def _list_indent_width(value: str) -> int:
    return len(value.replace("\t", "    "))

def _list_tag(marker: str) -> str:
    return "ol" if marker.endswith(".") else "ul"

def _render_wiki_list(
    lines: Sequence[str],
    index: int,
    pages: Mapping[str, WikiPageSource],
    broken_links: list[str],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
    base_indent: int | None = None,
    expected_tag: str | None = None,
) -> tuple[str, int]:
    first_match = _LIST_ITEM_RE.match(lines[index])
    if not first_match:
        return "", index
    if base_indent is None:
        base_indent = _list_indent_width(first_match.group("indent"))
    tag = expected_tag or _list_tag(first_match.group("marker"))
    items: list[str] = []
    while index < len(lines):
        match = _LIST_ITEM_RE.match(lines[index])
        if not match:
            break
        indent = _list_indent_width(match.group("indent"))
        current_tag = _list_tag(match.group("marker"))
        if indent < base_indent:
            break
        if indent > base_indent:
            if not items:
                break
            nested_html, index = _render_wiki_list(
                lines,
                index,
                pages,
                broken_links,
                base_url=base_url,
                base_indent=indent,
                expected_tag=current_tag,
            )
            items[-1] += nested_html
            continue
        if current_tag != tag:
            break
        # Gather the item's text, including lazily-wrapped continuation lines so a
        # bullet authored across several source lines renders as one list item
        # (with correct hanging indent) instead of spilling its wrapped text into
        # a separate full-width paragraph. A blank line, a new list item, or a
        # block element (heading/code/table/rule) ends the item.
        item_text_parts = [match.group("text")]
        index += 1
        while index < len(lines):
            candidate = lines[index]
            candidate_stripped = candidate.strip()
            if not candidate_stripped:
                break
            if (
                _LIST_ITEM_RE.match(candidate)
                or _MARKDOWN_HEADING_RE.match(candidate)
                or candidate_stripped.startswith("```")
                or candidate_stripped == "---"
                or _is_table_start(lines, index)
            ):
                break
            item_text_parts.append(candidate_stripped)
            index += 1
        item_text = " ".join(item_text_parts)
        items.append(_render_wiki_inline(item_text, pages, broken_links, base_url=base_url))
    body = "".join(f"<li>{item}</li>" for item in items)
    return f"<{tag}>{body}</{tag}>", index

def _render_wiki_markdown_fragment(
    text: str,
    pages: Mapping[str, WikiPageSource],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
    heading_slug_overrides: Mapping[str, str | Sequence[str]] | None = None,
    page_slug: str | None = None,
    heading_icons: bool = False,
) -> tuple[str, tuple[WikiHeading, ...], tuple[str, ...]]:
    lines = text.splitlines()
    blocks: list[str] = []
    headings: list[WikiHeading] = []
    broken_links: list[str] = []
    used_heading_slugs: dict[str, int] = {}
    slug_override_counts: dict[str, int] = {}
    slug_overrides = heading_slug_overrides or {}
    section_icon_count = 0
    used_icon_kinds: set[str] = set()
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            index += 1
            continue
        if stripped.startswith("```"):
            language = re.sub(r"[^A-Za-z0-9_+-]+", "", stripped[3:].strip())
            code_lines: list[str] = []
            index += 1
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code_lines.append(lines[index])
                index += 1
            if index < len(lines):
                index += 1
            class_attr = f' class="language-{escape(language)}"' if language else ""
            blocks.append(f"<pre><code{class_attr}>{escape(chr(10).join(code_lines))}</code></pre>")
            continue
        heading_match = _MARKDOWN_HEADING_RE.match(line)
        if heading_match:
            level = len(heading_match.group(1))
            heading_text = _plain_wiki_inline_text(heading_match.group(2)).strip()
            slug_override = slug_overrides.get(heading_text)
            if isinstance(slug_override, str):
                slug = slug_override
            elif slug_override:
                override_index = slug_override_counts.get(heading_text, 0)
                slug_override_counts[heading_text] = override_index + 1
                slug = slug_override[min(override_index, len(slug_override) - 1)]
            else:
                slug = _unique_heading_slug(heading_text, used_heading_slugs)
            if slug_override:
                slug = _unique_slug(slug, used_heading_slugs)
            headings.append(WikiHeading(level=level, text=heading_text, slug=slug))
            inline_heading = _render_wiki_inline(heading_match.group(2), pages, broken_links, base_url=base_url)
            icon_kind = (
                _wiki_icon_kind_for_heading(
                    level=level,
                    heading_text=heading_text,
                    page_slug=page_slug,
                    section_icon_count=section_icon_count,
                )
                if heading_icons
                else None
            )
            if icon_kind in used_icon_kinds:
                icon_kind = None
            if icon_kind:
                used_icon_kinds.add(icon_kind)
                if level == 2:
                    section_icon_count += 1
            blocks.append(_render_wiki_heading_html(level, slug, inline_heading, icon_kind))
            index += 1
            continue
        if stripped == "---":
            blocks.append("<hr>")
            index += 1
            continue
        if _is_table_start(lines, index):
            table_rows = [lines[index], lines[index + 1]]
            index += 2
            while index < len(lines) and lines[index].strip() and "|" in lines[index]:
                table_rows.append(lines[index])
                index += 1
            blocks.append(_render_wiki_table(table_rows, pages, broken_links, base_url=base_url))
            continue
        if _LIST_ITEM_RE.match(line):
            list_html, index = _render_wiki_list(lines, index, pages, broken_links, base_url=base_url)
            blocks.append(list_html)
            continue
        paragraph_lines = [stripped]
        index += 1
        while index < len(lines):
            candidate = lines[index]
            candidate_stripped = candidate.strip()
            if not candidate_stripped:
                break
            if (
                candidate_stripped.startswith("```")
                or _MARKDOWN_HEADING_RE.match(candidate)
                or candidate_stripped == "---"
                or _is_table_start(lines, index)
                or _LIST_ITEM_RE.match(candidate)
            ):
                break
            paragraph_lines.append(candidate_stripped)
            index += 1
        paragraph = " ".join(paragraph_lines)
        rendered_paragraph = _render_wiki_inline(paragraph, pages, broken_links, base_url=base_url)
        paragraph_class = ' class="wiki-image-block"' if _is_image_only_html(rendered_paragraph) else ""
        blocks.append(f"<p{paragraph_class}>{rendered_paragraph}</p>")
    return "\n".join(blocks), tuple(headings), tuple(dict.fromkeys(broken_links))

def _render_wiki_toc(headings: Sequence[WikiHeading], *, page_title: str = "") -> str:
    title_key = _wiki_lookup_key(page_title) if page_title else ""
    toc_headings = tuple(
        heading
        for heading in headings
        if heading.level > 1 and (not title_key or _wiki_lookup_key(heading.text) != title_key)
    )
    if not toc_headings:
        return ""
    items = "".join(
        f'<li class="toc-level-{heading.level}"><a href="#{escape(heading.slug)}">{escape(heading.text)}</a></li>'
        for heading in toc_headings
    )
    return f'<section class="wiki-toc" aria-label="Table of contents"><h2>On this page</h2><ol>{items}</ol></section>'
