"""The wiki page shell, navigation, and page writer."""

from __future__ import annotations

from .assets import render_asset

import re
from html import escape
from pathlib import Path
from typing import Sequence
from ...config import DEFAULT_PAGES_BASE_URL
from ..artifacts import _write_public_artifact_text
from .components import _site_brand_icon_html
from ..constants import (
    GITHUB_REPOSITORY_URL,
    WIKI_FAVICON_DATA_URL,
    WIKI_SOURCE_DIR,
    _ORDERED_LIST_RE,
)
from .wiki_markdown import _render_wiki_markdown_fragment, _render_wiki_toc
from .wiki_model import WikiHeading, WikiPageSource
from .wiki_sources import (
    _changelog_pages_base_url,
    _pages_root_url,
    _pages_wiki_url,
    _plain_wiki_inline_text,
    _prepare_wiki_sources,
    _wiki_helper_text,
    _wiki_output_relative_path,
    _wiki_page_href,
    _wiki_page_map,
    _wiki_source_display_name,
)


_WIKI_NAV_GROUP_RE = re.compile(r"<p><strong>(.*?)</strong></p>(?=\s*<[uo]l>)", re.DOTALL)

_WIKI_NAV_GROUP_CLASS_RE = re.compile(r'<p class="wiki-nav-group"><strong>.*?</strong></p>', re.DOTALL)


def _mark_current_wiki_navigation_html(site_navigation_html: str, current_url: str | None) -> str:
    html = _WIKI_NAV_GROUP_RE.sub(r'<p class="wiki-nav-group"><strong>\1</strong></p>', site_navigation_html)
    if not current_url:
        return html

    safe_current_url = escape(current_url, quote=True)
    anchor_pattern = re.compile(rf'<a href="{re.escape(safe_current_url)}">')
    first_anchor = anchor_pattern.search(html)
    if not first_anchor:
        return html

    html = anchor_pattern.sub(
        f'<a href="{safe_current_url}" class="is-current-page" aria-current="page">',
        html,
    )
    active_index = html.find(f'href="{safe_current_url}" class="is-current-page"')
    if active_index < 0:
        return html

    groups = list(_WIKI_NAV_GROUP_CLASS_RE.finditer(html))
    for group_index, group in enumerate(groups):
        next_group_start = groups[group_index + 1].start() if group_index + 1 < len(groups) else len(html)
        if group.end() <= active_index < next_group_start:
            marked_group = group.group(0).replace(
                'class="wiki-nav-group"',
                'class="wiki-nav-group is-current-group"',
                1,
            )
            return html[: group.start()] + marked_group + html[group.end() :]
    return html


def _wiki_navigation_html(
    site_navigation_html: str,
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
    current_url: str | None = None,
    toc_html: str = "",
) -> str:
    changelog_href = _changelog_pages_base_url(base_url=base_url)
    current_normalized = current_url.rstrip("/") + "/" if current_url else ""
    changelog_normalized = changelog_href.rstrip("/") + "/"
    current_is_changelog = current_normalized.startswith(changelog_normalized)
    changelog_link_attrs = ' class="is-current-page" aria-current="page"' if current_is_changelog else ""
    current_site_navigation_html = _mark_current_wiki_navigation_html(site_navigation_html, current_url)
    primary_navigation_html = (
        '<section class="wiki-primary-nav" aria-label="Primary wiki navigation">'
        "<h2>Wiki</h2>"
        f'<ul><li class="wiki-nav-changelog"><a href="{escape(changelog_href, quote=True)}"{changelog_link_attrs}>'
        '<span class="wiki-nav-changelog-label">Changelog</span>'
        '<span class="wiki-nav-changelog-meta">Release history</span>'
        "</a></li></ul></section>"
    )
    return (
        '<section class="wiki-sidebar-header" aria-label="Wiki page navigation">'
        f"{primary_navigation_html}{toc_html}</section>"
        '<section class="wiki-source-nav" aria-label="Wiki source navigation">'
        f"{current_site_navigation_html}</section>"
    )


def _wiki_breadcrumbs_html(source: WikiPageSource, *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    dashboard_url = _pages_root_url(base_url=base_url)
    wiki_url = _pages_wiki_url(base_url=base_url)
    items = [
        f'<li><a href="{escape(dashboard_url, quote=True)}">Dashboard</a></li>',
        f'<li><a href="{escape(wiki_url, quote=True)}">Wiki</a></li>',
    ]
    if source.slug.startswith("changelog/"):
        items.append(
            f'<li><a href="{escape(_changelog_pages_base_url(base_url=base_url), quote=True)}">Changelog</a></li>'
        )
    items.append(f'<li aria-current="page">{escape(source.title)}</li>')
    return f'<nav class="wiki-breadcrumbs" aria-label="Breadcrumb"><ol>{"".join(items)}</ol></nav>'


def _render_default_wiki_navigation(sources: Sequence[WikiPageSource], *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    items = "".join(
        f'<li><a href="{escape(_wiki_page_href(source, base_url=base_url))}">{escape(source.title)}</a></li>'
        for source in sources
    )
    return f'<h2>Wiki</h2><ul>{items}</ul>'


def _render_wiki_broken_links(broken_links: Sequence[str]) -> str:
    if not broken_links:
        return ""
    items = "".join(f"<li>{escape(link)}</li>" for link in broken_links)
    return f'<section class="wiki-broken-links"><h2>Broken wiki links</h2><ul>{items}</ul></section>'


def _render_wiki_warnings(warnings: Sequence[str]) -> str:
    if not warnings:
        return ""
    items = "".join(f"<li>{escape(warning)}</li>" for warning in dict.fromkeys(warnings))
    return f'<section class="wiki-render-warnings"><h2>Generator warnings</h2><ul>{items}</ul></section>'


def _clean_meta_text(text: str) -> str:
    cleaned = _plain_wiki_inline_text(text)
    cleaned = re.sub(r"<[^>]+>", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def _meta_description(text: str, *, fallback: str, max_length: int = 180) -> str:
    cleaned = _clean_meta_text(text) or fallback
    if len(cleaned) <= max_length:
        return cleaned
    truncated = cleaned[: max_length - 1].rsplit(" ", 1)[0].strip()
    return (truncated or cleaned[: max_length - 1]).rstrip(".,;:") + "."


def _first_markdown_paragraph(text: str) -> str:
    lines = text.splitlines()
    paragraph: list[str] = []
    in_fence = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if not stripped:
            if paragraph:
                break
            continue
        if not paragraph and (
            stripped.startswith("#")
            or stripped.startswith("|")
            or stripped.startswith(("- ", "* "))
            or _ORDERED_LIST_RE.match(stripped)
            or stripped == "---"
        ):
            continue
        paragraph.append(stripped)
    return " ".join(paragraph)


def _wiki_meta_description(source: WikiPageSource, markdown_text: str) -> str:
    fallback = (
        f"{source.title} documentation for Windows 11 Release Guard, Windows 11 release compliance, "
        "the signed public policy feed, and fleet administration."
    )
    return _meta_description(_first_markdown_paragraph(markdown_text), fallback=fallback, max_length=280)


def _wiki_document_title(title: str) -> str:
    suffix = "Windows 11 Release Guard Wiki"
    return title if title.strip().casefold() == suffix.casefold() else f"{title} | {suffix}"


def _seo_meta_html(
    *,
    title: str,
    description: str,
    canonical_url: str,
    og_type: str = "website",
) -> str:
    safe_title = escape(title, quote=True)
    safe_description = escape(description, quote=True)
    safe_url = escape(canonical_url, quote=True)
    safe_type = escape(og_type, quote=True)
    return (
        f'  <meta name="description" content="{safe_description}">\n'
        f'  <link rel="canonical" href="{safe_url}">\n'
        f'  <meta property="og:title" content="{safe_title}">\n'
        f'  <meta property="og:description" content="{safe_description}">\n'
        f'  <meta property="og:type" content="{safe_type}">\n'
        f'  <meta property="og:url" content="{safe_url}">\n'
        '  <meta property="og:site_name" content="Windows 11 Release Guard">\n'
        '  <meta name="twitter:card" content="summary">\n'
        f'  <meta name="twitter:title" content="{safe_title}">\n'
        f'  <meta name="twitter:description" content="{safe_description}">\n'
    )


def _wiki_section_scrollspy_script_html() -> str:
    return render_asset("wiki-scrollspy.html")


def _wiki_copy_button_script_html() -> str:
    """Client-side, dependency-free copy button for wiki/changelog code blocks.

    Adds a half-transparent button to every ``.wiki-content pre`` that copies the
    block's source text. The code text is captured before the button is appended,
    so the button label never leaks into the copied content. Uses the Clipboard
    API with a hidden-textarea fallback; no external scripts, fonts, or network
    calls. The button is revealed on hover/focus via CSS.
    """
    return render_asset("wiki-copy-button.html")


# Shared Pages visual scale. The wiki/changelog theme is fully rem-based, so a
# single responsive root font-size lifts its typography, spacing, gutters, and
# rem widths to the dashboard's reading size at normal (100%) browser zoom,
# instead of relying on browser zoom or CSS zoom/transform/viewport hacks. The
# clamp keeps it responsive: ~17px on small screens up to ~20px on wide desktops.
_PAGES_WIKI_VISUAL_SCALE = "clamp(1.0625rem, 1rem + 0.45vw, 1.25rem)"


def _wiki_page_html(
    source: WikiPageSource,
    body_html: str,
    headings: Sequence[WikiHeading],
    *,
    site_navigation_html: str,
    footer_html: str,
    broken_links: Sequence[str],
    warnings: Sequence[str] = (),
    canonical_url: str,
    description: str,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    wiki_url = _pages_wiki_url(base_url=base_url)
    dashboard_url = _pages_root_url(base_url=base_url)
    page_title = _wiki_document_title(source.title)
    title = escape(source.title)
    seo_meta = _seo_meta_html(title=page_title, description=description, canonical_url=canonical_url)
    breadcrumbs_html = _wiki_breadcrumbs_html(source, base_url=base_url)
    toc_html = _render_wiki_toc(headings, page_title=source.title)
    navigation_html = _wiki_navigation_html(
        site_navigation_html,
        base_url=base_url,
        current_url=canonical_url,
        toc_html=toc_html,
    )
    broken_html = _render_wiki_broken_links(broken_links)
    warning_html = _render_wiki_warnings(warnings)
    content_class = "wiki-content changelog-content" if source.slug.startswith("changelog") else "wiki-content"
    scrollspy_script = _wiki_section_scrollspy_script_html()
    copy_button_script = _wiki_copy_button_script_html()
    return render_asset(
        "wiki-page.html",
        escape_page_title=f'{escape(page_title)}',
        wiki_favicon_data_url=f'{WIKI_FAVICON_DATA_URL}',
        seo_meta=f'{seo_meta}',
        pages_wiki_visual_scale=f'{_PAGES_WIKI_VISUAL_SCALE}',
        escape_dashboard_url=f'{escape(dashboard_url)}',
        site_brand_icon_html_wiki_brand_icon=f"{_site_brand_icon_html('wiki-brand-icon')}",
        escape_dashboard_url_2=f'{escape(dashboard_url)}',
        escape_wiki_url=f'{escape(wiki_url)}',
        escape_changelog_pages_base_url_base_url_base_ur=f'{escape(_changelog_pages_base_url(base_url=base_url))}',
        escape_github_repository_url=f'{escape(GITHUB_REPOSITORY_URL)}',
        navigation_html=f'{navigation_html}',
        content_class=f'{content_class}',
        breadcrumbs_html=f'{breadcrumbs_html}',
        warning_html=f'{warning_html}',
        body_html=f'{body_html}',
        broken_html=f'{broken_html}',
        footer_html=f'{footer_html}',
        scrollspy_script=f'{scrollspy_script}',
        copy_button_script=f'{copy_button_script}',
    )


def render_wiki_pages(
    *,
    wiki_dir: str | Path = WIKI_SOURCE_DIR,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> dict[str, str]:
    sources, texts, global_warnings = _prepare_wiki_sources(wiki_dir)
    pages = _wiki_page_map(sources)
    sidebar_text = _wiki_helper_text(texts, "_Sidebar.md")
    footer_text = _wiki_helper_text(texts, "_Footer.md")
    if sidebar_text is not None:
        site_navigation_html, _nav_headings, sidebar_broken = _render_wiki_markdown_fragment(
            sidebar_text, pages, base_url=base_url
        )
    else:
        site_navigation_html = _render_default_wiki_navigation(sources, base_url=base_url)
        sidebar_broken = ()
        global_warnings = (*global_warnings, "wiki/_Sidebar.md is missing; generated default Wiki navigation.")
    if footer_text is not None:
        footer_html, _footer_headings, footer_broken = _render_wiki_markdown_fragment(
            footer_text, pages, base_url=base_url
        )
    else:
        footer_html = f'<p>Windows 11 Release Guard documentation for <a href="{escape(GITHUB_REPOSITORY_URL)}">win11_release_guard</a>.</p>'
        footer_broken = ()
        global_warnings = (*global_warnings, "wiki/_Footer.md is missing; generated default Wiki footer.")

    rendered: dict[str, str] = {}
    for source in sources:
        source_text = texts[source.path]
        source_warnings = list(global_warnings)
        if not source_text.strip():
            source_warnings.append(
                f"{_wiki_source_display_name(source.path)} is empty; generated an empty Wiki page with this warning."
            )
        body_html, headings, body_broken = _render_wiki_markdown_fragment(
            source_text,
            pages,
            base_url=base_url,
            page_slug=source.slug,
            heading_icons=True,
        )
        broken_links = tuple(dict.fromkeys((*body_broken, *sidebar_broken, *footer_broken)))
        html = _wiki_page_html(
            source,
            body_html,
            headings,
            site_navigation_html=site_navigation_html,
            footer_html=footer_html,
            broken_links=broken_links,
            warnings=source_warnings,
            canonical_url=_wiki_page_href(source, base_url=base_url),
            description=_wiki_meta_description(source, source_text),
            base_url=base_url,
        )
        rendered[_wiki_output_relative_path(source).as_posix()] = html
    return rendered


def write_wiki_pages(
    output_dir: str | Path,
    *,
    wiki_dir: str | Path = WIKI_SOURCE_DIR,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> dict[str, Path]:
    output_path = Path(output_dir)
    written: dict[str, Path] = {}
    for relative_path, html in render_wiki_pages(wiki_dir=wiki_dir, base_url=base_url).items():
        target = output_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_public_artifact_text(target, html)
        written[relative_path] = target
    return written
