"""Changelog pages rendered from CHANGELOG.md."""

from __future__ import annotations

import re
from html import escape
from pathlib import Path
from typing import Sequence
from ...config import DEFAULT_PAGES_BASE_URL
from ..artifacts import _write_public_artifact_text
from ..constants import (
    CHANGELOG_SOURCE_PATH,
    GITHUB_RELEASES_BASE_URL,
    WIKI_SOURCE_DIR,
    _CHANGELOG_RELEASE_VERSION_RE,
    _CHANGELOG_VERSION_HEADING_RE,
)
from .wiki_markdown import _render_wiki_markdown_fragment
from .wiki_model import ChangelogSection, WikiHeading, WikiPageSource
from .wiki_page import _wiki_page_html
from .wiki_sources import (
    _changelog_pages_base_url,
    _discover_wiki_sources,
    _heading_slug_base,
    _plain_wiki_inline_text,
    _prepare_wiki_sources,
    _read_markdown_source,
    _unique_slug,
    _wiki_page_href,
    _wiki_page_map,
)


def _wiki_sitemap_urls(*, wiki_dir: str | Path = WIKI_SOURCE_DIR, base_url: str = DEFAULT_PAGES_BASE_URL) -> tuple[str, ...]:
    sources, _texts, _warnings = _prepare_wiki_sources(wiki_dir)
    if not sources:
        return ()
    urls = [_wiki_page_href(source, base_url=base_url) for source in sources]
    return tuple(dict.fromkeys(urls))

def _changelog_anchor_slug(title: str) -> str:
    if "unreleased" in title.casefold():
        return "unreleased"
    version = _changelog_version_from_title(title)
    if version:
        return version
    return _heading_slug_base(title)

def _changelog_version_from_title(title: str) -> str | None:
    if "unreleased" in title.casefold():
        return None
    match = _CHANGELOG_RELEASE_VERSION_RE.search(title)
    if not match:
        return None
    return f"v{match.group(1)}"

def _changelog_release_href(version: str | None) -> str | None:
    if not version:
        return None
    return f"{GITHUB_RELEASES_BASE_URL}/{version}"

def _changelog_index_description() -> str:
    return (
        "Windows 11 Release Guard changelog for Windows 11 release compliance, signed public policy feed "
        "changes, RMM, and fleet administration release history."
    )

def _changelog_section_description(section: ChangelogSection) -> str:
    version_label = section.version or section.title
    description = (
        f"Windows 11 Release Guard {version_label} changelog covering Windows 11 release compliance, "
        "signed public policy feed changes, RMM, and fleet administration."
    )
    lower_markdown = section.markdown.casefold()
    if "25h2" in lower_markdown or "26h1" in lower_markdown:
        description += " Includes Windows 11 25H2 and 26H1 release targeting notes."
    return description

def _parse_changelog_sections(text: str) -> tuple[ChangelogSection, ...]:
    lines = text.splitlines()
    starts: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        match = _CHANGELOG_VERSION_HEADING_RE.match(line)
        if match:
            starts.append((index, _plain_wiki_inline_text(match.group("title")).strip()))
    sections: list[ChangelogSection] = []
    used_slugs: dict[str, int] = {}
    for position, (start, title) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        markdown = "\n".join(lines[start:end]).strip() + "\n"
        version = _changelog_version_from_title(title)
        slug = _unique_slug(_changelog_anchor_slug(title), used_slugs)
        sections.append(
            ChangelogSection(
                title=title,
                slug=slug,
                markdown=markdown,
                version=version,
                release_href=_changelog_release_href(version),
            )
        )
    return tuple(sections)

def _changelog_render_warnings(text: str, sections: Sequence[ChangelogSection]) -> tuple[str, ...]:
    warnings: list[str] = []
    if not text.strip():
        warnings.append("CHANGELOG.md is empty; generated a changelog page with no release history.")
    elif not sections:
        warnings.append(
            "CHANGELOG.md contains no recognized version sections; use h2 headings like [Unreleased] or vX.Y.Z."
        )
    recognized_titles = {section.title.casefold() for section in sections}
    for line in text.splitlines():
        if not line.startswith("## "):
            continue
        title = _plain_wiki_inline_text(line[3:]).strip()
        if title and title.casefold() not in recognized_titles:
            warnings.append(f"CHANGELOG.md h2 heading is not a recognized version section: {title}")
    titles = [section.title.casefold() for section in sections]
    if len(set(titles)) != len(titles):
        warnings.append("CHANGELOG.md contains duplicate version headings; generated duplicate-safe anchors.")
    return tuple(dict.fromkeys(warnings))

def _changelog_section_href(section: ChangelogSection, *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    return f"{_changelog_pages_base_url(base_url=base_url)}#{section.slug}"

def _changelog_version_page_href(section: ChangelogSection, *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str | None:
    if not section.version:
        return None
    return f"{_changelog_pages_base_url(base_url=base_url)}{section.version}/"

def _changelog_section_is_unreleased(section: ChangelogSection) -> bool:
    return section.title.strip().casefold() == "[unreleased]"

def _changelog_heading_overrides(sections: Sequence[ChangelogSection]) -> dict[str, str | tuple[str, ...]]:
    grouped: dict[str, list[str]] = {}
    for section in sections:
        grouped.setdefault(section.title, []).append(section.slug)
    return {title: slugs[0] if len(slugs) == 1 else tuple(slugs) for title, slugs in grouped.items()}

def _render_changelog_version_actions(
    section: ChangelogSection,
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    section_link_label = "pre-release" if _changelog_section_is_unreleased(section) else "Changelog section"
    section_link_class = ' class="changelog-pre-release-badge"' if _changelog_section_is_unreleased(section) else ""
    links = [
        f'<a href="{escape(_changelog_section_href(section, base_url=base_url))}"{section_link_class}>'
        f"{section_link_label}</a>",
    ]
    version_page_href = _changelog_version_page_href(section, base_url=base_url)
    if version_page_href:
        links.append(f'<a href="{escape(version_page_href)}">Version page</a>')
    if section.release_href:
        links.append(f'<a href="{escape(section.release_href)}" rel="noopener noreferrer">GitHub release</a>')
    return f'<nav class="changelog-version-actions" aria-label="{escape(section.title)} links">{"".join(links)}</nav>'

def _inject_changelog_version_actions(
    body_html: str,
    sections: Sequence[ChangelogSection],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    updated = body_html
    for section in sections:
        safe_slug = escape(section.slug, quote=True)
        heading_pattern = re.compile(rf'(<h2 id="{re.escape(safe_slug)}"[^>]*>.*?</h2>)', re.DOTALL)
        updated = heading_pattern.sub(
            lambda match: match.group(1) + "\n" + _render_changelog_version_actions(section, base_url=base_url),
            updated,
            count=1,
        )
    return updated

def _render_changelog_navigation(
    sections: Sequence[ChangelogSection],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
    local_anchors: bool = True,
) -> str:
    if not sections:
        return "<h2>Changelog</h2><p>No changelog versions found.</p>"
    items: list[str] = []
    for section in sections:
        section_href = f"#{section.slug}" if local_anchors else _changelog_section_href(section, base_url=base_url)
        is_unreleased = _changelog_section_is_unreleased(section)
        section_link_label = "pre-release" if is_unreleased else "Section"
        section_link_class = ' class="changelog-pre-release-badge"' if is_unreleased else ""
        section_link_title = "Open pre-release section" if is_unreleased else "Open section on Pages changelog"
        links = [
            (
                f'<a href="{escape(_changelog_section_href(section, base_url=base_url))}" '
                f'aria-label="Open {escape(section.title)} section on the Pages changelog" '
                f'title="{section_link_title}"{section_link_class}>{section_link_label}</a>'
            )
        ]
        version_page_href = _changelog_version_page_href(section, base_url=base_url)
        if version_page_href:
            links.append(
                f'<a href="{escape(version_page_href)}" '
                f'aria-label="Open {escape(section.title)} version page" title="Open version page">Version page</a>'
            )
        if section.release_href:
            links.append(
                f'<a href="{escape(section.release_href)}" rel="noopener noreferrer" '
                f'aria-label="Open GitHub release for {escape(section.title)}" title="Open GitHub release">GH release</a>'
            )
        items.append(
            '<li>'
            f'<a href="{escape(section_href)}">{escape(section.title)}</a>'
            f'<div class="version-meta">{"".join(links)}</div>'
            '</li>'
        )
    return f'<section class="changelog-version-nav" aria-label="Changelog versions"><h2>Versions</h2><ol>{"".join(items)}</ol></section>'

def _render_changelog_body(
    markdown: str,
    sections: Sequence[ChangelogSection],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
    page_slug: str = "changelog",
) -> tuple[str, tuple[WikiHeading, ...], tuple[str, ...]]:
    wiki_sources, _texts = _discover_wiki_sources()
    pages = _wiki_page_map(wiki_sources)
    body_html, headings, broken_links = _render_wiki_markdown_fragment(
        markdown,
        pages,
        base_url=base_url,
        heading_slug_overrides=_changelog_heading_overrides(sections),
        page_slug=page_slug,
        heading_icons=True,
    )
    return _inject_changelog_version_actions(body_html, sections, base_url=base_url), headings, broken_links

def render_changelog_pages(
    *,
    changelog_path: str | Path = CHANGELOG_SOURCE_PATH,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> dict[str, str]:
    source = Path(changelog_path)
    if not source.is_file():
        return {}
    text = _read_markdown_source(source)
    sections = _parse_changelog_sections(text)
    changelog_warnings = _changelog_render_warnings(text, sections)
    body_html, _headings, broken_links = _render_changelog_body(text, sections, base_url=base_url)
    navigation_html = _render_changelog_navigation(sections, base_url=base_url)
    version_navigation_html = _render_changelog_navigation(sections, base_url=base_url, local_anchors=False)
    footer_html = (
        f'<p>Rendered from <code>CHANGELOG.md</code>. Historical version sections remain in source order for '
        f'<a href="{escape(_changelog_pages_base_url(base_url=base_url))}">Pages changelog</a>, release history, '
        "SEO, and auditability.</p>"
    )
    index_source = WikiPageSource(path=source, title="Changelog", slug="changelog", lookup_keys=())
    rendered = {
        "wiki/changelog/index.html": _wiki_page_html(
            index_source,
            body_html,
            (),
            site_navigation_html=navigation_html,
            footer_html=footer_html,
            broken_links=broken_links,
            warnings=changelog_warnings,
            canonical_url=_changelog_pages_base_url(base_url=base_url),
            description=_changelog_index_description(),
            base_url=base_url,
        )
    }
    for section in sections:
        if not section.version:
            continue
        version_body, _version_headings, version_broken = _render_changelog_body(
            f"# Changelog\n\n{section.markdown}",
            (section,),
            base_url=base_url,
        )
        version_source = WikiPageSource(
            path=source,
            title=f"Changelog {section.version}",
            slug=section.version,
            lookup_keys=(),
        )
        rendered[f"wiki/changelog/{section.version}/index.html"] = _wiki_page_html(
            version_source,
            version_body,
            (),
            site_navigation_html=version_navigation_html,
            footer_html=footer_html,
            broken_links=version_broken,
            warnings=changelog_warnings,
            canonical_url=_changelog_version_page_href(section, base_url=base_url) or _changelog_section_href(
                section, base_url=base_url
            ),
            description=_changelog_section_description(section),
            base_url=base_url,
        )
    return rendered

def write_changelog_pages(
    output_dir: str | Path,
    *,
    changelog_path: str | Path = CHANGELOG_SOURCE_PATH,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> dict[str, Path]:
    output_path = Path(output_dir)
    written: dict[str, Path] = {}
    for relative_path, html in render_changelog_pages(changelog_path=changelog_path, base_url=base_url).items():
        target = output_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_public_artifact_text(target, html)
        written[relative_path] = target
    return written

def _changelog_sitemap_urls(
    *,
    changelog_path: str | Path = CHANGELOG_SOURCE_PATH,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> tuple[str, ...]:
    source = Path(changelog_path)
    if not source.is_file():
        return ()
    sections = _parse_changelog_sections(_read_markdown_source(source))
    urls = [_changelog_pages_base_url(base_url=base_url)]
    urls.extend(
        href
        for href in (_changelog_version_page_href(section, base_url=base_url) for section in sections)
        if href
    )
    return tuple(dict.fromkeys(urls))
