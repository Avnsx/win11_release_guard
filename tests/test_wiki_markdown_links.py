from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from win11_release_guard.policy_generator import _wiki_sitemap_urls, render_wiki_pages, write_wiki_pages


ROOT = Path(__file__).resolve().parents[1]
WIKI = ROOT / "wiki"
ABSOLUTE_WIKI_PAGE_RE = re.compile(r"https://github\.com/Avnsx/win11_release_guard/wiki/([A-Za-z0-9_.-]+)")
WIKI_LINK_RE = re.compile(r"\[\[([^\]\n]+)\]\]")
MARKDOWN_LINK_RE = re.compile(r"(?<!!)\[([^\]\n]+)\]\(([^)\n]+)\)")
SLUG_ONLY_RE = re.compile(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+")


@dataclass(frozen=True)
class TableRow:
    path: Path
    line_number: int
    raw: str
    cells: list[str]
    header: list[str]
    is_separator: bool


def _wiki_files() -> list[Path]:
    return sorted(WIKI.glob("*.md"))


def _documentation_files() -> list[Path]:
    return [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md")), *_wiki_files()]


def _split_table_row(line: str) -> list[str]:
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]

    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for char in stripped:
        if char == "|" and not escaped:
            cells.append("".join(current).strip())
            current = []
            continue
        current.append(char)
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
    cells.append("".join(current).strip())
    return cells


def _is_table_separator(line: str) -> bool:
    cells = _split_table_row(line)
    return len(cells) >= 2 and all(re.fullmatch(r":?-{3,}:?", cell.strip()) for cell in cells)


def _looks_like_table_row(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("|") and "|" in stripped[1:]


def _iter_table_rows(path: Path) -> list[TableRow]:
    rows: list[TableRow] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    in_fence = False
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            index += 1
            continue
        if in_fence:
            index += 1
            continue
        if (
            index + 1 < len(lines)
            and _looks_like_table_row(lines[index])
            and _is_table_separator(lines[index + 1])
        ):
            header = _split_table_row(lines[index])
            row_index = index
            while row_index < len(lines) and _looks_like_table_row(lines[row_index]):
                raw = lines[row_index]
                rows.append(
                    TableRow(
                        path=path,
                        line_number=row_index + 1,
                        raw=raw,
                        cells=_split_table_row(raw),
                        header=header,
                        is_separator=row_index == index + 1,
                    )
                )
                row_index += 1
            index = row_index
            continue
        index += 1
    return rows


def _table_rows(paths: list[Path]) -> list[TableRow]:
    rows: list[TableRow] = []
    for path in paths:
        rows.extend(_iter_table_rows(path))
    return rows


def _wiki_target(body: str) -> str:
    return body.rsplit("|", 1)[-1].strip()


def _is_external_or_repo_relative_link(target: str) -> bool:
    normalized = target.strip()
    return (
        "://" in normalized
        or normalized.startswith("#")
        or normalized.startswith("/")
        or normalized.startswith("../")
        or normalized.startswith("./")
        or "/" in normalized
        or normalized.lower().startswith("mailto:")
    )


def _page_path(target: str) -> Path:
    page = target.split("#", 1)[0].strip()
    if page.endswith(".md"):
        page = page[:-3]
    return WIKI / f"{page}.md"


def _is_external_link(target: str) -> bool:
    normalized = target.strip().lower()
    return "://" in normalized or normalized.startswith("mailto:")


def _resolve_local_markdown_target(path: Path, target: str) -> Path | None:
    link = target.split("#", 1)[0].strip()
    if not link or _is_external_link(link) or link.startswith("#"):
        return None
    if path.parent == WIKI and "/" not in link and not link.startswith("."):
        return _page_path(link)
    if link.startswith("/"):
        return ROOT / link.lstrip("/")
    return (path.parent / link).resolve()


def test_wiki_markdown_tables_do_not_use_wiki_link_syntax() -> None:
    findings = [
        f"{row.path.relative_to(ROOT)}:{row.line_number}: {row.raw}"
        for row in _table_rows(_wiki_files())
        if "[[" in row.raw or "]]" in row.raw
    ]

    assert findings == []


def test_readme_and_docs_tables_do_not_use_wiki_link_syntax() -> None:
    paths = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    findings = [
        f"{row.path.relative_to(ROOT)}:{row.line_number}: {row.raw}"
        for row in _table_rows(paths)
        if "[[" in row.raw or "]]" in row.raw
    ]

    assert findings == []


def test_wiki_markdown_tables_have_consistent_column_counts() -> None:
    findings: list[str] = []
    for row in _table_rows(_wiki_files()):
        expected = len(row.header)
        actual = len(row.cells)
        if actual != expected:
            findings.append(
                f"{row.path.relative_to(ROOT)}:{row.line_number}: expected {expected} cells, got {actual}: {row.raw}"
            )

    assert findings == []


def test_wiki_markdown_table_cells_do_not_contain_split_wiki_fragments() -> None:
    findings: list[str] = []
    for row in _table_rows(_wiki_files()):
        for cell in row.cells:
            if ("[[" in cell) != ("]]" in cell):
                findings.append(f"{row.path.relative_to(ROOT)}:{row.line_number}: {cell}")

    assert findings == []


def test_wiki_markdown_why_columns_are_explanatory() -> None:
    findings: list[str] = []
    for row in _table_rows(_wiki_files()):
        if row.is_separator:
            continue
        normalized_header = [cell.strip().lower() for cell in row.header]
        if "why" not in normalized_header or row.cells == row.header:
            continue
        why_cell = row.cells[normalized_header.index("why")].strip()
        if SLUG_ONLY_RE.fullmatch(why_cell) or MARKDOWN_LINK_RE.fullmatch(why_cell):
            findings.append(f"{row.path.relative_to(ROOT)}:{row.line_number}: {why_cell}")

    assert findings == []


def test_all_local_wiki_link_targets_exist() -> None:
    findings: list[str] = []
    for path in _wiki_files():
        text = path.read_text(encoding="utf-8")
        for match in WIKI_LINK_RE.finditer(text):
            target = _wiki_target(match.group(1))
            if "|" in target or not _page_path(target).is_file():
                findings.append(f"{path.relative_to(ROOT)}: [[{match.group(1)}]] -> {target}")
        for match in MARKDOWN_LINK_RE.finditer(text):
            target = match.group(2).strip()
            if _is_external_or_repo_relative_link(target):
                continue
            if not _page_path(target).is_file():
                findings.append(f"{path.relative_to(ROOT)}: [{match.group(1)}]({target})")

    assert findings == []


def test_readme_docs_and_wiki_absolute_wiki_urls_target_existing_pages() -> None:
    findings: list[str] = []
    for path in _documentation_files():
        text = path.read_text(encoding="utf-8")
        for match in ABSOLUTE_WIKI_PAGE_RE.finditer(text):
            target = match.group(1)
            if not _page_path(target).is_file():
                findings.append(f"{path.relative_to(ROOT)}: {match.group(0)}")

    assert findings == []


def test_readme_docs_and_wiki_local_markdown_links_target_existing_files() -> None:
    findings: list[str] = []
    for path in _documentation_files():
        text = path.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK_RE.finditer(text):
            resolved = _resolve_local_markdown_target(path, match.group(2))
            if resolved is None:
                continue
            if not resolved.is_file():
                findings.append(f"{path.relative_to(ROOT)}: [{match.group(1)}]({match.group(2)})")

    assert findings == []


def test_sidebar_wiki_links_target_existing_pages() -> None:
    sidebar = WIKI / "_Sidebar.md"
    findings = []
    for match in WIKI_LINK_RE.finditer(sidebar.read_text(encoding="utf-8")):
        target = _wiki_target(match.group(1))
        if not _page_path(target).is_file():
            findings.append(f"[[{match.group(1)}]] -> {target}")

    assert findings == []


def test_sidebar_lists_every_release_page() -> None:
    # _Sidebar.md is the only navigation into a release page on both the generated Pages wiki and
    # the synced GitHub Wiki, and nothing else enumerates it: a new Release-vX.Y.Z.md page that the
    # release-prep commit forgets to list here is orphaned while the whole suite stays green.
    sidebar = (WIKI / "_Sidebar.md").read_text(encoding="utf-8")
    listed = {_wiki_target(match.group(1)) for match in WIKI_LINK_RE.finditer(sidebar)}
    missing = sorted(path.stem for path in WIKI.glob("Release-*.md") if path.stem not in listed)

    assert missing == []


def test_sidebar_keeps_wiki_link_syntax_outside_tables() -> None:
    sidebar = WIKI / "_Sidebar.md"
    text = sidebar.read_text(encoding="utf-8")

    assert _iter_table_rows(sidebar) == []
    assert "[[Quick Start|Quick-Start]]" in text
    assert "[[CLI and RMM Usage|CLI-and-RMM-Usage]]" in text


def test_home_and_release_wiki_pages_have_no_broken_table_link_fragments() -> None:
    home = (WIKI / "Home.md").read_text(encoding="utf-8")
    release = (WIKI / "Release-v0.3.3.md").read_text(encoding="utf-8")

    assert "## Pick Your Path" in home
    assert "[[Quick Start" not in home
    assert "Quick-Start]]" not in home
    release_table_has_wiki_link = any(
        "[[" in row.raw or "]]" in row.raw for row in _iter_table_rows(WIKI / "Release-v0.3.3.md")
    )
    assert not release_table_has_wiki_link
    assert "[Quick Start](Quick-Start)" in release


def test_static_wiki_pages_render_from_markdown(tmp_path: Path) -> None:
    output_dir = tmp_path / "site"
    written = write_wiki_pages(output_dir)

    assert (output_dir / "wiki/index.html").is_file()
    assert (output_dir / "wiki/Quick-Start/index.html").is_file()
    assert not (output_dir / "wiki/_Sidebar/index.html").exists()
    assert not (output_dir / "wiki/_Footer/index.html").exists()
    assert "wiki/_Sidebar/index.html" not in written
    assert "wiki/_Footer/index.html" not in written
    assert written["wiki/index.html"] == output_dir / "wiki/index.html"

    home = (output_dir / "wiki/index.html").read_text(encoding="utf-8")
    assert "<title>Windows 11 Release Guard Wiki</title>" in home
    assert '<link rel="icon" href="data:image/svg+xml,' in home
    assert 'class="wiki-brand-icon"' in home
    assert '<a class="wiki-brand" href="https://avnsx.github.io/win11_release_guard/">' in home
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/Quick-Start/"' in home
    assert 'class="wiki-sidebar"' in home
    assert 'class="skip-link" href="#wiki-content"' in home
    assert 'id="wiki-content" class="wiki-content" tabindex="-1"' in home
    assert 'class="wiki-breadcrumbs" aria-label="Breadcrumb"' in home
    assert "On this page" in home
    assert "prefers-reduced-motion: reduce" in home
    assert "@media (max-width: 860px)" in home
    assert "position: sticky" in home
    assert 'class="wiki-sidebar-header"' in home
    assert "wiki-sidebar-pinned" not in home
    assert ".wiki-sidebar-header {" in home
    assert ".wiki-sidebar > nav {" in home
    assert "overflow: auto;" in home
    assert "scrollbar-gutter: stable;" in home
    assert ".wiki-source-nav {" in home
    assert "padding-top: 1.15rem;" in home
    assert "border-top: 1px solid var(--border);" in home
    assert ".wiki-source-nav > h1:first-child {" in home
    assert ".wiki-source-nav { padding-top: 0.95rem; }" in home
    assert ".wiki-source-nav::after" not in home
    assert ".wiki-sidebar::after" in home
    assert "background: var(--surface);" in home
    assert "-webkit-backdrop-filter: none;" in home
    assert "backdrop-filter: blur(10px);" not in home
    assert "-webkit-backdrop-filter: blur(10px);" not in home
    assert "grid-template-columns: minmax(0, 1fr) max-content;" in home
    assert "column-gap: 1.65rem;" in home
    assert 'class="wiki-nav-changelog-label">Changelog</span>' in home
    assert 'class="wiki-nav-changelog-meta">Release history</span>' in home
    assert "white-space: nowrap;" in home
    assert "transition: color 140ms ease, box-shadow 140ms ease, background-color 140ms ease;" in home
    assert '<p class="wiki-image-block"><img' in home
    assert ".wiki-content h2 {" in home
    assert "margin-top: 3.25rem;" in home
    assert "padding-top: 1rem;" in home
    assert ".wiki-heading-with-icon {" in home
    assert ".wiki-heading-icon .wiki-icon-tile {" in home
    assert ".wiki-heading-icon .wiki-icon-line {" in home
    assert ".wiki-heading-icon .wiki-icon-fill {" in home
    assert ".wiki-content hr + h2 {" in home
    assert "margin-top: 1.55rem;" in home
    assert "border-top: 0;" in home
    assert ".wiki-content p + p:not(.wiki-image-block) { margin-top: 0.2rem; }" in home
    assert ".wiki-content .wiki-image-block {" in home
    assert "margin: 1.15rem 0 0.8rem;" in home
    assert ".wiki-content .wiki-image-block + hr {" in home
    assert "margin: 1.35rem 0 2.25rem;" in home
    assert ".wiki-content h2 { margin-top: 2.55rem; margin-bottom: 0.95rem; padding-top: 0.8rem; }" in home
    assert ".wiki-content hr + h2 { margin-top: 1.45rem; }" in home
    assert ".wiki-content .wiki-image-block { margin: 1rem 0 0.7rem; }" in home
    assert ".wiki-content table { margin-bottom: 1.65rem; }" in home
    sidebar_start = home.index('<aside class="wiki-sidebar"')
    changelog_index = home.index('href="https://avnsx.github.io/win11_release_guard/wiki/changelog/"', sidebar_start)
    toc_index = home.index('<section class="wiki-toc" aria-label="Table of contents">', sidebar_start)
    source_nav_index = home.index('<section class="wiki-source-nav" aria-label="Wiki source navigation">', sidebar_start)
    quick_start_index = home.index('href="https://avnsx.github.io/win11_release_guard/wiki/Quick-Start/"', sidebar_start)
    assert changelog_index < toc_index < source_nav_index < quick_start_index
    article_index = home.index('<article id="wiki-content"', sidebar_start)
    sidebar_html = home[sidebar_start:article_index]
    assert 'class="wiki-heading-icon' not in sidebar_html
    home_article = home[article_index : home.index("</article>", article_index)]
    assert 'class="wiki-heading-icon wiki-icon-windows"' in home_article
    assert 'class="wiki-heading-icon wiki-icon-start"' in home_article
    assert 'aria-hidden="true" focusable="false"' in home_article
    assert '<span class="wiki-heading-text">Windows 11 Release Guard Wiki</span></h1>' in home_article
    assert '<span class="wiki-heading-text">Pick Your Path</span></h2>' in home_article
    assert 2 <= home_article.count('class="wiki-heading-icon') <= 4
    home_toc = home[toc_index:source_nav_index]
    assert 'wiki-heading-icon' not in home_toc
    assert 'href="#windows-11-release-guard-wiki"' not in home_toc
    assert 'href="#pick-your-path">Pick Your Path</a>' in home_toc
    assert "toc-level-1" not in home_toc
    local_detection = (output_dir / "wiki/Local-Windows-Detection/index.html").read_text(encoding="utf-8")
    assert ".wiki-sidebar a.is-current-page" in local_detection
    assert ".wiki-source-nav .wiki-nav-group.is-current-group" in local_detection
    assert ".wiki-sidebar::after" in local_detection
    assert "min-height: min(34rem, 58vh);" in local_detection
    assert ".wiki-sidebar::after { display: none; }" in local_detection
    assert "scrollArea" not in local_detection
    assert "function alignSidebarTarget(target, force, behavior)" in local_detection
    assert "function sidebarContentOffsetTop(target)" in local_detection
    assert "function sidebarScrollOffset()" in local_detection
    assert "sidebarAlignmentTargetForCurrentPage" in local_detection
    assert "manualSidebarScrollUntil = now() + 1200" in local_detection
    assert 'sidebarNavigationStorageKey = "win11_release_guard.wikiSidebarScroll.v1"' in local_detection
    assert "function restoreSidebarNavigationPosition()" in local_detection
    assert "var restoredSidebarNavigationPosition = restoreSidebarNavigationPosition();" in local_detection
    assert 'return restoredSidebarNavigationPosition && !prefersReducedMotion ? "smooth" : "auto";' in local_detection
    assert "rememberSidebarScrollForHref(href);" in local_detection
    assert "var targetTop = sidebarContentOffsetTop(target) - sidebarScrollOffset();" in local_detection
    assert 'sidebar.scrollTo({ top: targetTop, behavior: scrollBehavior });' in local_detection
    assert '<p class="wiki-nav-group is-current-group"><strong>Architecture</strong></p>' in local_detection
    assert (
        'href="https://avnsx.github.io/win11_release_guard/wiki/Local-Windows-Detection/" '
        'class="is-current-page" aria-current="page">Local Windows Detection</a>'
    ) in local_detection
    local_sidebar_start = local_detection.index('<aside class="wiki-sidebar"')
    local_toc_index = local_detection.index('<section class="wiki-toc" aria-label="Table of contents">', local_sidebar_start)
    local_source_nav_index = local_detection.index(
        '<section class="wiki-source-nav" aria-label="Wiki source navigation">',
        local_sidebar_start,
    )
    local_toc = local_detection[local_toc_index:local_source_nav_index]
    assert 'href="#local-windows-detection">Local Windows Detection</a>' not in local_toc
    assert 'href="#signal-map">Signal Map</a>' in local_toc
    assert "toc-level-1" not in local_toc
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/Architecture/" class="is-current-page"' not in local_detection
    policy_feed = (output_dir / "wiki/Policy-Feed-and-Trust-Model/index.html").read_text(encoding="utf-8")
    assert "two build numbers that are easy to mix up" in policy_feed
    assert "does not decide compliance by itself" in policy_feed
    assert "minimum signed build this policy currently requires" in policy_feed
    assert "detached Ed25519 signature over those exact bytes" in policy_feed
    anti_static = (output_dir / "wiki/Anti-Static-Freshness/index.html").read_text(encoding="utf-8")
    assert "latest compilation timestamp for the current policy results parsed" in anti_static
    assert "publish-policy.yml" in anti_static
    assert "14 days starts a refresh-due warning" in anti_static
    source_diagnostics = (output_dir / "wiki/Source-Diagnostics/index.html").read_text(encoding="utf-8")
    assert "Source diagnostics explain the health of the policy inputs" in source_diagnostics
    assert "errors are publish-blocking" in source_diagnostics
    dashboard = (output_dir / "wiki/GitHub-Pages-Dashboard/index.html").read_text(encoding="utf-8")
    assert "The dashboard is a static public control surface" in dashboard
    assert "scripts should use the published JSON" in dashboard
    for html in render_wiki_pages().values():
        lower = html.lower()
        if '<article id="wiki-content"' in html:
            article_start = html.index('<article id="wiki-content"')
            article_html = html[article_start : html.index("</article>", article_start)]
            icon_count = article_html.count('class="wiki-heading-icon')
            assert icon_count <= 4
            if "<h1" in article_html:
                assert icon_count >= 1
            if icon_count:
                assert 'aria-hidden="true" focusable="false"' in article_html
            icon_kinds = re.findall(r'class="wiki-heading-icon wiki-icon-([^"\s]+)"', article_html)
            assert len(icon_kinds) == len(set(icon_kinds)), f"duplicate wiki icons in article: {icon_kinds}"
        assert 'data-section-scrollspy="true"' in html
        assert 'if (!sidebar || !content) return;' in html
        assert ".wiki-sidebar a.is-active-section" in html
        assert ".wiki-sidebar a.is-current-page" in html
        assert "margin-left: -" not in html
        assert "script src" not in lower
        assert 'rel="stylesheet"' not in lower
        assert "cdn.jsdelivr" not in lower
        assert "esm.sh" not in lower
        assert "npmjs.com" not in lower
        assert "autotoc" not in lower
        assert "auto-table-of-content-generator" not in lower
        assert "fonts.googleapis" not in lower
        assert "fonts.gstatic" not in lower
        assert "unpkg.com" not in lower
        assert "authorization:" not in lower
        assert "bearer " not in lower


def test_static_wiki_renderer_converts_links_anchors_and_escapes_html(tmp_path: Path) -> None:
    wiki_dir = tmp_path / "wiki"
    wiki_dir.mkdir()
    (wiki_dir / "Home.md").write_text(
        "\n".join(
            [
                "# Home",
                "## First Section",
                "[[Friendly page|Page-Name]]",
                "[Internal](Page-Name#Target Section)",
                "[External](https://example.com/a?b=1&c=2)",
                "<script>alert('blocked')</script>",
            ]
        ),
        encoding="utf-8",
    )
    (wiki_dir / "Page-Name.md").write_text("# Page Name\n## Target Section\n", encoding="utf-8")
    (wiki_dir / "_Sidebar.md").write_text("## Navigation\n- [[Home]]\n- [[Friendly|Page-Name]]\n", encoding="utf-8")
    (wiki_dir / "_Footer.md").write_text("Repository footer\n", encoding="utf-8")

    pages = render_wiki_pages(wiki_dir=wiki_dir)
    home = pages["wiki/index.html"]

    assert "wiki/_Sidebar/index.html" not in pages
    assert "wiki/_Footer/index.html" not in pages
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/Page-Name/"' in home
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/Page-Name/#target-section"' in home
    assert 'id="first-section"' in home
    assert '<a href="#first-section">First Section</a>' in home
    assert "&lt;script&gt;alert(&#x27;blocked&#x27;)&lt;/script&gt;" in home
    assert "<script>alert" not in home
    assert 'href="https://example.com/a?b=1&amp;c=2" rel="noopener noreferrer"' in home

    page_name = pages["wiki/Page-Name/index.html"]
    assert (
        'href="https://avnsx.github.io/win11_release_guard/wiki/Page-Name/" '
        'class="is-current-page" aria-current="page">Friendly</a>'
    ) in page_name
    assert 'class="wiki-nav-group is-current-group"' not in page_name
    urls = _wiki_sitemap_urls(wiki_dir=wiki_dir)
    assert "https://avnsx.github.io/win11_release_guard/wiki/" in urls
    assert "https://avnsx.github.io/win11_release_guard/wiki/Page-Name/" in urls
    assert not any("/wiki/_Sidebar/" in url or "/wiki/_Footer/" in url for url in urls)


def test_static_wiki_renderer_marks_broken_internal_links(tmp_path: Path) -> None:
    wiki_dir = tmp_path / "wiki"
    wiki_dir.mkdir()
    (wiki_dir / "Home.md").write_text("# Home\n[[Missing Page]]\n[Also missing](Missing-Page)\n", encoding="utf-8")

    home = render_wiki_pages(wiki_dir=wiki_dir)["wiki/index.html"]

    assert 'data-broken-link="Missing Page"' in home
    assert 'data-broken-link="Missing-Page"' in home
    assert "Broken wiki links" in home


def test_static_wiki_renderer_warns_for_missing_home_sidebar_footer_and_empty_sources(tmp_path: Path) -> None:
    wiki_dir = tmp_path / "wiki"
    wiki_dir.mkdir()
    (wiki_dir / "Empty.md").write_text("", encoding="utf-8")
    (wiki_dir / "Page-Name.md").write_text("# Page Name\nContent.\n", encoding="utf-8")

    pages = render_wiki_pages(wiki_dir=wiki_dir)

    assert "wiki/index.html" in pages
    assert "wiki/Empty/index.html" in pages
    home = pages["wiki/index.html"]
    empty = pages["wiki/Empty/index.html"]
    assert "Generator warnings" in home
    assert "wiki/Home.md is missing" in home
    assert "wiki/_Sidebar.md is missing" in home
    assert "wiki/_Footer.md is missing" in home
    assert "Empty.md is empty" in empty
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/Page-Name/"' in home

    page_name = pages["wiki/Page-Name/index.html"]
    assert (
        'href="https://avnsx.github.io/win11_release_guard/wiki/Page-Name/" '
        'class="is-current-page" aria-current="page">Page Name</a>'
    ) in page_name


def test_static_wiki_renderer_generates_fallback_when_wiki_dir_is_missing(tmp_path: Path) -> None:
    missing_wiki = tmp_path / "missing-wiki"
    pages = render_wiki_pages(wiki_dir=missing_wiki)

    assert set(pages) == {"wiki/index.html"}
    assert "Generator warnings" in pages["wiki/index.html"]
    assert "missing-wiki is missing" in pages["wiki/index.html"]
    assert _wiki_sitemap_urls(wiki_dir=missing_wiki) == ("https://avnsx.github.io/win11_release_guard/wiki/",)


def test_static_wiki_renderer_handles_link_variants_duplicate_unicode_headings_and_structures(tmp_path: Path) -> None:
    wiki_dir = tmp_path / "wiki"
    wiki_dir.mkdir()
    (wiki_dir / "Home.md").write_text(
        "\n".join(
            [
                "# Home",
                "## Duplicate",
                "## Duplicate",
                "## Über Café",
                "[[Home]]",
                "[[Label|Page-Name]]",
                "[[Page Name With Spaces]]",
                "`<b>inline</b>`",
                "```powershell",
                "<script>alert('blocked')</script>",
                "```",
                "| Name | Value |",
                "| --- | --- |",
                "| Link | [[Label|Page-Name]] |",
                "- Parent",
                "  - Nested stays readable",
                "1. Ordered",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (wiki_dir / "Page-Name.md").write_text("# Page Name\n", encoding="utf-8")
    (wiki_dir / "Page Name With Spaces.md").write_text("# Page Name With Spaces\n", encoding="utf-8")

    home = render_wiki_pages(wiki_dir=wiki_dir)["wiki/index.html"]

    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/"' in home
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/Page-Name/"' in home
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/Page-Name-With-Spaces/"' in home
    assert 'id="duplicate"' in home
    assert 'id="duplicate-2"' in home
    assert 'id="ber-caf"' in home
    assert "&lt;b&gt;inline&lt;/b&gt;" in home
    assert "&lt;script&gt;alert(&#x27;blocked&#x27;)&lt;/script&gt;" in home
    assert "<table>" in home
    assert "<ul><li>Parent<ul><li>Nested stays readable</li></ul></li></ul>" in home
    assert "<ol>" in home
    assert "<script>alert" not in home
