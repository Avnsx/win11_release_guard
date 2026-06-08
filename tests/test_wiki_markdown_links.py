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


def test_sidebar_keeps_wiki_link_syntax_outside_tables() -> None:
    sidebar = WIKI / "_Sidebar.md"
    text = sidebar.read_text(encoding="utf-8")

    assert _iter_table_rows(sidebar) == []
    assert "[[Quick Start|Quick-Start]]" in text
    assert "[[CLI and RMM Usage|CLI-and-RMM-Usage]]" in text


def test_home_and_release_wiki_pages_have_no_broken_table_link_fragments() -> None:
    home = (WIKI / "Home.md").read_text(encoding="utf-8")
    release = (WIKI / "Release-v0.3.1.md").read_text(encoding="utf-8")

    assert "## Pick Your Path" in home
    assert "[[Quick Start" not in home
    assert "Quick-Start]]" not in home
    release_table_has_wiki_link = any(
        "[[" in row.raw or "]]" in row.raw for row in _iter_table_rows(WIKI / "Release-v0.3.1.md")
    )
    assert not release_table_has_wiki_link
    assert "[Quick Start](Quick-Start)" in release


def test_static_wiki_pages_render_from_markdown(tmp_path: Path) -> None:
    output_dir = tmp_path / "site"
    written = write_wiki_pages(output_dir)

    assert (output_dir / "wiki/index.html").is_file()
    assert (output_dir / "wiki/Quick-Start/index.html").is_file()
    assert written["wiki/index.html"] == output_dir / "wiki/index.html"

    home = (output_dir / "wiki/index.html").read_text(encoding="utf-8")
    assert "<title>Windows 11 Release Guard Wiki</title>" in home
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/Quick-Start/"' in home
    assert 'class="wiki-sidebar"' in home
    assert 'class="skip-link" href="#wiki-content"' in home
    assert 'id="wiki-content" class="wiki-content" tabindex="-1"' in home
    assert 'class="wiki-breadcrumbs" aria-label="Breadcrumb"' in home
    assert "On this page" in home
    assert "prefers-reduced-motion: reduce" in home
    assert "@media (max-width: 860px)" in home
    assert "position: sticky" in home
    sidebar_start = home.index('<aside class="wiki-sidebar"')
    changelog_index = home.index('href="https://avnsx.github.io/win11_release_guard/wiki/changelog/"', sidebar_start)
    quick_start_index = home.index('href="https://avnsx.github.io/win11_release_guard/wiki/Quick-Start/"', sidebar_start)
    assert changelog_index < quick_start_index
    for html in render_wiki_pages().values():
        lower = html.lower()
        assert 'data-section-scrollspy="true"' in html
        assert 'if (!sidebar || !content) return;' in html
        assert ".wiki-sidebar a.is-active-section" in html
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

    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/Page-Name/"' in home
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/Page-Name/#target-section"' in home
    assert 'id="first-section"' in home
    assert '<a href="#first-section">First Section</a>' in home
    assert "&lt;script&gt;alert(&#x27;blocked&#x27;)&lt;/script&gt;" in home
    assert "<script>alert" not in home
    assert 'href="https://example.com/a?b=1&amp;c=2" rel="noopener noreferrer"' in home


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
