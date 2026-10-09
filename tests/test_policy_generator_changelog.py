from __future__ import annotations

import re
from pathlib import Path
import win11_release_guard.policy_generator as policy_generator_module
from win11_release_guard.policy_generator import render_changelog_pages


def test_changelog_renderer_preserves_history_order_and_links(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "\n".join(
            [
                "# Changelog",
                "",
                "## [Unreleased]",
                "",
                "### Added",
                "",
                "* Next change.",
                "",
                "## v0.3.1 - 2026-06-05",
                "",
                "### Changed",
                "",
                "* Current release.",
                "",
                "## v0.3.0 - 2026-05-20",
                "",
                "### Fixed",
                "",
                "* Older release remains visible.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    pages = render_changelog_pages(changelog_path=changelog)
    index = pages["wiki/changelog/index.html"]

    assert "wiki/changelog/v0.3.1/index.html" in pages
    assert "wiki/changelog/v0.3.0/index.html" in pages
    assert index.index("[Unreleased]") < index.index("v0.3.1 - 2026-06-05")
    assert index.index("v0.3.1 - 2026-06-05") < index.index("v0.3.0 - 2026-05-20")
    assert "Older release remains visible." in index
    assert '<section class="changelog-version-nav" aria-label="Changelog versions">' in index
    assert 'href="#unreleased"' in index
    assert 'href="#v0.3.1"' in index
    assert 'href="#v0.3.0"' in index
    assert 'href="https://github.com/Avnsx/win11_release_guard/releases/tag/v0.3.1"' in index
    assert 'href="https://github.com/Avnsx/win11_release_guard/releases/tag/v0.3.0"' in index
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/changelog/#unreleased"' in index
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/changelog/v0.3.1/"' in index
    assert 'title="Open pre-release section" class="changelog-pre-release-badge">pre-release</a>' in index
    assert 'title="Open section on Pages changelog">Section</a>' in index
    assert 'title="Open version page">Version page</a>' in index
    assert 'title="Open GitHub release">GH release</a>' in index
    assert '<h1 id="changelog" class="wiki-heading-with-icon">' in index
    assert 'class="wiki-heading-icon wiki-icon-changelog"' in index
    assert '<h2 id="unreleased" class="wiki-heading-with-icon">' in index
    assert 'class="wiki-heading-icon wiki-icon-release"' in index
    article_start = index.index('<article id="wiki-content"')
    article_html = index[article_start : index.index("</article>", article_start)]
    icon_kinds = re.findall(r'class="wiki-heading-icon wiki-icon-([^"\s]+)"', article_html)
    assert len(icon_kinds) == len(set(icon_kinds)), f"duplicate changelog icons: {icon_kinds}"
    assert index.index('<h2 id="unreleased" class="wiki-heading-with-icon">') < index.index(
        '<nav class="changelog-version-actions" aria-label="[Unreleased] links">'
    )
    assert index.count('class="wiki-heading-icon') <= 4
    assert 'aria-label="Open [Unreleased] section on the Pages changelog"' in index
    assert 'aria-label="Open v0.3.1 - 2026-06-05 version page"' in index
    assert 'aria-label="Open GitHub release for v0.3.1 - 2026-06-05"' in index
    assert "border-color: #f0c74c;" in index
    assert "background: linear-gradient(180deg, #fff8db, #ffefad);" in index
    assert ".changelog-content h2[id]:first-of-type" in index
    assert "margin-top: 4.75rem;" in index
    assert "margin: -0.25rem 0 1.9rem 1.05rem;" in index
    assert ".changelog-version-nav ol {" in index
    assert "gap: 1.18rem;" in index
    assert "margin: 0.3rem 0 0 0.65rem;" in index
    assert ".changelog-version-nav .version-meta a {" in index
    assert "font-size: 0.76rem;" in index
    assert "min-height: 1.42rem;" in index
    assert ">Pages</a>" not in index
    assert ">Page</a>" not in index
    assert (
        'href="https://avnsx.github.io/win11_release_guard/wiki/changelog/" '
        'class="is-current-page" aria-current="page"><span class="wiki-nav-changelog-label">Changelog</span>'
        '<span class="wiki-nav-changelog-meta">Release history</span></a>'
    ) in index
    assert 'data-section-scrollspy="true"' in index
    assert ".wiki-sidebar a.is-active-section" in index
    assert ".wiki-sidebar a.is-current-page" in index
    assert "margin-left: -" not in index
    assert 'entry.link.setAttribute("aria-current", "location")' in index
    assert 'entry.item.classList.toggle("is-active-section", selected)' in index
    assert 'if (!sidebar || !content) return;' in index
    assert 'if (!items.length) {' in index
    assert 'alignCurrentPageLink(initialSidebarAlignmentBehavior());' in index
    assert 'function alignSidebarTarget(target, force, behavior)' in index
    assert "function sidebarContentOffsetTop(target)" in index
    assert "function sidebarScrollOffset()" in index
    assert "manualSidebarScrollUntil = now() + 1200" in index
    assert 'sidebarNavigationStorageKey = "win11_release_guard.wikiSidebarScroll.v1"' in index
    assert "function restoreSidebarNavigationPosition()" in index
    assert "var restoredSidebarNavigationPosition = restoreSidebarNavigationPosition();" in index
    assert 'return restoredSidebarNavigationPosition && !prefersReducedMotion ? "smooth" : "auto";' in index
    assert "rememberSidebarScrollForHref(href);" in index
    assert "if (pendingSidebarNavigationHref) return;" in index
    assert "var targetTop = sidebarContentOffsetTop(target) - sidebarScrollOffset();" in index
    assert "wiki-sidebar-pinned" not in index
    assert "scrollArea" not in index
    assert 'sidebar.scrollTo({ top: targetTop, behavior: scrollBehavior });' in index
    assert "window.location.hash && initialActive" in index
    assert "allowSectionAutoAlign = true;" in index
    assert 'node.classList.contains("version-meta")' in index
    assert 'new IntersectionObserver(scheduleUpdate' in index
    assert "script src" not in index.lower()
    assert 'rel="stylesheet"' not in index.lower()
    assert "cdn.jsdelivr" not in index.lower()
    assert "esm.sh" not in index.lower()
    assert "fonts.googleapis" not in index.lower()


def test_changelog_renderer_handles_missing_unreleased_without_warning(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "\n".join(
            [
                "# Changelog",
                "",
                "## v0.3.1 - 2026-06-05",
                "",
                "### Changed",
                "",
                "* Current release.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    index = render_changelog_pages(changelog_path=changelog)["wiki/changelog/index.html"]

    assert "v0.3.1 - 2026-06-05" in index
    assert "Generator warnings" not in index
    assert 'href="#v0.3.1"' in index


def test_changelog_renderer_warns_for_empty_and_nonstandard_sections(tmp_path: Path) -> None:
    empty_changelog = tmp_path / "EMPTY_CHANGELOG.md"
    empty_changelog.write_text("", encoding="utf-8")
    empty_index = render_changelog_pages(changelog_path=empty_changelog)["wiki/changelog/index.html"]

    assert "Generator warnings" in empty_index
    assert "CHANGELOG.md is empty" in empty_index
    assert "No changelog versions found." in empty_index
    assert 'data-section-scrollspy="true"' in empty_index
    assert 'if (!items.length) {' in empty_index
    assert 'alignCurrentPageLink(initialSidebarAlignmentBehavior());' in empty_index
    assert "script src" not in empty_index.lower()

    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "\n".join(
            [
                "# Changelog",
                "",
                "## Version 0.3.1",
                "",
                "* Non-standard release header remains visible but is not a version route.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    pages = render_changelog_pages(changelog_path=changelog)
    index = pages["wiki/changelog/index.html"]

    assert set(pages) == {"wiki/changelog/index.html"}
    assert "Version 0.3.1" in index
    assert "CHANGELOG.md contains no recognized version sections" in index
    assert "CHANGELOG.md h2 heading is not a recognized version section: Version 0.3.1" in index


def test_changelog_renderer_uses_duplicate_safe_anchors_and_escapes_long_sections(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    long_note = " ".join(["Long release note"] * 80)
    changelog.write_text(
        "\n".join(
            [
                "# Changelog",
                "",
                "## v0.3.1 - 2026-06-05",
                "",
                f"* {long_note}",
                "",
                "## v0.3.1 - 2026-06-05",
                "",
                "* <script>alert('blocked')</script>",
                "",
            ]
        ),
        encoding="utf-8",
    )

    pages = render_changelog_pages(changelog_path=changelog)
    index = pages["wiki/changelog/index.html"]

    assert 'id="v0.3.1"' in index
    assert 'id="v0.3.1-2"' in index
    assert 'href="#v0.3.1"' in index
    assert 'href="#v0.3.1-2"' in index
    assert 'document.getElementById(hashId(hash))' in index
    assert 'return hash.slice(1);' in index
    assert "duplicate version headings" in index
    assert "Long release note" in index
    assert "&lt;script&gt;alert(&#x27;blocked&#x27;)&lt;/script&gt;" in index
    assert "<script>alert" not in index


def test_render_changelog_pages_survives_invalid_utf8(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_bytes(
        b"# Changelog\n\n## [Unreleased]\n\nBroken \xff\xfe bytes.\n\n"
        b"## v0.3.3 - 2026-06-11\n\n- item\n"
    )

    rendered = policy_generator_module.render_changelog_pages(changelog_path=changelog)
    assert rendered
    assert any("changelog" in name for name in rendered)


def test_wiki_changelog_renders_wrapped_bullets_as_list_items(tmp_path: Path) -> None:
    pages = policy_generator_module.render_changelog_pages()
    assert pages
    for name, html in pages.items():
        # No changelog bullet text should spill into a paragraph that opens with a
        # lowercase wrapped-continuation word (the symptom of broken list tabbing).
        assert "<p>wording (" not in html
        assert "<p>pages carry the shared" not in html
        assert "<p>so commands stay fully visible" not in html
