from __future__ import annotations

from pathlib import Path
import win11_release_guard.policy_generator as policy_generator_module
from tests.support.pages_landing_helpers import WIKI_SCALE_DECLARATION, WIKI_VISUAL_SCALE, _render_landing


def _assert_no_external_or_zoom_hacks(html: str) -> None:
    lower = html.lower()
    # No browser/CSS zoom or transform-scale tricks.
    assert "zoom:" not in lower
    assert "transform: scale" not in lower
    assert ".style.zoom" not in lower
    assert "initial-scale=1.25" not in lower
    assert "minimum-scale" not in lower
    assert "maximum-scale" not in lower
    # No external assets, fonts, CDNs, tokens, or runtime API calls.
    assert "script src" not in lower
    assert 'rel="stylesheet"' not in lower
    assert "@import" not in lower
    assert "fonts.googleapis" not in lower
    assert "fonts.gstatic" not in lower
    assert "cdnjs" not in lower
    assert "cdn.jsdelivr" not in lower
    assert "unpkg.com" not in lower
    assert "github_pat" not in lower
    assert "ghp_" not in lower
    assert "api.github.com" not in lower


def test_wiki_pages_use_dashboard_scale_tokens() -> None:
    pages = policy_generator_module.render_wiki_pages()
    home = pages["wiki/index.html"]
    subpages = [
        html
        for name, html in pages.items()
        if name != "wiki/index.html" and name.endswith("index.html")
    ]
    assert subpages, "expected at least one generated wiki subpage"
    # The shared responsive scale is a real CSS clamp, not a fixed desktop pixel size.
    assert "clamp(" in WIKI_VISUAL_SCALE
    assert WIKI_SCALE_DECLARATION in home
    for html in subpages:
        assert WIKI_SCALE_DECLARATION in html


def test_wiki_scale_does_not_use_browser_zoom_hacks() -> None:
    pages = {
        **policy_generator_module.render_wiki_pages(),
        **policy_generator_module.render_changelog_pages(),
    }
    assert pages
    for html in pages.values():
        _assert_no_external_or_zoom_hacks(html)
        # The scale is achieved with a real responsive root font size.
        assert WIKI_SCALE_DECLARATION in html


def test_wiki_scale_keeps_responsive_code_and_tables() -> None:
    home = policy_generator_module.render_wiki_pages()["wiki/index.html"]
    # Code blocks scroll, content wraps long words/URLs, tables scroll on narrow
    # screens, and the layout is responsive (not fixed desktop-only).
    assert "overflow: auto" in home
    assert "overflow-wrap: break-word" in home
    assert "overflow-x: auto" in home
    assert "@media (max-width: 860px)" in home
    assert "@media (max-width: 520px)" in home


def test_pages_dashboard_and_wiki_share_visual_scale_system(tmp_path: Path) -> None:
    dashboard = _render_landing(tmp_path)
    wiki = policy_generator_module.render_wiki_pages()["wiki/index.html"]
    # Same product visual language: shared Segoe UI font stack and responsive
    # clamp()-based type scale on both surfaces.
    for html in (dashboard, wiki):
        lower = html.lower()
        assert "segoe ui" in lower
        assert "arial" in lower
        assert "clamp(" in html
    # The wiki adopts an explicit responsive root font scale to reach the
    # dashboard's reading size at normal browser zoom; the dashboard itself is
    # not re-scaled by this token.
    assert WIKI_SCALE_DECLARATION in wiki
    assert WIKI_VISUAL_SCALE not in dashboard
    # No zoom hacks on either surface.
    _assert_no_external_or_zoom_hacks(wiki)


def test_wiki_prose_uses_available_horizontal_width() -> None:
    # Prose blocks use nearly the full content width (>=88% of the column) so they
    # look unified with the full-width tables and code blocks.
    pages = policy_generator_module.render_wiki_pages()
    for name in ("wiki/index.html", "wiki/Source-Diagnostics/index.html"):
        assert "max-width: max(74ch, 96%)" in pages[name]


def test_wiki_code_blocks_have_hover_copy_button() -> None:
    pages = {
        **policy_generator_module.render_wiki_pages(),
        **policy_generator_module.render_changelog_pages(),
    }
    home = pages["wiki/index.html"]
    # Half-transparent, hover/focus-revealed copy affordance on code blocks.
    assert ".wiki-copy-btn" in home
    assert ".wiki-content pre:hover .wiki-copy-btn" in home
    assert "opacity: 0;" in home  # hidden until hover/focus
    # Dependency-free copy: Clipboard API with a hidden-textarea fallback.
    assert 'document.querySelectorAll(".wiki-content pre")' in home
    assert "navigator.clipboard" in home
    assert 'document.execCommand("copy")' in home
    # Present on every generated wiki and changelog page, with no external assets.
    for html in pages.values():
        assert ".wiki-copy-btn" in html
        _assert_no_external_or_zoom_hacks(html)
