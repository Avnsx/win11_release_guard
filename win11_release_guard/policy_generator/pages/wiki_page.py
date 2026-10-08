"""The wiki page shell, navigation, and page writer."""

from __future__ import annotations

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
    return """  <script>
    (function () {
      var sidebar = document.querySelector(".wiki-sidebar");
      var content = document.getElementById("wiki-content");
      if (!sidebar || !content) return;
      var currentPageLink = sidebar.querySelector('a.is-current-page[aria-current="page"]');
      var manualSidebarScrollUntil = 0;
      var autoScrollingSidebar = false;
      var allowSectionAutoAlign = false;
      var pendingSidebarNavigationHref = "";
      var sidebarNavigationStorageKey = "win11_release_guard.wikiSidebarScroll.v1";
      var prefersReducedMotion = false;
      try {
        prefersReducedMotion = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
      } catch (error) {
        prefersReducedMotion = false;
      }

      function now() {
        return Date.now ? Date.now() : new Date().getTime();
      }

      function normalizedUrl(value) {
        try {
          return new URL(value, window.location.href);
        } catch (error) {
          return null;
        }
      }

      function sameDocumentUrl(left, right) {
        return !!(
          left &&
          right &&
          left.origin === right.origin &&
          left.pathname === right.pathname &&
          left.search === right.search &&
          left.hash === right.hash
        );
      }

      function rememberSidebarScrollForHref(href) {
        var destination = normalizedUrl(href);
        if (!destination) return;
        try {
          if (!window.sessionStorage) return;
          window.sessionStorage.setItem(sidebarNavigationStorageKey, JSON.stringify({
            href: destination.href,
            scrollTop: Math.max(0, Math.round(sidebar.scrollTop || 0)),
            savedAt: now()
          }));
        } catch (error) {
          return;
        }
      }

      function restoreSidebarNavigationPosition() {
        try {
          if (!window.sessionStorage) return false;
          var raw = window.sessionStorage.getItem(sidebarNavigationStorageKey);
          if (!raw) return false;
          var state = JSON.parse(raw);
          if (!state || typeof state.href !== "string" || typeof state.scrollTop !== "number") return false;
          if (state.savedAt && now() - state.savedAt > 30000) return false;
          if (!sameDocumentUrl(normalizedUrl(state.href), normalizedUrl(window.location.href))) return false;
          autoScrollingSidebar = true;
          sidebar.scrollTop = Math.max(0, Math.round(state.scrollTop));
          window.setTimeout(function () {
            autoScrollingSidebar = false;
          }, 80);
          return true;
        } catch (error) {
          return false;
        }
      }

      function markManualSidebarScroll() {
        if (!autoScrollingSidebar) manualSidebarScrollUntil = now() + 1200;
      }

      sidebar.addEventListener("wheel", markManualSidebarScroll, { passive: true });
      sidebar.addEventListener("touchstart", markManualSidebarScroll, { passive: true });
      sidebar.addEventListener("keydown", markManualSidebarScroll);
      sidebar.addEventListener("scroll", markManualSidebarScroll, { passive: true });
      sidebar.addEventListener("click", function (event) {
        var link = event.target && event.target.closest ? event.target.closest("a[href]") : null;
        if (!link || !sidebar.contains(link) || event.defaultPrevented) return;
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        if ("button" in event && event.button !== 0) return;
        var href = link.getAttribute("href") || "";
        if (!href || href.charAt(0) === "#") return;
        pendingSidebarNavigationHref = href;
        rememberSidebarScrollForHref(href);
      });
      window.addEventListener("pagehide", function () {
        if (pendingSidebarNavigationHref) return;
        rememberSidebarScrollForHref(window.location.href);
      });
      var restoredSidebarNavigationPosition = restoreSidebarNavigationPosition();

      function sidebarAlignmentTargetForCurrentPage() {
        if (!currentPageLink) return null;
        var sourceNav = currentPageLink.closest ? currentPageLink.closest(".wiki-source-nav") : null;
        if (!sourceNav) return currentPageLink;
        return sourceNav.querySelector(".wiki-nav-group.is-current-group") || currentPageLink;
      }

      function sidebarTargetIsVisible(target) {
        var sidebarBox = sidebar.getBoundingClientRect();
        var targetBox = target.getBoundingClientRect();
        return targetBox.top >= sidebarBox.top + 8 && targetBox.bottom <= sidebarBox.bottom - 8;
      }

      function sidebarContentOffsetTop(target) {
        if (!sidebar.contains(target)) return 0;
        var sidebarBox = sidebar.getBoundingClientRect();
        var targetBox = target.getBoundingClientRect();
        return sidebar.scrollTop + targetBox.top - sidebarBox.top;
      }

      function sidebarScrollOffset() {
        return 10;
      }

      function alignSidebarTarget(target, force, behavior) {
        if (!target || !sidebar.contains(target)) return;
        if (!force && (now() < manualSidebarScrollUntil || sidebarTargetIsVisible(target))) return;
        var targetTop = sidebarContentOffsetTop(target) - sidebarScrollOffset();
        targetTop = Math.max(0, Math.round(targetTop));
        var scrollBehavior = behavior || (prefersReducedMotion ? "auto" : "smooth");
        autoScrollingSidebar = true;
        try {
          sidebar.scrollTo({ top: targetTop, behavior: scrollBehavior });
        } catch (error) {
          sidebar.scrollTop = targetTop;
        }
        window.setTimeout(function () {
          autoScrollingSidebar = false;
        }, scrollBehavior === "smooth" ? 360 : 80);
      }

      function initialSidebarAlignmentBehavior() {
        return restoredSidebarNavigationPosition && !prefersReducedMotion ? "smooth" : "auto";
      }

      function alignCurrentPageLink(behavior) {
        alignSidebarTarget(sidebarAlignmentTargetForCurrentPage(), true, behavior);
      }

      function isVersionMetaLink(link) {
        var node = link;
        while (node && node !== sidebar) {
          if (node.classList && node.classList.contains("version-meta")) return true;
          node = node.parentElement;
        }
        return false;
      }

      function samePageHash(link) {
        var href = link.getAttribute("href") || "";
        if (!href || isVersionMetaLink(link)) return "";
        if (href.charAt(0) === "#") return href;
        if (typeof URL === "undefined") return "";
        try {
          var url = new URL(href, window.location.href);
          if (url.origin !== window.location.origin || url.pathname !== window.location.pathname) return "";
          return url.hash || "";
        } catch (error) {
          return "";
        }
      }

      function hashId(hash) {
        try {
          return decodeURIComponent(hash.slice(1));
        } catch (error) {
          return hash.slice(1);
        }
      }

      var items = Array.prototype.slice.call(sidebar.querySelectorAll("a[href]")).map(function (link) {
        var hash = samePageHash(link);
        if (!hash || hash === "#") return null;
        var target = document.getElementById(hashId(hash));
        if (!target || !content.contains(target)) return null;
        return { link: link, item: link.closest ? link.closest("li") : null, target: target };
      }).filter(Boolean);
      if (!items.length) {
        alignCurrentPageLink(initialSidebarAlignmentBehavior());
        return;
      }

      function setActive(active, alignActive) {
        items.forEach(function (entry) {
          var selected = entry === active;
          entry.link.classList.toggle("is-active-section", selected);
          if (entry.item) entry.item.classList.toggle("is-active-section", selected);
          if (selected) {
            entry.link.setAttribute("aria-current", "location");
          } else {
            entry.link.removeAttribute("aria-current");
          }
        });
        if (alignActive && active) alignSidebarTarget(active.item || active.link, false);
      }

      function updateActiveSection(alignActive) {
        var activationLine = Math.min(window.innerHeight * 0.28, 180);
        var active = items[0];
        items.forEach(function (entry) {
          if (entry.target.getBoundingClientRect().top <= activationLine) active = entry;
        });
        if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) {
          active = items[items.length - 1];
        }
        setActive(active, alignActive);
        return active;
      }

      var requestFrame = window.requestAnimationFrame || function (callback) { return window.setTimeout(callback, 16); };
      var scheduled = false;
      function scheduleUpdate() {
        if (scheduled) return;
        scheduled = true;
        requestFrame(function () {
          scheduled = false;
          updateActiveSection(allowSectionAutoAlign);
        });
      }

      window.addEventListener("scroll", scheduleUpdate, { passive: true });
      window.addEventListener("resize", scheduleUpdate);
      window.addEventListener("hashchange", function () {
        allowSectionAutoAlign = true;
        scheduleUpdate();
      });
      if ("IntersectionObserver" in window) {
        var observer = new IntersectionObserver(scheduleUpdate, { rootMargin: "-18% 0px -70% 0px", threshold: [0, 1] });
        items.forEach(function (entry) { observer.observe(entry.target); });
      }
      var initialActive = updateActiveSection(false);
      if (window.location.hash && initialActive) {
        alignSidebarTarget(initialActive.item || initialActive.link, true, initialSidebarAlignmentBehavior());
      } else {
        alignCurrentPageLink(initialSidebarAlignmentBehavior());
      }
      window.setTimeout(function () {
        allowSectionAutoAlign = true;
      }, 300);
    })();
  </script>
"""

def _wiki_copy_button_script_html() -> str:
    """Client-side, dependency-free copy button for wiki/changelog code blocks.

    Adds a half-transparent button to every ``.wiki-content pre`` that copies the
    block's source text. The code text is captured before the button is appended,
    so the button label never leaks into the copied content. Uses the Clipboard
    API with a hidden-textarea fallback; no external scripts, fonts, or network
    calls. The button is revealed on hover/focus via CSS.
    """
    return """  <script>
    (function () {
      var blocks = document.querySelectorAll(".wiki-content pre");
      if (!blocks.length) return;
      function flash(btn, label, ok) {
        var original = btn.getAttribute("data-label") || "Copy";
        btn.textContent = label;
        btn.classList.toggle("is-copied", !!ok);
        window.setTimeout(function () {
          btn.textContent = original;
          btn.classList.remove("is-copied");
        }, 1400);
      }
      function copyText(text, btn) {
        function fallback() {
          try {
            var ta = document.createElement("textarea");
            ta.value = text;
            ta.setAttribute("readonly", "");
            ta.style.position = "absolute";
            ta.style.left = "-9999px";
            document.body.appendChild(ta);
            ta.select();
            var ok = document.execCommand("copy");
            document.body.removeChild(ta);
            flash(btn, ok ? "Copied" : "Copy failed", ok);
          } catch (e) {
            flash(btn, "Copy failed", false);
          }
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () {
            flash(btn, "Copied", true);
          }, fallback);
        } else {
          fallback();
        }
      }
      Array.prototype.forEach.call(blocks, function (pre) {
        if (pre.querySelector(".wiki-copy-btn")) return;
        var code = pre.querySelector("code");
        var text = code ? code.textContent : pre.textContent;
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "wiki-copy-btn";
        btn.textContent = "Copy";
        btn.setAttribute("data-label", "Copy");
        btn.setAttribute("aria-label", "Copy code to clipboard");
        btn.addEventListener("click", function () { copyText(text, btn); });
        pre.appendChild(btn);
      });
    })();
  </script>
"""

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
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(page_title)}</title>
  <link rel="icon" href="{WIKI_FAVICON_DATA_URL}">
{seo_meta}  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f9ff;
      --surface: #ffffff;
      --surface-soft: #eef6ff;
      --border: #c8ddf7;
      --text: #172033;
      --muted: #53657f;
      --brand: #0f6cbd;
      --brand-strong: #0b4f8a;
      --brand-soft: #e8f3ff;
      --brand-line: #9cccf6;
      --focus: #005fb8;
      --warn-bg: #fff7e6;
      --warn-border: #f2c36b;
      --shadow: 0 18px 45px rgba(15, 108, 189, 0.12);
    }}
    * {{ box-sizing: border-box; }}
    html {{
      scroll-behavior: smooth;
      /* Unify the wiki visual scale with the dashboard at normal browser zoom
         level using a real responsive root font size (not a browser or layout
         trick), so this rem-based theme scales proportionally and stays clean
         on small screens. */
      font-size: {_PAGES_WIKI_VISUAL_SCALE};
      /* Contain any stray horizontal overflow at the narrowest viewports.
         `clip` does not create a scroll container, so the sticky sidebar still
         pins to the viewport and wrappable nav/content is never hidden. */
      overflow-x: clip;
    }}
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: "Segoe UI", Arial, sans-serif;
      line-height: 1.55;
      color: var(--text);
      background:
        linear-gradient(180deg, rgba(232, 243, 255, 0.96), rgba(245, 249, 255, 1) 18rem),
        var(--bg);
    }}
    a {{ color: var(--brand); text-decoration-thickness: 0.08em; text-underline-offset: 0.18em; }}
    a:hover {{ color: var(--brand-strong); }}
    a:focus-visible, summary:focus-visible {{
      outline: 3px solid rgba(0, 95, 184, 0.34);
      outline-offset: 3px;
      border-radius: 4px;
    }}
    .skip-link {{
      position: absolute;
      left: 1rem;
      top: 0.75rem;
      z-index: 20;
      transform: translateY(-160%);
      border: 1px solid var(--brand-line);
      border-radius: 6px;
      background: #ffffff;
      box-shadow: var(--shadow);
      color: var(--brand-strong);
      font-weight: 700;
      padding: 0.6rem 0.85rem;
      text-decoration: none;
    }}
    .skip-link:focus {{ transform: translateY(0); }}
    .wiki-topbar {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 1rem clamp(1rem, 4vw, 3rem);
      background: rgba(255, 255, 255, 0.92);
      border-bottom: 1px solid var(--border);
      box-shadow: 0 8px 24px rgba(15, 108, 189, 0.08);
    }}
    .wiki-brand {{
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      color: var(--text);
      font-weight: 750;
      text-decoration: none;
    }}
    .wiki-brand-icon {{
      width: 1.18rem;
      height: 1.18rem;
      flex: 0 0 auto;
      filter: drop-shadow(0 5px 10px rgba(15, 108, 189, 0.18));
    }}
    .wiki-brand span {{ color: var(--brand); }}
    .wiki-topbar nav {{ display: flex; flex-wrap: wrap; gap: 0.55rem; font-size: 0.94rem; max-width: 100%; }}
    .wiki-topbar nav a {{
      display: inline-flex;
      align-items: center;
      min-height: 2rem;
      border: 1px solid transparent;
      border-radius: 999px;
      padding: 0.28rem 0.7rem;
      text-decoration: none;
      font-weight: 650;
    }}
    .wiki-topbar nav a:hover {{ border-color: var(--brand-line); background: var(--brand-soft); }}
    .wiki-layout {{
      display: grid;
      grid-template-columns: minmax(15rem, 20rem) minmax(0, 1fr);
      gap: clamp(1rem, 3vw, 2.5rem);
      /* Use the available horizontal space so the content column is wide enough
         for tables and code blocks instead of cramming them while wide gutters
         sit empty. Prose stays readable (paragraphs are capped at ~74ch below),
         while tables and pre blocks fill the wider column. */
      width: min(1880px, calc(100% - 2rem));
      margin: 1.6rem auto 3rem;
      align-items: start;
    }}
    .wiki-sidebar {{
      position: sticky;
      top: 1rem;
      display: grid;
      gap: 1rem;
      padding: 1rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      box-shadow: 0 12px 30px rgba(15, 108, 189, 0.08);
      max-height: calc(100vh - 2rem);
      overflow: auto;
      scrollbar-gutter: stable;
    }}
    .wiki-sidebar > nav {{
      display: grid;
      gap: 1.35rem;
      min-height: 0;
    }}
    .wiki-sidebar::after {{
      content: "";
      display: block;
      min-height: min(34rem, 58vh);
    }}
    .wiki-sidebar-header {{
      position: static;
      z-index: auto;
      display: grid;
      gap: 1rem;
      margin: 0;
      padding: 0 0 0.2rem;
      background: var(--surface);
      box-shadow: none;
      backdrop-filter: none;
      -webkit-backdrop-filter: none;
    }}
    .wiki-sidebar h1, .wiki-sidebar h2, .wiki-sidebar h3 {{
      margin: 0.35rem 0 0.2rem;
      font-size: 0.88rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0;
    }}
    .wiki-sidebar ul, .wiki-sidebar ol {{ margin: 0; padding-left: 1.2rem; }}
    .wiki-sidebar li {{ margin: 0.32rem 0; }}
    .wiki-sidebar a {{
      overflow-wrap: anywhere;
      transition: color 140ms ease, box-shadow 140ms ease, background-color 140ms ease;
    }}
    .wiki-sidebar a.is-active-section,
    .wiki-sidebar a.is-current-page {{
      display: inline-flex;
      align-items: center;
      max-width: 100%;
      border-radius: 6px;
      background: linear-gradient(90deg, rgba(15, 108, 189, 0.14), rgba(232, 243, 255, 0.52));
      box-shadow: inset 3px 0 0 var(--brand);
      color: var(--brand-strong);
      font-weight: 800;
      padding: 0.1rem 0.35rem;
      text-decoration: none;
    }}
    .wiki-sidebar li.is-active-section > a {{
      text-decoration: none;
    }}
    .wiki-primary-nav {{
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.9rem;
    }}
    .wiki-primary-nav ul {{ list-style: none; padding: 0; }}
    .wiki-sidebar .wiki-nav-changelog a {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) max-content;
      align-items: center;
      column-gap: 1.65rem;
      row-gap: 0.2rem;
      width: 100%;
      box-sizing: border-box;
      min-height: 2.35rem;
      border: 1px solid var(--brand-line);
      border-radius: 8px;
      background: linear-gradient(180deg, #ffffff, var(--brand-soft));
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.9);
      color: var(--brand-strong);
      font-weight: 750;
      padding: 0.45rem 0.7rem;
      text-decoration: none;
    }}
    .wiki-nav-changelog-label {{
      min-width: 0;
      color: var(--brand-strong);
      font-weight: 760;
      white-space: nowrap;
    }}
    .wiki-nav-changelog-meta {{
      justify-self: end;
      color: var(--muted);
      font-size: 0.78rem;
      font-weight: 600;
      white-space: nowrap;
    }}
    .wiki-source-nav {{
      display: grid;
      gap: 0.75rem;
      min-height: 0;
      padding-top: 1.15rem;
      border-top: 1px solid var(--border);
      background: var(--surface);
      backdrop-filter: none;
      -webkit-backdrop-filter: none;
    }}
    .wiki-source-nav > h1:first-child {{
      margin-top: 0;
    }}
    .wiki-source-nav .wiki-nav-group {{
      margin: 0.35rem 0 0.2rem;
      color: var(--text);
      font-weight: 760;
      letter-spacing: 0;
    }}
    .wiki-source-nav .wiki-nav-group strong {{ font-weight: inherit; }}
    .wiki-source-nav .wiki-nav-group.is-current-group {{
      color: var(--brand-strong);
      font-weight: 850;
    }}
    .wiki-toc ol {{ list-style: none; padding-left: 0; }}
    .wiki-toc a {{ text-decoration: none; }}
    .wiki-toc .toc-level-2 {{ padding-left: 0.6rem; }}
    .wiki-toc .toc-level-3, .wiki-toc .toc-level-4, .wiki-toc .toc-level-5, .wiki-toc .toc-level-6 {{
      padding-left: 1.2rem;
    }}
    .wiki-content {{
      min-width: 0;
      overflow-wrap: break-word;
      padding: clamp(1.25rem, 4vw, 2.25rem);
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }}
    .wiki-content:focus {{ outline: none; }}
    .wiki-breadcrumbs {{
      margin: 0 0 1.15rem;
      color: var(--muted);
      font-size: 0.92rem;
    }}
    .wiki-breadcrumbs ol {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      list-style: none;
      margin: 0;
      padding: 0;
    }}
    .wiki-breadcrumbs li {{ display: inline-flex; align-items: center; gap: 0.4rem; }}
    .wiki-breadcrumbs li + li::before {{ content: "/"; color: #8aa3bd; }}
    .wiki-breadcrumbs [aria-current="page"] {{ color: var(--text); font-weight: 650; }}
    .wiki-content h1, .wiki-content h2, .wiki-content h3 {{ line-height: 1.2; letter-spacing: 0; scroll-margin-top: 1rem; }}
    .wiki-content h1 {{ margin-top: 0; font-size: clamp(1.8rem, 3vw, 2.55rem); }}
    .wiki-heading-with-icon {{
      display: flex;
      align-items: flex-start;
      gap: 0.58rem;
      min-width: 0;
    }}
    .wiki-heading-text {{
      min-width: 0;
      overflow-wrap: anywhere;
    }}
    .wiki-heading-icon {{
      flex: 0 0 auto;
      width: 1.05em;
      height: 1.05em;
      margin-top: 0.04em;
      color: var(--brand);
      filter: drop-shadow(0 8px 14px rgba(15, 108, 189, 0.12));
    }}
    .wiki-content h1 .wiki-heading-icon {{
      width: 1.02em;
      height: 1.02em;
      margin-top: 0.02em;
    }}
    .wiki-content h2 .wiki-heading-icon {{
      width: 1em;
      height: 1em;
      margin-top: 0.03em;
    }}
    .wiki-heading-icon .wiki-icon-tile {{
      fill: #edf6ff;
      stroke: #b7dcff;
      stroke-width: 1;
    }}
    .wiki-heading-icon .wiki-icon-line {{
      fill: none;
      stroke: currentColor;
      stroke-width: 1.75;
      stroke-linecap: round;
      stroke-linejoin: round;
    }}
    .wiki-heading-icon .wiki-icon-fill {{
      fill: currentColor;
      stroke: none;
      opacity: 0.88;
    }}
    .wiki-content h2 {{
      margin-top: 3.25rem;
      margin-bottom: 1.2rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border);
    }}
    .wiki-content hr + h2 {{
      margin-top: 1.55rem;
      padding-top: 0;
      border-top: 0;
    }}
    .wiki-content h3 {{ margin-top: 2rem; margin-bottom: 0.85rem; color: #21395d; }}
    .wiki-content p, .wiki-content li {{ color: var(--text); }}
    .wiki-content p {{
      /* Let prose blocks use nearly the full content width so they look unified
         with the full-width tables and code blocks (at least ~88% of the column),
         instead of sitting in a narrow measure with empty space beside them.
         Narrower columns fall back to the readable ~74ch measure. */
      max-width: max(74ch, 96%);
      margin-top: 0;
      margin-bottom: 1.55rem;
    }}
    .wiki-content p + p:not(.wiki-image-block) {{ margin-top: 0.2rem; }}
    .wiki-content .wiki-image-block {{
      max-width: none;
      margin: 1.15rem 0 0.8rem;
    }}
    .wiki-content .wiki-image-block + p {{
      margin-top: 0;
      margin-bottom: 1.65rem;
    }}
    .wiki-content .wiki-image-block + hr {{
      margin-top: 1.05rem;
      margin-bottom: 1.25rem;
    }}
    .wiki-content ul, .wiki-content ol {{
      margin-top: 0.6rem;
      margin-bottom: 1.8rem;
    }}
    .wiki-content li + li {{ margin-top: 0.45rem; }}
    .wiki-content hr {{
      margin: 2rem 0 2.35rem;
      border: 0;
      border-top: 1px solid var(--border);
    }}
    .wiki-content code {{
      padding: 0.1rem 0.28rem;
      background: var(--surface-soft);
      border-radius: 4px;
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 0.92em;
    }}
    .wiki-content pre {{
      /* Show commands in full. The content column is wide, but some shell
         commands are longer than any viewport, so wrap at argument/whitespace
         boundaries (and break pathological unbreakable tokens) instead of
         clipping behind a horizontal scrollbar. Explicit line breaks are kept. */
      position: relative;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      overflow-x: auto;
      padding: 1rem;
      background: #0b1f33;
      color: #eaf4ff;
      border-radius: 8px;
    }}
    .wiki-content pre code {{ padding: 0; background: transparent; color: inherit; white-space: inherit; }}
    /* Half-transparent copy button revealed on hover/focus of a code block.
       Injected client-side; no external scripts, fonts, or network calls. */
    .wiki-copy-btn {{
      position: absolute;
      top: 0.5rem;
      right: 0.5rem;
      display: inline-flex;
      align-items: center;
      gap: 0.3rem;
      font: inherit;
      font-size: 0.78rem;
      line-height: 1;
      padding: 0.35rem 0.6rem;
      color: #eaf4ff;
      background: rgba(255, 255, 255, 0.14);
      border: 1px solid rgba(255, 255, 255, 0.26);
      border-radius: 6px;
      cursor: pointer;
      opacity: 0;
      transition: opacity 0.15s ease, background 0.15s ease, border-color 0.15s ease;
    }}
    .wiki-content pre:hover .wiki-copy-btn,
    .wiki-content pre:focus-within .wiki-copy-btn,
    .wiki-copy-btn:focus-visible {{ opacity: 1; }}
    .wiki-copy-btn:hover {{ background: rgba(255, 255, 255, 0.26); }}
    .wiki-copy-btn.is-copied {{
      background: rgba(120, 220, 150, 0.28);
      border-color: rgba(120, 220, 150, 0.55);
    }}
    @media (hover: none) {{ .wiki-copy-btn {{ opacity: 0.6; }} }}
    .wiki-content table {{
      width: 100%;
      border-collapse: collapse;
      margin: 1.35rem 0 2.25rem;
      font-size: 0.95rem;
      box-shadow: 0 1px 0 rgba(15, 108, 189, 0.06);
    }}
    .wiki-content th, .wiki-content td {{ padding: 0.65rem 0.75rem; border: 1px solid var(--border); text-align: left; }}
    .wiki-content th {{ background: var(--surface-soft); }}
    .wiki-content img {{ max-width: 100%; height: auto; border-radius: 8px; border: 1px solid var(--border); }}
    .broken-link {{
      color: #8a4b00;
      background: var(--warn-bg);
      border-bottom: 1px dotted #8a4b00;
    }}
    .wiki-broken-links {{
      margin-top: 2rem;
      padding: 1rem;
      background: var(--warn-bg);
      border: 1px solid var(--warn-border);
      border-radius: 8px;
    }}
    .wiki-render-warnings {{
      margin: 1.2rem 0;
      padding: 1rem;
      background: var(--warn-bg);
      border: 1px solid var(--warn-border);
      border-radius: 8px;
    }}
    .wiki-render-warnings h2, .wiki-broken-links h2 {{ margin-top: 0; color: #8a4b00; }}
    .changelog-version-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.55rem;
      margin: -0.25rem 0 1.9rem 1.05rem;
    }}
    .changelog-version-actions a, .changelog-version-nav .version-meta a {{
      display: inline-flex;
      align-items: center;
      min-height: 1.8rem;
      padding: 0.18rem 0.5rem;
      border: 1px solid var(--border);
      border-radius: 999px;
      background: var(--surface-soft);
      font-size: 0.86rem;
      font-weight: 600;
      text-decoration: none;
      white-space: nowrap;
    }}
    .changelog-version-actions a.changelog-pre-release-badge,
    .changelog-version-nav .version-meta a.changelog-pre-release-badge {{
      border-color: #f0c74c;
      background: linear-gradient(180deg, #fff8db, #ffefad);
      color: #7a4c00;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.82);
    }}
    .changelog-content h2[id] {{
      margin-top: 4.75rem;
      margin-bottom: 1.25rem;
      border: 1px solid var(--border);
      border-left: 4px solid var(--brand);
      border-radius: 8px;
      background: linear-gradient(180deg, #ffffff, #f7fbff);
      box-shadow: 0 8px 22px rgba(15, 108, 189, 0.07);
      padding: 0.85rem 1rem;
    }}
    .changelog-content h2[id]:first-of-type {{
      margin-top: 2.35rem;
    }}
    .changelog-content h2[id] + .changelog-version-actions + h3 {{
      margin-top: 1.55rem;
    }}
    .changelog-version-nav .version-meta {{
      display: flex;
      flex-wrap: wrap;
      align-items: flex-start;
      gap: 0.28rem;
      margin: 0.3rem 0 0 0.65rem;
    }}
    .changelog-version-nav .version-meta a {{
      min-height: 1.42rem;
      padding: 0.08rem 0.4rem;
      font-size: 0.76rem;
      line-height: 1.08;
    }}
    .changelog-version-nav ol {{
      display: grid;
      gap: 1.18rem;
    }}
    .wiki-footer {{
      width: min(1220px, calc(100% - 2rem));
      margin: 0 auto 2rem;
      color: var(--muted);
      font-size: 0.94rem;
    }}
    @media (prefers-reduced-motion: reduce) {{
      html {{ scroll-behavior: auto; }}
      *, *::before, *::after {{
        animation-duration: 0.001ms !important;
        animation-iteration-count: 1 !important;
        scroll-behavior: auto !important;
        transition-duration: 0.001ms !important;
      }}
    }}
    @media (max-width: 860px) {{
      .wiki-layout {{ grid-template-columns: 1fr; margin-top: 1rem; }}
      .wiki-sidebar {{ position: static; max-height: none; overflow: visible; }}
      .wiki-sidebar > nav {{ max-height: none; }}
      .wiki-sidebar::after {{ display: none; }}
      .wiki-sidebar-header {{ margin: 0; padding: 0; }}
      .wiki-source-nav {{ padding-top: 0.95rem; }}
      .wiki-topbar {{ align-items: flex-start; flex-direction: column; }}
      .wiki-sidebar .wiki-nav-changelog a {{ grid-template-columns: 1fr; justify-items: start; row-gap: 0.25rem; }}
      .wiki-nav-changelog-meta {{ justify-self: start; }}
      .wiki-content table {{ display: block; overflow-x: auto; }}
    }}
    @media (max-width: 520px) {{
      .wiki-layout {{ width: min(100% - 1rem, 1220px); }}
      .wiki-content, .wiki-sidebar {{ padding: 0.9rem; }}
      .wiki-content h2 {{ margin-top: 2.55rem; margin-bottom: 0.95rem; padding-top: 0.8rem; }}
      .wiki-heading-with-icon {{ gap: 0.45rem; }}
      .wiki-content hr + h2 {{ margin-top: 1.45rem; }}
      .wiki-content p {{ margin-bottom: 1.35rem; }}
      .wiki-content .wiki-image-block {{ margin: 1rem 0 0.7rem; }}
      .wiki-content table {{ margin-bottom: 1.65rem; }}
      .changelog-content h2[id] {{ margin-top: 3.55rem; margin-bottom: 1.05rem; }}
      .changelog-content h2[id]:first-of-type {{ margin-top: 2rem; }}
      .changelog-version-actions {{ margin: -0.15rem 0 1.55rem 0.8rem; }}
      .changelog-version-nav .version-meta a {{ font-size: 0.74rem; min-height: 1.36rem; }}
      .changelog-version-nav ol {{ gap: 1.05rem; }}
      .wiki-topbar {{ padding: 0.85rem 0.75rem; }}
      .wiki-topbar nav a {{ padding-inline: 0.55rem; }}
    }}
  </style>
</head>
<body>
  <a class="skip-link" href="#wiki-content">Skip to content</a>
  <header class="wiki-topbar">
    <a class="wiki-brand" href="{escape(dashboard_url)}">{_site_brand_icon_html("wiki-brand-icon")}<span>Windows 11</span> Release Guard</a>
    <nav aria-label="Site">
      <a href="{escape(dashboard_url)}">Dashboard</a>
      <a href="{escape(wiki_url)}">Wiki</a>
      <a href="{escape(_changelog_pages_base_url(base_url=base_url))}">Changelog</a>
      <a href="{escape(GITHUB_REPOSITORY_URL)}">Repository</a>
    </nav>
  </header>
  <main class="wiki-layout">
    <aside class="wiki-sidebar" aria-label="Wiki navigation" data-section-scrollspy="true">
      <nav aria-label="Wiki pages">{navigation_html}</nav>
    </aside>
    <article id="wiki-content" class="{content_class}" tabindex="-1">
      {breadcrumbs_html}
      {warning_html}
      {body_html}
      {broken_html}
    </article>
  </main>
  <footer class="wiki-footer">{footer_html}</footer>
{scrollspy_script}{copy_button_script}</body>
</html>
"""

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
