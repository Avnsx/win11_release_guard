"""Discovering wiki Markdown sources and Pages URLs."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Mapping, Sequence
from ...config import DEFAULT_PAGES_BASE_URL
from ..constants import (
    PYPI_DOWNLOAD_IMAGE_PATH,
    WIKI_HELPER_PAGE_NAMES,
    WIKI_SOURCE_DIR,
    _MARKDOWN_HEADING_RE,
)
from .wiki_model import WikiPageSource


def _wiki_page_url_slug(stem: str) -> str:
    slug = re.sub(r"\s+", "-", stem.strip())
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", slug)
    slug = re.sub(r"-{2,}", "-", slug).strip("-")
    return slug or "page"


def _wiki_lookup_key(value: str) -> str:
    normalized = value.strip()
    if normalized.lower().endswith(".md"):
        normalized = normalized[:-3]
    normalized = normalized.replace("_", "-")
    normalized = re.sub(r"\s+", "-", normalized)
    normalized = re.sub(r"-{2,}", "-", normalized)
    return normalized.strip("-").casefold()


def _wiki_first_heading(text: str) -> str | None:
    for line in text.splitlines():
        match = _MARKDOWN_HEADING_RE.match(line)
        if match:
            return _plain_wiki_inline_text(match.group(2)).strip() or None
    return None


def _wiki_title_from_path(path: Path, text: str) -> str:
    heading = _wiki_first_heading(text)
    if heading:
        return heading
    if path.stem.casefold() == "home":
        return "Home"
    return path.stem.replace("-", " ").replace("_", " ").strip() or path.stem


def _plain_wiki_inline_text(text: str) -> str:
    text = re.sub(r"!\[([^\]\n]*)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"\[([^\]\n]+)\]\([^)]+\)", r"\1", text)

    def replace_wiki_link(match: re.Match[str]) -> str:
        value = match.group(1)
        if "|" in value:
            label, _target = value.split("|", 1)
            return label.strip()
        return value.strip()

    text = re.sub(r"\[\[([^\]\n]+)\]\]", replace_wiki_link, text)
    text = text.replace("**", "").replace("__", "").replace("`", "")
    return text


def _heading_slug_base(text: str) -> str:
    normalized = _plain_wiki_inline_text(text).casefold()
    normalized = re.sub(r"[^a-z0-9]+", "-", normalized)
    normalized = normalized.strip("-")
    return normalized or "section"


def _unique_heading_slug(text: str, used_slugs: dict[str, int]) -> str:
    base = _heading_slug_base(text)
    count = used_slugs.get(base, 0) + 1
    used_slugs[base] = count
    if count == 1:
        return base
    return f"{base}-{count}"


def _unique_slug(base: str, used_slugs: dict[str, int]) -> str:
    clean_base = base.strip() or "section"
    count = used_slugs.get(clean_base, 0) + 1
    used_slugs[clean_base] = count
    if count == 1:
        return clean_base
    return f"{clean_base}-{count}"


def _wiki_home_source(wiki_dir: Path) -> WikiPageSource:
    title = "Home"
    slug = _wiki_page_url_slug(title)
    lookup_keys = tuple(dict.fromkeys((_wiki_lookup_key(title), _wiki_lookup_key(slug))))
    return WikiPageSource(path=wiki_dir / "Home.md", title=title, slug=slug, lookup_keys=lookup_keys)


def _fallback_wiki_home_markdown(message: str) -> str:
    return "\n".join(("# Home", "", message, ""))


def _wiki_dir_display_name(source_dir: Path) -> str:
    if source_dir.is_absolute():
        return source_dir.name or "wiki"
    return source_dir.as_posix()


def _wiki_source_display_name(path: Path) -> str:
    if path.is_absolute():
        return path.name
    return path.as_posix()


def _is_wiki_helper_page(path: Path) -> bool:
    return path.name.casefold() in WIKI_HELPER_PAGE_NAMES


def _wiki_helper_text(texts: Mapping[Path, str], helper_name: str) -> str | None:
    normalized = helper_name.casefold()
    for path, text in texts.items():
        if path.name.casefold() == normalized:
            return text
    return None


def _read_markdown_source(path: Path) -> str:
    """Read repo-controlled Markdown without aborting generation on invalid bytes.

    Valid UTF-8 is returned unchanged so normal Markdown rendering and link
    generation are unaffected. Undecodable bytes degrade deterministically to the
    Unicode replacement character instead of raising ``UnicodeDecodeError``, so a
    single malformed wiki/changelog source cannot crash the whole Pages generator;
    the replacement characters keep the problem visible in generated output.
    """
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_bytes().decode("utf-8", errors="replace")


def _discover_wiki_sources(wiki_dir: str | Path = WIKI_SOURCE_DIR) -> tuple[tuple[WikiPageSource, ...], dict[Path, str]]:
    source_dir = Path(wiki_dir)
    if not source_dir.exists():
        return (), {}
    texts: dict[Path, str] = {}
    sources: list[WikiPageSource] = []
    for path in sorted(source_dir.glob("*.md"), key=lambda item: item.name.casefold()):
        if not path.is_file():
            continue
        text = _read_markdown_source(path)
        texts[path] = text
        if _is_wiki_helper_page(path):
            continue
        title = _wiki_title_from_path(path, text)
        slug = _wiki_page_url_slug(path.stem)
        lookup_keys = tuple(
            dict.fromkeys(
                (
                    _wiki_lookup_key(path.stem),
                    _wiki_lookup_key(slug),
                    _wiki_lookup_key(title),
                    _wiki_lookup_key(path.stem.replace("-", " ")),
                    _wiki_lookup_key(path.stem.replace("_", " ")),
                )
            )
        )
        sources.append(WikiPageSource(path=path, title=title, slug=slug, lookup_keys=lookup_keys))
    return tuple(sources), texts


def _prepare_wiki_sources(
    wiki_dir: str | Path = WIKI_SOURCE_DIR,
) -> tuple[tuple[WikiPageSource, ...], dict[Path, str], tuple[str, ...]]:
    source_dir = Path(wiki_dir)
    source_dir_label = _wiki_dir_display_name(source_dir)
    sources, texts = _discover_wiki_sources(source_dir)
    warnings: list[str] = []
    if not source_dir.exists():
        fallback_source = _wiki_home_source(source_dir)
        warnings.append(f"{source_dir_label} is missing; generated a fallback Wiki index page.")
        texts[fallback_source.path] = _fallback_wiki_home_markdown(
            f"The source directory `{source_dir_label}` is missing. Add `wiki/Home.md` and related Markdown "
            "sources to publish a full Pages Wiki."
        )
        return (fallback_source,), texts, tuple(warnings)
    if not sources:
        fallback_source = _wiki_home_source(source_dir)
        warnings.append(f"{source_dir_label} contains no Markdown sources; generated a fallback Wiki index page.")
        texts[fallback_source.path] = _fallback_wiki_home_markdown(
            f"The source directory `{source_dir_label}` contains no Markdown files. Add `wiki/Home.md` "
            "to publish a full Pages Wiki."
        )
        return (fallback_source,), texts, tuple(warnings)
    if not any(source.path.stem.casefold() == "home" for source in sources):
        fallback_source = _wiki_home_source(source_dir)
        warnings.append("wiki/Home.md is missing; generated a fallback Wiki index page from discovered sources.")
        texts[fallback_source.path] = _fallback_wiki_home_markdown(
            "`wiki/Home.md` is missing. This fallback index keeps the Pages Wiki reachable while the source "
            "Markdown is repaired."
        )
        sources = (fallback_source, *sources)
    return sources, texts, tuple(warnings)


def _wiki_page_map(sources: Sequence[WikiPageSource]) -> dict[str, WikiPageSource]:
    pages: dict[str, WikiPageSource] = {}
    for source in sources:
        for key in source.lookup_keys:
            pages.setdefault(key, source)
    return pages


def _wiki_output_relative_path(source: WikiPageSource) -> Path:
    if source.path.stem.casefold() == "home":
        return Path("wiki") / "index.html"
    return Path("wiki") / source.slug / "index.html"


def _pages_wiki_url(*, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    return f"{base_url.rstrip('/')}/wiki/"


def _pages_root_url(*, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    return f"{base_url.rstrip('/')}/"


def _pypi_download_image_url(*, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    _ = base_url
    return PYPI_DOWNLOAD_IMAGE_PATH.as_posix()


def _wiki_page_href(source: WikiPageSource, *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    wiki_base = _pages_wiki_url(base_url=base_url)
    if source.path.stem.casefold() == "home":
        return wiki_base
    return f"{wiki_base}{source.slug}/"


def _resolve_wiki_target(
    target: str,
    pages: Mapping[str, WikiPageSource],
    *,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> tuple[str | None, str | None]:
    page_name, separator, fragment = target.strip().partition("#")
    if not page_name and separator:
        return f"#{_heading_slug_base(fragment)}", None
    page = pages.get(_wiki_lookup_key(page_name))
    if not page:
        return None, page_name.strip() or target.strip()
    href = _wiki_page_href(page, base_url=base_url)
    if fragment:
        href = f"{href}#{_heading_slug_base(fragment)}"
    return href, None


def _changelog_pages_base_url(*, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    return f"{base_url.rstrip('/')}/wiki/changelog/"
