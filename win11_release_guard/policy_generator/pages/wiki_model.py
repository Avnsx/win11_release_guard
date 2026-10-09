"""Data types for wiki and changelog pages."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WikiHeading:
    level: int
    text: str
    slug: str


@dataclass(frozen=True)
class WikiPageSource:
    path: Path
    title: str
    slug: str
    lookup_keys: tuple[str, ...]


@dataclass(frozen=True)
class RenderedWikiPage:
    source: WikiPageSource
    html: str
    headings: tuple[WikiHeading, ...]
    broken_links: tuple[str, ...]


@dataclass(frozen=True)
class ChangelogSection:
    title: str
    slug: str
    markdown: str
    version: str | None = None
    release_href: str | None = None
