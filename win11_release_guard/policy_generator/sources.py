"""Fetching and loading Microsoft source documents."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from ..config import DEFAULT_HTTP_TIMEOUT_SECONDS
from ..exceptions import PolicyFetchError
from .. import http_client
from ..json_utils import DEFAULT_MAX_MICROSOFT_SOURCE_BYTES
from ..servicing_toc import ServicingTocEntry
from ..wu_offer_probe import WindowsUpdateOffer
from .constants import PROGRAMMING_ERROR_TYPES
from . import clock


@dataclass(frozen=True)
class SourceText:
    text: str
    status: Mapping[str, Any]


WindowsUpdateProbe = Callable[[], Sequence[WindowsUpdateOffer]]


@dataclass(frozen=True)
class AtomFeedEntry:
    title: str
    entry_id: str | None = None
    support_article_id: str | None = None
    diagnostic_id_hint: str | None = None
    link: str | None = None
    published: str | None = None
    updated: str | None = None
    content: str | None = None
    kb_article: str | None = None
    builds: tuple[str, ...] = ()
    preview: bool = False
    out_of_band: bool = False
    release: str | None = None


def fetch_url(
    url: str,
    *,
    timeout: float,
    max_bytes: int = DEFAULT_MAX_MICROSOFT_SOURCE_BYTES,
    final_url_validator: Callable[[str], str | None] | None = None,
    charset: str | None = None,
) -> str:
    result = http_client.request(
        url,
        headers={"Accept": "text/html,application/xhtml+xml,application/atom+xml,application/xml,text/xml"},
        timeout=timeout,
        max_bytes=max_bytes,
        label="Microsoft source response",
        final_url_validator=final_url_validator,
    )
    content_type = http_client.get_header(result.headers, "Content-Type")
    response_charset = charset or http_client.charset_from_content_type(content_type) or "utf-8"
    return result.content.decode(response_charset, errors="replace")


def load_source_text(
    *,
    url: str,
    fixture_path: str | Path | None = None,
    source_name: str,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    required: bool = True,
    charset: str | None = None,
    max_bytes: int = DEFAULT_MAX_MICROSOFT_SOURCE_BYTES,
) -> SourceText:
    if fixture_path is not None:
        path = Path(fixture_path)
        try:
            text = path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            if required:
                raise PolicyFetchError(f"{source_name} source failure: could not read {path}: {exc}") from exc
            return SourceText(
                text="",
                status={
                    "url": url,
                    "source": "fixture",
                    "path": str(path),
                    "status": "error",
                    "error": str(exc),
                    "fetched_at_utc": clock.utc_now(),
                },
            )
        return SourceText(
            text=text,
            status={
                "url": url,
                "source": "fixture",
                "path": str(path),
                "status": "ok",
                "bytes": len(text.encode("utf-8")),
                "fetched_at_utc": clock.utc_now(),
            },
        )

    try:
        text = fetch_url(url, timeout=timeout, charset=charset, max_bytes=max_bytes)
    except PROGRAMMING_ERROR_TYPES:
        raise
    except Exception as exc:
        if required:
            raise PolicyFetchError(f"{source_name} source failure: could not fetch {url}: {exc}") from exc
        return SourceText(
            text="",
            status={
                "url": url,
                "source": "network",
                "status": "error",
                "error": str(exc),
                "fetched_at_utc": clock.utc_now(),
            },
        )
    return SourceText(
        text=text,
        status={
            "url": url,
            "source": "network",
            "status": "ok",
            "bytes": len(text.encode("utf-8")),
            "fetched_at_utc": clock.utc_now(),
        },
    )


def _feed_entries_from_servicing_toc(
    entries: tuple[ServicingTocEntry, ...],
) -> tuple[AtomFeedEntry, ...]:
    return tuple(
        AtomFeedEntry(
            title=entry.title,
            link=entry.url,
            published=entry.published,
            updated=entry.published,
            kb_article=entry.kb_article,
            builds=entry.builds,
            preview=entry.preview,
            out_of_band=entry.out_of_band,
            release=entry.release,
        )
        for entry in entries
    )
