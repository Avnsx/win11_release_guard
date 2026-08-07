from __future__ import annotations

import json
from pathlib import Path

import pytest

from win11_release_guard.exceptions import PolicyParseError
from win11_release_guard.servicing_toc import (
    SERVICING_ARTICLE_BASE,
    SERVICING_TOC_URL,
    ServicingTocEntry,
    parse_servicing_toc,
)

FIXTURES = Path("tests/fixtures")
KB5101650_URL = (
    "https://support.microsoft.com/en-us/servicing/os/windows-11/"
    "2026/07/july-14-2026-kb5101650-os-builds-26200-8875-and-26100-8875"
)


def _july_toc_text() -> str:
    return (FIXTURES / "windows11-servicing-toc-july-2026.json").read_text(encoding="utf-8")


def _entry(entries: tuple[ServicingTocEntry, ...], kb_article: str, release: str) -> ServicingTocEntry:
    return next(
        entry for entry in entries if entry.kb_article == kb_article and entry.release == release
    )


def test_servicing_toc_constants_point_at_the_public_windows11_index() -> None:
    assert SERVICING_TOC_URL == "https://support.microsoft.com/en-us/servicing/os/windows-11/toc.json"
    assert SERVICING_ARTICLE_BASE == "https://support.microsoft.com/en-us/servicing/os/windows-11/"


def test_parse_servicing_toc_reads_builds_release_url_and_published_date() -> None:
    entry = _entry(parse_servicing_toc(_july_toc_text()), "KB5101650", "25H2")

    assert isinstance(entry, ServicingTocEntry)
    assert entry.builds == ("26200.8875", "26100.8875")
    assert entry.release == "25H2"
    assert entry.preview is False
    assert entry.out_of_band is False
    assert entry.published == "2026-07-14"
    assert entry.href == "2026/07/july-14-2026-kb5101650-os-builds-26200-8875-and-26100-8875"
    assert entry.url == KB5101650_URL
    assert entry.title.count("—") == 1


def test_parse_servicing_toc_flags_preview_and_out_of_band_titles() -> None:
    entries = parse_servicing_toc(_july_toc_text())
    preview = _entry(entries, "KB5101684", "25H2")
    out_of_band = _entry(entries, "KB5121767", "25H2")

    assert (preview.preview, preview.out_of_band) == (True, False)
    assert (out_of_band.out_of_band, out_of_band.preview) == (True, False)
    assert preview.builds == ("26200.8973", "26100.8973")
    assert out_of_band.builds == ("26200.8894",)
    assert preview.published == "2026-07-28"
    assert out_of_band.published == "2026-07-18"


def test_parse_servicing_toc_keeps_one_entry_per_lane_for_shared_articles() -> None:
    entries = parse_servicing_toc(_july_toc_text())

    assert sorted(entry.release for entry in entries if entry.kb_article == "KB5101650") == [
        "24H2",
        "25H2",
    ]


def test_parse_servicing_toc_skips_lane_parents_and_hrefless_nodes() -> None:
    entries = parse_servicing_toc(_july_toc_text())

    assert len(entries) == 7
    assert all(entry.href for entry in entries)
    assert all(entry.kb_article for entry in entries)
    assert not any(entry.title.startswith("Windows 11, version ") for entry in entries)


def test_parse_servicing_toc_accepts_a_parsed_mapping() -> None:
    assert parse_servicing_toc(json.loads(_july_toc_text())) == parse_servicing_toc(_july_toc_text())


def test_parse_servicing_toc_raises_policy_parse_error_on_malformed_json() -> None:
    with pytest.raises(PolicyParseError, match="Servicing TOC is malformed"):
        parse_servicing_toc('{"items": [')


def test_parse_servicing_toc_rejects_a_non_object_document() -> None:
    with pytest.raises(PolicyParseError, match="Servicing TOC is malformed"):
        parse_servicing_toc("[]")


def test_parse_servicing_toc_returns_empty_for_blank_payload() -> None:
    assert parse_servicing_toc("   ") == ()


def test_parse_servicing_toc_strips_a_utf8_bom_and_refuses_absolute_hrefs() -> None:
    payload = {
        "items": [
            {
                "toc_title": "Windows 11, version 25H2",
                "children": [
                    {
                        "href": "https://evil.example/2026/07/kb5101650",
                        "toc_title": "July 14, 2026—KB5101650 (OS Build 26200.8875)",
                    },
                    {
                        "href": "../../../etc/passwd",
                        "toc_title": "July 14, 2026—KB5101651 (OS Build 26200.8876)",
                    },
                ],
            }
        ]
    }
    entries = parse_servicing_toc("﻿" + json.dumps(payload))

    assert len(entries) == 2
    assert all(entry.url is None for entry in entries)
    assert entries[0].href == "https://evil.example/2026/07/kb5101650"


def test_servicing_entry_date_falls_back_to_the_href_month() -> None:
    payload = {
        "items": [
            {
                "toc_title": "Windows 11, version 25H2",
                "children": [
                    {
                        "href": "2026/07/kb5121767-out-of-band",
                        "toc_title": "KB5121767 (OS Build 26200.8894) Out-of-band",
                    },
                    {
                        "href": "kb5121768-undated",
                        "toc_title": "KB5121768 (OS Build 26200.8895)",
                    },
                ],
            }
        ]
    }
    entries = parse_servicing_toc(payload)

    assert entries[0].published == "2026-07-01"
    assert entries[1].published is None


def test_live_capture_parses_every_lane_and_carries_dates() -> None:
    entries = parse_servicing_toc(
        (FIXTURES / "windows11-servicing-toc-live-sample.json").read_text(encoding="utf-8")
    )

    assert {entry.release for entry in entries} == {"26H1", "25H2", "24H2", "23H2", "22H2", "21H2"}
    assert len(entries) >= 250
    assert all(entry.kb_article and entry.url and entry.published for entry in entries)
    assert _entry(entries, "KB5101650", "25H2").builds == ("26200.8875", "26100.8875")
    assert _entry(entries, "KB5101650", "25H2").published == "2026-07-14"
