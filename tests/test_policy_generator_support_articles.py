from __future__ import annotations

import json
import pytest
from win11_release_guard.exceptions import PolicyFetchError
import urllib.request
import win11_release_guard.policy_generator as policy_generator_module
from win11_release_guard.policy_generator import support_articles as generator_support_articles
from tests.support.policy_generator_helpers import (
    KB5094126_SUPPORT_HTML,
    KB5094126_SUPPORT_URL,
    KB5101650_SERVICING_URL,
    _broad_target_25h2,
    _release_history_25h2,
    _support_article_html,
)


def test_unsafe_servicing_article_urls_are_rejected() -> None:
    assert policy_generator_module._safe_support_article_url(
        "https://evil.example/servicing/os/windows-11/2026/07/kb5101650"
    ) is None
    assert policy_generator_module._safe_support_article_url(
        "https://support.microsoft.com/en-us/search?query=KB5101650"
    ) is None
    assert policy_generator_module._safe_support_article_url(
        "https://support.microsoft.com/en-us/servicing/os/windows-11/../../secret"
    ) is None


def test_safe_servicing_article_url_is_accepted_and_canonicalized() -> None:
    url = (
        "https://support.microsoft.com/en-us/servicing/os/windows-11/"
        "2026/07/july-14-2026-kb5101650-os-builds-26200-8875-and-26100-8875"
    )

    assert policy_generator_module._safe_support_article_url(url) == url


@pytest.mark.parametrize(
    ("url", "expected"),
    (
        (
            f"{KB5094126_SUPPORT_URL}?utm_source=feed&ocid=tracking",
            KB5094126_SUPPORT_URL,
        ),
        (
            "https://support.microsoft.com:443/en-us/topic/kb5094126",
            "https://support.microsoft.com/en-us/topic/kb5094126",
        ),
        (
            "https://support.microsoft.com/en-us/topic/kb5094126#knownissues",
            "https://support.microsoft.com/en-us/topic/kb5094126",
        ),
        (
            "https://support.microsoft.com/en-us/topic/kb5094126?utm_source=feed&ocid=tracking#knownissues",
            "https://support.microsoft.com/en-us/topic/kb5094126",
        ),
        ("https://SUPPORT.MICROSOFT.COM/help/5094126?utm_source=feed", "https://support.microsoft.com/help/5094126"),
        ("https://support.microsoft.com/en-us/help/5094126", "https://support.microsoft.com/en-us/help/5094126"),
    ),
)
def test_safe_atom_support_article_url_accepts_articles_and_strips_queries(url: str, expected: str) -> None:
    assert policy_generator_module._safe_atom_support_article_url(url) == expected


@pytest.mark.parametrize(
    "url",
    (
        "https://evil.example/en-us/topic/kb5094126",
        "http://support.microsoft.com/en-us/topic/kb5094126",
        "https://user@support.microsoft.com/en-us/topic/kb5094126",
        "https://support.microsoft.com:444/en-us/topic/kb5094126",
        "https://support.microsoft.com:bad/en-us/topic/kb5094126",
        "https://support.microsoft.com/",
        "https://support.microsoft.com/en-us/feed/atom/example",
        "https://support.microsoft.com/en-us/api/article/5094126",
        "https://support.microsoft.com/en-us/search?query=KB5094126",
        "https://support.microsoft.com/en-us/download/5094126",
        "https://support.microsoft.com/en-us/assets/file.js",
        "https://support.microsoft.com/en-us/static/file.js",
        "https://support.microsoft.com/en-us/topic/../admin",
        "https://support.microsoft.com/en-us/topic/%2e%2e/admin",
        "https://support.microsoft.com/en-us/topic/kb%2f5094126",
        "https://support.microsoft.com/en-us/topic/kb%5c5094126",
        "https://support.microsoft.com/en-us/topic/" + ("a" * 1100),
    ),
)
def test_safe_atom_support_article_url_rejects_unsafe_sources(url: str) -> None:
    assert policy_generator_module._safe_atom_support_article_url(url) is None


def test_default_support_article_fetcher_rejects_redirect_to_non_support_host(monkeypatch: pytest.MonkeyPatch) -> None:
    class Headers:
        def get_content_charset(self) -> str:
            return "utf-8"

        def get(self, name: str) -> None:
            return None

    class Response:
        headers = Headers()

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def geturl(self) -> str:
            return "https://evil.example/en-us/topic/kb5094126"

        def read(self, size: int) -> bytes:
            return b"<html></html>"

    def fake_urlopen(request: object, timeout: float) -> Response:
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(PolicyFetchError, match="unsafe URL"):
        generator_support_articles.default_support_article_fetcher(KB5094126_SUPPORT_URL, 1.0, 1024)


def test_support_article_fact_extraction_for_kb5094126() -> None:
    facts = policy_generator_module._extract_support_article_facts(
        KB5094126_SUPPORT_URL,
        KB5094126_SUPPORT_HTML,
    )

    assert facts["title"] == "June 9, 2026-KB5094126 (OS Builds 26200.8655 and 26100.8655)"
    assert facts["kb_article"] == "KB5094126"
    assert facts["builds"] == ["26200.8655", "26100.8655"]
    assert facts["release_date"] == "June 9, 2026"
    assert facts["applies_to"] == "Windows 11, version 25H2; Windows 11, version 24H2"
    assert facts["known_issue_status"] == "not_currently_aware"
    assert facts["improvement_labels"] == [
        "Secure Boot",
        "Virtualization",
        "desktop.ini",
        "AI components",
    ]
    assert facts["improvement_details"] == [
        "Secure Boot: Updates hardening for startup components.",
        "Virtualization: Improves reliability for protected workloads.",
        "desktop.ini: Hardens desktop.ini processing.",
        "AI components: Updates Windows AI components.",
    ]
    assert all("Known issues" not in detail for detail in facts["improvement_details"])
    assert all("not currently aware" not in detail for detail in facts["improvement_details"])
    assert facts["is_security"] is True
    assert facts["security_evidence_source"] == "support_article"
    assert "includes the latest security fixes" in facts["security_signals"]
    assert "ignored" not in json.dumps(facts)


def test_support_article_applies_to_extraction_preserves_multi_release_and_server_values() -> None:
    multi_release = policy_generator_module._extract_support_article_facts(
        KB5094126_SUPPORT_URL,
        _support_article_html(
            applies_to="Windows 11, version 25H2; Windows 11, version 24H2",
            security=False,
        ),
    )
    server = policy_generator_module._extract_support_article_facts(
        KB5094126_SUPPORT_URL,
        _support_article_html(applies_to="Windows Server 2025", security=False),
    )

    assert multi_release["applies_to"] == "Windows 11, version 25H2; Windows 11, version 24H2"
    assert multi_release["applies_to_releases"] == ["25H2", "24H2"]
    assert server["applies_to"] == "Windows Server 2025"


def test_support_article_heading_list_applies_to_stops_before_following_sections() -> None:
    facts = policy_generator_module._extract_support_article_facts(
        KB5094126_SUPPORT_URL,
        """
        <html><head><title>June 9, 2026-KB5094126 (OS Build 26200.8655)</title></head><body>
          <main>
            <h1>June 9, 2026-KB5094126 (OS Build 26200.8655)</h1>
            <h2>Applies to</h2>
            <ul>
              <li>Windows 11, version 25H2</li>
              <li>Windows 11, version 24H2</li>
            </ul>
            <h2>Prerequisites</h2>
            <p>[Secure Boot] Enable the prerequisite before installing.</p>
            <h2>Highlights</h2>
            <p>This update improves reliability.</p>
          </main>
        </body></html>
        """,
    )

    assert facts["applies_to"] == "Windows 11, version 25H2; Windows 11, version 24H2"
    assert facts["applies_to_releases"] == ["25H2", "24H2"]
    assert "Prerequisites" not in facts["applies_to"]
    assert "Secure Boot" not in facts["applies_to"]


def test_support_article_heading_paragraph_applies_to_extraction() -> None:
    facts = policy_generator_module._extract_support_article_facts(
        KB5094126_SUPPORT_URL,
        """
        <html><head><title>June 9, 2026-KB5094126 (OS Build 26200.8655)</title></head><body>
          <main>
            <h1>June 9, 2026-KB5094126 (OS Build 26200.8655)</h1>
            <h2>Applies to</h2>
            <p>Windows 11, version 25H2</p>
            <h2>How to get this update</h2>
            <p>Install from Windows Update.</p>
          </main>
        </body></html>
        """,
    )

    assert facts["applies_to"] == "Windows 11, version 25H2"
    assert facts["applies_to_releases"] == ["25H2"]


@pytest.mark.parametrize(
    ("title", "bucket"),
    (
        ("June 2026 Safe OS Dynamic Update for Windows 11", "Safe OS Dynamic Update"),
        ("June 2026 Setup Dynamic Update for Windows 11", "Setup Dynamic Update"),
        ("Out of Box Experience Update for Windows 11", "OOBE Update"),
        ("Windows 11 Hotpatch update", "Hotpatch"),
        ("AI component update for Windows 11", "AI Component Update"),
        ("AI execution provider update for Windows 11", "AI Execution Provider Update"),
        ("Servicing Stack Update for Windows 11", "Servicing Stack Update"),
        ("June 2026 Preview (OS Build 26200.1)", "Preview OS Build Update"),
        ("June 2026 Out-of-band (OS Build 26200.1)", "Out-of-band OS Build Update"),
    ),
)
def test_atom_title_bucket_classification_is_low_confidence(title: str, bucket: str) -> None:
    classification = policy_generator_module._atom_title_bucket(title)

    assert classification == {"bucket": bucket, "confidence": "low"}


def test_generic_os_build_title_bucket_is_not_security() -> None:
    classification = policy_generator_module._atom_title_bucket(
        "June 9, 2026-KB5094126 (OS Builds 26200.8655 and 26100.8655)"
    )

    assert classification == {"bucket": "OS Build Update", "confidence": "low"}


def test_msrc_month_id_derives_from_atom_published_date() -> None:
    assert policy_generator_module._msrc_month_id_from_atom_date("2026-06-09T17:04:01Z") == "2026-Jun"
    assert policy_generator_module._msrc_month_id_from_atom_date("not a date") is None


def test_support_article_enrichment_propagates_programming_error_from_fetcher() -> None:
    # A bug in our own code (or a test double) must never be reclassified as a
    # degraded "source unavailable" record: it has to surface as itself.
    def raising_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        raise AssertionError("support fetch must not be attempted")

    with pytest.raises(AssertionError, match="support fetch must not be attempted"):
        policy_generator_module._support_article_enrichment(
            KB5094126_SUPPORT_URL,
            fetcher=raising_fetcher,
            timeout=1.0,
        )


def test_support_article_enrichment_still_degrades_genuine_fetch_failure() -> None:
    # A real source failure (network/IO) must still degrade to the existing
    # error-record shape, unchanged.
    def failing_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        raise PolicyFetchError("support unavailable")

    result = policy_generator_module._support_article_enrichment(
        KB5094126_SUPPORT_URL,
        fetcher=failing_fetcher,
        timeout=1.0,
    )

    assert result == {
        "url": KB5094126_SUPPORT_URL,
        "status": "error",
        "error": "support unavailable",
    }


SERVICING_HUB_URL = "https://support.microsoft.com/en-us/servicing/os/windows-11"


@pytest.mark.parametrize(
    ("url", "expected"),
    (
        (KB5101650_SERVICING_URL, KB5101650_SERVICING_URL),
        (f"{KB5101650_SERVICING_URL}?ocid=feed#knownissues", KB5101650_SERVICING_URL),
        (SERVICING_HUB_URL, SERVICING_HUB_URL),
        (f"{SERVICING_HUB_URL}/", f"{SERVICING_HUB_URL}/"),
    ),
)
def test_safe_support_article_url_accepts_servicing_article_paths(url: str, expected: str) -> None:
    assert policy_generator_module._safe_support_article_url(url) == expected


@pytest.mark.parametrize(
    "url",
    (
        "https://support.microsoft.com/en-us/servicing/../etc",
        "https://support.microsoft.com/en-us/api/servicing/os/windows-11/2026/07/july-14-2026-kb5101650",
        "https://evil.example/en-us/servicing/os/windows-11/2026/07/july-14-2026-kb5101650",
        "http://support.microsoft.com/en-us/servicing/os/windows-11/2026/07/july-14-2026-kb5101650",
        "https://support.microsoft.com:444/en-us/servicing/os/windows-11/2026/07/july-14-2026-kb5101650",
        "https://support.microsoft.com/en-us/servicing/os/windows-11/2026/07/" + ("a" * 1100),
        "https://support.microsoft.com/en-us/servicing/os/windows-11/2026/13/july-14-2026-kb5101650",
        "https://support.microsoft.com/en-us/servicing/os/windows-11/2026/07/kb%2f5101650",
    ),
)
def test_safe_support_article_url_rejects_unsafe_servicing_paths(url: str) -> None:
    assert policy_generator_module._safe_support_article_url(url) is None


def test_safe_atom_support_article_url_alias_is_the_renamed_helper() -> None:
    assert (
        policy_generator_module._safe_atom_support_article_url
        is policy_generator_module._safe_support_article_url
    )


def test_default_support_article_fetcher_follows_help_kb_redirect_to_servicing_article(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Headers:
        def get_content_charset(self) -> str:
            return "utf-8"

        def get(self, name: str) -> None:
            return None

    class Response:
        headers = Headers()

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def geturl(self) -> str:
            return KB5101650_SERVICING_URL

        def read(self, size: int) -> bytes:
            return b"<html><title>KB5101650</title></html>"

    def fake_urlopen(request: object, timeout: float) -> Response:
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    html = generator_support_articles.default_support_article_fetcher(
        "https://support.microsoft.com/help/5101650", 1.0, 4096
    )

    assert html == "<html><title>KB5101650</title></html>"


def test_release_history_enrichment_record_selects_the_newest_broad_target_b_row() -> None:
    record = policy_generator_module._release_history_enrichment_record(
        _broad_target_25h2(), _release_history_25h2()
    )

    assert record is not None
    assert record["kb_article"] == "KB5101650"
    assert record["build"] == "26200.8875"
    assert record["release"] == "25H2"
    assert record["build_family"] == 26200
    assert record["update_type_letter"] == "B"
    assert record["availability_date"] == "2026-07-14"
    assert record["release_history_record"] is True
    assert record["preview"] is False
    assert record["out_of_band"] is False
    assert record["support_url"] == KB5101650_SERVICING_URL
    assert record["atom_feed_url"] == KB5101650_SERVICING_URL
    assert record["msrc_cvrf_month_fallback"] == "2026-Jul"
    assert policy_generator_module._record_msrc_month_id(record) == "2026-Jul"
