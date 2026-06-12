from __future__ import annotations

import json
import hashlib
import re
from dataclasses import replace
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

import pytest

from tools import generate_policy as generate_policy_cli
from win11_release_guard.config import (
    DEFAULT_POLICY_STRICT_STALE_AGE_SECONDS,
    DEFAULT_POLICY_URL,
    DEFAULT_POLICY_WARNING_AGE_SECONDS,
    DEFAULT_PUBLISHED_POLICY_URLS,
    DEFAULT_RELEASE_HEALTH_URL,
)
from win11_release_guard.exceptions import PolicyFetchError, PolicyParseError
from win11_release_guard.freshness import epoch_milliseconds_from_iso
from win11_release_guard.models import QualityPolicy, ReleasePolicy, ReleasePolicyEntry
import win11_release_guard.policy_generator as policy_generator_module
from win11_release_guard.policy_generator import (
    SOURCE_DIAGNOSTIC_ID_PREFIX,
    _source_label,
    _source_diagnostic_id,
    build_policy_from_sources,
    generate_policy,
    parse_atom_feed,
    render_changelog_pages,
    render_robots_txt,
    write_policy_outputs,
)
from win11_release_guard.remote_policy import load_policy_text
from win11_release_guard.policy_schema import GENERATOR_VERSION, is_source_diagnostic_id, validate_policy_document


FIXTURES = Path("tests/fixtures")
EXPECTED_ROBOTS_TXT = (
    "User-agent: *\n"
    "Allow: /\n"
    "Sitemap: https://avnsx.github.io/win11_release_guard/sitemap.xml\n"
)
REMOVED_SCHEMA_PANEL_LABELS = (
    "API " + "and schema",
    "Policy " + "schema",
    "Reader " + "range",
)
ATOM_SOURCE_DIAGNOSTIC_ID = "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480"
ATOM_ENTRY_ID = "uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480"
ATOM_SUPPORT_ARTICLE_ID = "968480"
KB5094126_SUPPORT_URL = (
    "https://support.microsoft.com/en-us/topic/"
    "june-9-2026-kb5094126-os-builds-26200-8655-and-26100-8655-1a9bcba6-5f53-4075-8156-fe11ac631737"
)
KB5094126_SUPPORT_HTML = """
<!doctype html>
<html>
  <head>
    <title>June 9, 2026-KB5094126 (OS Builds 26200.8655 and 26100.8655) - Microsoft Support</title>
    <script>window.secret = "ignored";</script>
    <style>.ignored{display:none}</style>
  </head>
  <body>
    <main>
      <h1>June 9, 2026-KB5094126 (OS Builds 26200.8655 and 26100.8655)</h1>
      <p>Applies to: Windows 11, version 25H2; Windows 11, version 24H2</p>
      <h2>Highlights</h2>
      <ul>
        <li>[Secure Boot] Updates hardening for startup components.</li>
        <li>[Virtualization] Improves reliability for protected workloads.</li>
        <li>[desktop.ini] Hardens desktop.ini processing.</li>
        <li>[AI components] Updates Windows AI components.</li>
      </ul>
      <p>This update includes the latest security fixes and addresses security vulnerabilities.</p>
      <h2>Known issues in this update</h2>
      <p>Microsoft is not currently aware of any issues in this update.</p>
    </main>
  </body>
</html>
"""
KB5094126_SUPPORT_HTML_NO_SECURITY = KB5094126_SUPPORT_HTML.replace(
    "<p>This update includes the latest security fixes and addresses security vulnerabilities.</p>",
    "<p>This update improves reliability and quality for Windows components.</p>",
)
FAKE_MSRC_CVRF_WITH_KB5094126 = {
    "Vulnerability": [
        {
            "CVE": "CVE-2026-0001",
            "Threats": [
                {
                    "Type": "Severity",
                    "Description": {"Value": "Important"},
                }
            ],
            "Remediations": [
                {
                    "Description": {"Value": "Security Update for KB5094126"},
                    "ProductID": ["11568", "11569"],
                }
            ],
        },
        {
            "CVE": "CVE-2026-0002",
            "Threats": [
                {
                    "Type": "Severity",
                    "Description": {"Value": "Critical"},
                }
            ],
            "Remediations": [
                {
                    "URL": "https://support.microsoft.com/help/5094126",
                    "ProductID": "11570",
                }
            ],
        },
        {
            "CVE": "CVE-2026-9999",
            "Threats": [
                {
                    "Type": "Severity",
                    "Description": {"Value": "Low"},
                }
            ],
            "Remediations": [
                {
                    "Description": {"Value": "Security Update for KB5000000"},
                    "ProductID": ["other"],
                }
            ],
        },
    ]
}
FAKE_MSRC_CVRF_WITHOUT_KB5094126 = {
    "Vulnerability": [
        {
            "CVE": "CVE-2026-9999",
            "Threats": [
                {
                    "Type": "Severity",
                    "Description": {"Value": "Important"},
                }
            ],
            "Remediations": [
                {
                    "Description": {"Value": "Security Update for KB5000000"},
                    "ProductID": ["other"],
                }
            ],
        }
    ]
}


def _assert_local_fragment_links_resolve(html: str) -> None:
    ids = set(re.findall(r'\bid="([^"]+)"', html))
    fragments = re.findall(r'href="#([^"]*)"', html)
    assert "" not in fragments
    assert [fragment for fragment in fragments if fragment not in ids] == []


def _html() -> str:
    return (FIXTURES / "windows11-release-health.html").read_text(encoding="utf-8")


def test_generator_utc_now_is_monotonic_at_millisecond_precision() -> None:
    values = [policy_generator_module._utc_now() for _ in range(4)]
    epochs = [epoch_milliseconds_from_iso(value) for value in values]

    assert all(epoch is not None for epoch in epochs)
    assert epochs == sorted(epochs)
    assert len(set(epochs)) == len(epochs)
    assert all("." in value for value in values)


def _html_file(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _atom() -> str:
    return (FIXTURES / "windows11-atom.xml").read_text(encoding="utf-8")


def _kb5094126_atom_fixture() -> str:
    return (FIXTURES / "windows11-atom-kb5094126.xml").read_text(encoding="utf-8")


def _kb5094126_support_fixture() -> str:
    return (FIXTURES / "support-kb5094126.html").read_text(encoding="utf-8")


def _kb5094126_msrc_fixture() -> dict[str, object]:
    return json.loads((FIXTURES / "msrc-cvrf-2026-Jun-kb5094126.json").read_text(encoding="utf-8"))


def _kb5094126_fixture_policy() -> ReleasePolicy:
    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        assert url == KB5094126_SUPPORT_URL
        return _kb5094126_support_fixture()

    def msrc_fetcher(url: str, timeout: float, max_bytes: int) -> dict[str, object]:
        assert url == "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun"
        return _kb5094126_msrc_fixture()

    return generate_policy(
        release_health_html=_html_file("windows11-release-health-header-variants.html"),
        atom_feed_xml=_kb5094126_atom_fixture(),
        generated_at_utc="2026-06-11T00:00:00+00:00",
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )


def _release_health_caught_up_to_kb5094126() -> str:
    html = _html_file("windows11-release-health-current-d-26h1.html")
    current_old = """      <tr>
        <td>25H2</td>
        <td>General Availability Channel</td>
        <td>2025-09-30</td>
        <td>2027-10-12</td>
        <td>2028-10-10</td>
        <td>2026-05-27</td>
        <td>26200.8524</td>
      </tr>"""
    current_new = """      <tr>
        <td>25H2</td>
        <td>General Availability Channel</td>
        <td>2025-09-30</td>
        <td>2027-10-12</td>
        <td>2028-10-10</td>
        <td>2026-06-09</td>
        <td>26200.8655</td>
      </tr>"""
    history_old = """      <tr>
        <td>General Availability Channel</td>
        <td>2026-05 B</td>
        <td>2026-05-12</td>
        <td>26200.8457</td>
        <td>KB5089549</td>
      </tr>"""
    history_new = """      <tr>
        <td>General Availability Channel</td>
        <td>2026-06 B</td>
        <td>2026-06-09</td>
        <td>26200.8655</td>
        <td>KB5094126</td>
      </tr>"""
    assert current_old in html
    assert history_old in html
    return html.replace(current_old, current_new, 1).replace(history_old, history_new, 1)


def _release_health_caught_up_to_kb5094126_with_update_type(update_type: str) -> str:
    html = _html_file("windows11-release-health-current-d-26h1.html")
    current_old = """      <tr>
        <td>25H2</td>
        <td>General Availability Channel</td>
        <td>2025-09-30</td>
        <td>2027-10-12</td>
        <td>2028-10-10</td>
        <td>2026-05-27</td>
        <td>26200.8524</td>
      </tr>"""
    current_new = """      <tr>
        <td>25H2</td>
        <td>General Availability Channel</td>
        <td>2025-09-30</td>
        <td>2027-10-12</td>
        <td>2028-10-10</td>
        <td>2026-06-09</td>
        <td>26200.8655</td>
      </tr>"""
    history_old = """      <tr>
        <td>General Availability Channel</td>
        <td>2026-05 B</td>
        <td>2026-05-12</td>
        <td>26200.8457</td>
        <td>KB5089549</td>
      </tr>"""
    history_extra = f"""      <tr>
        <td>General Availability Channel</td>
        <td>{update_type}</td>
        <td>2026-06-09</td>
        <td>26200.8655</td>
        <td>KB5094126</td>
      </tr>
{history_old}"""
    assert current_old in html
    assert history_old in html
    return html.replace(current_old, current_new, 1).replace(history_old, history_extra, 1)


def _kb5094126_generated_fixture_policy(
    release_health_html: str,
    *,
    support_html: str | None = None,
    msrc_payload: object | None = None,
    msrc_error: Exception | None = None,
    generated_at_utc: str = "2026-06-11T18:00:00+00:00",
) -> ReleasePolicy:
    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        assert url == KB5094126_SUPPORT_URL
        return support_html if support_html is not None else _kb5094126_support_fixture()

    def msrc_fetcher(url: str, timeout: float, max_bytes: int) -> object:
        assert url == "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun"
        if msrc_error is not None:
            raise msrc_error
        return msrc_payload if msrc_payload is not None else _kb5094126_msrc_fixture()

    return generate_policy(
        release_health_html=release_health_html,
        atom_feed_xml=_kb5094126_atom_fixture(),
        generated_at_utc=generated_at_utc,
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )


def _generated_output_bundle(policy: ReleasePolicy, output_dir: Path) -> dict[str, object]:
    write_policy_outputs(
        policy,
        output_dir=output_dir,
        write_index=True,
        write_manifest=True,
    )
    policy_path = output_dir / "windows-release-policy.json"
    manifest_path = output_dir / "policy-manifest.json"
    index_path = output_dir / "index.html"
    api_policy_path = output_dir / "api" / "v1" / "policy.json"
    api_manifest_path = output_dir / "api" / "v1" / "manifest.json"
    assert api_policy_path.read_bytes() == policy_path.read_bytes()
    assert api_manifest_path.read_bytes() == manifest_path.read_bytes()
    policy_data = json.loads(policy_path.read_text(encoding="utf-8"))
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    api_policy_data = json.loads(api_policy_path.read_text(encoding="utf-8"))
    api_manifest_data = json.loads(api_manifest_path.read_text(encoding="utf-8"))
    assert api_policy_data == policy_data
    assert api_manifest_data == manifest_data
    validate_policy_document(policy_data)
    parsed = load_policy_text(json.dumps(policy_data), source_url=DEFAULT_POLICY_URL)
    assert parsed.broad_target_existing_devices is not None
    return {
        "policy": policy_data,
        "manifest": manifest_data,
        "index": index_path.read_text(encoding="utf-8"),
        "policy_text": policy_path.read_text(encoding="utf-8"),
        "manifest_text": manifest_path.read_text(encoding="utf-8"),
    }


def _rendered_diagnostic_ids(index: str) -> list[str]:
    return re.findall(
        r'data-diagnostic-id="(wrg-source-diagnostic-v1:(?:[0-9a-f]{16}|uuid:[0-9a-f-]{36};id=[1-9][0-9]*))"',
        index,
    )


def _assert_unique_source_diagnostic_ids(policy_data: dict[str, object], index: str) -> None:
    source_diagnostics = policy_data["source_diagnostics"]
    assert isinstance(source_diagnostics, dict)
    events = source_diagnostics["events"]
    assert isinstance(events, list)
    event_ids = [str(event["id"]) for event in events if isinstance(event, dict)]
    row_ids = _rendered_diagnostic_ids(index)
    assert event_ids
    assert len(event_ids) == len(set(event_ids))
    assert row_ids
    assert len(row_ids) == len(set(row_ids))
    assert set(event_ids) <= set(row_ids)
    assert "function visibleDiagnosticEntries()" in index
    assert "diagnostic_id:row.getAttribute('data-diagnostic-id')||''" in index


def _assert_no_raw_support_article_leakage(outputs: dict[str, object], support_html: str) -> None:
    combined = "\n".join(
        str(outputs[key])
        for key in ("policy_text", "manifest_text", "index")
    )
    assert support_html.strip() not in combined
    assert "window.secret" not in combined
    assert "Microsoft is not currently aware of any issues in this update." not in combined
    assert "https://support.microsoft.com/help/5094126" not in combined


def _support_article_html(
    *,
    kb_article: str = "KB5094126",
    builds: tuple[str, ...] = ("26200.8655", "26100.8655"),
    applies_to: str = "Windows 11, version 25H2; Windows 11, version 24H2",
    security: bool = True,
    labels: tuple[str, ...] = ("Secure Boot", "Virtualization"),
) -> str:
    build_label = ""
    if builds:
        build_word = "Build" if len(builds) == 1 else "Builds"
        build_label = f" (OS {build_word} {' and '.join(builds)})"
    label_items = "".join(f"<li>[{label}] Validated update note.</li>" for label in labels)
    security_text = (
        "<p>This update includes the latest security fixes and addresses security vulnerabilities.</p>"
        if security
        else "<p>This update improves reliability and quality for Windows components.</p>"
    )
    return f"""
<!doctype html>
<html>
  <head>
    <title>June 9, 2026-{kb_article}{build_label} - Microsoft Support</title>
    <script>window.secret = "ignored";</script>
  </head>
  <body>
    <main>
      <h1>June 9, 2026-{kb_article}{build_label}</h1>
      <p>Applies to: {applies_to}</p>
      <h2>Highlights</h2>
      <ul>{label_items}</ul>
      {security_text}
      <h2>Known issues in this update</h2>
      <p>Microsoft is not currently aware of any issues in this update.</p>
    </main>
  </body>
</html>
"""


def _kb5094126_policy_with_support_html(
    html_text: str,
    *,
    msrc_payload: dict[str, object] | None = None,
) -> ReleasePolicy:
    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        assert url == KB5094126_SUPPORT_URL
        return html_text

    msrc_fetcher = None
    if msrc_payload is not None:
        def msrc_fetcher(url: str, timeout: float, max_bytes: int) -> dict[str, object]:
            assert url == "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun"
            return msrc_payload

    return generate_policy(
        release_health_html=_html_file("windows11-release-health-header-variants.html"),
        atom_feed_xml=_kb5094126_atom_fixture(),
        generated_at_utc="2026-06-11T00:00:00+00:00",
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )


def _kb5094126_atom_event(policy: ReleasePolicy, build: str = "26200.8655") -> dict[str, object]:
    return next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history"
        and event["kb_article"] == "KB5094126"
        and event["build"] == build
    )


@pytest.mark.parametrize(
    "diagnostic_id",
    (
        "wrg-source-diagnostic-v1:1111111111111111",
        ATOM_SOURCE_DIAGNOSTIC_ID,
    ),
)
def test_source_diagnostic_id_validator_accepts_supported_forms(diagnostic_id: str) -> None:
    assert is_source_diagnostic_id(diagnostic_id)


@pytest.mark.parametrize(
    "diagnostic_id",
    (
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af;id=968480",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=0",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=-1",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=notnumeric",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1C3E09919AF3;id=968480",
        "WRG-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3 ;id=968480",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480 extra",
        "wrg-source-diagnostic-v1:1111111111111111-suffix",
        "arbitrary-string-id",
    ),
)
def test_source_diagnostic_id_validator_rejects_malformed_atom_forms(diagnostic_id: str) -> None:
    assert not is_source_diagnostic_id(diagnostic_id)


def _atom_with_new_b_release() -> str:
    entry = """
  <entry>
    <id>tag:support.microsoft.com,2026:KB5089600</id>
    <title>June 9, 2026-KB5089600 (OS Build 26200.8461)</title>
    <published>2026-06-09T18:00:00Z</published>
    <updated>2026-06-09T18:00:00Z</updated>
    <link rel="alternate" href="https://support.microsoft.com/help/5089600" />
    <content type="text">Monthly security update for Windows 11.</content>
  </entry>
"""
    return _atom().replace("</feed>", entry + "</feed>")


def _atom_with_new_preview_release() -> str:
    entry = """
  <entry>
    <id>tag:support.microsoft.com,2026:KB5089601</id>
    <title>June 9, 2026-KB5089601 Preview (OS Build 26200.8461)</title>
    <published>2026-06-09T18:00:00Z</published>
    <updated>2026-06-09T18:00:00Z</updated>
    <link rel="alternate" href="https://support.microsoft.com/help/5089601" />
    <content type="text">Preview update for Windows 11.</content>
  </entry>
"""
    return _atom().replace("</feed>", entry + "</feed>")


def _atom_with_duplicate_new_b_release() -> str:
    entry = """
  <entry>
    <id>tag:support.microsoft.com,2026:KB5089600-duplicate</id>
    <title>June 9, 2026-KB5089600 (OS Build 26200.8461)</title>
    <published>2026-06-09T18:00:00Z</published>
    <updated>2026-06-09T18:00:00Z</updated>
    <link rel="alternate" href="https://support.microsoft.com/help/5089600" />
    <content type="text">Monthly security update for Windows 11.</content>
  </entry>
"""
    return _atom_with_new_b_release().replace("</feed>", entry + "</feed>")


def _atom_feed_with_entries(*entries: str) -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<feed xmlns="http://www.w3.org/2005/Atom">\n'
        "  <title>Windows 11 update history</title>\n"
        + "\n".join(entries)
        + "\n</feed>\n"
    )


def _atom_entry(
    entry_id: str,
    title: str,
    *,
    published: str = "2026-06-09T18:00:00Z",
    updated: str = "2026-06-09T18:00:00Z",
    link: str = "https://support.microsoft.com/help/5089600",
    content: str = "Monthly security update for Windows 11.",
) -> str:
    return f"""  <entry>
    <id>tag:support.microsoft.com,2026:{entry_id}</id>
    <title>{title}</title>
    <published>{published}</published>
    <updated>{updated}</updated>
    <link rel="alternate" href="{link}" />
    <content type="text">{content}</content>
  </entry>"""


def _atom_entry_with_raw_id(
    entry_id: str,
    title: str,
    *,
    published: str = "2026-06-09T17:04:01Z",
    updated: str = "2026-06-10T17:20:31Z",
    link: str = KB5094126_SUPPORT_URL,
    content: str = "",
) -> str:
    return f"""  <entry>
    <id>{entry_id}</id>
    <title type="text">{title}</title>
    <published>{published}</published>
    <updated>{updated}</updated>
    <link rel="alternate" href="{link}" />
    <content type="text">{content}</content>
  </entry>"""


def _atom_entry_with_links(
    title: str,
    links: tuple[str, ...],
    *,
    entry_id: str = ATOM_ENTRY_ID,
    published: str = "2026-06-09T17:04:01Z",
    updated: str = "2026-06-10T17:20:31Z",
    content: str = "",
) -> str:
    link_markup = "\n".join(f"    {link}" for link in links)
    return f"""  <entry>
    <id>{entry_id}</id>
    <title type="text">{title}</title>
    <published>{published}</published>
    <updated>{updated}</updated>
{link_markup}
    <content type="text">{content}</content>
  </entry>"""


def test_source_label_requires_exact_upstream_hosts() -> None:
    release_health_url = "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information"
    localized_release_health_url = (
        "https://learn.microsoft.com/de-de/windows/release-health/windows11-release-information"
    )
    atom_url = "https://support.microsoft.com/en-us/feed/atom/4ec863cc-2ecd-e187-6cb3-b50c6545db92"
    localized_atom_url = "https://support.microsoft.com/de-de/feed/atom/4ec863cc-2ecd-e187-6cb3-b50c6545db92"
    spoofed_release_health_url = (
        "https://learn.microsoft.com.attacker.invalid/en-us/windows/release-health/windows11-release-information"
    )
    spoofed_atom_url = "https://support.microsoft.com.attacker.invalid/en-us/feed/atom/example"

    assert _source_label(release_health_url) == "Microsoft Release Health"
    assert _source_label(localized_release_health_url) == "Microsoft Release Health"
    assert _source_label(atom_url) == "Microsoft Atom feed"
    assert _source_label(localized_atom_url) == "Microsoft Atom feed"
    assert _source_label(spoofed_release_health_url) == spoofed_release_health_url
    assert _source_label(spoofed_atom_url) == spoofed_atom_url


def test_atom_link_selection_prefers_safe_alternate_after_self_feed_url() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_links(
            "June 9, 2026-KB5094126 (OS Build 26200.8655)",
            (
                '<link rel="self" href="https://support.microsoft.com/en-us/feed/atom/not-an-article" />',
                f'<link rel="alternate" href="{KB5094126_SUPPORT_URL}?utm_source=feed" />',
            ),
        )
    )

    entry = parse_atom_feed(atom)[0]

    assert entry.link == KB5094126_SUPPORT_URL


def test_atom_link_selection_skips_unsafe_alternate_before_safe_alternate() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_links(
            "June 9, 2026-KB5094126 (OS Build 26200.8655)",
            (
                '<link rel="alternate" href="https://evil.example/topic/kb5094126" />',
                '<link rel="alternate" href="https://support.microsoft.com/help/5094126" />',
            ),
        )
    )

    entry = parse_atom_feed(atom)[0]

    assert entry.link == "https://support.microsoft.com/help/5094126"


def test_atom_unsafe_links_create_missing_href_without_latest_observed_advancement() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_links(
            "June 9, 2026-KB5094126 (OS Build 26200.8655)",
            (
                '<link rel="self" href="https://support.microsoft.com/en-us/feed/atom/not-an-article" />',
                '<link rel="alternate" href="https://support.microsoft.com/en-us/search?query=KB5094126" />',
                '<link rel="alternate" href="https://evil.example/topic/kb5094126" />',
            ),
        )
    )

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        atom_feed_xml=atom,
        generated_at_utc="2026-06-11T00:00:00+00:00",
    )
    target = policy.broad_target_existing_devices

    assert parse_atom_feed(atom)[0].link is None
    assert target is not None
    assert target.latest_build == "26200.8524"
    assert target.latest_observed_build == "26200.8524"
    assert "latest_observed_source_url" not in target.metadata
    assert not policy.source_diagnostics["support_articles"]
    missing = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_support_article_href_missing"
    )
    assert missing["kb_article"] == "KB5094126"
    assert missing["build"] == "26200.8655"
    assert "support_url" not in missing


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

    monkeypatch.setattr(policy_generator_module.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(PolicyFetchError, match="unsafe URL"):
        policy_generator_module._default_support_article_fetcher(KB5094126_SUPPORT_URL, 1.0, 1024)


def _with_26h2_ga(html: str) -> str:
    row = """      <tr>
        <td>26H2</td>
        <td>General Availability Channel</td>
        <td>2026-10-01</td>
        <td>2028-10-10</td>
        <td>2029-10-09</td>
        <td>2026-10-13</td>
        <td>28200.1000</td>
      </tr>
"""
    history = """
  <h3>Version 26H2 (OS build 28200)</h3>
  <table>
    <thead>
      <tr>
        <th>Servicing option</th>
        <th>Update type</th>
        <th>Availability date</th>
        <th>Build</th>
        <th>KB article</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>General Availability Channel</td>
        <td>2026-10 B</td>
        <td>2026-10-13</td>
        <td>28200.1000</td>
        <td>KB5090001</td>
      </tr>
    </tbody>
  </table>
"""
    html = html.replace("      <tr>\n        <td>26H1</td>", row + "      <tr>\n        <td>26H1</td>", 1)
    return html.replace("  <h3>Version 26H1 (OS build 28000)</h3>", history + "\n  <h3>Version 26H1 (OS build 28000)</h3>", 1)


def _with_27h1_special(html: str) -> str:
    note = """
  <p>
    Windows 11, version 27H1 is scoped to support new devices and is not
    designed as a feature update for existing devices. This version is not
    offered as an in-place update from 25H2 or 26H2 on existing devices.
  </p>
"""
    row = """      <tr>
        <td>27H1</td>
        <td>General Availability Channel</td>
        <td>2027-02-10</td>
        <td>2029-03-13</td>
        <td>2030-03-12</td>
        <td>2027-02-10</td>
        <td>29000.1000</td>
      </tr>
"""
    history = """
  <h3>Version 27H1 (OS build 29000)</h3>
  <table>
    <thead>
      <tr>
        <th>Servicing option</th>
        <th>Update type</th>
        <th>Availability date</th>
        <th>Build</th>
        <th>KB article</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>General Availability Channel</td>
        <td>2027-02 B</td>
        <td>2027-02-10</td>
        <td>29000.1000</td>
        <td>KB5097001</td>
      </tr>
    </tbody>
  </table>
"""
    html = html.replace("  <h2>Windows 11 current versions by servicing option</h2>", note + "\n  <h2>Windows 11 current versions by servicing option</h2>", 1)
    html = html.replace("      <tr>\n        <td>26H2</td>", row + "      <tr>\n        <td>26H2</td>", 1)
    return html.replace("  <h3>Version 26H2 (OS build 28200)</h3>", history + "\n  <h3>Version 26H2 (OS build 28200)</h3>", 1)


def _with_oob_row(html: str) -> str:
    row = """      <tr>
        <td>General Availability Channel</td>
        <td>2026-05</td>
        <td>2026-05-16</td>
        <td>26200.8460</td>
        <td>KB5089550</td>
      </tr>
"""
    return html.replace("      <tr>\n        <td>General Availability Channel</td>\n        <td>2026-04 D</td>", row + "      <tr>\n        <td>General Availability Channel</td>\n        <td>2026-04 D</td>", 1)


def _with_25h2_current_latest_build(html: str, build: str) -> str:
    return html.replace("        <td>26200.8457</td>\n      </tr>", f"        <td>{build}</td>\n      </tr>", 1)


def _without_26h1_special_note(html: str) -> str:
    start = html.index("  <p>\n    Windows 11, version 26H1")
    end = html.index("  </p>", start) + len("  </p>\n")
    return html[:start] + html[end:]


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


def test_generate_policy_from_local_html_and_atom_fixtures(tmp_path):
    policy = build_policy_from_sources(
        release_health_html_path=FIXTURES / "windows11-release-health.html",
        atom_feed_path=FIXTURES / "windows11-atom.xml",
        signature_status="valid",
    )
    data = policy.to_dict()
    validation_warnings = validate_policy_document(data)
    assert not any("source_diagnostics" in warning for warning in validation_warnings)
    written = write_policy_outputs(
        policy,
        output_dir=tmp_path,
        write_index=True,
        write_robots=True,
        write_sitemap=True,
        write_manifest=True,
    )

    assert written["policy"].name == "windows-release-policy.json"
    assert written["index"].name == "index.html"
    assert written["asset:pypi_download"].as_posix().endswith("assets/images/download_from_pypi.png")
    assert written["asset:pypi_download"].read_bytes() == Path("assets/images/download_from_pypi.png").read_bytes()
    assert written["robots"].name == "robots.txt"
    assert written["sitemap"].name == "sitemap.xml"
    assert written["manifest"].name == "policy-manifest.json"
    assert written["nojekyll"].name == ".nojekyll"
    assert json.loads(written["policy"].read_text(encoding="utf-8"))["broad_target_existing_devices"]["version"] == "25H2"
    assert written["robots"].read_bytes() == EXPECTED_ROBOTS_TXT.encode("utf-8")
    assert "windows-release-policy.json" in written["sitemap"].read_text(encoding="utf-8")
    assert json.loads(written["manifest"].read_text(encoding="utf-8"))["broad_target_existing_devices"]["version"] == "25H2"
    assert data["source_fetch_status"]["release_health_html"]["status"] == "ok"
    assert data["source_fetch_status"]["atom_feed"]["status"] == "ok"
    assert data["source_fetch_status"]["release_health_html"]["fetched_at_utc"]
    assert data["source_fetch_status"]["atom_feed"]["fetched_at_utc"]
    diagnostics = data["source_diagnostics"]
    assert data["schema_version"] == 1
    assert data["min_reader_schema_version"] == 1
    assert data["max_reader_schema_version"] == 1
    assert data["api_version"] == "v1"
    assert data["generator_version"] == GENERATOR_VERSION
    assert data["compatibility"]["required_core_schema_version"] == 1
    assert diagnostics["release_health_html"]["source_url"] == DEFAULT_RELEASE_HEALTH_URL
    assert diagnostics["release_health_html"]["bytes"] > 0
    assert diagnostics["release_health_html"]["newest_current_version_revision_date"] == "2026-05-12"
    assert diagnostics["release_health_html"]["newest_release_history_availability_date"] == "2026-05-12"
    assert diagnostics["atom_feed"]["newest_atom_updated"] == "2026-05-16T18:00:00Z"
    assert diagnostics["atom_feed"]["newest_atom_published"] == "2026-05-16T18:00:00Z"
    assert diagnostics["atom_feed"]["newest_atom_build"] == "26200.8460"
    assert any(event["severity"] == "notice" for event in diagnostics["events"])
    assert "quality_baselines" in data
    assert "preview_builds" in data


def test_write_signed_policy_output_includes_key_id(tmp_path):
    policy = generate_policy(
        release_health_html=_html(),
        atom_feed_xml=_atom(),
        generated_at_utc="2026-05-31T14:11:50+00:00",
        signature_status="valid",
    )

    written = write_policy_outputs(
        policy,
        output_dir=tmp_path,
        signing_key="krtF2muLgucP7JDVNKk2g+YQfz92c7xM49dzszxHxjs=",
        key_id="test-policy-key",
    )
    signature = json.loads(written["signature"].read_text(encoding="utf-8"))

    assert signature["algorithm"] == "ed25519"
    assert signature["key_id"] == "test-policy-key"
    assert signature["signature"]
    assert signature["signed_at_utc"]


def test_fixture_with_26h1_25h2_24h2_chooses_25h2():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    special = {entry.version: entry for entry in policy.special_releases}
    assert special["26H1"].metadata["special_release"] is True
    assert special["26H1"].metadata["new_devices_only"] is True
    assert special["26H1"].metadata["not_broad_target_existing_devices"] is True


def test_generate_policy_from_release_health_current_d_preview_fixture():
    policy = generate_policy(
        release_health_html=_html_file("windows11-release-health-current-d-26h1.html"),
        atom_feed_xml=_atom(),
    )
    target = policy.broad_target_existing_devices
    baseline = policy.quality_baselines["25H2"][QualityPolicy.B_RELEASE_ONLY.value]

    assert target is not None
    assert target.latest_observed_build == "26200.8524"
    assert target.required_baseline_build == "26200.8457"
    assert baseline["build"] == "26200.8457"
    current_25h2 = next(entry for entry in policy.current_versions if entry.version == "25H2")
    assert current_25h2.latest_build == "26200.8524"
    assert current_25h2.latest_observed_build == "26200.8524"
    assert current_25h2.baseline_build == "26200.8457"
    assert current_25h2.required_baseline_build == "26200.8457"
    assert any(item["build"] == "26200.8524" for item in policy.preview_builds)
    assert {entry.version for entry in policy.special_releases} == {"26H1"}


def test_generate_policy_fails_on_release_health_26h1_without_special_note():
    with pytest.raises(PolicyParseError, match="26H1 new-devices-only special release note"):
        generate_policy(release_health_html=_without_26h1_special_note(_html()), atom_feed_xml=_atom())


def test_future_26h2_ga_chooses_26h2():
    policy = generate_policy(release_health_html=_with_26h2_ga(_html()), atom_feed_xml=_atom())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "26H2"
    assert policy.broad_target_existing_devices.build_family == 28200


def test_future_27h1_special_does_not_choose_27h1():
    policy = generate_policy(release_health_html=_with_27h1_special(_with_26h2_ga(_html())), atom_feed_xml=_atom())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "26H2"
    special = {entry.version for entry in policy.special_releases}
    assert "27H1" in special


def test_atom_feed_marks_preview_when_table_is_ambiguous():
    html = _html().replace("2026-04 D", "2026-04")
    policy = generate_policy(release_health_html=html, atom_feed_xml=_atom())
    row = next(row for row in policy.release_history if row.kb_article == "KB5083631")

    assert row.preview is True
    assert row.update_type_letter == "D"
    assert row.metadata["atom_enriched"] is True
    assert row.metadata["atom_entry_id"] == "tag:support.microsoft.com,2026:KB5083631"
    assert "atom_support_article_id" not in row.metadata
    assert "diagnostic_id_hint" not in row.metadata
    assert row.kb_url == "https://support.microsoft.com/help/5083631"
    assert row.catalog_url == "https://www.catalog.update.microsoft.com/Search.aspx?q=KB5083631"


def test_atom_feed_marks_oob_when_table_is_ambiguous():
    policy = generate_policy(release_health_html=_with_oob_row(_html()), atom_feed_xml=_atom())
    row = next(row for row in policy.release_history if row.kb_article == "KB5089550")

    assert row.out_of_band is True
    assert row.update_type_letter == "OOB"
    assert row.metadata["atom_enriched"] is True
    assert any(item["kb_article"] == "KB5089550" for item in policy.out_of_band_builds)


def test_source_diagnostics_notice_when_atom_oob_is_newer_than_release_history():
    policy = generate_policy(
        release_health_html=_html(),
        atom_feed_xml=_atom(),
        generated_at_utc="2026-05-20T00:00:00+00:00",
    )
    diagnostics = policy.source_diagnostics
    drift = diagnostics["drift"]["atom_newer_than_release_history"]
    events = diagnostics["events"]

    assert drift[0]["build"] == "26200.8460"
    assert drift[0]["kb_article"] == "KB5089550"
    assert drift[0]["out_of_band"] is True
    assert diagnostics["drift"]["generated_after_newest_source_hours"] == 78.0
    assert any(
        event["kind"] == "atom_newer_than_release_history"
        and event["severity"] == "notice"
        and event["id"].startswith(f"{SOURCE_DIAGNOSTIC_ID_PREFIX}:")
        and event["affects_required_baseline"] is False
        for event in events
    )
    assert not any(event["kind"] == "source_drift_unresolved_after_24h" for event in events)
    assert not any("Atom feed shows a newer non-preview build" in warning for warning in policy.validation_warnings)


def test_source_diagnostics_notice_when_atom_preview_is_newer_than_release_history():
    policy = generate_policy(
        release_health_html=_html(),
        atom_feed_xml=_atom_with_new_preview_release(),
        generated_at_utc="2026-06-10T00:00:00+00:00",
    )
    events = policy.source_diagnostics["events"]

    event = next(
        event
        for event in events
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8461"
    )
    assert event["severity"] == "notice"
    assert event["release"] == "25H2"
    assert event["kb_article"] == "KB5089601"
    assert event["affects_broad_target"] is True
    assert event["affects_required_baseline"] is False
    assert not any("newer non-preview build for the broad target" in warning for warning in policy.validation_warnings)


def test_source_diagnostics_notice_when_atom_newer_is_not_broad_target() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry(
            "KB5089602",
            "June 9, 2026-KB5089602 (OS Build 28000.2114)",
            link="https://support.microsoft.com/help/5089602",
        )
    )
    policy = generate_policy(
        release_health_html=_html(),
        atom_feed_xml=atom,
        generated_at_utc="2026-06-10T00:00:00+00:00",
    )

    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "28000.2114"
    )
    assert event["severity"] == "notice"
    assert event["release"] == "26H1"
    assert event["affects_broad_target"] is False
    assert event["affects_required_baseline"] is False
    assert not any("newer non-preview build for the broad target" in warning for warning in policy.validation_warnings)


def test_source_diagnostics_notice_when_atom_build_family_has_no_release_mapping() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry(
            "KB5089603",
            "June 9, 2026-KB5089603 (OS Build 29999.1000)",
            link="https://support.microsoft.com/help/5089603",
        )
    )
    policy = generate_policy(
        release_health_html=_html(),
        atom_feed_xml=atom,
        generated_at_utc="2026-06-10T00:00:00+00:00",
    )

    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "29999.1000"
    )
    assert event["severity"] == "notice"
    assert event["release"] is None
    assert event["build_family"] == 29999
    assert event["affects_broad_target"] is False
    assert event["affects_required_baseline"] is False


def test_source_diagnostics_notice_when_atom_broad_target_build_lacks_kb() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry(
            "no-kb-build",
            "June 9, 2026 servicing update (OS Build 26200.8462)",
            link="https://support.microsoft.com/help/no-kb-build",
            content="Windows 11 servicing update without KB metadata.",
        )
    )
    policy = generate_policy(
        release_health_html=_html(),
        atom_feed_xml=atom,
        generated_at_utc="2026-06-10T00:00:00+00:00",
    )

    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8462"
    )
    assert event["severity"] == "notice"
    assert event["release"] == "25H2"
    assert event["kb_article"] is None
    assert event["affects_broad_target"] is True
    assert event["affects_required_baseline"] is False
    assert not any("unknown KB build 26200.8462" in warning for warning in policy.validation_warnings)


def test_source_diagnostics_ignores_atom_build_older_than_release_history() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry(
            "KB5089000",
            "May 1, 2026-KB5089000 (OS Build 26200.8000)",
            published="2026-05-01T18:00:00Z",
            updated="2026-05-01T18:00:00Z",
            link="https://support.microsoft.com/help/5089000",
        )
    )
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=atom)

    assert policy.source_diagnostics["drift"]["atom_newer_than_release_history"] == []
    assert not any(
        event["kind"] == "atom_newer_than_release_history"
        for event in policy.source_diagnostics["events"]
    )


def test_source_diagnostic_id_is_stable_for_equivalent_input():
    first = _source_diagnostic_id(
        severity="Warning",
        source="Atom feed",
        title="Atom Newer Than Release History",
        message="Atom feed reports a newer baseline build.",
        tags=("Release 25H2", "Build 26200.8461", "KB5089600"),
    )
    second = _source_diagnostic_id(
        severity=" warning ",
        source="Atom  feed",
        title="Atom Newer Than Release History",
        message="Atom feed reports a newer baseline   build.",
        tags=("Release 25H2", "Build 26200.8461", "KB5089600"),
    )

    assert first == second
    assert re.fullmatch(r"wrg-source-diagnostic-v1:[0-9a-f]{16}", first)


def test_source_diagnostic_id_ignores_volatile_timestamp_tag_order_and_message_wording():
    first = _source_diagnostic_id(
        severity="warning",
        source="Atom feed",
        title="Atom Newer Than Release History",
        message="Atom feed reports a newer baseline build.",
        tags=(
            "Release 25H2",
            "Build 26200.8461",
            "KB5089600",
            "Family 26200",
            "Required baseline",
            "2026-06-09T18:00:00Z",
        ),
    )
    second = _source_diagnostic_id(
        severity="warning",
        source="Atom feed",
        title="Atom Newer Than Release History",
        message="A newer baseline build is present in the Atom feed.",
        tags=(
            "2026-06-10T09:30:00Z",
            "Required baseline",
            "Family 26200",
            "KB 5089600",
            "Build 26200.8461",
            "Release 25H2",
        ),
    )

    assert second == first


def test_source_diagnostic_event_id_ignores_volatile_message_and_timestamp_fields():
    event = {
        "severity": "warning",
        "kind": "atom_newer_than_release_history",
        "release": "25H2",
        "build_family": 26200,
        "build": "26200.8461",
        "kb_article": "KB5089600",
        "affects_broad_target": True,
        "affects_required_baseline": True,
        "updated": "2026-06-09T18:00:00Z",
        "message": "Atom feed reports a newer baseline build.",
    }
    changed = {
        **event,
        "updated": "2026-06-10T09:30:00Z",
        "message": "A newer baseline build is present in the Atom feed.",
    }

    assert policy_generator_module._source_diagnostic_id_for_event(changed) == (
        policy_generator_module._source_diagnostic_id_for_event(event)
    )


def test_source_diagnostic_id_changes_when_meaning_changes():
    base = {
        "severity": "warning",
        "source": "Atom feed",
        "title": "Atom Newer Than Release History",
        "message": "Atom feed reports a newer baseline build.",
        "tags": ("Release 25H2", "Build 26200.8461", "KB5089600"),
    }
    base_id = _source_diagnostic_id(**base)

    for key, value in (
        ("severity", "error"),
        ("source", "Release Health"),
        ("title", "Current Versions Lag Release History"),
        ("tags", ("Release 25H2", "Build 26200.8462", "KB5089600")),
    ):
        changed = dict(base)
        changed[key] = value
        assert _source_diagnostic_id(**changed) != base_id


def test_source_diagnostic_event_id_changes_when_stable_fields_change():
    base = {
        "severity": "warning",
        "kind": "atom_newer_than_release_history",
        "release": "25H2",
        "build_family": 26200,
        "build": "26200.8461",
        "kb_article": "KB5089600",
        "affects_broad_target": True,
        "affects_required_baseline": True,
        "updated": "2026-06-09T18:00:00Z",
        "message": "Atom feed reports a newer baseline build.",
    }
    base_id = policy_generator_module._source_diagnostic_id_for_event(base)

    for key, value in (
        ("severity", "error"),
        ("kind", "current_versions_lag_release_history"),
        ("release", "24H2"),
        ("build_family", 26100),
        ("build", "26200.8462"),
        ("kb_article", "KB5089601"),
        ("affects_broad_target", False),
        ("affects_required_baseline", False),
    ):
        changed = dict(base)
        changed[key] = value
        assert policy_generator_module._source_diagnostic_id_for_event(changed) != base_id


def test_source_diagnostic_event_id_uses_valid_atom_diagnostic_hint() -> None:
    event = {
        "severity": "warning",
        "kind": "atom_newer_than_release_history",
        "release": "25H2",
        "build_family": 26200,
        "build": "26200.8655",
        "kb_article": "KB5094126",
        "affects_broad_target": True,
        "affects_required_baseline": True,
        "diagnostic_id_hint": ATOM_SOURCE_DIAGNOSTIC_ID,
        "message": "Atom feed reports a newer baseline build.",
    }

    assert policy_generator_module._source_diagnostic_id_for_event(event) == ATOM_SOURCE_DIAGNOSTIC_ID
    assert policy_generator_module._source_diagnostic_row_from_event(event)["id"] == ATOM_SOURCE_DIAGNOSTIC_ID


def test_source_diagnostic_event_id_ignores_invalid_atom_diagnostic_hint() -> None:
    event = {
        "severity": "warning",
        "kind": "atom_newer_than_release_history",
        "release": "25H2",
        "build_family": 26200,
        "build": "26200.8655",
        "kb_article": "KB5094126",
        "affects_broad_target": True,
        "affects_required_baseline": True,
        "diagnostic_id_hint": "wrg-source-diagnostic-v1:uuid:not-a-canonical-id;id=968480",
        "message": "Atom feed reports a newer baseline build.",
    }

    assert re.fullmatch(
        r"wrg-source-diagnostic-v1:[0-9a-f]{16}",
        policy_generator_module._source_diagnostic_id_for_event(event),
    )


def test_source_diagnostics_warn_when_atom_has_newer_b_release_for_broad_target():
    policy = generate_policy(
        release_health_html=_html(),
        atom_feed_xml=_atom_with_new_b_release(),
        generated_at_utc="2026-06-10T00:00:00+00:00",
    )
    events = policy.source_diagnostics["events"]

    event = next(
        event
        for event in events
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8461"
    )
    assert event["severity"] == "warning"
    assert event["release"] == "25H2"
    assert event["affects_broad_target"] is True
    assert event["affects_required_baseline"] is True
    assert re.fullmatch(r"wrg-source-diagnostic-v1:[0-9a-f]{16}", event["id"])
    assert any("newer non-preview build for the broad target" in warning for warning in policy.validation_warnings)


def test_source_diagnostics_atom_entry_id_propagates_to_event_and_dashboard() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_raw_id(
            ATOM_ENTRY_ID,
            "June 9, 2026&#8212;KB5094126 (OS Builds 26200.8655 and 26100.8655) - Microsoft Support",
        )
    )
    policy = generate_policy(
        release_health_html=_html(),
        atom_feed_xml=atom,
        generated_at_utc="2026-06-10T18:00:00+00:00",
    )
    drift = [
        item
        for item in policy.source_diagnostics["drift"]["atom_newer_than_release_history"]
        if item["build"] == "26200.8655"
    ]
    events = [
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8655"
    ]

    assert len(drift) == 1
    assert drift[0]["kb_article"] == "KB5094126"
    assert drift[0]["atom_entry_id"] == ATOM_ENTRY_ID
    assert drift[0]["atom_support_article_id"] == ATOM_SUPPORT_ARTICLE_ID
    assert drift[0]["atom_feed_url"] == KB5094126_SUPPORT_URL
    assert drift[0]["support_url"] == KB5094126_SUPPORT_URL
    assert drift[0]["diagnostic_id_hint"] == ATOM_SOURCE_DIAGNOSTIC_ID
    assert len(events) == 1
    event = events[0]
    assert event["id"] == ATOM_SOURCE_DIAGNOSTIC_ID
    assert event["severity"] == "warning"
    assert event["release"] == "25H2"
    assert event["kb_article"] == "KB5094126"
    assert event["affects_broad_target"] is True
    assert event["affects_required_baseline"] is True
    assert event["atom_entry_id"] == ATOM_ENTRY_ID
    assert event["atom_support_article_id"] == ATOM_SUPPORT_ARTICLE_ID
    assert event["atom_feed_url"] == KB5094126_SUPPORT_URL
    assert event["support_url"] == KB5094126_SUPPORT_URL
    assert event["source_url"] == KB5094126_SUPPORT_URL
    assert event["diagnostic_id_hint"] == ATOM_SOURCE_DIAGNOSTIC_ID
    assert any("newer non-preview build for the broad target" in warning for warning in policy.validation_warnings)
    validate_policy_document(policy.to_dict())

    index = policy_generator_module.render_policy_index(policy, policy_bytes=None, signature=None)
    assert f'data-diagnostic-id="{ATOM_SOURCE_DIAGNOSTIC_ID}"' in index
    assert "diagnostic_id:row.getAttribute('data-diagnostic-id')||''" in index


def test_kb5094126_multi_build_atom_events_get_unique_diagnostic_ids() -> None:
    policy = _kb5094126_fixture_policy()
    events = [
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history"
        and event["kb_article"] == "KB5094126"
        and event["build"] in {"26100.8655", "26200.8655"}
    ]

    assert [(event["severity"], event["release"], event["build"]) for event in events] == [
        ("notice", "24H2", "26100.8655"),
        ("warning", "25H2", "26200.8655"),
    ]
    ids = [event["id"] for event in events]
    assert len(set(ids)) == len(ids)

    notice = next(event for event in events if event["build"] == "26100.8655")
    warning = next(event for event in events if event["build"] == "26200.8655")
    assert warning["id"] == ATOM_SOURCE_DIAGNOSTIC_ID
    assert re.fullmatch(r"wrg-source-diagnostic-v1:[0-9a-f]{16}", notice["id"])
    assert notice["id"] != ATOM_SOURCE_DIAGNOSTIC_ID
    for event in (notice, warning):
        assert event["atom_entry_id"] == ATOM_ENTRY_ID
        assert event["atom_support_article_id"] == ATOM_SUPPORT_ARTICLE_ID
        assert event["support_url"] == KB5094126_SUPPORT_URL
        assert event["source_url"] == KB5094126_SUPPORT_URL
        assert "id=968480" in policy_generator_module._source_diagnostic_event_tags(event)
    validate_policy_document(policy.to_dict())


def test_kb5094126_dashboard_rows_and_visible_export_ids_are_unique(tmp_path: Path) -> None:
    policy = _kb5094126_fixture_policy()
    written = write_policy_outputs(policy, output_dir=tmp_path, write_index=True, write_manifest=True)
    index = written["index"].read_text(encoding="utf-8")
    row_ids = re.findall(
        r'data-diagnostic-id="(wrg-source-diagnostic-v1:(?:[0-9a-f]{16}|uuid:[0-9a-f-]{36};id=[1-9][0-9]*))"',
        index,
    )
    event_ids = [
        event["id"]
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history"
    ]

    assert len(set(row_ids)) == len(row_ids)
    assert set(event_ids) <= set(row_ids)
    assert ATOM_SOURCE_DIAGNOSTIC_ID in row_ids
    assert "function visibleDiagnosticEntries()" in index
    assert "diagnostic_id:row.getAttribute('data-diagnostic-id')||''" in index

    export_like_ids = [
        match.group(1)
        for match in re.finditer(
            r'<article class="diag-row [^"]+" data-diagnostic-severity="[^"]+" '
            r'data-diagnostic-id="([^"]+)"',
            index,
        )
    ]
    assert export_like_ids == row_ids
    assert len(set(export_like_ids)) == len(export_like_ids)


def test_atom_support_latest_observed_does_not_change_required_baseline() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_raw_id(
            ATOM_ENTRY_ID,
            "June 9, 2026&#8212;KB5094126 (OS Builds 26200.8655 and 26100.8655) - Microsoft Support",
        )
    )
    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        atom_feed_xml=atom,
        generated_at_utc="2026-06-10T18:00:00+00:00",
    )

    target = policy.broad_target_existing_devices
    assert target is not None
    assert target.version == "25H2"
    assert target.latest_build == "26200.8524"
    assert target.latest_observed_build == "26200.8655"
    assert target.baseline_build == "26200.8457"
    assert target.required_baseline_build == "26200.8457"
    assert target.metadata["latest_observed_source"] == "atom_support_article"
    assert target.metadata["latest_observed_source_url"] == KB5094126_SUPPORT_URL
    assert target.metadata["latest_observed_kb_article"] == "KB5094126"
    assert target.metadata["latest_observed_published"] == "2026-06-09T17:04:01Z"
    assert target.metadata["latest_observed_updated"] == "2026-06-10T17:20:31Z"
    assert target.metadata["latest_observed_atom_entry_id"] == ATOM_ENTRY_ID
    assert target.metadata["latest_observed_atom_support_article_id"] == ATOM_SUPPORT_ARTICLE_ID

    current_25h2 = next(
        entry
        for entry in policy.current_versions
        if entry.version == "25H2" and entry.build_family == 26200
    )
    assert current_25h2.latest_build == "26200.8524"
    assert current_25h2.latest_observed_build == "26200.8655"
    assert current_25h2.required_baseline_build == "26200.8457"
    assert current_25h2.metadata["latest_observed_source_url"] == KB5094126_SUPPORT_URL

    generated_policy = policy.to_dict()
    broad_target = generated_policy["broad_target_existing_devices"]
    assert broad_target["latest_build"] == "26200.8524"
    assert broad_target["latest_observed_build"] == "26200.8655"
    assert broad_target["required_baseline_build"] == "26200.8457"
    assert broad_target["metadata"]["latest_observed_atom_entry_id"] == ATOM_ENTRY_ID
    validate_policy_document(generated_policy)


def test_atom_support_latest_observed_renders_dashboard_and_manifest_evidence() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_raw_id(
            ATOM_ENTRY_ID,
            "June 9, 2026&#8212;KB5094126 (OS Builds 26200.8655 and 26100.8655) - Microsoft Support",
        )
    )
    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        atom_feed_xml=atom,
    )

    index = policy_generator_module.render_policy_index(policy, policy_bytes=None, signature=None)
    assert "26200.8655" in index
    assert "Microsoft Support article via Atom feed" in index
    assert (
        '<div class="metric">26200.8655</div><span class="label">Microsoft Current Versions table</span>'
        not in index
    )

    policy_bytes = json.dumps(policy.to_dict(), sort_keys=True).encode("utf-8")
    manifest = json.loads(
        policy_generator_module.render_policy_manifest(
            policy,
            policy_bytes=policy_bytes,
            signature_bytes=None,
        )
    )
    evidence = manifest["latest_observed_evidence"]
    assert manifest["latest_observed_build"] == "26200.8655"
    assert manifest["broad_target_existing_devices"]["latest_observed_build"] == "26200.8655"
    assert manifest["broad_target_existing_devices"]["latest_observed_evidence"] == evidence
    assert evidence["latest_observed_source"] == "atom_support_article"
    assert evidence["latest_observed_source_url"] == KB5094126_SUPPORT_URL
    assert evidence["latest_observed_kb_article"] == "KB5094126"
    assert evidence["latest_observed_atom_entry_id"] == ATOM_ENTRY_ID
    assert evidence["latest_observed_atom_support_article_id"] == ATOM_SUPPORT_ARTICLE_ID


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
    ("applies_to", "release", "expected"),
    (
        ("Windows 11, version 25H2", "25H2", "compatible"),
        ("Windows 11, version 25H2; Windows 11, version 24H2", "24H2", "compatible"),
        ("Windows 11, version 24H2", "25H2", "release_unmatched"),
        ("Windows 10, version 22H2", "25H2", "incompatible"),
        ("", "25H2", "unknown"),
        ("Windows 11", "25H2", "unknown"),
    ),
)
def test_support_article_applies_to_compatibility(applies_to: str, release: str, expected: str) -> None:
    assert (
        policy_generator_module._support_article_applies_to_compatibility(
            applies_to,
            release=release,
            build_family=26200,
        )
        == expected
    )


def test_support_article_missing_applies_to_is_degraded_not_mismatch() -> None:
    validation = policy_generator_module._support_article_validation_for_record(
        {
            "kb_article": "KB5094126",
            "build": "26200.8655",
            "release": "25H2",
            "build_family": 26200,
            "support_url": KB5094126_SUPPORT_URL,
        },
        {
            "url": KB5094126_SUPPORT_URL,
            "status": "ok",
            "kb_article": "KB5094126",
            "builds": ["26200.8655"],
        },
    )

    assert validation["support_article_validation_status"] == "degraded"
    assert validation["support_article_validation_reasons"] == ["applies_to_missing"]


def test_support_article_applies_to_release_miss_degrades_windows11_event() -> None:
    validation = policy_generator_module._support_article_validation_for_record(
        {
            "kb_article": "KB5094126",
            "build": "26200.8655",
            "release": "25H2",
            "build_family": 26200,
            "support_url": KB5094126_SUPPORT_URL,
        },
        {
            "url": KB5094126_SUPPORT_URL,
            "status": "ok",
            "kb_article": "KB5094126",
            "builds": ["26200.8655"],
            "applies_to": "Windows 11, version 24H2",
            "applies_to_releases": ["24H2"],
        },
    )

    assert validation["support_article_validation_status"] == "degraded"
    assert validation["support_article_validation_reasons"] == ["applies_to_release_unmatched"]


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


def test_msrc_cvrf_kb_join_collects_cves_severities_and_products() -> None:
    result = policy_generator_module._cvrf_kb_join(FAKE_MSRC_CVRF_WITH_KB5094126, "KB5094126")

    assert result == {
        "is_security": True,
        "cves": ["CVE-2026-0001", "CVE-2026-0002"],
        "severities": ["Critical", "Important"],
        "products": ["11568", "11569", "11570"],
        "evidence_source": "msrc_cvrf",
    }


def test_msrc_cvrf_kb_join_minimal_exact_kb_remediation_is_security() -> None:
    result = policy_generator_module._cvrf_kb_join(
        {
            "Vulnerability": [
                {
                    "Remediations": [
                        {"Description": {"Value": "Security Update for KB5094126"}},
                    ],
                }
            ]
        },
        "KB5094126",
    )

    assert result == {
        "is_security": True,
        "cves": [],
        "severities": [],
        "products": [],
        "evidence_source": "msrc_cvrf",
    }


def test_msrc_cvrf_kb_join_caps_large_context_lists_deterministically() -> None:
    vulnerabilities = []
    for index in range(20, 0, -1):
        vulnerabilities.append(
            {
                "CVE": f"CVE-2026-{index:04d}",
                "Threats": [{"Type": "Severity", "Description": {"Value": f"Severity {index:02d}"}}],
                "Remediations": [
                    {
                        "Description": {"Value": "Security Update for KB5094126"},
                        "ProductID": [f"P{index:03d}", f"P{index + 100:03d}"],
                    }
                ],
            }
        )

    result = policy_generator_module._cvrf_kb_join({"Vulnerability": vulnerabilities}, "KB5094126")

    assert result["is_security"] is True
    assert result["evidence_source"] == "msrc_cvrf"
    assert result["cves"] == [f"CVE-2026-{index:04d}" for index in range(1, 13)]
    assert result["severities"] == [f"Severity {index:02d}" for index in range(1, 9)]
    assert result["products"] == [f"P{index:03d}" for index in range(1, 17)]


def _fake_cvrf_with_remediation_text(text: str) -> dict[str, object]:
    return {
        "Vulnerability": [
            {
                "CVE": "CVE-2026-1234",
                "Threats": [{"Type": "Severity", "Description": {"Value": "Important"}}],
                "Remediations": [{"Description": {"Value": text}, "ProductID": ["11568"]}],
            }
        ]
    }


@pytest.mark.parametrize(
    "text",
    (
        "Security Update for KB5094126",
        "https://catalog.update.microsoft.com/Search.aspx?q=KB5094126",
        "Article 5094126",
    ),
)
def test_msrc_cvrf_kb_join_matches_exact_kb_tokens(text: str) -> None:
    result = policy_generator_module._cvrf_kb_join(_fake_cvrf_with_remediation_text(text), "5094126")

    assert result["is_security"] is True
    assert result["cves"] == ["CVE-2026-1234"]
    assert result["evidence_source"] == "msrc_cvrf"


@pytest.mark.parametrize(
    "text",
    (
        "Security Update for KB15094126",
        "Security Update for KB50941260",
        "Security Update for 15094126",
        "Security Update for 5094126a",
        "https://catalog.update.microsoft.com/Search.aspx?q=KB50941260",
        "https://catalog.update.microsoft.com/Search.aspx?q=KB5094127",
    ),
)
def test_msrc_cvrf_kb_join_rejects_substring_false_positives(text: str) -> None:
    result = policy_generator_module._cvrf_kb_join(_fake_cvrf_with_remediation_text(text), "KB5094126")

    assert result == {
        "is_security": False,
        "cves": [],
        "severities": [],
        "products": [],
        "evidence_source": "none",
    }


def test_msrc_cvrf_kb_join_malformed_payload_is_unknown_not_false() -> None:
    result = policy_generator_module._cvrf_kb_join(["not", "a", "mapping"], "KB5094126")  # type: ignore[arg-type]

    assert result == {
        "is_security": None,
        "cves": [],
        "severities": [],
        "products": [],
        "evidence_source": "unavailable",
    }


def test_msrc_cvrf_kb_absent_is_not_security() -> None:
    result = policy_generator_module._cvrf_kb_join(FAKE_MSRC_CVRF_WITHOUT_KB5094126, "KB5094126")

    assert result == {
        "is_security": False,
        "cves": [],
        "severities": [],
        "products": [],
        "evidence_source": "none",
    }


def test_support_article_enrichment_adds_diagnostic_context_and_dashboard_summary() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_raw_id(
            ATOM_ENTRY_ID,
            "June 9, 2026&#8212;KB5094126 (OS Builds 26200.8655 and 26100.8655) - Microsoft Support",
        )
    )
    fetched: list[tuple[str, float, int]] = []

    def fetcher(url: str, timeout: float, max_bytes: int) -> str:
        fetched.append((url, timeout, max_bytes))
        return KB5094126_SUPPORT_HTML

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        atom_feed_xml=atom,
        support_article_fetcher=fetcher,
        support_article_timeout=3.5,
    )

    assert fetched == [(KB5094126_SUPPORT_URL, 3.5, policy_generator_module.DEFAULT_MAX_SUPPORT_ARTICLE_BYTES)]
    article = policy.source_diagnostics["support_articles"][KB5094126_SUPPORT_URL]
    assert article["status"] == "ok"
    assert article["kb_article"] == "KB5094126"
    assert article["builds"] == ["26200.8655", "26100.8655"]
    assert article["is_security"] is True
    assert article["security_evidence_source"] == "support_article"
    assert article["improvement_labels"] == ["Secure Boot", "Virtualization", "desktop.ini", "AI components"]

    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8655"
    )
    assert event["support_article_status"] == "ok"
    assert event["support_article_title"] == "June 9, 2026-KB5094126 (OS Builds 26200.8655 and 26100.8655)"
    assert event["support_article_known_issue_status"] == "not_currently_aware"
    assert event["support_article_improvement_labels"] == [
        "Secure Boot",
        "Virtualization",
        "desktop.ini",
        "AI components",
    ]
    assert event["is_security"] is True
    assert event["security_evidence_source"] == "support_article"
    assert event["user_message"] == (
        "Security Patch June 2026: Windows 11 KB5094126 moves 25H2 to 26200.8655; "
        "public notes mention Secure Boot, Virtualization, desktop.ini, and AI components."
    )

    index = policy_generator_module.render_policy_index(policy, policy_bytes=None, signature=None)
    assert event["user_message"] in index
    assert "Atom feed shows a newer non-preview build for the broad target" in index
    validate_policy_document(policy.to_dict())


def test_support_article_kb_mismatch_does_not_contaminate_summary_or_security() -> None:
    policy = _kb5094126_policy_with_support_html(
        _support_article_html(kb_article="KB5000000", builds=("26200.1111",), security=True)
    )

    event = _kb5094126_atom_event(policy)
    assert event["support_article_validation_status"] == "mismatch"
    assert event["support_article_validation_reasons"] == ["kb_mismatch", "build_missing"]
    assert event["support_article_expected_kb"] == "KB5094126"
    assert event["support_article_expected_build"] == "26200.8655"
    assert event["support_article_expected_release"] == "25H2"
    assert event["kb_article"] == "KB5094126"
    assert event["build"] == "26200.8655"
    assert "support_article_kb_article" not in event
    assert "support_article_title" not in event
    assert event.get("user_message") is None
    assert event["is_security"] is None
    assert event["security_evidence_source"] == "unavailable"
    assert event["support_article_status"] == "ok"
    assert "Security patch" not in policy_generator_module._source_diagnostic_row_from_event(event)["tags"]

    summaries = [
        str(item.get("user_message") or item.get("notice_summary") or "")
        for item in policy.source_diagnostics["events"]
    ]
    assert all("KB5000000" not in summary for summary in summaries)
    mismatch = next(
        item for item in policy.source_diagnostics["events"] if item["kind"] == "support_article_enrichment_mismatch"
    )
    assert mismatch["severity"] == "warning"
    assert mismatch["support_article_validation_reasons"] == ["kb_mismatch", "build_missing"]
    article = policy.source_diagnostics["support_articles"][KB5094126_SUPPORT_URL]
    assert article["support_article_validation_status"] == "mismatch"
    assert article["security_evidence_source"] == "unavailable"
    assert "security_signals" not in article
    validate_policy_document(policy.to_dict())


def test_support_article_build_mismatch_is_not_validation_ok() -> None:
    policy = _kb5094126_policy_with_support_html(
        _support_article_html(kb_article="KB5094126", builds=("26200.1111",), security=True)
    )

    event = _kb5094126_atom_event(policy)
    assert event["support_article_validation_status"] == "mismatch"
    assert event["support_article_validation_reasons"] == ["build_missing"]
    assert event["support_article_expected_build"] == "26200.8655"
    assert "support_article_builds" not in event
    assert event["is_security"] is None
    assert event["security_evidence_source"] == "unavailable"
    assert event.get("user_message") is None


def test_support_article_incompatible_applies_to_is_visible_but_untrusted() -> None:
    policy = _kb5094126_policy_with_support_html(
        _support_article_html(
            kb_article="KB5094126",
            builds=("26200.8655",),
            applies_to="Windows 10, version 22H2",
            security=True,
        )
    )

    event = _kb5094126_atom_event(policy)
    assert event["support_article_validation_status"] == "mismatch"
    assert event["support_article_validation_reasons"] == ["applies_to_mismatch"]
    assert event["support_article_applies_to"] == "Windows 10, version 22H2"
    assert event["support_article_expected_release"] == "25H2"
    assert event["is_security"] is None
    assert event["security_evidence_source"] == "unavailable"
    assert event.get("user_message") is None


def test_support_article_partial_compatible_article_is_degraded_atom_grounded_summary() -> None:
    policy = _kb5094126_policy_with_support_html(
        _support_article_html(
            kb_article="KB5094126",
            builds=(),
            applies_to="Windows 11, version 25H2",
            security=False,
            labels=(),
        )
    )

    event = _kb5094126_atom_event(policy)
    assert event["support_article_validation_status"] == "degraded"
    assert event["support_article_validation_reasons"] == ["builds_missing"]
    assert event["support_article_expected_kb"] == "KB5094126"
    assert event["support_article_expected_build"] == "26200.8655"
    assert event["support_article_title"] == "June 9, 2026-KB5094126"
    assert "support_article_builds" not in event
    assert event["is_security"] is None
    assert event["security_evidence_source"] == "unavailable"
    assert event["user_message"] == (
        "Windows Update June 2026: Windows 11 KB5094126 moves 25H2 to 26200.8655; "
        "support article validation degraded: builds_missing."
    )
    assert "KB5000000" not in event["user_message"]
    degraded = next(
        item for item in policy.source_diagnostics["events"] if item["kind"] == "support_article_enrichment_degraded"
    )
    assert degraded["support_article_validation_reasons"] == ["builds_missing"]


def test_msrc_exact_kb_security_survives_mismatched_support_article() -> None:
    policy = _kb5094126_policy_with_support_html(
        _support_article_html(kb_article="KB5000000", builds=("26200.1111",), security=True),
        msrc_payload=FAKE_MSRC_CVRF_WITH_KB5094126,
    )

    event = _kb5094126_atom_event(policy)
    assert event["support_article_validation_status"] == "mismatch"
    assert event["security_evidence_source"] == "msrc_cvrf"
    assert event["is_security"] is True
    assert "cves" not in event
    assert event["msrc_cvrf_status"] == "ok"
    assert event.get("user_message") is None
    assert "support_article_kb_article" not in event
    assert "security_signals" not in event
    assert "Security patch" in policy_generator_module._source_diagnostic_row_from_event(event)["tags"]


def test_support_article_validation_renders_and_exports_without_raw_html(tmp_path: Path) -> None:
    bad_html = _support_article_html(kb_article="KB5000000", builds=("26200.1111",), security=True)
    policy = _kb5094126_policy_with_support_html(bad_html)
    written = write_policy_outputs(policy, output_dir=tmp_path, write_index=True, write_manifest=True)
    generated_policy = json.loads(written["policy"].read_text(encoding="utf-8"))
    index = written["index"].read_text(encoding="utf-8")
    policy_json = json.dumps(generated_policy, sort_keys=True)
    event = _kb5094126_atom_event(policy)

    validate_policy_document(generated_policy)
    assert event["id"] in index
    assert 'data-support-article-validation-status="mismatch"' in index
    assert 'data-support-article-validation-reasons="kb_mismatch, build_missing"' in index
    assert 'data-support-article-expected-kb="KB5094126"' in index
    assert 'data-support-article-expected-build="26200.8655"' in index
    assert 'data-support-article-expected-release="25H2"' in index
    assert "addListAttr('data-support-article-validation-reasons','support_article_validation_reasons')" in index
    assert "Support article mismatch" in index
    assert "Validation reasons: kb_mismatch, build_missing." in index
    assert "KB5000000 moves" not in index
    assert "window.secret" not in index
    assert "window.secret" not in policy_json
    assert bad_html.strip() not in policy_json
    visible_row = policy_generator_module._source_diagnostic_row_from_event(event)
    assert visible_row["support_article_validation_status"] == "mismatch"
    assert visible_row["support_article_validation_reasons"] == ["kb_mismatch", "build_missing"]


def test_msrc_cvrf_marks_atom_diagnostic_as_security_and_uses_single_month_fetch() -> None:
    second_support_url = (
        "https://support.microsoft.com/en-us/topic/"
        "june-9-2026-kb5094127-os-build-26200-8660-1a9bcba6-5f53-4075-8156-fe11ac631738"
    )
    atom = _atom_feed_with_entries(
        _atom_entry_with_raw_id(
            ATOM_ENTRY_ID,
            "June 9, 2026&#8212;KB5094126 (OS Build 26200.8655) - Microsoft Support",
        ),
        _atom_entry_with_raw_id(
            "uuid:07747009-7264-44f2-86c2-1c3e09919af4;id=968481",
            "June 9, 2026&#8212;KB5094127 (OS Build 26200.8660) - Microsoft Support",
            link=second_support_url,
        ),
    )
    msrc_urls: list[tuple[str, float, int]] = []

    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        return KB5094126_SUPPORT_HTML_NO_SECURITY

    def msrc_fetcher(url: str, timeout: float, max_bytes: int):
        msrc_urls.append((url, timeout, max_bytes))
        return FAKE_MSRC_CVRF_WITH_KB5094126

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        atom_feed_xml=atom,
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
        msrc_cvrf_timeout=4.0,
    )

    assert msrc_urls == [
        (
            "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun",
            4.0,
            policy_generator_module.DEFAULT_MAX_MSRC_CVRF_BYTES,
        )
    ]
    assert policy.source_diagnostics["msrc_cvrf"]["2026-Jun"]["status"] == "ok"
    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history"
        and event["kb_article"] == "KB5094126"
        and event["build"] == "26200.8655"
    )
    assert event["kb_update_bucket"] == "OS Build Update"
    assert event["kb_update_bucket_confidence"] == "low"
    assert event["is_security"] is True
    assert event["security_evidence_source"] == "msrc_cvrf"
    assert "cves" not in event
    assert event["security_severities"] == ["Critical", "Important"]
    assert event["security_products"] == ["11568", "11569", "11570"]
    assert event["msrc_cvrf_month_id"] == "2026-Jun"
    assert event["msrc_cvrf_status"] == "ok"
    assert "Security Patch June 2026" in event["user_message"]

    row = policy_generator_module._source_diagnostic_row_from_event(event)
    assert "Security patch" in row["tags"]
    assert "CVEs 2" not in row["tags"]
    assert "cves" not in row


def test_kb5094126_fixture_end_to_end_policy_dashboard_manifest_and_issue_title(tmp_path: Path) -> None:
    support_calls: list[tuple[str, float, int]] = []
    msrc_calls: list[tuple[str, float, int]] = []

    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        support_calls.append((url, timeout, max_bytes))
        assert url == KB5094126_SUPPORT_URL
        return _kb5094126_support_fixture()

    def msrc_fetcher(url: str, timeout: float, max_bytes: int) -> dict[str, object]:
        msrc_calls.append((url, timeout, max_bytes))
        assert url == "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun"
        return _kb5094126_msrc_fixture()

    policy = generate_policy(
        release_health_html=_html_file("windows11-release-health-current-d-26h1.html"),
        atom_feed_xml=_kb5094126_atom_fixture(),
        generated_at_utc="2026-06-11T18:00:00+00:00",
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )
    data = policy.to_dict()
    validate_policy_document(data)

    assert support_calls == [
        (
            KB5094126_SUPPORT_URL,
            policy_generator_module.DEFAULT_HTTP_TIMEOUT_SECONDS,
            policy_generator_module.DEFAULT_MAX_SUPPORT_ARTICLE_BYTES,
        )
    ]
    assert msrc_calls == [
        (
            "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun",
            policy_generator_module.DEFAULT_HTTP_TIMEOUT_SECONDS,
            policy_generator_module.DEFAULT_MAX_MSRC_CVRF_BYTES,
        )
    ]

    target = policy.broad_target_existing_devices
    assert target is not None
    assert target.version == "25H2"
    assert target.latest_build == "26200.8524"
    assert target.latest_observed_build == "26200.8655"
    assert target.required_baseline_build == "26200.8457"
    assert target.metadata["latest_observed_source"] == "atom_support_article"
    assert target.metadata["latest_observed_source_url"] == KB5094126_SUPPORT_URL
    assert target.metadata["latest_observed_atom_entry_id"] == ATOM_ENTRY_ID

    current_25h2 = next(
        entry
        for entry in policy.current_versions
        if entry.version == "25H2" and entry.build_family == 26200
    )
    assert current_25h2.latest_build == "26200.8524"
    assert current_25h2.latest_observed_build == "26200.8655"
    assert current_25h2.required_baseline_build == "26200.8457"

    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history"
        and event["kb_article"] == "KB5094126"
        and event["build"] == "26200.8655"
    )
    assert event["id"] == ATOM_SOURCE_DIAGNOSTIC_ID
    assert event["atom_entry_id"] == ATOM_ENTRY_ID
    assert event["atom_support_article_id"] == ATOM_SUPPORT_ARTICLE_ID
    assert event["support_article_status"] == "ok"
    assert event["support_article_url"] == KB5094126_SUPPORT_URL
    assert event["support_article_improvement_labels"] == [
        "Secure Boot",
        "Virtualization",
        "desktop.ini",
        "AI components",
    ]
    assert event["is_security"] is True
    assert event["security_evidence_source"] == "msrc_cvrf"
    assert "cves" not in event
    assert event["security_severities"] == ["Critical", "Important"]
    assert event["msrc_cvrf_status"] == "ok"
    assert event["msrc_cvrf_month_id"] == "2026-Jun"
    assert event["user_message"] == (
        "Security Patch June 2026: Windows 11 KB5094126 moves 25H2 to 26200.8655; "
        "public notes mention Secure Boot, Virtualization, desktop.ini, and AI components."
    )

    from tools import sync_source_diagnostics_issues as sync_tool

    diagnostic = sync_tool.diagnostics_from_policy({"source_diagnostics": {"events": [event]}})[0]
    issue_body = sync_tool.issue_body(diagnostic)
    assert sync_tool.issue_title(diagnostic).endswith("[id=968480]")
    assert f"Source diagnostic ID: `{ATOM_SOURCE_DIAGNOSTIC_ID}`" in issue_body
    assert f"<!-- {sync_tool.DIAGNOSTIC_ID_COMMENT_PREFIX}: {ATOM_SOURCE_DIAGNOSTIC_ID} -->" in issue_body

    written = write_policy_outputs(
        policy,
        output_dir=tmp_path,
        write_index=True,
        write_manifest=True,
    )
    generated_policy = json.loads(written["policy"].read_text(encoding="utf-8"))
    manifest = json.loads(written["manifest"].read_text(encoding="utf-8"))
    index = written["index"].read_text(encoding="utf-8")
    validate_policy_document(generated_policy)

    assert generated_policy["broad_target_existing_devices"]["latest_build"] == "26200.8524"
    assert generated_policy["broad_target_existing_devices"]["latest_observed_build"] == "26200.8655"
    assert generated_policy["broad_target_existing_devices"]["required_baseline_build"] == "26200.8457"
    assert manifest["latest_observed_build"] == "26200.8655"
    assert manifest["latest_observed_evidence"]["latest_observed_source_url"] == KB5094126_SUPPORT_URL
    assert manifest["latest_observed_evidence"]["latest_observed_atom_entry_id"] == ATOM_ENTRY_ID
    assert "26200.8655" in index
    assert "Microsoft Support article via Atom feed" in index
    assert ATOM_SOURCE_DIAGNOSTIC_ID in index
    assert "Security Patch June 2026" in index
    assert "Security patch" in index
    assert "id=968480" in index
    assert "Atom feed shows a newer non-preview build for the broad target" in index

    policy_json = json.dumps(generated_policy, sort_keys=True)
    support_record_json = json.dumps(
        generated_policy["source_diagnostics"]["support_articles"][KB5094126_SUPPORT_URL],
        sort_keys=True,
    )
    assert "<html" not in policy_json.lower()
    assert "window.secret" not in policy_json
    assert "Microsoft is not currently aware of any issues in this update." not in policy_json
    assert _kb5094126_support_fixture().strip() not in policy_json
    assert len(support_record_json) < 2500


def test_kb5094126_generated_output_when_release_health_has_not_caught_up(tmp_path: Path) -> None:
    policy = _kb5094126_generated_fixture_policy(_html_file("windows11-release-health-current-d-26h1.html"))
    outputs = _generated_output_bundle(policy, tmp_path)
    data = outputs["policy"]
    manifest = outputs["manifest"]
    index = str(outputs["index"])
    assert isinstance(data, dict)
    assert isinstance(manifest, dict)
    _assert_unique_source_diagnostic_ids(data, index)
    _assert_no_raw_support_article_leakage(outputs, _kb5094126_support_fixture())

    target = data["broad_target_existing_devices"]
    assert isinstance(target, dict)
    assert target["version"] == "25H2"
    assert target["latest_build"] == "26200.8524"
    assert target["latest_observed_build"] == "26200.8655"
    assert target["required_baseline_build"] == "26200.8457"
    assert target["metadata"]["latest_observed_source"] == "atom_support_article"
    assert target["metadata"]["latest_observed_source_url"] == KB5094126_SUPPORT_URL
    assert manifest["broad_target_existing_devices"]["latest_build"] == "26200.8524"
    assert manifest["broad_target_existing_devices"]["latest_observed_build"] == "26200.8655"
    assert manifest["broad_target_existing_devices"]["required_baseline_build"] == "26200.8457"
    assert manifest["latest_observed_evidence"]["latest_observed_source"] == "atom_support_article"

    events = data["source_diagnostics"]["events"]
    atom_events = [
        event
        for event in events
        if event["kind"] == "atom_newer_than_release_history"
        and event["kb_article"] == "KB5094126"
        and event["build"] in {"26100.8655", "26200.8655"}
    ]
    assert [(event["severity"], event["release"], event["build"]) for event in atom_events] == [
        ("notice", "24H2", "26100.8655"),
        ("warning", "25H2", "26200.8655"),
    ]
    notice = next(event for event in atom_events if event["release"] == "24H2")
    warning = next(event for event in atom_events if event["release"] == "25H2")
    assert warning["id"] == ATOM_SOURCE_DIAGNOSTIC_ID
    assert re.fullmatch(r"wrg-source-diagnostic-v1:[0-9a-f]{16}", notice["id"])
    assert notice["id"] != warning["id"]
    assert warning["support_article_validation_status"] == "ok"
    assert notice["support_article_validation_status"] == "ok"
    assert ATOM_SOURCE_DIAGNOSTIC_ID in _rendered_diagnostic_ids(index)
    assert "https://support.microsoft.com/help/5094126" not in index


def test_kb5094126_generated_output_when_release_health_has_caught_up(tmp_path: Path) -> None:
    policy = _kb5094126_generated_fixture_policy(_release_health_caught_up_to_kb5094126())
    outputs = _generated_output_bundle(policy, tmp_path)
    data = outputs["policy"]
    manifest = outputs["manifest"]
    index = str(outputs["index"])
    assert isinstance(data, dict)
    assert isinstance(manifest, dict)
    _assert_unique_source_diagnostic_ids(data, index)
    _assert_no_raw_support_article_leakage(outputs, _kb5094126_support_fixture())

    target = data["broad_target_existing_devices"]
    assert isinstance(target, dict)
    assert target["latest_build"] == "26200.8655"
    assert target["latest_observed_build"] == "26200.8655"
    assert target["required_baseline_build"] == "26200.8655"
    assert manifest["broad_target_existing_devices"]["latest_build"] == "26200.8655"
    assert manifest["broad_target_existing_devices"]["latest_observed_build"] == "26200.8655"
    assert manifest["broad_target_existing_devices"]["required_baseline_build"] == "26200.8655"

    events = data["source_diagnostics"]["events"]
    assert not any(
        event["kind"] == "atom_newer_than_release_history"
        and event.get("release") == "25H2"
        and event.get("build") == "26200.8655"
        for event in events
    )
    assert "Atom feed shows a newer non-preview build for the broad target" not in index


def test_caught_up_kb5094126_creates_active_baseline_update_notice(tmp_path: Path) -> None:
    policy = _kb5094126_generated_fixture_policy(_release_health_caught_up_to_kb5094126())
    outputs = _generated_output_bundle(policy, tmp_path)
    data = outputs["policy"]
    index = str(outputs["index"])
    assert isinstance(data, dict)
    source_diagnostics = data["source_diagnostics"]
    assert isinstance(source_diagnostics, dict)

    notice = source_diagnostics["baseline_update_notice"]
    assert notice == {
        "schema": "win11_release_guard.baseline_update_notice.v1",
        "active": True,
        "release": "25H2",
        "build_family": 26200,
        "build": "26200.8655",
        "kb_article": "KB5094126",
        "update_type": "2026-06 B",
        "quality_policy": "b_release_only",
        "summary": (
            "New required baseline: Windows 11 25H2 build 26200.8655 now matches the latest observed "
            "Microsoft build. KB5094126 is the 2026-06 B security baseline; Atom first spotted it at "
            "2026-06-09T17:04:01Z, and Release Health lists the baseline date as 2026-06-09."
        ),
        "update_summary": (
            "Update highlights: Secure Boot: Updates hardening for startup components. "
            "Virtualization: Improves reliability for protected workloads. desktop.ini: Hardens "
            "desktop.ini processing. AI components: Updates Windows AI components."
        ),
        "technical_summary": (
            "Release Health B-release row 2026-06 B selected 25H2/26200 build 26200.8655; support "
            "validation ok; security evidence trusted via msrc_cvrf."
        ),
        "source_url": KB5094126_SUPPORT_URL,
        "atom_entry_id": ATOM_ENTRY_ID,
        "atom_support_article_id": ATOM_SUPPORT_ARTICLE_ID,
        "first_spotted_atom_published_utc": "2026-06-09T17:04:01Z",
        "support_article_updated_utc": "2026-06-10T17:20:31Z",
        "official_release_date": "2026-06-09",
        "official_release_precision": "date",
        "release_health_latest_revision_date": "2026-06-09",
        "visible_from_utc": "2026-06-09T00:00:00Z",
        "visible_until_utc": "2026-06-30T00:00:00Z",
        "policy_generated_at_utc": "2026-06-11T18:00:00+00:00",
        "is_security": True,
        "security_evidence_source": "msrc_cvrf",
        "security_evidence_status": "trusted",
        "support_article_validation_status": "ok",
        "support_article_improvement_labels": [
            "Secure Boot",
            "Virtualization",
            "desktop.ini",
            "AI components",
        ],
        "support_article_improvement_details": [
            "Secure Boot: Updates hardening for startup components.",
            "Virtualization: Improves reliability for protected workloads.",
            "desktop.ini: Hardens desktop.ini processing.",
            "AI components: Updates Windows AI components.",
        ],
    }
    event = next(
        event
        for event in source_diagnostics["events"]
        if event["kind"] == "required_baseline_matched_latest_observed"
    )
    assert event["severity"] == "notice"
    assert event["release"] == "25H2"
    assert event["build"] == "26200.8655"
    assert event["kb_article"] == "KB5094126"
    assert event["is_security"] is True
    assert event["security_evidence_source"] == "msrc_cvrf"
    assert "cves" not in event
    assert "New required baseline" in index

    from tools import sync_source_diagnostics_issues as sync_tool

    assert sync_tool.diagnostics_from_policy({"source_diagnostics": {"events": [event]}}) == []


def test_caught_up_kb5094126_renders_baseline_update_notice_before_operational_panels(tmp_path: Path) -> None:
    policy = _kb5094126_generated_fixture_policy(_release_health_caught_up_to_kb5094126())
    outputs = _generated_output_bundle(policy, tmp_path)
    index = str(outputs["index"])
    data = outputs["policy"]
    assert isinstance(data, dict)
    HTMLParser().feed(index)

    notice_marker = 'class="panel span-12 baseline-update-notice"'
    freshness_marker = 'id="live-freshness-panel"'
    diagnostics_marker = 'class="panel span-7 source-diagnostics"'
    assert notice_marker in index
    assert index.index(notice_marker) < index.index(freshness_marker)
    assert index.index(notice_marker) < index.index(diagnostics_marker)
    assert 'class="grid dashboard-grid has-baseline-notice"' in index
    assert 'role="status" aria-live="polite" data-baseline-notice="active"' in index
    assert 'data-baseline-notice-build="26200.8655"' in index
    assert 'data-baseline-notice-kb="KB5094126"' in index
    assert 'data-baseline-notice-visible-until="2026-06-30T00:00:00Z"' in index
    assert f'data-baseline-notice-source-url="{KB5094126_SUPPORT_URL}"' in index
    assert 'data-baseline-notice-security-url="https://msrc.microsoft.com/update-guide"' in index
    assert "New required baseline: 25H2 build 26200.8655" in index
    assert "KB5094126" in index
    assert "2026-06 B" in index
    assert "Security confirmed by MSRC" in index
    assert "MSRC CVE entries: 2" not in index
    assert "data-cves=" not in index
    assert "data-cve-count=" not in index
    assert (
        '<div class="baseline-review"><span class="baseline-review-label">Update highlights:</span>'
        '<ul class="baseline-review-list"><li>Secure Boot: Updates hardening for startup components.</li>'
        '<li>Virtualization: Improves reliability for protected workloads.</li>'
        '<li>desktop.ini: Hardens desktop.ini processing.</li>'
        '<li>AI components: Updates Windows AI components.</li></ul>'
        f' <a class="baseline-read-more" href="{KB5094126_SUPPORT_URL}" '
        'rel="noopener noreferrer">Read more</a></div>'
    ) in index
    assert "Atom first spotted June 9, 2026 at 19:04 CEST / 17:04 UTC" in index
    assert "Support updated June 10, 2026 at 19:20 CEST / 17:20 UTC" in index
    assert "Official baseline date: 2026-06-09 (Release Health date-only)" in index
    assert "Visible until June 30, 2026 at 02:00 CEST / 00:00 UTC" in index
    assert 'baseline source. Security evidence: Security confirmed by MSRC.</p>' in index
    assert "Atom first spotted 2026-06-09T17:04:01Z" not in index
    assert "Support updated 2026-06-10T17:20:31Z" not in index
    assert "update-guide/vulnerability/CVE-2026-0001" not in index
    assert "baseline update notice expiry" in index
    assert "Date.parse(until)" in index
    assert ".baseline-update-notice{position:relative" in index
    assert '<span class="baseline-chip">KB5094126</span>' in index
    assert '<span class="baseline-chip security">Security confirmed by MSRC</span>' in index
    assert '<span class="baseline-chip security">MSRC CVE entries: 2</span>' not in index
    notice_html = index[
        index.index(notice_marker) : index.index(freshness_marker)
    ]
    assert notice_html.count(f'href="{KB5094126_SUPPORT_URL}"') == 1
    assert ".baseline-read-more" in index
    assert ".dashboard-grid.has-baseline-notice .baseline-update-notice{grid-column:1/-1;grid-row:1}" in index
    assert ".dashboard-grid.has-baseline-notice #live-freshness-panel{grid-row:2/span 2}" in index
    assert ".dashboard-grid.has-baseline-notice .source-diagnostics{grid-row:2/span 2}" in index
    assert ".dashboard-grid.has-baseline-notice.diagnostics-expanded .source-diagnostics{grid-row:2/span 3}" in index
    assert "script src" not in index.lower()
    assert "rel=\"stylesheet\"" not in index.lower()
    assert "github_token" not in index.lower()
    assert "function visibleDiagnosticEntries()" in index
    _assert_no_raw_support_article_leakage(outputs, _kb5094126_support_fixture())
    validate_policy_document(data)


def test_not_caught_up_kb5094126_does_not_create_baseline_update_notice() -> None:
    policy = _kb5094126_generated_fixture_policy(_html_file("windows11-release-health-current-d-26h1.html"))

    target = policy.broad_target_existing_devices
    assert target is not None
    assert target.required_baseline_build == "26200.8457"
    assert target.latest_observed_build == "26200.8655"
    assert "baseline_update_notice" not in policy.source_diagnostics
    assert not any(
        event["kind"] == "required_baseline_matched_latest_observed"
        for event in policy.source_diagnostics["events"]
    )
    index = policy_generator_module.render_policy_index(policy, policy_bytes=None, signature=None)
    assert 'class="panel span-12 baseline-update-notice"' not in index
    assert "New required baseline:" not in index


def test_caught_up_baseline_update_notice_expires_after_visibility_window() -> None:
    policy = _kb5094126_generated_fixture_policy(
        _release_health_caught_up_to_kb5094126(),
        generated_at_utc="2026-07-01T00:00:00+00:00",
    )

    notice = policy.source_diagnostics["baseline_update_notice"]
    assert notice["active"] is False
    assert notice["visible_from_utc"] == "2026-06-09T00:00:00Z"
    assert notice["visible_until_utc"] == "2026-06-30T00:00:00Z"
    assert not any(
        event["kind"] == "required_baseline_matched_latest_observed"
        for event in policy.source_diagnostics["events"]
    )
    index = policy_generator_module.render_policy_index(policy, policy_bytes=None, signature=None)
    assert 'class="panel span-12 baseline-update-notice"' not in index
    assert "New required baseline:" not in index


def test_baseline_update_notice_and_warnings_panel_use_separate_grid_rows() -> None:
    policy = _kb5094126_generated_fixture_policy(_release_health_caught_up_to_kb5094126())
    warning_policy = replace(
        policy,
        validation_warnings=("Manual validation warning for grid placement.",),
    )

    index = policy_generator_module.render_policy_index(warning_policy, policy_bytes=None, signature=None)

    assert 'class="grid dashboard-grid has-baseline-notice has-validation-warnings"' in index
    assert index.index('class="panel span-12 baseline-update-notice"') < index.index(
        'class="panel span-12 dashboard-warning-panel"'
    )
    assert index.index('class="panel span-12 dashboard-warning-panel"') < index.index(
        'id="live-freshness-panel"'
    )
    assert index.index('class="panel span-12 dashboard-warning-panel"') < index.index(
        'class="panel span-7 source-diagnostics"'
    )
    assert ".dashboard-grid.has-baseline-notice.has-validation-warnings .dashboard-warning-panel{grid-row:2}" in index
    assert ".dashboard-grid.has-baseline-notice.has-validation-warnings #live-freshness-panel{grid-row:3/span 2}" in index
    assert ".dashboard-grid.has-baseline-notice.has-validation-warnings .source-diagnostics{grid-row:3/span 2}" in index
    assert ".dashboard-grid.has-baseline-notice.has-validation-warnings .signature-panel{grid-row:5}" in index
    assert ".dashboard-grid.has-baseline-notice.has-validation-warnings.diagnostics-expanded .source-diagnostics{grid-row:3/span 3}" in index


@pytest.mark.parametrize("update_type", ("2026-06 D Preview", "2026-06 OOB"))
def test_preview_or_oob_baseline_like_rows_do_not_create_baseline_update_notice(update_type: str) -> None:
    policy = _kb5094126_generated_fixture_policy(
        _release_health_caught_up_to_kb5094126_with_update_type(update_type)
    )

    assert "baseline_update_notice" not in policy.source_diagnostics
    assert not any(
        event["kind"] == "required_baseline_matched_latest_observed"
        for event in policy.source_diagnostics["events"]
    )


def test_baseline_update_notice_keeps_release_health_facts_when_support_article_mismatches() -> None:
    policy = _kb5094126_generated_fixture_policy(
        _release_health_caught_up_to_kb5094126(),
        support_html=_support_article_html(kb_article="KB5000000", builds=("26200.1111",), security=True),
        msrc_payload=FAKE_MSRC_CVRF_WITH_KB5094126,
    )

    notice = policy.source_diagnostics["baseline_update_notice"]
    assert notice["active"] is True
    assert notice["kb_article"] == "KB5094126"
    assert notice["build"] == "26200.8655"
    assert notice["support_article_validation_status"] == "mismatch"
    assert notice["support_article_validation_reasons"] == ["kb_mismatch", "build_missing"]
    assert notice["is_security"] is True
    assert notice["security_evidence_source"] == "msrc_cvrf"
    assert "KB5000000" not in notice["summary"]
    assert "26200.1111" not in notice["summary"]
    assert "security baseline" in notice["summary"]


def test_baseline_update_notice_uses_unknown_security_when_msrc_and_article_are_untrusted() -> None:
    policy = _kb5094126_generated_fixture_policy(
        _release_health_caught_up_to_kb5094126(),
        support_html=_support_article_html(security=False, labels=()),
        msrc_error=PolicyFetchError("MSRC unavailable"),
    )

    notice = policy.source_diagnostics["baseline_update_notice"]
    assert notice["active"] is True
    assert notice["security_evidence_source"] == "unavailable"
    assert notice["security_evidence_status"] == "unknown"
    assert "is_security" not in notice
    assert "security baseline" not in notice["summary"]
    assert "security evidence is unknown" in notice["summary"]
    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "required_baseline_matched_latest_observed"
    )
    assert "Security patch" not in policy_generator_module._source_diagnostic_row_from_event(event)["tags"]


def test_generated_output_surfaces_support_article_mismatch_and_degraded_states(tmp_path: Path) -> None:
    mismatch_policy = _kb5094126_generated_fixture_policy(
        _html_file("windows11-release-health-current-d-26h1.html"),
        support_html=_support_article_html(kb_article="KB5000000", builds=("26200.1111",), security=True),
    )
    mismatch_outputs = _generated_output_bundle(mismatch_policy, tmp_path / "mismatch")
    mismatch_data = mismatch_outputs["policy"]
    mismatch_index = str(mismatch_outputs["index"])
    assert isinstance(mismatch_data, dict)
    mismatch_event = _kb5094126_atom_event(mismatch_policy)
    assert mismatch_event["support_article_validation_status"] == "mismatch"
    assert "support_article_kb_article" not in mismatch_event
    assert "support_article_title" not in mismatch_event
    assert any(
        event["kind"] == "support_article_enrichment_mismatch"
        and event["support_article_validation_reasons"] == ["kb_mismatch", "build_missing"]
        for event in mismatch_data["source_diagnostics"]["events"]
    )
    assert "Support article mismatch" in mismatch_index
    assert "KB5000000 moves" not in mismatch_index
    _assert_no_raw_support_article_leakage(
        mismatch_outputs,
        _support_article_html(kb_article="KB5000000", builds=("26200.1111",), security=True),
    )

    degraded_policy = _kb5094126_generated_fixture_policy(
        _html_file("windows11-release-health-current-d-26h1.html"),
        support_html=_support_article_html(
            kb_article="KB5094126",
            builds=(),
            applies_to="Windows 11, version 25H2",
            security=False,
            labels=(),
        ),
        msrc_payload=FAKE_MSRC_CVRF_WITHOUT_KB5094126,
    )
    degraded_outputs = _generated_output_bundle(degraded_policy, tmp_path / "degraded")
    degraded_data = degraded_outputs["policy"]
    degraded_index = str(degraded_outputs["index"])
    assert isinstance(degraded_data, dict)
    assert any(
        event["kind"] == "support_article_enrichment_degraded"
        and event["support_article_validation_reasons"] == ["builds_missing"]
        for event in degraded_data["source_diagnostics"]["events"]
    )
    assert "Support article degraded" in degraded_index
    assert "support article validation degraded: builds_missing" in degraded_index


def test_generated_output_surfaces_msrc_unavailable_and_malformed_as_unknown(tmp_path: Path) -> None:
    unavailable_policy = _kb5094126_generated_fixture_policy(
        _html_file("windows11-release-health-current-d-26h1.html"),
        msrc_error=PolicyFetchError("MSRC unavailable"),
    )
    unavailable_outputs = _generated_output_bundle(unavailable_policy, tmp_path / "unavailable")
    unavailable_data = unavailable_outputs["policy"]
    unavailable_index = str(unavailable_outputs["index"])
    assert isinstance(unavailable_data, dict)
    unavailable_event = _kb5094126_atom_event(unavailable_policy)
    assert unavailable_event["msrc_cvrf_status"] == "error"
    assert unavailable_event["security_evidence_source"] == "support_article"
    assert unavailable_event["is_security"] is True
    assert any(
        event["kind"] == "msrc_cvrf_enrichment_unavailable"
        for event in unavailable_data["source_diagnostics"]["events"]
    )
    assert "MSRC CVRF enrichment for 2026-Jun is error" in unavailable_index

    malformed_policy = _kb5094126_generated_fixture_policy(
        _html_file("windows11-release-health-current-d-26h1.html"),
        support_html=KB5094126_SUPPORT_HTML_NO_SECURITY,
        msrc_payload=["not", "a", "cvrf", "object"],
    )
    malformed_outputs = _generated_output_bundle(malformed_policy, tmp_path / "malformed")
    malformed_data = malformed_outputs["policy"]
    malformed_index = str(malformed_outputs["index"])
    assert isinstance(malformed_data, dict)
    malformed_event = _kb5094126_atom_event(malformed_policy)
    assert malformed_event["msrc_cvrf_status"] == "degraded"
    assert malformed_event["is_security"] is None
    assert malformed_event["security_evidence_source"] == "unavailable"
    assert any(
        event["kind"] == "msrc_cvrf_enrichment_unavailable"
        for event in malformed_data["source_diagnostics"]["events"]
    )
    assert "Security patch" not in policy_generator_module._source_diagnostic_row_from_event(malformed_event)["tags"]
    assert "MSRC CVRF enrichment for 2026-Jun is degraded" in malformed_index


def test_msrc_cvrf_absent_kb_keeps_generic_os_build_non_security() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_raw_id(
            ATOM_ENTRY_ID,
            "June 9, 2026&#8212;KB5094126 (OS Builds 26200.8655 and 26100.8655) - Microsoft Support",
        )
    )

    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        return KB5094126_SUPPORT_HTML_NO_SECURITY

    def msrc_fetcher(url: str, timeout: float, max_bytes: int):
        return FAKE_MSRC_CVRF_WITHOUT_KB5094126

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        atom_feed_xml=atom,
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )
    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8655"
    )

    assert event["kb_update_bucket"] == "OS Build Update"
    assert event["kb_update_bucket_confidence"] == "low"
    assert event["is_security"] is False
    assert event["security_evidence_source"] == "none"
    assert "cves" not in event
    assert "Security Patch" not in event["user_message"]
    assert "Security patch" not in policy_generator_module._source_diagnostic_row_from_event(event)["tags"]


def test_msrc_cvrf_unavailable_uses_support_article_security_fallback() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_raw_id(
            ATOM_ENTRY_ID,
            "June 9, 2026&#8212;KB5094126 (OS Builds 26200.8655 and 26100.8655) - Microsoft Support",
        )
    )

    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        return KB5094126_SUPPORT_HTML

    def msrc_fetcher(url: str, timeout: float, max_bytes: int):
        raise PolicyFetchError("MSRC unavailable")

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        atom_feed_xml=atom,
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )
    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8655"
    )

    assert policy.source_diagnostics["msrc_cvrf"]["2026-Jun"]["status"] == "error"
    assert policy.source_diagnostics["msrc_cvrf"]["2026-Jun"]["error"] == "MSRC unavailable"
    assert event["is_security"] is True
    assert event["security_evidence_source"] == "support_article"
    assert "cves" not in event
    assert event["msrc_cvrf_status"] == "error"
    assert event["msrc_cvrf_error"] == "MSRC unavailable"
    assert event["user_message"].startswith("Security Patch June 2026")
    assert any(
        item["kind"] == "msrc_cvrf_enrichment_unavailable"
        and item["msrc_cvrf_month_id"] == "2026-Jun"
        for item in policy.source_diagnostics["events"]
    )


def test_malformed_msrc_cvrf_is_nonfatal_unknown_security_status() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_raw_id(
            ATOM_ENTRY_ID,
            "June 9, 2026&#8212;KB5094126 (OS Builds 26200.8655 and 26100.8655) - Microsoft Support",
        )
    )

    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        return KB5094126_SUPPORT_HTML_NO_SECURITY

    def msrc_fetcher(url: str, timeout: float, max_bytes: int):
        return ["not", "a", "cvrf", "object"]

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        atom_feed_xml=atom,
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )
    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8655"
    )

    assert policy.source_diagnostics["msrc_cvrf"]["2026-Jun"]["status"] == "degraded"
    assert event["is_security"] is None
    assert event["security_evidence_source"] == "unavailable"
    assert event["msrc_cvrf_status"] == "degraded"
    assert any(item["kind"] == "msrc_cvrf_enrichment_unavailable" for item in policy.source_diagnostics["events"])


def test_support_article_fetch_failure_is_source_diagnostic_metadata() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_raw_id(
            ATOM_ENTRY_ID,
            "June 9, 2026&#8212;KB5094126 (OS Builds 26200.8655 and 26100.8655) - Microsoft Support",
        )
    )

    def fetcher(url: str, timeout: float, max_bytes: int) -> str:
        raise PolicyFetchError("network unavailable")

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        atom_feed_xml=atom,
        support_article_fetcher=fetcher,
    )

    article = policy.source_diagnostics["support_articles"][KB5094126_SUPPORT_URL]
    assert article["status"] == "error"
    assert article["error"] == "network unavailable"
    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "support_article_enrichment_unavailable"
    )
    assert event["severity"] == "warning"
    assert event["support_article_status"] == "error"
    assert event["support_article_error"] == "network unavailable"
    assert event["source_url"] == KB5094126_SUPPORT_URL
    assert event["affects_broad_target"] is True
    assert event["affects_required_baseline"] is False
    atom_event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8655"
    )
    assert atom_event["support_article_status"] == "error"
    assert atom_event["support_article_error"] == "network unavailable"
    assert atom_event["is_security"] is None
    assert atom_event["security_evidence_source"] == "unavailable"


def test_malformed_support_article_html_is_degraded_metadata() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_raw_id(
            ATOM_ENTRY_ID,
            "June 9, 2026&#8212;KB5094126 (OS Builds 26200.8655 and 26100.8655) - Microsoft Support",
        )
    )

    def fetcher(url: str, timeout: float, max_bytes: int) -> str:
        return "<html><head><script>ignored()</script></head><body><svg>ignored</svg></body></html>"

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        atom_feed_xml=atom,
        support_article_fetcher=fetcher,
    )

    article = policy.source_diagnostics["support_articles"][KB5094126_SUPPORT_URL]
    assert article["status"] == "degraded"
    assert article["reason"] == "support_article_parse_incomplete"
    assert "ignored" not in json.dumps(article)
    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "support_article_enrichment_degraded"
    )
    assert event["support_article_status"] == "degraded"
    assert event["support_article_reason"] == "support_article_parse_incomplete"
    atom_event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history" and event["build"] == "26200.8655"
    )
    assert atom_event["message"].startswith("Atom feed shows a newer non-preview build")
    assert atom_event["support_article_status"] == "degraded"
    assert atom_event["support_article_reason"] == "support_article_parse_incomplete"


def test_atom_support_missing_href_creates_diagnostic_without_help_fallback() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_raw_id(
            ATOM_ENTRY_ID,
            "June 9, 2026&#8212;KB5094126 (OS Builds 26200.8655 and 26100.8655) - Microsoft Support",
            link="",
        )
    )
    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        atom_feed_xml=atom,
    )
    target = policy.broad_target_existing_devices
    assert target is not None
    assert target.latest_build == "26200.8524"
    assert target.latest_observed_build == "26200.8524"
    assert "latest_observed_source_url" not in target.metadata

    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_support_article_href_missing"
    )
    assert event["severity"] == "warning"
    assert event["release"] == "25H2"
    assert event["build"] == "26200.8655"
    assert event["kb_article"] == "KB5094126"
    assert event["affects_broad_target"] is True
    assert event["affects_required_baseline"] is True
    assert event["atom_entry_id"] == ATOM_ENTRY_ID
    assert "https://support.microsoft.com/help/5094126" not in json.dumps(policy.to_dict())


@pytest.mark.parametrize(
    "href",
    (
        "http://support.microsoft.com/en-us/topic/kb5094126",
        "https://example.com/en-us/topic/kb5094126",
        "https://support.microsoft.com/feed/atom/kb5094126",
    ),
)
def test_malformed_or_non_support_atom_href_is_not_fetched(href: str) -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_raw_id(
            ATOM_ENTRY_ID,
            "June 9, 2026&#8212;KB5094126 (OS Builds 26200.8655 and 26100.8655) - Microsoft Support",
            link=href,
        )
    )

    def fetcher(url: str, timeout: float, max_bytes: int) -> str:
        raise AssertionError(f"unexpected support article fetch: {url}")

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        atom_feed_xml=atom,
        support_article_fetcher=fetcher,
    )

    target = policy.broad_target_existing_devices
    assert target is not None
    assert parse_atom_feed(atom)[0].link is None
    assert target.latest_observed_build == "26200.8524"
    assert not policy.source_diagnostics["support_articles"]
    missing = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_support_article_href_missing"
    )
    assert missing["kb_article"] == "KB5094126"
    assert missing["build"] == "26200.8655"
    assert "atom_feed_url" not in missing
    assert "support_url" not in missing


def test_preview_atom_support_entry_does_not_update_latest_observed() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_raw_id(
            ATOM_ENTRY_ID,
            "June 9, 2026&#8212;KB5094126 Preview (OS Builds 26200.8655 and 26100.8655)",
        )
    )
    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        atom_feed_xml=atom,
    )

    target = policy.broad_target_existing_devices
    assert target is not None
    assert target.latest_build == "26200.8524"
    assert target.latest_observed_build == "26200.8524"
    assert "latest_observed_source" not in target.metadata


def test_out_of_band_atom_support_entry_does_not_update_latest_observed() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry_with_raw_id(
            ATOM_ENTRY_ID,
            "June 9, 2026&#8212;KB5094126 Out-of-band (OS Builds 26200.8655 and 26100.8655)",
        )
    )
    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        atom_feed_xml=atom,
    )

    target = policy.broad_target_existing_devices
    assert target is not None
    assert target.latest_build == "26200.8524"
    assert target.latest_observed_build == "26200.8524"
    assert "latest_observed_source" not in target.metadata


def test_source_diagnostics_dedupes_duplicate_atom_ids_by_newest_updated() -> None:
    atom = _atom_feed_with_entries(
        _atom_entry(
            "KB5094126",
            "June 9, 2026-KB5094126 (OS Build 26200.8655)",
            updated="2026-06-09T17:20:31Z",
            link=KB5094126_SUPPORT_URL,
        ),
        _atom_entry_with_raw_id(
            ATOM_ENTRY_ID,
            "June 9, 2026&#8212;KB5094126 (OS Build 26200.8655) - Microsoft Support",
            updated="2026-06-10T17:20:31Z",
        ),
    )
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=atom)
    events = [
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history"
        and event["build"] == "26200.8655"
        and event["kb_article"] == "KB5094126"
    ]

    assert len(events) == 1
    assert events[0]["id"] == ATOM_SOURCE_DIAGNOSTIC_ID
    assert events[0]["atom_entry_id"] == ATOM_ENTRY_ID


def test_source_diagnostics_dedupes_duplicate_atom_ids_by_stable_id_tiebreaker() -> None:
    earlier_entry_id = "uuid:00000000-0000-4000-8000-000000000001;id=111"
    later_entry_id = "uuid:ffffffff-ffff-4fff-8fff-ffffffffffff;id=999"
    atom = _atom_feed_with_entries(
        _atom_entry_with_raw_id(
            later_entry_id,
            "June 9, 2026-KB5094126 (OS Build 26200.8655)",
            updated="2026-06-10T17:20:31Z",
        ),
        _atom_entry_with_raw_id(
            earlier_entry_id,
            "June 9, 2026-KB5094126 (OS Build 26200.8655)",
            updated="2026-06-10T17:20:31Z",
        ),
    )
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=atom)
    event = next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history"
        and event["build"] == "26200.8655"
        and event["kb_article"] == "KB5094126"
    )

    assert event["atom_entry_id"] == earlier_entry_id
    assert event["id"] == f"{SOURCE_DIAGNOSTIC_ID_PREFIX}:{earlier_entry_id}"


def test_source_diagnostics_unresolved_after_24h_only_for_warning_drift() -> None:
    policy = generate_policy(
        release_health_html=_html(),
        atom_feed_xml=_atom_with_new_b_release(),
        generated_at_utc="2026-06-11T18:00:00+00:00",
    )
    events = policy.source_diagnostics["events"]

    assert policy.source_diagnostics["drift"]["generated_after_newest_source_hours"] == 48.0
    assert any(
        event["kind"] == "atom_newer_than_release_history"
        and event["severity"] == "warning"
        and event["affects_required_baseline"] is True
        for event in events
    )
    unresolved = next(event for event in events if event["kind"] == "source_drift_unresolved_after_24h")
    assert unresolved["severity"] == "warning"
    assert unresolved["affects_broad_target"] is True
    assert unresolved["affects_required_baseline"] is False


def test_source_diagnostics_dedupes_duplicate_atom_events():
    policy = generate_policy(
        release_health_html=_html(),
        atom_feed_xml=_atom_with_duplicate_new_b_release(),
    )
    events = [
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history"
        and event["build"] == "26200.8461"
        and event["kb_article"] == "KB5089600"
    ]

    assert len(events) == 1


def test_source_diagnostics_warn_when_current_versions_lag_release_history():
    policy = generate_policy(release_health_html=_with_oob_row(_html()), atom_feed_xml=_atom())
    drift = policy.source_diagnostics["drift"]["current_version_latest_older_than_release_history"]

    assert drift[0]["version"] == "25H2"
    assert drift[0]["latest_build"] == "26200.8457"
    assert drift[0]["newest_release_history_build"] == "26200.8460"
    assert any("Current Versions latest_build appears older" in warning for warning in policy.validation_warnings)


def test_policy_schema_accepts_source_diagnostics_without_unknown_key_warning():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom())

    warnings = validate_policy_document(policy.to_dict())

    assert not any("unknown top-level key 'source_diagnostics'" in warning for warning in warnings)


def test_policy_schema_accepts_structured_source_diagnostics_events():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom_with_new_b_release())
    data = policy.to_dict()

    validate_policy_document(data)

    assert data["source_diagnostics"]["events"]
    assert all(
        re.fullmatch(r"wrg-source-diagnostic-v1:[0-9a-f]{16}", event["id"])
        for event in data["source_diagnostics"]["events"]
    )
    assert data["source_diagnostics"]["event_counts"]["warning"] >= 1


def test_policy_schema_accepts_newer_latest_observed_without_baseline_change():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom())
    data = policy.to_dict()
    target = data["broad_target_existing_devices"]
    target["latest_observed_build"] = "26200.8655"
    target["required_baseline_build"] = "26200.8457"
    current_25h2 = next(
        entry
        for entry in data["current_versions"]
        if entry["version"] == "25H2" and entry["build_family"] == 26200
    )
    current_25h2["latest_observed_build"] = "26200.8655"
    current_25h2["required_baseline_build"] = "26200.8457"

    validate_policy_document(data)

    assert target["latest_build"] == "26200.8457"
    assert target["latest_observed_build"] == "26200.8655"
    assert target["required_baseline_build"] == "26200.8457"
    assert current_25h2["latest_build"] == "26200.8457"
    assert current_25h2["latest_observed_build"] == "26200.8655"
    assert current_25h2["required_baseline_build"] == "26200.8457"


def test_policy_schema_rejects_older_latest_observed_build():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom())
    data = policy.to_dict()
    data["broad_target_existing_devices"]["latest_observed_build"] = "26200.7000"

    with pytest.raises(PolicyParseError, match="latest_observed_build must not be older than latest_build"):
        validate_policy_document(data)


def test_policy_schema_rejects_invalid_source_diagnostics_event_id():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom_with_new_b_release())
    data = policy.to_dict()
    data["source_diagnostics"]["events"][0]["id"] = "not-a-diagnostic-id"

    with pytest.raises(PolicyParseError, match=r"source_diagnostics\.events\[0\]\.id"):
        validate_policy_document(data)


def test_policy_schema_accepts_atom_source_diagnostic_event_and_issue_status_id():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom_with_new_b_release())
    data = policy.to_dict()
    data["source_diagnostics"]["events"][0]["id"] = ATOM_SOURCE_DIAGNOSTIC_ID
    data["source_diagnostics"]["issue_status"] = {
        ATOM_SOURCE_DIAGNOSTIC_ID: {
            "number": 42,
            "state": "open",
            "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
        }
    }

    warnings = validate_policy_document(data)

    assert not any("source_diagnostics" in warning for warning in warnings)


def test_policy_schema_accepts_source_diagnostic_issue_status():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom_with_new_b_release())
    data = policy.to_dict()
    diagnostic_id = data["source_diagnostics"]["events"][0]["id"]
    data["source_diagnostics"]["issue_status"] = {
        diagnostic_id: {
            "number": 42,
            "state": "open",
            "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
        }
    }

    warnings = validate_policy_document(data)
    assert not any("issue_status" in warning for warning in warnings)


def test_policy_schema_accepts_source_diagnostic_issue_sync_unavailable_metadata():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom_with_new_b_release())
    data = policy.to_dict()
    data["source_diagnostics"]["issue_sync"] = {
        "status": "unavailable",
        "reason": "github_issues_sync_failed",
        "message": "GitHub Issues sync failed during publish-policy.",
    }

    warnings = validate_policy_document(data)
    assert not any("issue_sync" in warning for warning in warnings)


def test_policy_schema_rejects_invalid_source_diagnostic_issue_sync_metadata():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom_with_new_b_release())
    data = policy.to_dict()
    data["source_diagnostics"]["issue_sync"] = {
        "status": "unavailable",
        "token": "must-not-be-accepted",
    }

    with pytest.raises(PolicyParseError, match="source_diagnostics.issue_sync contains unsupported fields"):
        validate_policy_document(data)


def test_policy_schema_rejects_invalid_source_diagnostic_issue_status_url():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom_with_new_b_release())
    data = policy.to_dict()
    diagnostic_id = data["source_diagnostics"]["events"][0]["id"]
    data["source_diagnostics"]["issue_status"] = {
        diagnostic_id: {
            "number": 42,
            "state": "open",
            "url": "https://github.com/Avnsx/not-the-repo/issues/42",
        }
    }

    with pytest.raises(PolicyParseError, match=r"source_diagnostics\.issue_status\..*\.url"):
        validate_policy_document(data)


def test_policy_schema_rejects_extra_source_diagnostic_issue_status_fields():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom_with_new_b_release())
    data = policy.to_dict()
    diagnostic_id = data["source_diagnostics"]["events"][0]["id"]
    data["source_diagnostics"]["issue_status"] = {
        diagnostic_id: {
            "number": 42,
            "state": "open",
            "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
            "body": "raw API body must not be public policy metadata",
        }
    }

    with pytest.raises(PolicyParseError, match=r"source_diagnostics\.issue_status\..*unsupported fields"):
        validate_policy_document(data)


def test_policy_schema_rejects_invalid_source_diagnostics_shape():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom())
    data = policy.to_dict()
    data["source_diagnostics"] = {"release_health_html": "not an object"}

    with pytest.raises(PolicyParseError, match="source_diagnostics.release_health_html"):
        validate_policy_document(data)


def test_policy_schema_rejects_invalid_source_diagnostics_event_counts():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom())
    data = policy.to_dict()
    data["source_diagnostics"]["event_counts"]["warning"] = -1

    with pytest.raises(PolicyParseError, match="source_diagnostics.event_counts.warning"):
        validate_policy_document(data)


def test_b_release_quality_baseline_does_not_require_preview():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom())
    baseline = policy.quality_baselines["25H2"][QualityPolicy.B_RELEASE_ONLY.value]

    assert baseline["build"] == "26200.8457"
    assert baseline["preview"] is False


def test_current_table_preview_latest_stays_distinct_from_required_baseline():
    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        atom_feed_xml=_atom(),
    )
    validate_policy_document(policy.to_dict())
    target = policy.broad_target_existing_devices
    baseline = policy.quality_baselines["25H2"][QualityPolicy.B_RELEASE_ONLY.value]

    assert target is not None
    assert target.latest_build == "26200.8524"
    assert target.latest_observed_build == "26200.8524"
    assert target.baseline_build == "26200.8457"
    assert target.required_baseline_build == "26200.8457"
    current_25h2 = next(entry for entry in policy.current_versions if entry.version == "25H2")
    assert current_25h2.latest_build == "26200.8524"
    assert current_25h2.latest_observed_build == "26200.8524"
    assert current_25h2.baseline_build == "26200.8457"
    assert current_25h2.required_baseline_build == "26200.8457"
    assert baseline["build"] == "26200.8457"
    assert baseline["preview"] is False


def test_missing_atom_feed_still_generates_policy_with_warning():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=None)

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert any("Atom feed missing" in warning for warning in policy.validation_warnings)
    event = next(event for event in policy.source_diagnostics["events"] if event["kind"] == "atom_feed_missing")
    assert event["severity"] == "warning"
    assert event["affects_required_baseline"] is False


def test_atom_feed_parse_failure_is_structured_source_diagnostic():
    policy = generate_policy(
        release_health_html=_html(),
        atom_feed_xml="<feed>",
        generated_at_utc="2026-05-20T00:00:00+00:00",
    )

    assert any("Atom feed could not be parsed" in warning for warning in policy.validation_warnings)
    event = next(event for event in policy.source_diagnostics["events"] if event["kind"] == "atom_feed_parse_failed")
    assert event["severity"] == "warning"
    assert "Atom feed could not be parsed" in event["message"]
    assert not any(
        event["kind"] == "source_drift_unresolved_after_24h"
        for event in policy.source_diagnostics["events"]
    )


def test_generate_policy_fails_hard_when_release_health_tables_are_unusable():
    with pytest.raises(PolicyParseError, match="release_history tables"):
        generate_policy(release_health_html="<html><body>No release data</body></html>", atom_feed_xml=_atom())


def test_publish_workflow_keeps_source_diagnostic_error_events_publish_relevant() -> None:
    workflow = Path(".github/workflows/publish-policy.yml").read_text(encoding="utf-8")

    assert 'event.get("severity") == "error"' in workflow
    assert "source diagnostics error events block publish" in workflow


def test_parse_atom_feed_extracts_kb_build_and_classification():
    entries = parse_atom_feed(_atom())
    preview = next(entry for entry in entries if entry.kb_article == "KB5083631")
    oob = next(entry for entry in entries if entry.kb_article == "KB5089550")

    assert preview.preview is True
    assert preview.builds == ("26200.8328",)
    assert oob.out_of_band is True


def test_parse_atom_feed_preserves_namespaced_atom_entry_id_metadata():
    entries = parse_atom_feed(
        _atom_feed_with_entries(
            _atom_entry_with_raw_id(
                ATOM_ENTRY_ID,
                "June 9, 2026&#8212;KB5094126 (OS Builds 26200.8655 and 26100.8655) - Microsoft Support",
            )
        )
    )

    assert len(entries) == 1
    entry = entries[0]
    assert entry.entry_id == ATOM_ENTRY_ID
    assert entry.support_article_id == ATOM_SUPPORT_ARTICLE_ID
    assert entry.diagnostic_id_hint == ATOM_SOURCE_DIAGNOSTIC_ID
    assert entry.link == KB5094126_SUPPORT_URL
    assert entry.kb_article == "KB5094126"
    assert entry.builds == ("26200.8655", "26100.8655")


def test_parse_atom_feed_preserves_non_namespaced_atom_entry_id_metadata():
    atom = f"""<?xml version="1.0" encoding="utf-8"?>
<feed>
  {_atom_entry_with_raw_id(
        ATOM_ENTRY_ID,
        "June 9, 2026&#8212;KB5094126 (OS Builds 26200.8655 and 26100.8655) - Microsoft Support",
    )}
</feed>
"""

    entry = parse_atom_feed(atom)[0]

    assert entry.entry_id == ATOM_ENTRY_ID
    assert entry.support_article_id == ATOM_SUPPORT_ARTICLE_ID
    assert entry.diagnostic_id_hint == ATOM_SOURCE_DIAGNOSTIC_ID
    assert entry.link == KB5094126_SUPPORT_URL


def test_parse_atom_feed_keeps_legacy_or_malformed_ids_without_diagnostic_hint():
    atom = _atom_feed_with_entries(
        _atom_entry(
            "KB5089600",
            "June 9, 2026-KB5089600 (OS Build 26200.8461)",
        ),
        _atom_entry_with_raw_id(
            "uuid:not-a-canonical-id;id=968480",
            "June 9, 2026-KB5094126 (OS Build 26200.8655)",
        ),
        """  <entry>
    <title>June 9, 2026-KB5094127 (OS Build 26200.8656)</title>
    <link rel="alternate" href="https://support.microsoft.com/help/5094127" />
  </entry>""",
    )

    entries = parse_atom_feed(atom)

    assert entries[0].entry_id == "tag:support.microsoft.com,2026:KB5089600"
    assert entries[0].diagnostic_id_hint is None
    assert entries[1].entry_id == "uuid:not-a-canonical-id;id=968480"
    assert entries[1].support_article_id == ATOM_SUPPORT_ARTICLE_ID
    assert entries[1].diagnostic_id_hint is None
    assert entries[2].entry_id is None
    assert entries[2].diagnostic_id_hint is None


def test_generator_source_failure_exits_nonzero_and_explains_failure(tmp_path, capsys):
    code = generate_policy_cli.main([
        "--release-health-html",
        str(tmp_path / "missing.html"),
        "--atom-feed",
        str(FIXTURES / "windows11-atom.xml"),
        "--output-dir",
        str(tmp_path / "site"),
    ])

    captured = capsys.readouterr()
    assert code == 1
    assert "release_health_html source failure" in captured.err


def test_generator_cli_writes_pages_support_files(tmp_path):
    output_dir = tmp_path / "site"

    code = generate_policy_cli.main([
        "--release-health-html",
        str(FIXTURES / "windows11-release-health.html"),
        "--atom-feed",
        str(FIXTURES / "windows11-atom.xml"),
        "--output-dir",
        str(output_dir),
        "--write-index",
        "--write-robots",
        "--write-sitemap",
        "--write-manifest",
    ])

    assert code == 0
    assert (output_dir / "windows-release-policy.json").exists()
    assert (output_dir / "index.html").exists()
    assert (output_dir / "robots.txt").exists()
    assert (output_dir / "sitemap.xml").exists()
    assert (output_dir / "policy-manifest.json").exists()
    assert (output_dir / "api/v1/policy.json").exists()
    assert (output_dir / "api/v1/manifest.json").exists()
    assert (output_dir / ".nojekyll").exists()
    assert (output_dir / "robots.txt").read_bytes() == EXPECTED_ROBOTS_TXT.encode("utf-8")


def test_generator_cli_does_not_accept_github_issue_mutation_flags():
    help_text = generate_policy_cli._build_parser().format_help()

    assert "--sync-source-diagnostics-issues" not in help_text
    assert "--github-token-env" not in help_text
    assert "--issue-sync-dry-run" not in help_text
    assert "GITHUB_TOKEN" not in help_text
    assert "--source-diagnostic-issue-status-file" in help_text


def test_generator_cli_merges_static_source_diagnostic_issue_status(tmp_path):
    output_dir = tmp_path / "site"
    atom_feed = tmp_path / "windows11-atom-new-baseline.xml"
    atom_feed.write_text(_atom_with_new_b_release(), encoding="utf-8")
    preview_policy = generate_policy(release_health_html=_html(), atom_feed_xml=atom_feed.read_text(encoding="utf-8"))
    diagnostic_id = next(
        event["id"]
        for event in preview_policy.source_diagnostics["events"]
        if event.get("severity") in {"warning", "error"}
    )
    issue_status = tmp_path / "issue-status.json"
    issue_status.write_text(
        json.dumps(
            {
                "issue_status": {
                    diagnostic_id: {
                        "number": 42,
                        "state": "open",
                        "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    code = generate_policy_cli.main([
        "--release-health-html",
        str(FIXTURES / "windows11-release-health.html"),
        "--atom-feed",
        str(atom_feed),
        "--output-dir",
        str(output_dir),
        "--write-index",
        "--write-manifest",
        "--source-diagnostic-issue-status-file",
        str(issue_status),
    ])

    assert code == 0
    policy = json.loads((output_dir / "windows-release-policy.json").read_text(encoding="utf-8"))
    validate_policy_document(policy)
    assert policy["source_diagnostics"]["issue_status"][diagnostic_id]["number"] == 42
    index = (output_dir / "index.html").read_text(encoding="utf-8")
    assert "#Ticket 42" in index
    assert 'href="https://github.com/Avnsx/win11_release_guard/issues/42"' in index


def test_generator_cli_issue_status_mapping_accepts_atom_source_diagnostic_id():
    records = generate_policy_cli._issue_status_mapping(
        {
            "issue_status": {
                ATOM_SOURCE_DIAGNOSTIC_ID: {
                    "number": "42",
                    "state": "open",
                    "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
                }
            }
        }
    )

    assert records[ATOM_SOURCE_DIAGNOSTIC_ID] == {
        "number": 42,
        "state": "open",
        "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
    }


def test_policy_index_issue_status_links_only_real_warning_error_event_rows() -> None:
    event = {
        "severity": "warning",
        "kind": "atom_newer_than_release_history",
        "release": "25H2",
        "build_family": 26200,
        "build": "26200.8461",
        "kb_article": "KB5089600",
        "message": "Atom feed reports a newer baseline build.",
    }
    diagnostic_id = policy_generator_module._source_diagnostic_id_for_event(event)
    event_index = policy_generator_module.render_policy_index(
        ReleasePolicy(
            source_diagnostics={
                "event_counts": {"notice": 0, "warning": 1, "error": 0},
                "events": [event],
                "issue_status": {
                    diagnostic_id: {
                        "number": 42,
                        "state": "open",
                        "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
                    }
                },
            }
        ),
        policy_bytes=None,
        signature=None,
    )

    assert f'data-diagnostic-id="{diagnostic_id}"' in event_index
    assert "#Ticket 42" in event_index
    assert 'href="https://github.com/Avnsx/win11_release_guard/issues/42"' in event_index

    excluded_entry = ReleasePolicyEntry(
        version="26H1",
        build_family=26200,
        latest_build="26200.1000",
        reason="new devices only",
    )
    preview_policy = ReleasePolicy(
        excluded_for_existing_devices=(excluded_entry,),
        source_diagnostics={"event_counts": {"notice": 0, "warning": 0, "error": 0}},
    )
    clear_id = policy_generator_module._source_diagnostic_row_id(
        policy_generator_module._clear_source_diagnostic_row()
    )
    excluded_id = policy_generator_module._source_diagnostic_row_id(
        policy_generator_module._excluded_release_diagnostic_rows(preview_policy)[0]
    )
    derived_index = policy_generator_module.render_policy_index(
        ReleasePolicy(
            excluded_for_existing_devices=(excluded_entry,),
            source_diagnostics={
                "event_counts": {"notice": 0, "warning": 0, "error": 0},
                "issue_status": {
                    clear_id: {
                        "number": 70,
                        "state": "open",
                        "url": "https://github.com/Avnsx/win11_release_guard/issues/70",
                    },
                    excluded_id: {
                        "number": 71,
                        "state": "open",
                        "url": "https://github.com/Avnsx/win11_release_guard/issues/71",
                    },
                },
            },
        ),
        policy_bytes=None,
        signature=None,
    )

    assert f'data-diagnostic-id="{clear_id}"' in derived_index
    assert f'data-diagnostic-id="{excluded_id}"' in derived_index
    assert "No source issues reported" in derived_index
    assert "26H1 excluded for existing devices" in derived_index
    assert "#Ticket 70" not in derived_index
    assert "#Ticket 71" not in derived_index
    assert '<a class="diag-ticket-link"' not in derived_index


def test_generator_cli_strips_extra_source_diagnostic_issue_status_fields(tmp_path):
    output_dir = tmp_path / "site"
    preview_policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom())
    diagnostic_id = preview_policy.source_diagnostics["events"][0]["id"]
    issue_status = tmp_path / "issue-status.json"
    forbidden = "safe-test-token-value-that-must-not-print"
    issue_status.write_text(
        json.dumps(
            {
                "issue_status": {
                    diagnostic_id: {
                        "number": "42",
                        "state": "open",
                        "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
                        "token": forbidden,
                        "body": "raw API body must not become public policy data",
                        "labels": ["internals: warning"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    code = generate_policy_cli.main([
        "--release-health-html",
        str(FIXTURES / "windows11-release-health.html"),
        "--atom-feed",
        str(FIXTURES / "windows11-atom.xml"),
        "--output-dir",
        str(output_dir),
        "--write-index",
        "--write-manifest",
        "--source-diagnostic-issue-status-file",
        str(issue_status),
    ])

    assert code == 0
    for path in (
        output_dir / "windows-release-policy.json",
        output_dir / "policy-manifest.json",
        output_dir / "index.html",
    ):
        text = path.read_text(encoding="utf-8")
        assert forbidden not in text
        assert "raw API body" not in text
        assert '"labels"' not in text
    policy = json.loads((output_dir / "windows-release-policy.json").read_text(encoding="utf-8"))
    record = policy["source_diagnostics"]["issue_status"][diagnostic_id]
    assert record == {
        "number": 42,
        "state": "open",
        "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
    }


def test_generator_cli_merges_degraded_source_diagnostic_issue_sync_metadata(tmp_path):
    output_dir = tmp_path / "site"
    issue_status = tmp_path / "issue-status.json"
    forbidden = "safe-test-token-value-that-must-not-print"
    issue_status.write_text(
        json.dumps(
            {
                "issue_status": {},
                "issue_sync": {
                    "status": "unavailable",
                    "reason": "github_issues_sync_failed",
                    "message": "GitHub Issues sync failed during publish-policy.",
                    "token": forbidden,
                },
            }
        ),
        encoding="utf-8",
    )

    code = generate_policy_cli.main([
        "--release-health-html",
        str(FIXTURES / "windows11-release-health.html"),
        "--atom-feed",
        str(FIXTURES / "windows11-atom.xml"),
        "--output-dir",
        str(output_dir),
        "--write-index",
        "--write-manifest",
        "--source-diagnostic-issue-status-file",
        str(issue_status),
    ])

    assert code == 0
    policy = json.loads((output_dir / "windows-release-policy.json").read_text(encoding="utf-8"))
    manifest = json.loads((output_dir / "policy-manifest.json").read_text(encoding="utf-8"))
    validate_policy_document(policy)
    assert policy["source_diagnostics"]["issue_sync"] == {
        "status": "unavailable",
        "reason": "github_issues_sync_failed",
        "message": "GitHub Issues sync failed during publish-policy.",
    }
    assert manifest["source_diagnostics"]["issue_sync"] == policy["source_diagnostics"]["issue_sync"]
    index = (output_dir / "index.html").read_text(encoding="utf-8")
    assert 'data-issue-sync-status="unavailable"' in index
    assert "Issue sync unavailable" in index
    assert "GitHub Issues sync failed during publish-policy." in index
    for path in (
        output_dir / "windows-release-policy.json",
        output_dir / "policy-manifest.json",
        output_dir / "index.html",
    ):
        assert forbidden not in path.read_text(encoding="utf-8")


def test_generator_cli_rejects_invalid_source_diagnostic_issue_status_key(tmp_path, capsys):
    output_dir = tmp_path / "site"
    issue_status = tmp_path / "issue-status.json"
    issue_status.write_text(json.dumps({"issue_status": {"not-a-diagnostic-id": {"number": 42}}}), encoding="utf-8")

    code = generate_policy_cli.main([
        "--release-health-html",
        str(FIXTURES / "windows11-release-health.html"),
        "--atom-feed",
        str(FIXTURES / "windows11-atom.xml"),
        "--output-dir",
        str(output_dir),
        "--source-diagnostic-issue-status-file",
        str(issue_status),
    ])

    captured = capsys.readouterr()
    assert code == 1
    assert "source diagnostic issue status keys must be deterministic diagnostic IDs" in captured.err


def test_generator_cli_rejects_noncanonical_source_diagnostic_issue_status_url(tmp_path, capsys):
    output_dir = tmp_path / "site"
    diagnostic_id = "wrg-source-diagnostic-v1:1111111111111111"
    issue_status = tmp_path / "issue-status.json"
    issue_status.write_text(
        json.dumps(
            {
                "issue_status": {
                    diagnostic_id: {
                        "number": 42,
                        "state": "open",
                        "url": "https://github.com/Avnsx/win11_release_guard/issues/42?token=blocked",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    code = generate_policy_cli.main([
        "--release-health-html",
        str(FIXTURES / "windows11-release-health.html"),
        "--atom-feed",
        str(FIXTURES / "windows11-atom.xml"),
        "--output-dir",
        str(output_dir),
        "--source-diagnostic-issue-status-file",
        str(issue_status),
    ])

    captured = capsys.readouterr()
    assert code == 1
    assert "source diagnostic issue status URL must be canonical" in captured.err


def test_signed_pages_output_contains_manifest_aliases_and_polished_index(tmp_path):
    policy = generate_policy(
        release_health_html=_html(),
        atom_feed_xml=_atom(),
        generated_at_utc="2026-05-31T14:11:50+00:00",
        signature_status="valid",
    )
    written = write_policy_outputs(
        policy,
        output_dir=tmp_path,
        signing_key="krtF2muLgucP7JDVNKk2g+YQfz92c7xM49dzszxHxjs=",
        key_id="test-policy-key",
        write_index=True,
        write_robots=True,
        write_sitemap=True,
        write_manifest=True,
    )

    expected = {
        "index.html",
        "windows-release-policy.json",
        "windows-release-policy.json.sig",
        "policy-manifest.json",
        "api/v1/policy.json",
        "api/v1/policy.sig",
        "api/v1/manifest.json",
        "robots.txt",
        "sitemap.xml",
        ".nojekyll",
        "wiki/index.html",
        "wiki/Quick-Start/index.html",
        "wiki/changelog/index.html",
        "wiki/changelog/v0.3.3/index.html",
        "wiki/changelog/v0.3.2/index.html",
    }
    actual = {path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*") if path.is_file()}

    assert expected <= actual
    assert (tmp_path / "api/v1/policy.json").read_bytes() == (tmp_path / "windows-release-policy.json").read_bytes()
    assert (tmp_path / "api/v1/policy.sig").read_bytes() == (tmp_path / "windows-release-policy.json.sig").read_bytes()
    assert (tmp_path / "api/v1/manifest.json").read_bytes() == (tmp_path / "policy-manifest.json").read_bytes()

    policy_bytes = (tmp_path / "windows-release-policy.json").read_bytes()
    signature_bytes = (tmp_path / "windows-release-policy.json.sig").read_bytes()
    signature_record = json.loads(signature_bytes.decode("utf-8"))
    manifest = json.loads((tmp_path / "policy-manifest.json").read_text(encoding="utf-8"))
    generated_policy = json.loads((tmp_path / "windows-release-policy.json").read_text(encoding="utf-8"))
    api_policy = json.loads((tmp_path / "api/v1/policy.json").read_text(encoding="utf-8"))
    api_manifest = json.loads((tmp_path / "api/v1/manifest.json").read_text(encoding="utf-8"))
    assert manifest["policy_sha256"] == hashlib.sha256(policy_bytes).hexdigest()
    assert manifest["signature_sha256"] == hashlib.sha256(signature_bytes).hexdigest()
    assert manifest["signature_algorithm"] == "ed25519"
    assert manifest["key_id"] == "test-policy-key"
    assert manifest["signature_sha256"]
    assert "signature" not in manifest
    assert signature_record["signature"] not in (tmp_path / "index.html").read_text(encoding="utf-8")
    assert signature_record["signature"] not in (tmp_path / "policy-manifest.json").read_text(encoding="utf-8")
    assert signature_record["signature"] not in (tmp_path / "api/v1/manifest.json").read_text(encoding="utf-8")
    assert manifest["policy_schema_version"] == 1
    assert manifest["min_reader_schema_version"] == 1
    assert manifest["max_reader_schema_version"] == 1
    assert manifest["api_version"] == "v1"
    assert manifest["compatibility"]["required_core_schema_version"] == 1
    assert manifest["generated_at_epoch_s"] == 1780236710
    assert manifest["warn_after_epoch_s"] == 1781446310
    assert manifest["stale_after_epoch_s"] == 1784124710
    assert manifest["strict_stale_after_epoch_s"] == 1784124710
    assert manifest["max_ok_age_seconds"] == DEFAULT_POLICY_WARNING_AGE_SECONDS
    assert manifest["warning_age_seconds"] == DEFAULT_POLICY_WARNING_AGE_SECONDS
    assert manifest["strict_stale_age_seconds"] == DEFAULT_POLICY_STRICT_STALE_AGE_SECONDS
    assert manifest["freshness_policy"] == {
        "warning_after_days": 14,
        "strict_stale_after_days": 45,
        "max_ok_age_seconds": DEFAULT_POLICY_WARNING_AGE_SECONDS,
        "warning_age_seconds": DEFAULT_POLICY_WARNING_AGE_SECONDS,
        "strict_stale_age_seconds": DEFAULT_POLICY_STRICT_STALE_AGE_SECONDS,
        "client_recomputes_age": True,
    }
    assert api_policy == generated_policy
    assert api_manifest == manifest
    assert manifest["timezone"] == "Europe/Berlin"
    assert manifest["status"] == "Policy current"
    assert manifest["published_urls"]["policy"] == DEFAULT_POLICY_URL
    assert manifest["published_urls"]["api_policy"].endswith("/api/v1/policy.json")
    assert manifest["source_diagnostics"]["atom_feed"]["newest_atom_build"] == "26200.8460"
    source_diagnostic_ids = [
        event["id"] for event in generated_policy["source_diagnostics"]["events"]
    ]
    assert source_diagnostic_ids
    assert all(
        re.fullmatch(r"wrg-source-diagnostic-v1:[0-9a-f]{16}", diagnostic_id)
        for diagnostic_id in source_diagnostic_ids
    )
    assert [
        event["id"] for event in manifest["source_diagnostics"]["events"]
    ] == source_diagnostic_ids
    assert manifest["broad_target_existing_devices"]["latest_observed_build"] == "26200.8457"
    assert manifest["broad_target_existing_devices"]["required_baseline_build"] == "26200.8457"
    assert manifest["required_baseline_build"] == "26200.8457"
    assert generated_policy["published_urls"] == DEFAULT_PUBLISHED_POLICY_URLS
    assert generated_policy["metadata"]["freshness_policy"]["warning_after_days"] == 14
    assert generated_policy["metadata"]["freshness_policy"]["strict_stale_after_days"] == 45
    assert generated_policy["metadata"]["freshness_policy"]["client_recomputes_age"] is True
    roundtripped_policy = ReleasePolicy.from_dict(generated_policy)
    assert roundtripped_policy.metadata["freshness_policy"]["warning_age_seconds"] == DEFAULT_POLICY_WARNING_AGE_SECONDS
    assert DEFAULT_RELEASE_HEALTH_URL in generated_policy["source_urls"]
    source_hosts = {urlparse(url).hostname for url in generated_policy["source_urls"]}
    assert "avnsx.github.io" not in source_hosts

    sitemap = (tmp_path / "sitemap.xml").read_text(encoding="utf-8")
    assert "https://avnsx.github.io/win11_release_guard/wiki/changelog/" in sitemap
    assert "https://avnsx.github.io/win11_release_guard/wiki/changelog/v0.3.3/" in sitemap
    assert "https://avnsx.github.io/win11_release_guard/wiki/changelog/v0.3.2/" in sitemap

    changelog = (tmp_path / "wiki/changelog/index.html").read_text(encoding="utf-8")
    changelog_version = (tmp_path / "wiki/changelog/v0.3.3/index.html").read_text(encoding="utf-8")
    changelog_version_032 = (tmp_path / "wiki/changelog/v0.3.2/index.html").read_text(encoding="utf-8")
    wiki_home = (tmp_path / "wiki/index.html").read_text(encoding="utf-8")
    wiki_quick_start = (tmp_path / "wiki/Quick-Start/index.html").read_text(encoding="utf-8")
    assert "<title>Changelog | Windows 11 Release Guard Wiki</title>" in changelog
    assert 'id="wiki-content" class="wiki-content changelog-content" tabindex="-1"' in changelog
    assert 'class="wiki-breadcrumbs" aria-label="Breadcrumb"' in changelog
    assert 'class="skip-link" href="#wiki-content"' in changelog
    assert '<link rel="canonical" href="https://avnsx.github.io/win11_release_guard/wiki/changelog/">' in changelog
    assert '<meta property="og:url" content="https://avnsx.github.io/win11_release_guard/wiki/changelog/">' in changelog
    assert '<meta name="twitter:card" content="summary">' in changelog
    assert "Windows 11 release compliance" in changelog
    assert "signed public policy feed" in changelog
    assert "RMM" in changelog
    assert changelog.index("[Unreleased]") < changelog.index("v0.3.3 - 2026-06-11")
    assert changelog.index("v0.3.3 - 2026-06-11") < changelog.index("v0.3.2 - 2026-06-10")
    assert changelog.index("v0.3.2 - 2026-06-10") < changelog.index("v0.3.1 - 2026-06-05")
    assert "Version 0.3.3 is the corrective source-evidence hardening release" in changelog
    assert "Version 0.3.2 is the compatibility and documentation-alignment release" in changelog
    assert "Versions" in changelog
    assert ".changelog-content h2[id]" in changelog
    assert 'class="wiki-heading-icon wiki-icon-changelog"' in changelog
    assert 'class="wiki-heading-icon wiki-icon-release"' in changelog
    assert "white-space: nowrap;" in changelog
    assert ">pre-release</a>" in changelog
    assert 'class="changelog-pre-release-badge">pre-release</a>' in changelog
    assert "border-color: #f0c74c;" in changelog
    assert "margin-top: 4.75rem;" in changelog
    assert "margin: -0.25rem 0 1.9rem 1.05rem;" in changelog
    assert ".changelog-version-nav ol {" in changelog
    assert "margin: 0.3rem 0 0 0.65rem;" in changelog
    assert ".changelog-version-nav .version-meta a {" in changelog
    assert "font-size: 0.76rem;" in changelog
    assert ">Changelog section</a>" in changelog
    assert ">Version page</a>" in changelog
    assert ">GitHub release</a>" in changelog
    assert 'title="Open pre-release section" class="changelog-pre-release-badge">pre-release</a>' in changelog
    assert 'title="Open section on Pages changelog">Section</a>' in changelog
    assert 'title="Open version page">Version page</a>' in changelog
    assert 'title="Open GitHub release">GH release</a>' in changelog
    assert 'href="#v0.3.3"' in changelog
    assert 'href="https://github.com/Avnsx/win11_release_guard/releases/tag/v0.3.3"' in changelog
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/changelog/v0.3.3/"' in changelog
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/changelog/v0.3.2/"' in changelog
    assert "<title>Changelog v0.3.3 | Windows 11 Release Guard Wiki</title>" in changelog_version
    assert (
        '<link rel="canonical" href="https://avnsx.github.io/win11_release_guard/wiki/changelog/v0.3.3/">'
        in changelog_version
    )
    assert "unique multi-build Atom diagnostic IDs" in changelog_version
    assert "<title>Changelog v0.3.2 | Windows 11 Release Guard Wiki</title>" in changelog_version_032
    assert "extends declared and CI-tested Python support through 3.14" in changelog_version_032
    assert "<title>Windows 11 Release Guard Wiki</title>" in wiki_home
    assert 'class="wiki-brand-icon"' in wiki_home
    assert '<a class="wiki-brand" href="https://avnsx.github.io/win11_release_guard/">' in wiki_home
    assert 'id="wiki-content" class="wiki-content" tabindex="-1"' in wiki_home
    assert 'href="https://avnsx.github.io/win11_release_guard/wiki/changelog/"' in wiki_home
    assert wiki_home.index('href="https://avnsx.github.io/win11_release_guard/wiki/changelog/"') < wiki_home.index(
        'href="https://avnsx.github.io/win11_release_guard/wiki/Quick-Start/"'
    )
    assert "prefers-reduced-motion: reduce" in wiki_home
    assert "@media (max-width: 860px)" in wiki_home
    assert '<link rel="canonical" href="https://avnsx.github.io/win11_release_guard/wiki/">' in wiki_home
    assert "signed public JSON policy feed" in wiki_home
    assert '<meta property="og:site_name" content="Windows 11 Release Guard">' in wiki_home
    assert '<link rel="canonical" href="https://avnsx.github.io/win11_release_guard/wiki/Quick-Start/">' in wiki_quick_start
    for generated_html in (wiki_home, wiki_quick_start, changelog, changelog_version, changelog_version_032):
        _assert_local_fragment_links_resolve(generated_html)
        assert generated_html.count("<style>") == 1
        assert generated_html.count("</style>") == 1
    for rendered_changelog in (changelog, changelog_version, changelog_version_032):
        lower_changelog = rendered_changelog.lower()
        assert 'data-section-scrollspy="true"' in rendered_changelog
        assert ".wiki-sidebar a.is-active-section" in rendered_changelog
        assert 'if (!sidebar || !content) return;' in rendered_changelog
        assert "script src" not in lower_changelog
        assert 'rel="stylesheet"' not in lower_changelog
        assert "cdn.jsdelivr" not in lower_changelog
        assert "esm.sh" not in lower_changelog
        assert "fonts.googleapis" not in lower_changelog

    index = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "<title>Windows 11 Release Guard</title>" in index
    assert '<link rel="icon" href="data:image/svg+xml,' in index
    assert "<h1>Windows 11 Release Guard</h1>" in index
    assert "Broad-fleet Windows 11 release and quality baseline dashboard." in index
    assert 'class="header-nav"' in index
    assert 'class="pypi-download-link"' in index
    assert 'href="https://pypi.org/project/win11-release-guard/"' in index
    assert 'src="assets/images/download_from_pypi.png"' in index
    assert 'class="nav-hover-label"' in index
    assert "nav-binoculars" not in index
    assert "main{position:relative;z-index:1;width:calc(100% - 80px);max-width:1580px" in index
    assert "backdrop-filter:blur(28px)" in index
    assert "body:before" in index
    assert "body:after" in index
    assert 'class="winmark"' in index
    assert "kpi-card" in index
    assert "icon-bubble" in index
    assert 'class="ui-icon' in index
    assert "freshness-ring" in index
    assert "panel-action" in index
    assert "diag-row-icon" in index
    assert "--item-size:42px" in index
    assert ".nav-hover-label{display:none}" in index
    assert 'id="policy-summary"' in index
    assert 'href="https://avnsx.github.io/win11_release_guard/"' in index
    assert 'data-nav-label="Dashboard"' in index
    assert "Dashboard" in index
    assert 'data-nav-label="Write a Issue Ticket"' in index
    assert "Write a Issue Ticket" in index
    assert "https://github.com/Avnsx/win11_release_guard/issues/new" in index
    assert 'data-nav-label="Wiki"' in index
    assert "Wiki" in index
    assert "https://avnsx.github.io/win11_release_guard/wiki/" in index
    assert "https://github.com/Avnsx/win11_release_guard/wiki" not in index
    assert "animations/auto" not in index
    assert "auto-table-of-content" not in index
    assert "esm.sh" not in index
    assert "initHeaderNav" in index
    assert "reportUiError" in index
    assert "data-ui-last-error" in index
    assert "dataset.uiLastError" in index
    assert "data-ui-error-count" in index
    assert "reportMissingNode" in index
    assert "shutdownUi" in index
    assert "pagehide" in index
    assert "beforeunload" in index
    assert "safeSetTimeout" in index
    assert "safeSetInterval" in index
    assert "safeRequestFrame" in index
    assert "safeCancelFrame" in index
    assert "header nav leave" in index
    assert "header nav focusout" in index
    assert "button.isConnected" in index
    assert "nav.isConnected" in index
    assert "freshness update" in index
    assert "freshness update','data" in index
    assert "Bookmarks" not in index
    assert "Blogs" not in index
    assert "E-books" not in index
    assert "Account" not in index
    assert "Menu" not in index
    assert "Policy current" not in index
    assert "25H2" in index
    assert "Latest observed" in index
    assert "Required baseline" in index
    assert "26200" in index
    assert "26200.8457" in index
    assert "b_release_only" in index
    assert "26H1 excluded for existing devices" in index
    assert (
        "26H1 is excluded for existing devices because Microsoft scopes it to new devices and does not offer "
        "it as an in-place update from 24H2/25H2."
    ) in index
    assert "Release policy notes" not in index
    assert "release-note" not in index
    assert "No source issues reported" in index
    assert index.find("No source issues reported") < index.find("26H1 excluded for existing devices")
    assert "existing devi." not in index
    assert "Microsoft Release Health" in index
    assert "Microsoft Atom feed" in index
    assert "Ed25519" in index or "ed25519" in index
    assert "test-policy-key" in index
    assert "/windows-release-policy.json" in index
    assert "/windows-release-policy.json.sig" in index
    assert "/policy-manifest.json" in index
    assert "/api/v1/policy.json" in index
    assert "/api/v1/manifest.json" in index
    assert "Programmatic JSON endpoint" not in index
    assert "Independent Windows release-policy dashboard. Not affiliated with Microsoft." in index
    assert "&copy; 2026 Mikail (&quot;Avnsx&quot;) C. Maintained as an open-source project." in index
    assert "Source code and documentation are available on" in index
    assert "provided under the" in index
    assert "footer-repo-line" not in index
    assert "footer-symbol" not in index
    assert "</span></a>.</span></p>" not in index
    assert 'class="footer-github" href="https://github.com/Avnsx/win11_release_guard"' in index
    assert "<span>GitHub</span>" in index
    assert (
        'class="footer-license-basic" href="https://github.com/Avnsx/win11_release_guard/blob/main/LICENSE.txt"'
        in index
    )
    assert "GPL-3.0 license" in index
    assert "GPL-3.0 license</a>.</p>" not in index
    assert 'class="footer-license"' not in index
    assert "https://github.com/Avnsx/win11_release_guard/blob/main/LICENSE.txt" in index
    assert "github-icon" in index
    assert ">LICENSE.txt<" not in index
    assert "Europe/Berlin" not in index
    assert "Sunday, 31 May 2026, 16:11:50 CEST" in index
    assert "Generated age" not in index
    assert "Policy Feed Currency" in index
    assert "Published feed age" in index
    assert "days at render-time fallback" in index
    assert "Full feed metadata" not in index
    assert '<details class="freshness-metadata"' not in index
    assert '<summary>Full feed metadata</summary>' not in index
    assert '<div class="freshness-metadata"><dl class="kv metadata">' in index
    assert ".freshness-metadata summary" not in index
    assert ".freshness-metadata[open]" not in index
    assert "Browser recalculates published policy feed age from the GitHub Actions generated timestamp" in index
    assert "Date.now" in index
    assert "Current" in index
    assert "Refresh Due" in index
    assert "Stale" in index
    assert "Published policy feed currency: Unknown" in index
    assert "Workflow refresh" in index
    assert "GitHub workflow static feed generation" in index
    assert "Release Health fetched" not in index
    assert "Atom feed fetched" not in index
    assert "Berlin, Germany" in index
    assert "Program versioning" not in index
    assert "Program Version" in index
    program_version = GENERATOR_VERSION.rsplit("/", 1)[-1]
    assert f"https://github.com/Avnsx/win11_release_guard/releases/tag/v{program_version}" in index
    assert "GitHub release tag" not in index
    assert "Logic ID" not in index
    assert "Policy generated by" not in index
    assert "public /api/v1 lane" not in index
    assert "signed policy document schema" not in index
    assert "API version" not in index
    assert "Policy Schema Version" not in index
    for removed_label in REMOVED_SCHEMA_PANEL_LABELS:
        assert removed_label not in index
    assert "Source diagnostics" in index
    assert "diag-feed" in index
    assert 'aria-label="Source diagnostic event feed"' in index
    assert "data-diagnostic-id" in index
    assert f'data-diagnostic-id="{source_diagnostic_ids[0]}"' in index
    assert "data-diagnostic-filter-root" in index
    assert "guard('source diagnostics filter'" in index
    assert "source diagnostics filter','root" in index
    assert "source diagnostics filter','status" in index
    assert 'id="source-diagnostics-empty" class="diag-filter-empty" hidden' in index
    assert "This category currently contains no entries." in index
    assert '<article class="diag-row notice" data-diagnostic-severity="notice" hidden' not in index
    assert "<h2>Sources</h2>" not in index
    assert "sources-panel" not in index
    assert "source-health" in index
    assert "source-tile ok" in index
    assert "source-status" in index
    assert "Signed policy trust" in index
    assert "Signature status" in index
    assert "signature-head" in index
    assert "signature-status-card" in index
    assert "Document trust state" in index
    assert "Detached signature metadata for the published policy artifact." in index
    assert "signature-kv" in index
    assert "<dt>Algorithm</dt>" in index
    assert "<dt>key_id</dt>" in index
    assert "<dt>Policy SHA-256</dt>" in index
    assert "<dt>Signature status</dt>" in index
    assert "endpoint-pill" not in index
    assert "api-endpoints" in index
    assert "api-endpoint-row" in index
    assert "Signed policy JSON" in index
    assert "Primary signed policy document used by automation and fleet dashboards." in index
    assert "Detached signature" in index
    assert "Ed25519 signature that lets clients verify the policy before trusting it." in index
    assert "Policy manifest" in index
    assert "Compact metadata for hashes, freshness thresholds, source state, and API aliases." in index
    assert "API v1 policy alias" in index
    assert "Backward-compatible policy endpoint for stable reader integrations." in index
    assert "API v1 manifest alias" in index
    assert "Backward-compatible manifest endpoint for stable reader integrations." in index
    assert '<section class="panel span-5 signature-panel">' in index
    assert '<section class="panel span-7 programmatic-api">' in index
    assert ".programmatic-api{grid-column:6/span 7;grid-row:3}" in index
    assert ".signature-panel,.programmatic-api{grid-column:1/-1}" in index
    assert "Notices" in index
    assert "Warnings" in index
    assert "Errors" in index
    assert "auth" not in index.lower()
    assert "token" not in index.lower()
    assert "private-" + "key" not in index.lower()
    assert "http://cdn" not in index.lower()
    assert "https://cdn" not in index.lower()
    assert 'rel="stylesheet"' not in index.lower()
    assert "@import" not in index.lower()
    assert "fonts.googleapis" not in index.lower()
    assert "fonts.gstatic" not in index.lower()
    assert '<script type="application/json" id="policy-freshness-data">' in index
    assert "script src" not in index.lower()

    assert render_robots_txt() == EXPECTED_ROBOTS_TXT
    assert (tmp_path / "robots.txt").read_bytes() == EXPECTED_ROBOTS_TXT.encode("utf-8")

    sitemap = (tmp_path / "sitemap.xml").read_text(encoding="utf-8")
    assert "https://avnsx.github.io/win11_release_guard/" in sitemap
    assert "https://avnsx.github.io/win11_release_guard/windows-release-policy.json" in sitemap
    assert "https://avnsx.github.io/win11_release_guard/policy-manifest.json" in sitemap
