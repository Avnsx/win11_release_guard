from __future__ import annotations

import json
from pathlib import Path
import pytest
from tools import generate_policy as generate_policy_cli
from win11_release_guard.config import DEFAULT_RELEASE_HEALTH_URL
from win11_release_guard.exceptions import PolicyFetchError
from win11_release_guard.freshness import epoch_milliseconds_from_iso
import win11_release_guard.policy_generator as policy_generator_module
from win11_release_guard.policy_generator import clock as generator_clock
from win11_release_guard.policy_generator import _source_label, build_policy_from_sources, generate_policy, write_policy_outputs
from win11_release_guard.policy_schema import GENERATOR_VERSION, is_source_diagnostic_id, validate_policy_document
from tests.support.policy_generator_helpers import (
    ATOM_SOURCE_DIAGNOSTIC_ID,
    EXPECTED_ROBOTS_TXT,
    FAKE_MSRC_CVRF_WITH_KB5094126,
    FIXTURES,
    KB5094126_SUPPORT_HTML_NO_SECURITY,
    KB5094126_SUPPORT_URL,
    _assert_no_raw_support_article_leakage,
    _generated_output_bundle,
    _html,
    _html_file,
    _kb5094126_generated_fixture_policy,
    _kb5094126_msrc_fixture,
    _kb5094126_support_fixture,
    _kb5094126_toc_fixture,
    _offline_msrc_cvrf_fetcher,
    _offline_support_article_fetcher,
    _release_health_caught_up_to_kb5094126,
    _toc,
    _with_25h2_current_latest_build,
    offline_enrichment_fetchers,
)


ATOM_ENTRY_ID = "uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480"


ATOM_SUPPORT_ARTICLE_ID = "968480"


def test_generator_utc_now_is_monotonic_at_millisecond_precision() -> None:
    values = [generator_clock.utc_now() for _ in range(4)]
    epochs = [epoch_milliseconds_from_iso(value) for value in values]

    assert all(epoch is not None for epoch in epochs)
    assert epochs == sorted(epochs)
    assert len(set(epochs)) == len(epochs)
    assert all("." in value for value in values)


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


def _toc_with_entries(*entries: dict[str, object], release: str = "25H2") -> str:
    return json.dumps(
        {
            "items": [
                {
                    "toc_title": f"Windows 11, version {release}",
                    "children": list(entries),
                }
            ],
            "metadata": {"count_of_node_with_href": len(entries)},
        }
    )


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

    servicing_url = "https://support.microsoft.com/en-us/servicing/os/windows-11/toc.json"
    localized_servicing_url = "https://support.microsoft.com/de-de/servicing/os/windows-11/toc.json"
    spoofed_servicing_url = "https://support.microsoft.com.attacker.invalid/en-us/servicing/os/windows-11/toc.json"

    assert _source_label(servicing_url) == "Microsoft servicing index"
    assert _source_label(localized_servicing_url) == "Microsoft servicing index"
    assert _source_label(spoofed_servicing_url) == spoofed_servicing_url


def test_generate_policy_from_local_html_and_servicing_toc_fixtures(tmp_path):
    policy = build_policy_from_sources(
        release_health_html_path=FIXTURES / "windows11-release-health.html",
        servicing_toc_path=FIXTURES / "windows11-servicing-toc.json",
        signature_status="valid",
        support_article_fetcher=_offline_support_article_fetcher,
        msrc_cvrf_fetcher=_offline_msrc_cvrf_fetcher,
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
    assert data["source_fetch_status"]["servicing_toc"]["status"] == "ok"
    assert data["source_fetch_status"]["release_health_html"]["fetched_at_utc"]
    assert data["source_fetch_status"]["servicing_toc"]["fetched_at_utc"]
    assert "atom_feed" not in data["source_fetch_status"]
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
    assert diagnostics["servicing_toc"]["newest_servicing_build"] == "26200.8460"
    assert diagnostics["servicing_toc"]["entry_count"] == 4
    assert any(event["severity"] == "notice" for event in diagnostics["events"])
    assert "quality_baselines" in data
    assert "preview_builds" in data


def test_write_signed_policy_output_includes_key_id(tmp_path):
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=_toc(),
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


def test_msrc_cvrf_marks_atom_diagnostic_as_security_and_uses_single_month_fetch() -> None:
    toc = json.dumps(
        {
            "items": [
                {
                    "toc_title": "June 9, 2026-KB5094126 (OS Build 26200.8655)",
                    "href": "2026/06/june-9-2026-kb5094126-os-build-26200-8655",
                },
                {
                    "toc_title": "June 9, 2026-KB5094127 (OS Build 26200.8660)",
                    "href": "2026/06/june-9-2026-kb5094127-os-build-26200-8660",
                },
            ]
        }
    )
    msrc_urls: list[tuple[str, float, int]] = []

    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        return KB5094126_SUPPORT_HTML_NO_SECURITY

    def msrc_fetcher(url: str, timeout: float, max_bytes: int):
        msrc_urls.append((url, timeout, max_bytes))
        return FAKE_MSRC_CVRF_WITH_KB5094126

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        servicing_toc_json=toc,
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
    assert "Microsoft published KB5094126 for Windows 11 25H2 build 26200.8655" in event["user_message"]

    row = policy_generator_module._source_diagnostic_row_from_event(event)
    assert "Security patch" in row["tags"]
    assert "Security confirmed by MSRC" in row["tags"]
    assert "CVEs 2" not in row["tags"]
    assert "cves" not in row


def test_msrc_cvrf_payloads_propagates_programming_error_from_fetcher() -> None:
    def raising_fetcher(url: str, timeout: float, max_bytes: int) -> object:
        raise AssertionError("MSRC fetch must not be attempted")

    with pytest.raises(AssertionError, match="MSRC fetch must not be attempted"):
        policy_generator_module._msrc_cvrf_payloads(
            ({"published": "2026-06-09T00:00:00+00:00"},),
            fetcher=raising_fetcher,
            timeout=1.0,
        )


def test_msrc_cvrf_payloads_still_degrades_genuine_fetch_failure() -> None:
    def failing_fetcher(url: str, timeout: float, max_bytes: int) -> object:
        raise PolicyFetchError("MSRC unavailable")

    payloads, statuses = policy_generator_module._msrc_cvrf_payloads(
        ({"published": "2026-06-09T00:00:00+00:00"},),
        fetcher=failing_fetcher,
        timeout=1.0,
    )

    assert payloads == {}
    assert statuses == {
        "2026-Jun": {
            "status": "error",
            "url": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun",
            "error": "MSRC unavailable",
        }
    }


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
        servicing_toc_json=_kb5094126_toc_fixture(),
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
    assert "latest_observed_atom_entry_id" not in target.metadata

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
    assert is_source_diagnostic_id(event["id"])
    assert "atom_entry_id" not in event
    assert "atom_support_article_id" not in event
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
        "Microsoft published KB5094126 for Windows 11 25H2 build 26200.8655. This looks like the next "
        "stable broad-fleet baseline candidate, but this policy waits for Release Health baseline "
        "rules before requiring it (security update, June 2026); "
        "public notes mention Secure Boot, Virtualization, desktop.ini, and AI components."
    )

    from tools import sync_source_diagnostics_issues as sync_tool

    diagnostic = sync_tool.diagnostics_from_policy({"source_diagnostics": {"events": [event]}})[0]
    issue_body = sync_tool.issue_body(diagnostic)
    assert "[id=" not in sync_tool.issue_title(diagnostic)
    assert f"Source diagnostic ID: `{event['id']}`" in issue_body
    assert f"<!-- {sync_tool.DIAGNOSTIC_ID_COMMENT_PREFIX}: {event['id']} -->" in issue_body

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
    assert "latest_observed_atom_entry_id" not in manifest["latest_observed_evidence"]
    assert "26200.8655" in index
    assert "Microsoft Support article" in index
    assert event["id"] in index
    assert "Microsoft published KB5094126 for Windows 11 25H2 build 26200.8655" in index
    assert "Security patch" in index
    assert "Security confirmed by MSRC" in index
    assert "Servicing index shows a newer non-preview build for the broad target" in index

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


def test_generated_output_hardens_expired_notice_path(tmp_path: Path) -> None:
    support_calls: list[str] = []
    msrc_calls: list[str] = []

    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        support_calls.append(url)
        raise PolicyFetchError("support fetch should not run")

    def msrc_fetcher(url: str, timeout: float, max_bytes: int) -> dict[str, object]:
        msrc_calls.append(url)
        raise PolicyFetchError("msrc fetch should not run")

    expired_policy = generate_policy(
        release_health_html=_release_health_caught_up_to_kb5094126(),
        servicing_toc_json=_kb5094126_toc_fixture(),
        generated_at_utc="2026-07-01T00:00:00+00:00",
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )
    expired_outputs = _generated_output_bundle(expired_policy, tmp_path / "expired")
    expired_data = expired_outputs["policy"]
    assert isinstance(expired_data, dict)
    _assert_no_raw_support_article_leakage(expired_outputs, _kb5094126_support_fixture())
    validate_policy_document(expired_data)
    expired_ids = [
        str(event["id"])
        for event in expired_data["source_diagnostics"]["events"]
        if isinstance(event, dict) and "id" in event
    ]
    assert len(expired_ids) == len(set(expired_ids))
    assert support_calls == []
    assert msrc_calls == []
    assert not any(
        event["kind"] == "msrc_cvrf_enrichment_unavailable"
        for event in expired_data["source_diagnostics"]["events"]
    )


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
            "New required baseline: Windows 11 25H2 build 26200.8655 now matches Microsoft "
            "evidence and the signed fleet baseline. For broad-fleet 25H2 devices, this likely "
            "marks the stable rollout floor for KB5094126 / 2026-06 B. Release Health lists the "
            "baseline date as 2026-06-09. MSRC confirms it as a security update."
        ),
        "update_summary": (
            "Update highlights: Secure Boot: Updates hardening for startup components. "
            "Virtualization: Improves reliability for protected workloads. desktop.ini: Hardens "
            "desktop.ini processing. AI components: Updates Windows AI components."
        ),
        "technical_summary": (
            "Release Health selected 2026-06 B for Windows 11 25H2 build 26200.8655; support "
            "validation ok. Security confirmed by MSRC."
        ),
        "source_url": KB5094126_SUPPORT_URL,
        "first_spotted_atom_published_utc": "2026-06-09T00:00:00Z",
        "support_article_updated_utc": "2026-06-09T00:00:00Z",
        "official_release_date": "2026-06-09",
        "official_release_precision": "date",
        "release_health_latest_revision_date": "2026-06-09",
        "visible_from_utc": "2026-06-09T00:00:00Z",
        "visible_until_utc": "2026-06-23T00:00:00Z",
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


def test_publish_workflow_keeps_source_diagnostic_error_events_publish_relevant() -> None:
    workflow = Path(".github/workflows/publish-policy.yml").read_text(encoding="utf-8")

    assert 'event.get("severity") == "error"' in workflow
    assert "source diagnostics error events block publish" in workflow


def test_generator_source_failure_exits_nonzero_and_explains_failure(tmp_path, capsys, offline_enrichment_fetchers):
    code = generate_policy_cli.main([
        "--release-health-html",
        str(tmp_path / "missing.html"),
        "--servicing-toc",
        str(FIXTURES / "windows11-servicing-toc.json"),
        "--output-dir",
        str(tmp_path / "site"),
    ])

    captured = capsys.readouterr()
    assert code == 1
    assert "release_health_html source failure" in captured.err


def test_generator_cli_writes_pages_support_files(tmp_path, offline_enrichment_fetchers):
    output_dir = tmp_path / "site"

    code = generate_policy_cli.main([
        "--release-health-html",
        str(FIXTURES / "windows11-release-health.html"),
        "--servicing-toc",
        str(FIXTURES / "windows11-servicing-toc.json"),
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


def test_generator_cli_merges_degraded_source_diagnostic_issue_sync_metadata(tmp_path, offline_enrichment_fetchers):
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
        "--servicing-toc",
        str(FIXTURES / "windows11-servicing-toc.json"),
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
