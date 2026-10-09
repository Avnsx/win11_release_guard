from __future__ import annotations

from win11_release_guard import release_health as _release_health_module
import json
from dataclasses import replace
from pathlib import Path
import pytest
from tools import generate_policy as generate_policy_cli
from win11_release_guard.exceptions import PolicyFetchError, PolicyParseError
from win11_release_guard.models import QualityPolicy, ReleasePolicyEntry
import win11_release_guard.policy_generator as policy_generator_module
from win11_release_guard.policy_generator import build_policy_from_sources, generate_policy
from win11_release_guard.policy_schema import validate_policy_document
from tests.support.policy_generator_helpers import (
    ATOM_SOURCE_DIAGNOSTIC_ID,
    FIXTURES,
    PENDING_26H2_FIXTURE,
    _assert_no_raw_support_article_leakage,
    _generated_output_bundle,
    _html,
    _kb5094126_generated_fixture_policy,
    _offline_msrc_cvrf_fetcher,
    _offline_support_article_fetcher,
    _pending_26h2_policy,
    _pending_b_release_events,
    _release_health_caught_up_to_kb5094126,
    _support_article_html,
    _toc,
    _toc_with_new_b_release,
    _with_25h2_current_latest_build,
    offline_enrichment_fetchers,
)


def test_policy_schema_accepts_atom_source_diagnostic_event_and_issue_status_id():
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc_with_new_b_release())
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
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc_with_new_b_release())
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
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc_with_new_b_release())
    data = policy.to_dict()
    data["source_diagnostics"]["issue_sync"] = {
        "status": "unavailable",
        "reason": "github_issues_sync_failed",
        "message": "GitHub Issues sync failed during publish-policy.",
    }

    warnings = validate_policy_document(data)
    assert not any("issue_sync" in warning for warning in warnings)


def test_policy_schema_rejects_invalid_source_diagnostic_issue_sync_metadata():
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc_with_new_b_release())
    data = policy.to_dict()
    data["source_diagnostics"]["issue_sync"] = {
        "status": "unavailable",
        "token": "must-not-be-accepted",
    }

    with pytest.raises(PolicyParseError, match="source_diagnostics.issue_sync contains unsupported fields"):
        validate_policy_document(data)


def test_policy_schema_rejects_invalid_source_diagnostic_issue_status_url():
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc_with_new_b_release())
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
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc_with_new_b_release())
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
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc())
    data = policy.to_dict()
    data["source_diagnostics"] = {"release_health_html": "not an object"}

    with pytest.raises(PolicyParseError, match="source_diagnostics.release_health_html"):
        validate_policy_document(data)


def test_policy_schema_rejects_invalid_source_diagnostics_event_counts():
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc())
    data = policy.to_dict()
    data["source_diagnostics"]["event_counts"]["warning"] = -1

    with pytest.raises(PolicyParseError, match="source_diagnostics.event_counts.warning"):
        validate_policy_document(data)


def test_b_release_quality_baseline_does_not_require_preview():
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc())
    baseline = policy.quality_baselines["25H2"][QualityPolicy.B_RELEASE_ONLY.value]

    assert baseline["build"] == "26200.8457"
    assert baseline["preview"] is False


def test_current_table_preview_latest_stays_distinct_from_required_baseline():
    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        servicing_toc_json=_toc(),
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


def test_missing_servicing_toc_still_generates_policy_with_warning():
    policy = generate_policy(release_health_html=_html(), servicing_toc_json=None)

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert any("Servicing TOC missing" in warning for warning in policy.validation_warnings)
    event = next(event for event in policy.source_diagnostics["events"] if event["kind"] == "servicing_toc_missing")
    assert event["severity"] == "warning"
    assert event["affects_required_baseline"] is False


def test_servicing_toc_parse_failure_is_structured_source_diagnostic():
    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json='{"items": [',
        generated_at_utc="2026-05-20T00:00:00+00:00",
    )

    assert any("Servicing TOC could not be parsed" in warning for warning in policy.validation_warnings)
    event = next(event for event in policy.source_diagnostics["events"] if event["kind"] == "servicing_toc_parse_failed")
    assert event["severity"] == "warning"
    assert "Servicing TOC could not be parsed" in event["message"]
    assert not any(
        event["kind"] == "source_drift_unresolved_after_24h"
        for event in policy.source_diagnostics["events"]
    )


def test_generate_policy_fails_hard_when_release_health_tables_are_unusable():
    with pytest.raises(PolicyParseError, match="release_history tables"):
        generate_policy(release_health_html="<html><body>No release data</body></html>", servicing_toc_json=_toc())


def test_generator_cli_merges_static_source_diagnostic_issue_status(tmp_path, offline_enrichment_fetchers):
    output_dir = tmp_path / "site"
    servicing_toc = tmp_path / "windows11-servicing-toc-new-baseline.json"
    servicing_toc.write_text(_toc_with_new_b_release(), encoding="utf-8")
    preview_policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=servicing_toc.read_text(encoding="utf-8"),
        support_article_fetcher=_offline_support_article_fetcher,
        msrc_cvrf_fetcher=_offline_msrc_cvrf_fetcher,
    )
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
        "--servicing-toc",
        str(servicing_toc),
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


def test_generator_cli_strips_extra_source_diagnostic_issue_status_fields(tmp_path, offline_enrichment_fetchers):
    output_dir = tmp_path / "site"
    preview_policy = generate_policy(release_health_html=_html(), servicing_toc_json=_toc())
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


def test_baseline_update_notice_uses_support_wording_when_only_support_confirms_security(
    tmp_path: Path,
) -> None:
    # Support article validates and reports a security update, but MSRC CVRF is
    # unavailable. Security must be attributed to Microsoft Support, never MSRC.
    support_html = _support_article_html(security=True)
    policy = _kb5094126_generated_fixture_policy(
        _release_health_caught_up_to_kb5094126(),
        support_html=support_html,
        msrc_error=PolicyFetchError("MSRC unavailable"),
    )
    notice = policy.source_diagnostics["baseline_update_notice"]
    assert notice["active"] is True
    assert notice["is_security"] is True
    assert notice["security_evidence_source"] == "support_article"
    assert "MSRC confirms" not in notice["summary"]
    assert "Microsoft Support notes it includes the security update" in notice["summary"]

    outputs = _generated_output_bundle(policy, tmp_path)
    index = str(outputs["index"])
    # Dashboard chip and summary must agree on the Microsoft Support attribution.
    assert "Security confirmed by Microsoft Support" in index
    assert "MSRC confirms" not in index
    # Visible copy/export JSON must not carry contradictory MSRC source wording.
    assert "MSRC confirms" not in str(outputs["policy_text"])
    assert "MSRC confirms" not in str(outputs["manifest_text"])
    _assert_no_raw_support_article_leakage(outputs, support_html)


def _release_health_with_baseline_date(date_text: str) -> str:
    base = _release_health_caught_up_to_kb5094126()
    needle = "        <td>2026-06 B</td>\n        <td>2026-06-09</td>"
    assert needle in base
    return base.replace(needle, f"        <td>2026-06 B</td>\n        <td>{date_text}</td>", 1)


def test_generation_and_rendering_survive_impossible_baseline_date(tmp_path: Path) -> None:
    policy = _kb5094126_generated_fixture_policy(_release_health_with_baseline_date("2026-02-30"))
    notice = policy.source_diagnostics.get("baseline_update_notice")
    assert notice is None or notice.get("active") is not True
    outputs = _generated_output_bundle(policy, tmp_path)
    # The baseline-notice panel must not be rendered (the JS selector string for
    # the live timer can still appear, so assert on the panel section marker).
    assert 'class="panel span-12 baseline-update-notice"' not in str(outputs["index"])
    validate_policy_document(outputs["policy"])


def test_required_baseline_kb_is_enriched_alongside_a_newer_observed_kb() -> None:
    support_calls: list[str] = []
    msrc_calls: list[str] = []

    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        support_calls.append(url)
        return _offline_support_article_fetcher(url, timeout, max_bytes)

    def msrc_fetcher(url: str, timeout: float, max_bytes: int) -> dict[str, object]:
        msrc_calls.append(url)
        return _offline_msrc_cvrf_fetcher(url, timeout, max_bytes)

    policy = generate_policy(
        release_health_html=_html(),
        servicing_toc_json=_toc(),
        generated_at_utc="2026-05-20T00:00:00+00:00",
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )

    assert msrc_calls == ["https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-May"]
    assert (
        "https://support.microsoft.com/en-us/servicing/os/windows-11/"
        "2026/05/may-12-2026-kb5089549-os-builds-26200-8457-and-26100-8457"
    ) in support_calls
    assert policy.source_diagnostics["msrc_cvrf"]["2026-May"]["status"] == "ok"


def test_generated_policy_holds_broad_target_while_new_release_awaits_first_b_release(tmp_path):
    outputs = _generated_output_bundle(_pending_26h2_policy(), tmp_path)
    data = outputs["policy"]

    target = data["broad_target_existing_devices"]
    assert (target["version"], target["build_family"]) == ("25H2", 26200)
    assert target["required_baseline_build"] == "26200.9445"
    assert data["quality_baselines"]["25H2"]["b_release_only"]["build"] == "26200.9445"
    assert "b_release_only" not in data["quality_baselines"]["26H2"]
    pending = next(entry for entry in data["current_versions"] if entry["version"] == "26H2")
    assert pending["metadata"]["not_broad_target"] is True
    assert pending["metadata"]["not_broad_target_existing_devices"] is True
    assert pending["metadata"]["pending_first_b_release"] is True
    assert data["supported_build_families"]["26300"] == "26H2"
    assert [(note["type"], note["release"]) for note in data["known_notes"]] == [("special_release", "26H1")]


def test_generated_policy_promotes_new_release_once_it_has_a_b_release(tmp_path):
    october_b = (
        "      <tr>\n        <td>General Availability Channel</td>\n        <td>2026-10 B</td>\n"
        "        <td>2026-10-13</td>\n        <td>{build}</td>\n        <td>KB5130001</td>\n      </tr>\n"
    )
    html = PENDING_26H2_FIXTURE.read_text(encoding="utf-8")
    for heading, build in (("Version 26H2 (OS build 26300)", "26300.9700"), ("Version 25H2 (OS build 26200)", "26200.9700")):
        body = html.index("<tbody>\n", html.index(f"<h3>{heading}</h3>")) + len("<tbody>\n")
        html = html[:body] + october_b.format(build=build) + html[body:]
    source = tmp_path / "release-health.html"
    source.write_text(html, encoding="utf-8")

    policy = build_policy_from_sources(
        release_health_html_path=source,
        servicing_toc_path=FIXTURES / "windows11-servicing-toc.json",
        signature_status="valid",
        support_article_fetcher=_offline_support_article_fetcher,
        msrc_cvrf_fetcher=_offline_msrc_cvrf_fetcher,
    )
    data = _generated_output_bundle(policy, tmp_path / "site")["policy"]

    assert data["broad_target_existing_devices"]["version"] == "26H2"
    assert data["broad_target_existing_devices"]["required_baseline_build"] == "26300.9700"
    assert not _pending_b_release_events(data)


def test_generator_refuses_to_publish_when_runtime_clients_would_select_another_target(monkeypatch):
    import win11_release_guard.remote_policy as remote_policy_module

    monkeypatch.setattr(_release_health_module, "with_pending_b_release_metadata", lambda entry, hold: entry)

    with pytest.raises(PolicyParseError, match=r"Runtime clients would select 26H2/26300 .*25H2/26200"):
        _pending_26h2_policy()


def test_client_target_agreement_guard_checks_enterprise_education_scope():
    policy = _pending_26h2_policy()

    def enterprise_only_newer_release(entry: ReleasePolicyEntry) -> ReleasePolicyEntry:
        if entry.version != "26H2":
            return entry
        metadata = {
            key: value
            for key, value in entry.metadata.items()
            if key not in {"not_broad_target", "not_broad_target_existing_devices", "pending_first_b_release"}
        }
        metadata["home_pro_end"] = "End of updates"
        return replace(entry, metadata=metadata)

    split = replace(
        policy,
        current_versions=tuple(enterprise_only_newer_release(entry) for entry in policy.current_versions),
        supported_releases=tuple(enterprise_only_newer_release(entry) for entry in policy.supported_releases),
    )

    with pytest.raises(PolicyParseError, match=r"would select 26H2/26300 for enterprise_education devices"):
        policy_generator_module._raise_on_client_target_disagreement(split)
