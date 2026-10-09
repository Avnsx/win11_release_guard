from __future__ import annotations

import json
from pathlib import Path
from win11_release_guard.exceptions import PolicyFetchError
from win11_release_guard.models import ReleasePolicy, ReleasePolicyEntry
import win11_release_guard.policy_generator as policy_generator_module
from win11_release_guard.policy_generator import generate_policy, write_policy_outputs
from win11_release_guard.policy_schema import validate_policy_document
from tests.support.policy_generator_helpers import (
    ATOM_SOURCE_DIAGNOSTIC_ID,
    FAKE_MSRC_CVRF_WITHOUT_KB5094126,
    FAKE_MSRC_CVRF_WITH_KB5094126,
    KB5094126_SUPPORT_HTML_NO_SECURITY,
    _generated_output_bundle,
    _html,
    _html_file,
    _kb5094126_atom_event,
    _kb5094126_generated_fixture_policy,
    _kb5094126_policy_with_support_html,
    _kb5094126_toc_fixture,
    _support_article_html,
    _with_25h2_current_latest_build,
)


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
    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        return KB5094126_SUPPORT_HTML_NO_SECURITY

    def msrc_fetcher(url: str, timeout: float, max_bytes: int):
        return FAKE_MSRC_CVRF_WITHOUT_KB5094126

    policy = generate_policy(
        release_health_html=_with_25h2_current_latest_build(_html(), "26200.8524"),
        servicing_toc_json=_kb5094126_toc_fixture(),
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
