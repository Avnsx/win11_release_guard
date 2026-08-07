from __future__ import annotations

import json
from pathlib import Path

from win11_release_guard.policy_generator import generate_policy
from win11_release_guard.wu_offer_probe import WindowsUpdateOffer


FIXTURES = Path("tests/fixtures")
GENERATED_AT = "2026-06-11T00:00:00+00:00"
PROBE_UNAVAILABLE_KIND = "windows_update_probe_unavailable"
PROBE_CORROBORATION_KIND = "windows_update_probe_corroboration"


def _html() -> str:
    return (FIXTURES / "windows11-release-health.html").read_text(encoding="utf-8")


def _toc() -> str:
    return (FIXTURES / "windows11-servicing-toc.json").read_text(encoding="utf-8")


def _policy(probe=None):
    return generate_policy(
        release_health_html=_html(),
        servicing_toc_json=_toc(),
        generated_at_utc=GENERATED_AT,
        windows_update_probe=probe,
    )


def _without_probe_diagnostics(document: dict) -> dict:
    data = json.loads(json.dumps(document))
    diagnostics = data["source_diagnostics"]
    diagnostics.pop("event_counts", None)
    diagnostics["events"] = [
        event
        for event in diagnostics["events"]
        if not str(event.get("kind") or "").startswith("windows_update_probe")
    ]
    diagnostics["notices"] = [
        notice for notice in diagnostics["notices"] if "Windows Update offer" not in notice
    ]
    return data


def test_probe_failure_adds_one_notice_and_leaves_the_policy_identical() -> None:
    def failing_probe() -> tuple[WindowsUpdateOffer, ...]:
        raise TimeoutError("timed out reading the SyncUpdates response")

    baseline = _policy().to_dict()
    probed = _policy(failing_probe).to_dict()

    added = [
        event
        for event in probed["source_diagnostics"]["events"]
        if event not in baseline["source_diagnostics"]["events"]
    ]
    assert [event["kind"] for event in added] == [PROBE_UNAVAILABLE_KIND]
    assert added[0]["severity"] == "notice"
    assert added[0]["affects_broad_target"] is False
    assert added[0]["affects_required_baseline"] is False
    assert added[0]["build"] is None
    assert "timed out reading the SyncUpdates response" in added[0]["message"]
    assert probed["source_diagnostics"]["event_counts"] == {
        **baseline["source_diagnostics"]["event_counts"],
        "notice": baseline["source_diagnostics"]["event_counts"]["notice"] + 1,
    }
    assert probed["validation_warnings"] == baseline["validation_warnings"]
    assert _without_probe_diagnostics(probed) == _without_probe_diagnostics(baseline)


def test_probe_build_newer_than_every_document_source_never_moves_the_baseline() -> None:
    newer = WindowsUpdateOffer(
        kb_article="KB5101650",
        build="26200.9999",
        release_version="10.0.26200.9999",
        title="2026-07 Security Update (KB5101650) (26200.9999)",
        support_url="https://support.microsoft.com/help/5101650",
        is_preview=False,
    )
    baseline = _policy()
    probed = _policy(lambda: (newer,))

    assert baseline.broad_target_existing_devices.latest_observed_build == "26200.8457"
    assert probed.broad_target_existing_devices.latest_observed_build == "26200.8457"
    assert probed.broad_target_existing_devices.required_baseline_build == "26200.8457"
    assert probed.broad_target_existing_devices.latest_build == "26200.8457"
    assert probed.current_versions == baseline.current_versions
    assert probed.release_history == baseline.release_history

    corroboration = [
        event
        for event in probed.source_diagnostics["events"]
        if event["kind"] == PROBE_CORROBORATION_KIND
    ]
    assert len(corroboration) == 1
    assert corroboration[0]["severity"] == "notice"
    assert corroboration[0]["affects_required_baseline"] is False
    assert "26200.9999 (KB5101650)" in corroboration[0]["message"]
