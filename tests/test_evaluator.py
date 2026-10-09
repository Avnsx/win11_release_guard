from __future__ import annotations

from win11_release_guard.evaluator import _build_key, _release_key, evaluate_windows_update_state, select_broad_fleet_target, select_quality_baseline
from win11_release_guard.models import EvaluationResult, EvaluationStatus, ReleaseHistoryEntry
from tests.support.evaluator_helpers import _client_device, _pending_26h2_policy, _policy_with_26h1_25h2_24h2


def test_release_and_build_keys():
    assert _release_key("25H2") == (25, 2)
    assert _build_key("26200.8457") == (26200, 8457)
    assert _release_key("bad") == (-1, -1)
    assert _build_key("bad") == (-1, -1)


def test_select_broad_fleet_target_defaults_to_25h2_not_26h1():
    target = select_broad_fleet_target(_policy_with_26h1_25h2_24h2())

    assert target.version == "25H2"


def test_select_broad_fleet_target_honors_explicit_target_release():
    target = select_broad_fleet_target(
        _policy_with_26h1_25h2_24h2(),
        explicit_target_release="24H2",
    )

    assert target.version == "24H2"


def test_select_broad_fleet_target_honors_excluded_releases():
    target = select_broad_fleet_target(
        _policy_with_26h1_25h2_24h2(),
        excluded_releases={"26H1"},
    )

    assert target.version == "25H2"


def test_select_quality_baseline_b_release_only_skips_d_preview():
    baseline = select_quality_baseline(
        _policy_with_26h1_25h2_24h2(),
        "25H2",
        quality_policy="b_release_only",
    )

    assert isinstance(baseline, ReleaseHistoryEntry)
    assert baseline.build == "26200.8457"
    assert baseline.update_type_letter == "B"


def test_select_quality_baseline_latest_non_preview_can_pick_oob():
    baseline = select_quality_baseline(
        _policy_with_26h1_25h2_24h2(),
        "25H2",
        quality_policy="latest_non_preview",
    )

    assert isinstance(baseline, ReleaseHistoryEntry)
    assert baseline.build == "26200.8460"
    assert baseline.update_type_letter == "OOB"


def test_evaluation_result_candidate_status_round_trips():
    result = EvaluationResult(
        status=EvaluationStatus.CHECK_INCOMPLETE,
        candidate_status=EvaluationStatus.OUT_OF_SCOPE,
        local_scope_status=EvaluationStatus.OUT_OF_SCOPE,
        policy_age_hours=1104.0,
        feed_age_days=46.0,
    )

    payload = result.to_dict()
    restored = EvaluationResult.from_dict(payload)

    assert payload["candidate_status"] == EvaluationStatus.OUT_OF_SCOPE.value
    assert payload["local_scope_status"] == EvaluationStatus.OUT_OF_SCOPE.value
    assert restored.status is EvaluationStatus.CHECK_INCOMPLETE
    assert restored.candidate_status is EvaluationStatus.OUT_OF_SCOPE
    assert restored.local_scope_status is EvaluationStatus.OUT_OF_SCOPE
    assert restored.policy_age_hours == 1104.0
    assert restored.feed_age_days == 46.0


def test_static_build_family_map_recognises_26h2():
    from win11_release_guard.local_state import infer_release_from_build_family

    assert infer_release_from_build_family(26300) == "26H2"


def test_select_quality_baseline_b_release_only_never_falls_back_to_a_preview():
    assert select_quality_baseline(_pending_26h2_policy(), "26H2", quality_policy="b_release_only") == {}


def test_explicit_target_without_b_release_does_not_require_a_preview_build():
    result = evaluate_windows_update_state(
        _client_device(26300, 9457, "26H2"),
        _pending_26h2_policy(),
        explicit_target_release="26H2",
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.baseline_build is None
    assert any("no monthly security (B) release" in warning for warning in result.warnings)


def test_preview_device_on_explicit_target_without_b_release_gets_no_b_baseline_claim():
    result = evaluate_windows_update_state(
        _client_device(26300, 9550, "26H2"),
        _pending_26h2_policy(),
        explicit_target_release="26H2",
    )

    assert result.baseline_build is None
    assert not any("based on the B baseline" in warning for warning in result.warnings), result.warnings


def test_device_on_held_target_september_b_release_is_compliant():
    result = evaluate_windows_update_state(_client_device(26200, 9445, "25H2"), _pending_26h2_policy())

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.target.version == "25H2"
    assert result.baseline_build == "26200.9445"
