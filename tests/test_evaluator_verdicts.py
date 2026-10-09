from __future__ import annotations

from dataclasses import replace
from win11_release_guard.evaluator import evaluate, evaluate_windows_update_state, infer_installed_release
from win11_release_guard.models import BuildEvidenceSource, EditionScope, EvaluationStatus, InstalledBuildClassification, LocalWindowsState, ReleaseHistoryEntry, ReleasePolicy, ReleasePolicyEntry, ServicingChannel
from tests.support.evaluator_helpers import (
    _client_device,
    _live_26200_8524_local,
    _live_26200_8524_policy,
    _pending_26h2_policy,
    _policy_with_26h1_25h2_24h2,
)


def _edition_channel_policy() -> ReleasePolicy:
    return ReleasePolicy(
        broad_target_existing_devices=ReleasePolicyEntry(
            version="25H2",
            build_family=26200,
            latest_build="26200.8457",
            baseline_build="26200.8457",
            servicing_option="General Availability Channel",
            edition_scopes=(EditionScope.HOME_PRO, EditionScope.ENTERPRISE_EDUCATION),
            servicing_channel=ServicingChannel.GENERAL_AVAILABILITY,
        ),
        current_versions=(
            ReleasePolicyEntry(
                version="25H2",
                build_family=26200,
                latest_build="26200.8457",
                baseline_build="26200.8457",
                servicing_option="General Availability Channel",
                edition_scopes=(EditionScope.HOME_PRO, EditionScope.ENTERPRISE_EDUCATION),
                servicing_channel=ServicingChannel.GENERAL_AVAILABILITY,
            ),
            ReleasePolicyEntry(
                version="24H2",
                build_family=26100,
                latest_build="26100.8457",
                baseline_build="26100.8457",
                servicing_option="General Availability Channel",
                edition_scopes=(EditionScope.HOME_PRO, EditionScope.ENTERPRISE_EDUCATION),
                servicing_channel=ServicingChannel.GENERAL_AVAILABILITY,
            ),
            ReleasePolicyEntry(
                version="24H2",
                build_family=26100,
                latest_build="26100.8457",
                baseline_build="26100.8457",
                servicing_option="Long-Term Servicing Channel",
                edition_scopes=(EditionScope.ENTERPRISE_LTSC, EditionScope.IOT_ENTERPRISE_LTSC),
                servicing_channel=ServicingChannel.LTSC,
            ),
        ),
        release_history=(
            ReleaseHistoryEntry(
                release="25H2",
                build_family=26200,
                build="26200.8457",
                servicing_option="General Availability Channel",
                update_type="2026-05 B",
                update_type_letter="B",
                availability_date="2026-05-12",
            ),
            ReleaseHistoryEntry(
                release="24H2",
                build_family=26100,
                build="26100.8457",
                servicing_option="General Availability Channel",
                update_type="2026-05 B",
                update_type_letter="B",
                availability_date="2026-05-12",
            ),
            ReleaseHistoryEntry(
                release="24H2",
                build_family=26100,
                build="26100.8457",
                servicing_option="Long-Term Servicing Channel",
                update_type="2026-05 B",
                update_type_letter="B",
                availability_date="2026-05-12",
            ),
        ),
        supported_build_families={26100: "24H2", 26200: "25H2"},
    )


def test_evaluate_feature_update_required_uses_policy_target():
    policy = ReleasePolicy(
        broad_target_existing_devices=ReleasePolicyEntry(
            version="25H2",
            build_family=26200,
            baseline_build="26200.8457",
        ),
        current_versions=(
            ReleasePolicyEntry(
                version="25H2",
                build_family=26200,
                baseline_build="26200.8457",
                servicing_option="General Availability Channel",
            ),
        ),
        supported_build_families={26100: "24H2", 26200: "25H2"},
    )
    local = LocalWindowsState(current_build=26100, full_build="26100.8457")

    result = evaluate(local, policy)

    assert result.status is EvaluationStatus.FEATURE_UPDATE_REQUIRED
    assert result.target is not None
    assert result.target.version == "25H2"


def test_evaluate_unknown_without_policy_target():
    result = evaluate(LocalWindowsState(current_build=26200), ReleasePolicy())

    assert result.status is EvaluationStatus.UNKNOWN_LOCAL_RELEASE


def test_evaluate_windows_update_state_24h2_against_25h2_feature_update_required():
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26100, full_build="26100.8457"),
        _policy_with_26h1_25h2_24h2(),
    )

    assert result.status is EvaluationStatus.FEATURE_UPDATE_REQUIRED
    assert result.target is not None
    assert result.target.version == "25H2"
    assert result.baseline_build == "26200.8457"
    assert result.is_warning is True
    assert result.is_error is False
    assert "Feature update" in result.action
    assert result.summary is not None


def test_evaluate_windows_update_state_25h2_old_ubr_quality_update_required():
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26200, full_build="26200.7000"),
        _policy_with_26h1_25h2_24h2(),
    )

    assert result.status is EvaluationStatus.QUALITY_UPDATE_REQUIRED
    assert result.baseline_build == "26200.8457"
    assert result.is_warning is True
    assert result.is_error is False
    assert "cumulative update" in result.action


def test_evaluate_uses_required_baseline_when_latest_observed_is_preview():
    base_policy = _edition_channel_policy()
    assert base_policy.broad_target_existing_devices is not None
    target = replace(base_policy.broad_target_existing_devices, latest_observed_build="26200.8524")
    current_versions = tuple(
        replace(entry, latest_observed_build="26200.8524")
        if entry.version == "25H2" and entry.build_family == 26200
        else entry
        for entry in base_policy.current_versions
    )
    policy = replace(
        base_policy,
        broad_target_existing_devices=target,
        current_versions=current_versions,
    )

    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26200, full_build="26200.8457"),
        policy,
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.baseline_build == "26200.8457"
    assert result.target is not None
    assert result.target.latest_build == "26200.8457"
    assert result.target.latest_observed_build == "26200.8524"
    assert result.target.required_baseline_build == "26200.8457"
    assert result.details["target_latest_observed_build"] == "26200.8524"
    assert result.details["target_required_baseline_build"] == "26200.8457"
    current_25h2 = next(entry for entry in policy.current_versions if entry.version == "25H2")
    assert current_25h2.latest_build == "26200.8457"
    assert current_25h2.latest_observed_build == "26200.8524"
    assert current_25h2.required_baseline_build == "26200.8457"


def test_evaluate_windows_update_state_25h2_current_or_higher_compliant():
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26200, full_build="26200.9000"),
        _policy_with_26h1_25h2_24h2(),
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.is_warning is False
    assert result.is_error is False
    assert result.action == "No action required."


def test_evaluate_windows_update_state_26h1_above_broad_target_special_release():
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=28000, full_build="28000.2113"),
        _policy_with_26h1_25h2_24h2(),
    )

    assert result.status is EvaluationStatus.ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE
    assert result.target is not None
    assert result.target.version == "25H2"
    assert result.installed_release == "26H1"
    assert result.is_warning is True
    assert result.is_error is False
    assert "broad-fleet reference" in result.action


def test_wua_not_offered_does_not_override_feature_update_required():
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26100, full_build="26100.8457"),
        _policy_with_26h1_25h2_24h2(),
        wua_secondary={"target_feature_update_offered": False},
    )

    assert result.status is EvaluationStatus.FEATURE_UPDATE_REQUIRED
    assert result.wua_secondary == {"target_feature_update_offered": False}
    assert (
        "Windows Update bietet Zielrelease aktuell nicht an; Primary Policy bleibt maßgeblich."
        in result.notes
    )


def test_wua_not_offered_below_target_adds_discrepancy_warning():
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26100, full_build="26100.8457"),
        _policy_with_26h1_25h2_24h2(),
        wua_secondary={"target_feature_update_offered": False, "available": True},
    )

    assert result.status is EvaluationStatus.FEATURE_UPDATE_REQUIRED
    assert any("Discrepancy: WUA did not offer" in warning for warning in result.warnings)


def test_wua_not_offered_is_normal_when_already_on_target():
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26200, full_build="26200.8457"),
        _policy_with_26h1_25h2_24h2(),
        wua_secondary={"target_feature_update_offered": False, "available": True},
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert not any("Discrepancy: WUA did not offer" in warning for warning in result.warnings)


def test_wua_unavailable_warns_without_changing_primary_verdict():
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26200, full_build="26200.8457"),
        _policy_with_26h1_25h2_24h2(),
        wua_secondary={"available": False, "warnings": ["WUA probe timed out after 0.1 seconds."], "errors": []},
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert any("WUA secondary probe unavailable" in warning for warning in result.warnings)


def test_windows_10_22h2_is_out_of_scope_not_feature_update_required():
    result = evaluate_windows_update_state(
        LocalWindowsState(
            current_build=19045,
            full_build="19045.4046",
            display_version="22H2",
            product_name="Windows 10 Pro",
        ),
        _policy_with_26h1_25h2_24h2(),
    )

    assert result.status is EvaluationStatus.OUT_OF_SCOPE
    assert "major upgrade recommendation is disabled" in result.action


def test_windows_10_major_upgrade_requires_explicit_opt_in():
    result = evaluate_windows_update_state(
        LocalWindowsState(
            current_build=19045,
            full_build="19045.4046",
            display_version="22H2",
            product_name="Windows 10 Pro",
        ),
        _policy_with_26h1_25h2_24h2(),
        allow_major_upgrade_recommendation=True,
    )

    assert result.status is EvaluationStatus.FEATURE_UPDATE_REQUIRED
    assert result.installed_release == "22H2"
    assert result.metadata["installed_release_inference"]["confidence"] == "major_upgrade_local_hint"


def test_server_is_out_of_scope():
    result = evaluate_windows_update_state(
        LocalWindowsState(
            current_build=26100,
            full_build="26100.8457",
            product_name="Windows Server 2025 Datacenter",
            installation_type="Server",
        ),
        _policy_with_26h1_25h2_24h2(),
    )

    assert result.status is EvaluationStatus.OUT_OF_SCOPE
    assert "Windows Server" in result.action


def test_unknown_syntactic_release_is_unrecognized_not_above_target():
    result = evaluate_windows_update_state(
        LocalWindowsState(
            current_build=99000,
            full_build="99000.1000",
            display_version="99H2",
        ),
        _policy_with_26h1_25h2_24h2(),
    )

    assert result.status is EvaluationStatus.UNKNOWN_LOCAL_RELEASE
    assert "unrecognized" in result.action.lower()
    inference = result.metadata["installed_release_inference"]
    assert inference["confidence"] == "unrecognized"
    assert inference["release"] is None


def test_display_version_25h2_but_build_maps_24h2_policy_build_wins():
    local = LocalWindowsState(
        current_build=26100,
        full_build="26100.8457",
        display_version="25H2",
    )

    inference = infer_installed_release(local, _policy_with_26h1_25h2_24h2())
    result = evaluate_windows_update_state(local, _policy_with_26h1_25h2_24h2())

    assert inference.release == "24H2"
    assert inference.source == "policy.supported_build_families"
    assert inference.conflicts
    assert result.installed_release == "24H2"
    assert result.status is EvaluationStatus.FEATURE_UPDATE_REQUIRED


def test_display_version_24h2_but_build_maps_25h2_policy_build_wins():
    local = LocalWindowsState(
        current_build=26200,
        full_build="26200.8457",
        display_version="24H2",
    )

    inference = infer_installed_release(local, _policy_with_26h1_25h2_24h2())
    result = evaluate_windows_update_state(local, _policy_with_26h1_25h2_24h2())

    assert inference.release == "25H2"
    assert inference.source == "policy.supported_build_families"
    assert inference.conflicts
    assert result.installed_release == "25H2"
    assert result.status is EvaluationStatus.COMPLIANT


def test_pro_24h2_uses_ga_target_and_requires_feature_update():
    result = evaluate_windows_update_state(
        LocalWindowsState(
            current_build=26100,
            full_build="26100.8457",
            edition_id="Professional",
            edition_scope=EditionScope.HOME_PRO,
            servicing_channel=ServicingChannel.GENERAL_AVAILABILITY,
        ),
        _edition_channel_policy(),
    )

    assert result.status is EvaluationStatus.FEATURE_UPDATE_REQUIRED
    assert result.target is not None
    assert result.target.version == "25H2"
    assert result.target.servicing_channel is ServicingChannel.GENERAL_AVAILABILITY
    assert "General Availability" in (result.target_selection_reason or "")


def test_pro_25h2_current_is_compliant():
    result = evaluate_windows_update_state(
        LocalWindowsState(
            current_build=26200,
            full_build="26200.8457",
            edition_id="Professional",
            edition_scope=EditionScope.HOME_PRO,
            servicing_channel=ServicingChannel.GENERAL_AVAILABILITY,
        ),
        _edition_channel_policy(),
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.target is not None
    assert result.target.version == "25H2"


def test_enterprise_non_ltsc_24h2_uses_ga_target_and_requires_feature_update():
    result = evaluate_windows_update_state(
        LocalWindowsState(
            current_build=26100,
            full_build="26100.8457",
            edition_id="Enterprise",
            edition_scope=EditionScope.ENTERPRISE_EDUCATION,
            servicing_channel=ServicingChannel.GENERAL_AVAILABILITY,
        ),
        _edition_channel_policy(),
    )

    assert result.status is EvaluationStatus.FEATURE_UPDATE_REQUIRED
    assert result.target is not None
    assert result.target.version == "25H2"
    assert result.target.servicing_channel is ServicingChannel.GENERAL_AVAILABILITY


def test_enterprises_24h2_current_ltsc_is_compliant_not_feature_update_required():
    result = evaluate_windows_update_state(
        LocalWindowsState(
            current_build=26100,
            full_build="26100.8457",
            edition_id="EnterpriseS",
            edition_scope=EditionScope.ENTERPRISE_LTSC,
            servicing_channel=ServicingChannel.LTSC,
        ),
        _edition_channel_policy(),
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.target is not None
    assert result.target.version == "24H2"
    assert result.target.servicing_channel is ServicingChannel.LTSC
    assert "LTSC" in (result.target_selection_reason or "")


def test_iot_enterprises_24h2_uses_ltsc_policy_path():
    result = evaluate_windows_update_state(
        LocalWindowsState(
            current_build=26100,
            full_build="26100.8457",
            edition_id="IoTEnterpriseS",
            edition_scope=EditionScope.IOT_ENTERPRISE_LTSC,
            servicing_channel=ServicingChannel.LTSC,
        ),
        _edition_channel_policy(),
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.target is not None
    assert result.target.version == "24H2"
    assert result.target.servicing_channel is ServicingChannel.LTSC


def test_enterprises_24h2_old_ubr_requires_quality_update_not_feature_update():
    result = evaluate_windows_update_state(
        LocalWindowsState(
            current_build=26100,
            full_build="26100.7000",
            edition_id="EnterpriseS",
            edition_scope=EditionScope.ENTERPRISE_LTSC,
            servicing_channel=ServicingChannel.LTSC,
        ),
        _edition_channel_policy(),
    )

    assert result.status is EvaluationStatus.QUALITY_UPDATE_REQUIRED
    assert result.target is not None
    assert result.target.version == "24H2"
    assert result.target.servicing_channel is ServicingChannel.LTSC
    assert result.baseline_build == "26100.8457"


def test_unknown_edition_gets_conservative_warning():
    result = evaluate_windows_update_state(
        LocalWindowsState(
            current_build=26100,
            full_build="26100.8457",
            edition_scope=EditionScope.UNKNOWN,
            servicing_channel=ServicingChannel.UNKNOWN,
        ),
        _edition_channel_policy(),
    )

    assert result.status is EvaluationStatus.FEATURE_UPDATE_REQUIRED
    assert result.target is not None
    assert result.target.version == "25H2"
    assert any("Unknown Windows edition scope" in warning for warning in result.warnings)


def test_server_scope_remains_out_of_scope():
    result = evaluate_windows_update_state(
        LocalWindowsState(
            current_build=26100,
            full_build="26100.8457",
            product_name="Windows Server 2025 Datacenter",
            edition_scope=EditionScope.SERVER,
        ),
        _edition_channel_policy(),
    )

    assert result.status is EvaluationStatus.OUT_OF_SCOPE


def test_live_26200_8524_preview_row_is_compliant_with_preview_flag():
    result = evaluate_windows_update_state(
        _live_26200_8524_local(),
        _live_26200_8524_policy(),
        wua_secondary={
            "service_enabled": True,
            "available_updates": [{"title": "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602"}],
            "history": [{"title": "2026-05 Vorschauupdate (KB5089573) (26200.8524)"}],
        },
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.installed_build_origin is not None
    assert result.installed_build_origin.classification is InstalledBuildClassification.PREVIEW
    assert result.installed_build_origin.evidence_source is BuildEvidenceSource.POLICY_RELEASE_HISTORY
    assert result.installed_build_origin.kb_article == "KB5089573"
    assert "LOCAL_BUILD_IS_PREVIEW" in result.installed_build_origin.diagnostic_flags


def test_live_26200_8457_b_release_origin_flag():
    result = evaluate_windows_update_state(
        _live_26200_8524_local("26200.8457"),
        _live_26200_8524_policy(),
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.installed_build_origin is not None
    assert result.installed_build_origin.classification is InstalledBuildClassification.B_RELEASE
    assert result.installed_build_origin.kb_article == "KB5089549"
    assert "LOCAL_BUILD_IS_B_RELEASE" in result.installed_build_origin.diagnostic_flags


def test_live_26200_8524_disallow_preview_returns_preview_status():
    result = evaluate_windows_update_state(
        _live_26200_8524_local(),
        _live_26200_8524_policy(),
        disallow_preview_installed=True,
    )

    assert result.status is EvaluationStatus.PREVIEW_BUILD_INSTALLED
    assert result.installed_build_origin is not None
    assert result.installed_build_origin.classification is InstalledBuildClassification.PREVIEW


def test_unknown_newer_build_is_compliant_with_unknown_origin_flag():
    result = evaluate_windows_update_state(
        _live_26200_8524_local("26200.9000"),
        _live_26200_8524_policy(),
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.installed_build_origin is not None
    assert result.installed_build_origin.classification is InstalledBuildClassification.UNKNOWN_NEWER_THAN_BASELINE
    assert "LOCAL_BUILD_NEWER_THAN_POLICY_UNKNOWN_ORIGIN" in result.installed_build_origin.diagnostic_flags


def test_german_wua_vorschauupdate_identifies_preview_when_policy_row_absent():
    result = evaluate_windows_update_state(
        _live_26200_8524_local(),
        _live_26200_8524_policy(include_preview_row=False),
        wua_secondary={
            "service_enabled": True,
            "available_updates": [{"title": "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602"}],
            "history": [{"title": "2026-05 Vorschauupdate (KB5089573) (26200.8524)"}],
        },
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.installed_build_origin is not None
    assert result.installed_build_origin.classification is InstalledBuildClassification.PREVIEW
    assert result.installed_build_origin.evidence_source is BuildEvidenceSource.WUA_HISTORY
    assert result.installed_build_origin.kb_article == "KB5089573"
    assert "LOCAL_BUILD_IS_PREVIEW" in result.installed_build_origin.diagnostic_flags


def test_consensus_display_version_24h2_conflicts_with_26200_policy_build_25h2():
    local = LocalWindowsState(
        current_build=26200,
        ubr=8457,
        full_build="26200.8457",
        display_version="24H2",
        edition_id="Professional",
        product_name="Windows 11 Pro",
    )
    policy = _live_26200_8524_policy()
    inference = infer_installed_release(local, policy)
    result = evaluate_windows_update_state(local, policy)

    assert inference.release == "25H2"
    assert result.installed_release == "25H2"
    assert result.local_consensus is not None
    assert "DISPLAY_VERSION_CONFLICTS_WITH_BUILD" in result.local_consensus.conflicts
    assert any("DisplayVersion 24H2 was ignored" in warning for warning in result.warnings)


def test_consensus_display_version_25h2_conflicts_with_26100_policy_build_24h2():
    local = LocalWindowsState(
        current_build=26100,
        ubr=8457,
        full_build="26100.8457",
        display_version="25H2",
        edition_id="Professional",
        product_name="Windows 11 Pro",
    )
    policy = _policy_with_26h1_25h2_24h2()
    inference = infer_installed_release(local, policy)
    result = evaluate_windows_update_state(local, policy)

    assert inference.release == "24H2"
    assert result.installed_release == "24H2"
    assert result.local_consensus is not None
    assert "DISPLAY_VERSION_CONFLICTS_WITH_BUILD" in result.local_consensus.conflicts
    assert any("DisplayVersion 25H2 was ignored" in warning for warning in result.warnings)


def test_device_on_pending_release_reports_above_broad_target():
    result = evaluate_windows_update_state(_client_device(26300, 9550, "26H2"), _pending_26h2_policy())

    assert result.status is EvaluationStatus.ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE
    assert result.target.version == "25H2"
