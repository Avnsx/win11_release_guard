from __future__ import annotations

from win11_release_guard.evaluator import derive_display_os_name, derive_local_consensus, evaluate_windows_update_state, infer_installed_release
from win11_release_guard.models import EditionScope, LocalWindowsState, ServicingChannel
from tests.support.evaluator_helpers import _client_device, _live_26200_8524_local, _live_26200_8524_policy


def test_static_mapping_used_only_without_policy():
    inference = infer_installed_release(
        LocalWindowsState(current_build=26100, full_build="26100.8457"),
        None,
    )

    assert inference.release == "24H2"
    assert inference.confidence == "fallback_static"
    assert inference.is_recognized_by_policy is False


def test_stale_windows_10_product_name_build_26200_displays_windows_11_pro_with_conflict():
    local = _live_26200_8524_local()
    policy = _live_26200_8524_policy()
    inference = infer_installed_release(local, policy)
    consensus = derive_local_consensus(local, inference)
    result = evaluate_windows_update_state(local, policy)

    assert derive_display_os_name(local, inference) == "Windows 11 Pro"
    assert consensus.raw_product_name == "Windows 10 Pro"
    assert "LOCAL_PRODUCT_NAME_STALE" in consensus.conflicts
    assert consensus.edition_scope is EditionScope.HOME_PRO
    assert consensus.servicing_channel is ServicingChannel.GENERAL_AVAILABILITY
    assert result.local_consensus is not None
    assert result.local_consensus.display_os_name == "Windows 11 Pro"
    assert result.local_consensus.raw_product_name == "Windows 10 Pro"
    assert any("raw ProductName 'Windows 10 Pro' is display-only" in warning for warning in result.warnings)


def test_stale_windows_10_caption_build_26200_displays_windows_11_with_conflict():
    local = LocalWindowsState(
        current_build=26200,
        ubr=8524,
        full_build="26200.8524",
        display_version="25H2",
        edition_id="Professional",
        product_name="Windows 11 Pro",
        caption="Microsoft Windows 10 Pro",
    )
    inference = infer_installed_release(local, _live_26200_8524_policy())
    consensus = derive_local_consensus(local, inference)

    assert consensus.display_os_name == "Windows 11 Pro"
    assert "LOCAL_CAPTION_STALE" in consensus.conflicts


def test_consensus_surfaces_local_build_signal_conflict():
    local = LocalWindowsState(
        current_build=26200,
        ubr=8524,
        full_build="26200.8524",
        display_version="25H2",
        edition_id="Professional",
        product_name="Windows 11 Pro",
        rtl_version="10.0.26200",
        wmi_version="10.0.26100",
        kernel_file_version="10.0.26100.8457",
        dism_current_edition="Professional",
        dism_image_version="10.0.26200.8524",
        raw={
            "build_signal_conflicts": [
                "LOCAL_BUILD_SIGNAL_CONFLICT: build signals disagree "
                "(registry=26100, rtl=26200, wmi=26100, kernel=26100, dism_image=26200); "
                "selected current_build=26200."
            ]
        },
    )
    policy = _live_26200_8524_policy()
    inference = infer_installed_release(local, policy)
    consensus = derive_local_consensus(local, inference)
    result = evaluate_windows_update_state(local, policy)

    assert "LOCAL_BUILD_SIGNAL_CONFLICT" in consensus.conflicts
    assert any("dism_image=26200" in warning for warning in consensus.warnings)
    assert result.local_consensus is not None
    assert "LOCAL_BUILD_SIGNAL_CONFLICT" in result.local_consensus.conflicts
    assert any("LOCAL_BUILD_SIGNAL_CONFLICT" in warning for warning in result.warnings)


def test_consensus_keeps_build_signal_trust_classes_machine_readable():
    local = LocalWindowsState(
        current_build=26200,
        ubr=8524,
        full_build="26200.8524",
        display_version="25H2",
        edition_id="Professional",
        product_name="Windows 11 Pro",
        rtl_version="10.0.26200",
        wmi_version="10.0.26100",
        kernel_file_version="10.0.26100.8457",
        dism_current_edition="Professional",
        dism_image_version="10.0.26200.8524",
        raw={
            "registry": {"CurrentBuildNumber": "26100", "CurrentBuild": "26100"},
            "rtl": {"build": 26200},
            "wmi": {"Version": "10.0.26100", "BuildNumber": "26100"},
            "build_signal_conflicts": [
                "LOCAL_BUILD_SIGNAL_CONFLICT: build signals disagree "
                "(registry=26100, rtl=26200, wmi=26100, kernel=26100, dism_image=26200); "
                "selected current_build=26200."
            ],
            "build_signal_decision": {
                "selected_build": 26200,
                "selection_method": "weighted_trust",
                "selected_sources": ["rtl", "dism_image"],
                "conflict": True,
            },
        },
    )
    consensus = derive_local_consensus(local, infer_installed_release(local, _live_26200_8524_policy()))
    signals = {(signal.source, signal.name): signal for signal in consensus.signal_set.signals}

    assert "LOCAL_BUILD_SIGNAL_CONFLICT" in consensus.conflicts
    assert signals[("rtl", "RtlGetVersion.build")].trust == "runtime_truth"
    assert signals[("registry", "CurrentBuild")].trust == "registry_metadata"
    assert signals[("wmi", "BuildNumber")].trust == "wmi_metadata"
    assert signals[("kernel_file", "ntoskrnl.exe version")].trust == "runtime_file"
    assert signals[("dism", "Image Version")].trust == "dism_image"
    assert "selected_build_signal" in signals[("rtl", "RtlGetVersion.build")].diagnostic_flags
    assert "conflicting_build_signal" in signals[("wmi", "BuildNumber")].diagnostic_flags


def test_unknown_edition_displays_windows_11_unknown_edition_with_warning():
    local = LocalWindowsState(
        current_build=26200,
        ubr=8457,
        full_build="26200.8457",
        display_version="25H2",
        product_name="Windows 11",
        edition_scope=EditionScope.UNKNOWN,
        servicing_channel=ServicingChannel.UNKNOWN,
    )
    policy = _live_26200_8524_policy()
    inference = infer_installed_release(local, policy)
    result = evaluate_windows_update_state(local, policy)

    assert derive_display_os_name(local, inference) == "Windows 11 unknown edition"
    assert result.local_consensus is not None
    assert result.local_consensus.display_os_name == "Windows 11 unknown edition"
    assert any("UNKNOWN_EDITION_SCOPE" in warning for warning in result.warnings)


def test_infer_installed_release_without_policy_maps_26h2_build_family():
    inference = infer_installed_release(_client_device(26300, 9550, None), None)

    assert inference.release == "26H2"
    assert inference.confidence == "fallback_static"
