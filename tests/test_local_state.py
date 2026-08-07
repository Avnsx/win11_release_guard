import json
import subprocess
from pathlib import Path

from win11_release_guard import audit_probes, local_state
from win11_release_guard.config import DEFAULT_PANTHER_TAIL_MAX_BYTES, DEFAULT_PANTHER_TOTAL_MAX_BYTES
from win11_release_guard.diagnostic_tail import DiagnosticTail
from win11_release_guard.models import EditionScope, LocalWindowsState, ServicingChannel


def test_local_state_round_trip_and_build_family():
    state = LocalWindowsState(
        current_build=26200,
        ubr=8457,
        full_build="26200.8457",
        product_name="Windows 10 Pro",
        display_version="25H2",
        dism_image_version="10.0.26200.8457",
        dism_tool_version="10.0.26100.1",
        errors=("diagnostic message",),
    )

    restored = LocalWindowsState.from_dict(state.to_dict())

    assert restored.current_build == 26200
    assert restored.ubr == 8457
    assert restored.build_family == 26200
    assert restored.product_name == "Windows 10 Pro"
    assert restored.dism_image_version == "10.0.26200.8457"
    assert restored.dism_tool_version == "10.0.26100.1"
    assert restored.errors == ("diagnostic message",)
    assert restored.edition_scope is EditionScope.HOME_PRO
    assert restored.servicing_channel is ServicingChannel.GENERAL_AVAILABILITY


def test_non_windows_returns_unavailable_state(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "posix")

    state = local_state.get_local_windows_state()

    assert state.available is False
    assert state.source == "unsupported_platform"
    assert state.errors
    assert "requires Windows" in state.errors[0]


def test_get_local_windows_state_prefers_build_inference_over_display_version(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "nt")
    monkeypatch.setattr(
        local_state,
        "_read_registry_current_version",
        lambda: {
            "CurrentBuildNumber": "26200",
            "CurrentBuild": "26200",
            "UBR": 8457,
            "DisplayVersion": "24H2",
            "ReleaseId": "2009",
            "EditionID": "Professional",
            "InstallationType": "Client",
            "ProductName": "Windows 10 Pro",
        },
    )
    monkeypatch.setattr(
        local_state,
        "_read_rtl_get_version",
        lambda: {"major": 10, "minor": 0, "build": 26200, "version": "10.0.26200"},
    )
    monkeypatch.setattr(
        local_state,
        "_read_wmi_operating_system",
        lambda: {
            "Caption": "Microsoft Windows 11 Pro",
            "Version": "10.0.26200",
            "BuildNumber": "26200",
            "OperatingSystemSKU": 48,
            "OSArchitecture": "64-bit",
        },
    )
    monkeypatch.setattr(local_state, "_read_dism_current_edition", lambda: "Professional")
    monkeypatch.setattr(local_state, "_read_product_info", lambda major, minor: 0x30)
    monkeypatch.setattr(local_state, "_read_kernel_file_version", lambda: "10.0.26200.8457")

    state = local_state.get_local_windows_state()

    assert state.available is True
    assert state.current_build == 26200
    assert state.ubr == 8457
    assert state.full_build == "26200.8457"
    assert state.display_version == "24H2"
    assert state.inferred_release == "25H2"
    assert state.product_name == "Windows 10 Pro"
    assert state.caption == "Microsoft Windows 11 Pro"
    assert state.dism_current_edition == "Professional"
    assert any("DisplayVersion 24H2 differs" in error for error in state.errors)


def test_get_local_windows_state_falls_back_to_clean_display_version(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "nt")
    monkeypatch.setattr(
        local_state,
        "_read_registry_current_version",
        lambda: {
            "CurrentBuildNumber": "99999",
            "CurrentBuild": "99999",
            "UBR": 123,
            "DisplayVersion": "99H2",
            "ReleaseId": None,
            "EditionID": "Professional",
            "InstallationType": "Client",
            "ProductName": "Windows 11 Pro",
        },
    )
    monkeypatch.setattr(
        local_state,
        "_read_rtl_get_version",
        lambda: {"major": 10, "minor": 0, "build": 99999, "version": "10.0.99999"},
    )
    monkeypatch.setattr(local_state, "_read_wmi_operating_system", lambda: None)
    monkeypatch.setattr(local_state, "_read_dism_current_edition", lambda: None)
    monkeypatch.setattr(local_state, "_read_product_info", lambda major, minor: 0x30)
    monkeypatch.setattr(local_state, "_read_kernel_file_version", lambda: None)

    state = local_state.get_local_windows_state()

    assert state.current_build == 99999
    assert state.full_build == "99999.123"
    assert state.inferred_release == "99H2"


def test_get_local_windows_state_uses_rtl_when_registry_fails(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "nt")

    def fail_registry():
        raise OSError("registry unavailable")

    monkeypatch.setattr(local_state, "_read_registry_current_version", fail_registry)
    monkeypatch.setattr(
        local_state,
        "_read_rtl_get_version",
        lambda: {"major": 10, "minor": 0, "build": 26100, "version": "10.0.26100"},
    )
    monkeypatch.setattr(
        local_state,
        "_read_wmi_operating_system",
        lambda: {"Version": "10.0.26100", "BuildNumber": "26100"},
    )
    monkeypatch.setattr(local_state, "_read_dism_current_edition", lambda: None)
    monkeypatch.setattr(local_state, "_read_product_info", lambda major, minor: 0x30)
    monkeypatch.setattr(local_state, "_read_kernel_file_version", lambda: "10.0.26100.8457")

    state = local_state.get_local_windows_state()

    assert state.available is True
    assert state.current_build == 26100
    assert state.ubr == 8457
    assert state.full_build == "26100.8457"
    assert state.inferred_release == "24H2"
    assert any("registry read failed" in error for error in state.errors)


def test_get_local_windows_state_uses_dism_as_primary_edition_signal(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "nt")
    monkeypatch.setattr(
        local_state,
        "_read_registry_current_version",
        lambda: {
            "CurrentBuildNumber": "26100",
            "CurrentBuild": "26100",
            "UBR": 8457,
            "DisplayVersion": "24H2",
            "ReleaseId": "2009",
            "EditionID": "Professional",
            "InstallationType": "Client",
            "ProductName": "Windows 11 Pro",
        },
    )
    monkeypatch.setattr(
        local_state,
        "_read_rtl_get_version",
        lambda: {"major": 10, "minor": 0, "build": 26100, "version": "10.0.26100"},
    )
    monkeypatch.setattr(local_state, "_read_wmi_operating_system", lambda: None)
    monkeypatch.setattr(local_state, "_read_dism_current_edition", lambda: "EnterpriseS")
    monkeypatch.setattr(local_state, "_read_product_info", lambda major, minor: 0x30)
    monkeypatch.setattr(local_state, "_read_kernel_file_version", lambda: "10.0.26100.8457")

    state = local_state.get_local_windows_state()

    assert state.edition_scope is EditionScope.ENTERPRISE_LTSC
    assert state.servicing_channel is ServicingChannel.LTSC
    assert state.is_ltsc is True


def test_parse_dism_current_edition_extracts_english_and_german_versions():
    english = """
Deployment Image Servicing and Management tool
Version: 10.0.26100.1

Image Version: 10.0.26200.8457

Current Edition : Professional
"""
    german = """
Tool zur Imageverwaltung fuer die Bereitstellung
Version: 10.0.26100.1

Abbildversion: 10.0.26200.8524

Aktuelle Edition : EnterpriseS
"""

    assert local_state._parse_dism_current_edition_output(english) == {
        "current_edition": "Professional",
        "image_version": "10.0.26200.8457",
        "dism_tool_version": "10.0.26100.1",
    }
    assert local_state._parse_dism_current_edition_output(german) == {
        "current_edition": "EnterpriseS",
        "image_version": "10.0.26200.8524",
        "dism_tool_version": "10.0.26100.1",
    }


def test_get_local_windows_state_uses_dism_image_version_as_build_signal(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "nt")
    monkeypatch.setattr(
        local_state,
        "_read_registry_current_version",
        lambda: {
            "CurrentBuildNumber": None,
            "CurrentBuild": None,
            "UBR": None,
            "DisplayVersion": "25H2",
            "ReleaseId": "2009",
            "EditionID": "Professional",
            "InstallationType": "Client",
            "ProductName": "Windows 11 Pro",
        },
    )
    monkeypatch.setattr(
        local_state,
        "_read_rtl_get_version",
        lambda: {"major": 10, "minor": 0, "build": None, "version": None},
    )
    monkeypatch.setattr(local_state, "_read_wmi_operating_system", lambda: None)
    monkeypatch.setattr(
        local_state,
        "_read_dism_current_edition",
        lambda: {
            "current_edition": "Professional",
            "image_version": "10.0.26200.8457",
            "dism_tool_version": "10.0.26100.1",
        },
    )
    monkeypatch.setattr(local_state, "_read_product_info", lambda major, minor: 0x30)
    monkeypatch.setattr(local_state, "_read_kernel_file_version", lambda: None)

    state = local_state.get_local_windows_state()

    assert state.available is True
    assert state.current_build == 26200
    assert state.ubr == 8457
    assert state.full_build == "26200.8457"
    assert state.dism_current_edition == "Professional"
    assert state.dism_image_version == "10.0.26200.8457"
    assert state.dism_tool_version == "10.0.26100.1"
    assert state.raw["build_signals"] == {"dism_image": 26200}


def test_get_local_windows_state_reports_build_signal_conflicts(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "nt")
    monkeypatch.setattr(
        local_state,
        "_read_registry_current_version",
        lambda: {
            "CurrentBuildNumber": "26100",
            "CurrentBuild": "26100",
            "UBR": None,
            "DisplayVersion": "25H2",
            "ReleaseId": "2009",
            "EditionID": "Professional",
            "InstallationType": "Client",
            "ProductName": "Windows 11 Pro",
        },
    )
    monkeypatch.setattr(
        local_state,
        "_read_rtl_get_version",
        lambda: {"major": 10, "minor": 0, "build": 26200, "version": "10.0.26200"},
    )
    monkeypatch.setattr(
        local_state,
        "_read_wmi_operating_system",
        lambda: {"Version": "10.0.26100", "BuildNumber": "26100"},
    )
    monkeypatch.setattr(
        local_state,
        "_read_dism_current_edition",
        lambda: {
            "current_edition": "Professional",
            "image_version": "10.0.26200.8524",
            "dism_tool_version": "10.0.26100.1",
        },
    )
    monkeypatch.setattr(local_state, "_read_product_info", lambda major, minor: 0x30)
    monkeypatch.setattr(local_state, "_read_kernel_file_version", lambda: "10.0.26100.8457")

    state = local_state.get_local_windows_state()

    assert state.current_build == 26200
    assert state.ubr == 8524
    assert state.inferred_release == "25H2"
    assert state.raw["build_signals"] == {
        "registry": 26100,
        "rtl": 26200,
        "wmi": 26100,
        "kernel": 26100,
        "dism_image": 26200,
    }
    assert state.raw["build_signal_decision"]["selected_sources"] == ["rtl", "dism_image"]
    assert any("LOCAL_BUILD_SIGNAL_CONFLICT" in error for error in state.errors)
    assert any("dism_image=26200" in conflict for conflict in state.raw["build_signal_conflicts"])


def test_stale_product_labels_do_not_override_unanimous_26200_build_family(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "nt")
    monkeypatch.setattr(
        local_state,
        "_read_registry_current_version",
        lambda: {
            "CurrentBuildNumber": "26200",
            "CurrentBuild": "26200",
            "UBR": 8457,
            "DisplayVersion": "24H2",
            "ReleaseId": "2009",
            "EditionID": "Professional",
            "InstallationType": "Client",
            "ProductName": "Windows 10 Pro",
        },
    )
    monkeypatch.setattr(
        local_state,
        "_read_rtl_get_version",
        lambda: {"major": 10, "minor": 0, "build": 26200, "version": "10.0.26200"},
    )
    monkeypatch.setattr(
        local_state,
        "_read_wmi_operating_system",
        lambda: {
            "Caption": "Microsoft Windows 10 Pro",
            "Version": "10.0.26200",
            "BuildNumber": "26200",
            "OperatingSystemSKU": 48,
            "OSArchitecture": "64-bit",
        },
    )
    monkeypatch.setattr(
        local_state,
        "_read_dism_current_edition",
        lambda: {
            "current_edition": "Professional",
            "image_version": "10.0.26200.8457",
            "dism_tool_version": "10.0.26100.1",
        },
    )
    monkeypatch.setattr(local_state, "_read_product_info", lambda major, minor: 0x30)
    monkeypatch.setattr(local_state, "_read_kernel_file_version", lambda: "10.0.26200.8457")

    state = local_state.get_local_windows_state()

    assert state.current_build == 26200
    assert state.inferred_release == "25H2"
    assert state.product_name == "Windows 10 Pro"
    assert state.caption == "Microsoft Windows 10 Pro"
    assert "build_signal_conflicts" not in state.raw
    assert state.raw["build_signal_decision"]["selected_build"] == 26200
    assert state.raw["build_signal_decision"]["conflict"] is False


def test_weighted_build_signal_selection_prefers_rtl_and_dism_image_over_stale_majority(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "nt")
    monkeypatch.setattr(
        local_state,
        "_read_registry_current_version",
        lambda: {
            "CurrentBuildNumber": "26100",
            "CurrentBuild": "26100",
            "UBR": None,
            "DisplayVersion": "25H2",
            "ReleaseId": "2009",
            "EditionID": "Professional",
            "InstallationType": "Client",
            "ProductName": "Windows 11 Pro",
        },
    )
    monkeypatch.setattr(
        local_state,
        "_read_rtl_get_version",
        lambda: {"major": 10, "minor": 0, "build": 26200, "version": "10.0.26200"},
    )
    monkeypatch.setattr(
        local_state,
        "_read_wmi_operating_system",
        lambda: {"Version": "10.0.26100", "BuildNumber": "26100"},
    )
    monkeypatch.setattr(
        local_state,
        "_read_dism_current_edition",
        lambda: {
            "current_edition": "Professional",
            "image_version": "10.0.26200.8524",
            "dism_tool_version": "10.0.26100.1",
        },
    )
    monkeypatch.setattr(local_state, "_read_product_info", lambda major, minor: 0x30)
    monkeypatch.setattr(local_state, "_read_kernel_file_version", lambda: "10.0.26100.8457")

    state = local_state.get_local_windows_state()

    assert state.current_build == 26200
    assert state.ubr == 8524
    assert state.inferred_release == "25H2"
    assert state.raw["build_signal_decision"]["selected_build"] == 26200
    assert state.raw["build_signal_decision"]["selected_sources"] == ["rtl", "dism_image"]
    assert state.raw["build_signal_decision"]["conflict"] is True
    assert state.raw["build_signal_decision"]["conflicting_builds"]["26100"]["sources"] == [
        "registry",
        "wmi",
        "kernel",
    ]
    assert any("selected current_build=26200" in conflict for conflict in state.raw["build_signal_conflicts"])


def test_dism_newer_than_registry_without_rtl_is_visible_but_does_not_silently_win(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "nt")
    monkeypatch.setattr(
        local_state,
        "_read_registry_current_version",
        lambda: {
            "CurrentBuildNumber": "26100",
            "CurrentBuild": "26100",
            "UBR": 8457,
            "DisplayVersion": "24H2",
            "ReleaseId": "2009",
            "EditionID": "Professional",
            "InstallationType": "Client",
            "ProductName": "Windows 11 Pro",
        },
    )

    def fail_rtl():
        raise OSError("RtlGetVersion unavailable")

    monkeypatch.setattr(local_state, "_read_rtl_get_version", fail_rtl)
    monkeypatch.setattr(
        local_state,
        "_read_wmi_operating_system",
        lambda: {"Version": "10.0.26100", "BuildNumber": "26100"},
    )
    monkeypatch.setattr(
        local_state,
        "_read_dism_current_edition",
        lambda: {
            "current_edition": "Professional",
            "image_version": "10.0.26200.8524",
            "dism_tool_version": "10.0.26100.1",
        },
    )
    monkeypatch.setattr(local_state, "_read_product_info", lambda major, minor: 0x30)
    monkeypatch.setattr(local_state, "_read_kernel_file_version", lambda: "10.0.26100.8457")

    state = local_state.get_local_windows_state()

    assert state.current_build == 26100
    assert state.full_build == "26100.8457"
    assert state.inferred_release == "24H2"
    assert state.raw["build_signal_decision"]["selected_build"] == 26100
    assert state.raw["build_signal_decision"]["conflict"] is True
    assert state.raw["build_signal_decision"]["conflicting_builds"]["26200"]["sources"] == ["dism_image"]
    assert any("dism_image=26200" in conflict for conflict in state.raw["build_signal_conflicts"])


def test_get_local_windows_state_uses_getproductinfo_as_secondary_signal(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "nt")
    monkeypatch.setattr(
        local_state,
        "_read_registry_current_version",
        lambda: {
            "CurrentBuildNumber": "26100",
            "CurrentBuild": "26100",
            "UBR": 8457,
            "DisplayVersion": "24H2",
            "ReleaseId": "2009",
            "EditionID": None,
            "InstallationType": "Client",
            "ProductName": "Windows 11",
        },
    )
    monkeypatch.setattr(
        local_state,
        "_read_rtl_get_version",
        lambda: {"major": 10, "minor": 0, "build": 26100, "version": "10.0.26100"},
    )
    monkeypatch.setattr(local_state, "_read_wmi_operating_system", lambda: None)
    monkeypatch.setattr(local_state, "_read_dism_current_edition", lambda: None)
    monkeypatch.setattr(local_state, "_read_product_info", lambda major, minor: 0xBF)
    monkeypatch.setattr(local_state, "_read_kernel_file_version", lambda: "10.0.26100.8457")

    state = local_state.get_local_windows_state()

    assert state.product_info_code == 0xBF
    assert state.edition_scope is EditionScope.IOT_ENTERPRISE_LTSC
    assert state.servicing_channel is ServicingChannel.LTSC


def test_dism_timeout_is_returned_as_probe_error(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "nt")
    monkeypatch.setattr(
        local_state,
        "_read_registry_current_version",
        lambda: {
            "CurrentBuildNumber": "26200",
            "CurrentBuild": "26200",
            "UBR": 8457,
            "DisplayVersion": "25H2",
            "EditionID": "Professional",
            "InstallationType": "Client",
            "ProductName": "Windows 11 Pro",
        },
    )
    monkeypatch.setattr(
        local_state,
        "_read_rtl_get_version",
        lambda: {"major": 10, "minor": 0, "build": 26200, "version": "10.0.26200"},
    )
    monkeypatch.setattr(local_state, "_read_wmi_operating_system", lambda **kwargs: None)
    monkeypatch.setattr(local_state, "_read_product_info", lambda major, minor: 0x30)
    monkeypatch.setattr(local_state, "_read_kernel_file_version", lambda: None)

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="dism.exe", timeout=10)

    monkeypatch.setattr(local_state.subprocess, "run", fake_run)

    state = local_state.get_local_windows_state()

    assert state.available is True
    assert any("DISM current edition read failed" in error and "timed out" in error for error in state.errors)
    assert "timed out" in state.raw["dism_error"]


def test_powershell_timeout_is_returned_as_probe_error(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "nt")
    monkeypatch.setattr(
        local_state,
        "_read_registry_current_version",
        lambda: {
            "CurrentBuildNumber": "26200",
            "CurrentBuild": "26200",
            "UBR": 8457,
            "DisplayVersion": "25H2",
            "EditionID": "Professional",
            "InstallationType": "Client",
            "ProductName": "Windows 11 Pro",
        },
    )
    monkeypatch.setattr(
        local_state,
        "_read_rtl_get_version",
        lambda: {"major": 10, "minor": 0, "build": 26200, "version": "10.0.26200"},
    )
    monkeypatch.setattr(local_state, "_read_dism_current_edition", lambda **kwargs: None)
    monkeypatch.setattr(local_state, "_read_product_info", lambda major, minor: 0x30)
    monkeypatch.setattr(local_state, "_read_kernel_file_version", lambda: None)
    # Force the native OS-info read to be unusable so the WMI probe falls
    # back to spawning powershell.exe, which is what this test exercises.
    monkeypatch.setattr(local_state, "_read_native_operating_system", lambda: None)

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="powershell.exe", timeout=8)

    monkeypatch.setattr(local_state.subprocess, "run", fake_run)

    state = local_state.get_local_windows_state()

    assert state.available is True
    assert any("WMI/CIM read failed" in error and "timed out" in error for error in state.errors)
    assert "timed out" in state.raw["wmi_error"]


# --- native (non-PowerShell) OS-info read ---------------------------------


def test_os_architecture_from_processor_architecture_maps_known_codes():
    assert local_state._os_architecture_from_processor_architecture(9) == "64-bit"
    assert local_state._os_architecture_from_processor_architecture(12) == "ARM 64-bit Processor"
    assert local_state._os_architecture_from_processor_architecture(0) == "32-bit"
    assert local_state._os_architecture_from_processor_architecture(9999) is None
    assert local_state._os_architecture_from_processor_architecture(None) is None


def test_native_os_info_is_complete_requires_every_key_populated():
    complete = {
        "Caption": "Microsoft Windows 11 Pro",
        "Version": "10.0.26200",
        "BuildNumber": "26200",
        "OperatingSystemSKU": 48,
        "OSArchitecture": "64-bit",
    }
    assert local_state._native_os_info_is_complete(complete) is True
    assert local_state._native_os_info_is_complete(None) is False
    assert local_state._native_os_info_is_complete({}) is False
    for missing_key in local_state.NATIVE_OS_INFO_KEYS:
        incomplete = dict(complete)
        incomplete[missing_key] = None
        assert local_state._native_os_info_is_complete(incomplete) is False

    # Caption is deliberately not part of NATIVE_OS_INFO_KEYS: the native read
    # has no faithful source for it, so a missing/None Caption must not force
    # the (otherwise complete) result to be treated as unusable.
    caption_missing = dict(complete)
    caption_missing["Caption"] = None
    assert local_state._native_os_info_is_complete(caption_missing) is True


def test_read_native_operating_system_returns_expected_shape(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "nt")
    monkeypatch.setattr(
        local_state,
        "_read_registry_current_version",
        lambda: {
            "CurrentBuildNumber": "26200",
            "CurrentBuild": "26200",
            "UBR": 8457,
            "DisplayVersion": "25H2",
            "EditionID": "Professional",
            "InstallationType": "Client",
            "ProductName": "Windows 11 Pro",
        },
    )
    monkeypatch.setattr(
        local_state,
        "_read_rtl_get_version",
        lambda: {"major": 10, "minor": 0, "build": 26200, "version": "10.0.26200"},
    )
    monkeypatch.setattr(local_state, "_read_product_info", lambda major, minor: 48)
    monkeypatch.setattr(local_state, "_read_native_architecture", lambda: "64-bit")

    data = local_state._read_native_operating_system()

    # Caption is always None: the registry ProductName it would otherwise be
    # synthesized from can go stale after an in-place upgrade (still reading
    # "Windows 10" on an updated Windows 11 host), which previously produced
    # a bogus Caption that misfired the LOCAL_CAPTION_STALE conflict check on
    # every native read. A missing Caption does not affect completeness.
    assert data == {
        "Caption": None,
        "Version": "10.0.26200",
        "BuildNumber": "26200",
        "OperatingSystemSKU": 48,
        "OSArchitecture": "64-bit",
    }
    assert local_state._native_os_info_is_complete(data) is True


def test_read_native_operating_system_leaves_sku_none_when_getproductinfo_fails(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "nt")
    monkeypatch.setattr(
        local_state,
        "_read_registry_current_version",
        lambda: {"ProductName": "Windows 11 Pro"},
    )
    monkeypatch.setattr(
        local_state,
        "_read_rtl_get_version",
        lambda: {"major": 10, "minor": 0, "build": 26200, "version": "10.0.26200"},
    )

    def fail_product_info(major, minor):
        raise OSError("GetProductInfo failed with Win32 error 1.")

    monkeypatch.setattr(local_state, "_read_product_info", fail_product_info)
    monkeypatch.setattr(local_state, "_read_native_architecture", lambda: "64-bit")

    data = local_state._read_native_operating_system()

    # No fabricated SKU value: the key stays None rather than guessing, which
    # makes the dict "incomplete" and steers the caller to the PowerShell
    # fallback instead of shipping a wrong SKU.
    assert data["OperatingSystemSKU"] is None
    assert local_state._native_os_info_is_complete(data) is False


def test_read_native_operating_system_returns_none_on_non_windows(monkeypatch):
    monkeypatch.setattr(local_state.os, "name", "posix")

    assert local_state._read_native_operating_system() is None


def test_read_wmi_operating_system_uses_native_result_without_spawning_powershell(monkeypatch):
    native_result = {
        "Caption": "Microsoft Windows 11 Pro",
        "Version": "10.0.26200",
        "BuildNumber": "26200",
        "OperatingSystemSKU": 48,
        "OSArchitecture": "64-bit",
    }
    monkeypatch.setattr(local_state, "_read_native_operating_system", lambda: native_result)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("PowerShell fallback should not run when the native read succeeds.")

    monkeypatch.setattr(local_state.subprocess, "run", fail_if_called)

    assert local_state._read_wmi_operating_system() == native_result


def test_read_wmi_operating_system_falls_back_when_native_raises(monkeypatch):
    def fail_native():
        raise OSError("registry unavailable")

    monkeypatch.setattr(local_state, "_read_native_operating_system", fail_native)

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout='{"Caption":"Microsoft Windows 11 Pro","Version":"10.0.26200",'
            '"BuildNumber":"26200","OperatingSystemSKU":48,"OSArchitecture":"64-bit"}',
            stderr="",
        )

    monkeypatch.setattr(local_state.subprocess, "run", fake_run)

    result = local_state._read_wmi_operating_system()

    assert result == {
        "Caption": "Microsoft Windows 11 Pro",
        "Version": "10.0.26200",
        "BuildNumber": "26200",
        "OperatingSystemSKU": 48,
        "OSArchitecture": "64-bit",
    }


def test_read_wmi_operating_system_falls_back_when_native_incomplete(monkeypatch):
    # A native read that comes back partially populated (e.g. architecture
    # lookup failed) must not be shipped as-is; it should be treated the same
    # as a hard failure and fall back to the PowerShell probe.
    monkeypatch.setattr(
        local_state,
        "_read_native_operating_system",
        lambda: {
            "Caption": "Microsoft Windows 11 Pro",
            "Version": "10.0.26200",
            "BuildNumber": "26200",
            "OperatingSystemSKU": 48,
            "OSArchitecture": None,
        },
    )
    called = {}

    def fake_run(*args, **kwargs):
        called["ran"] = True
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout='{"Caption":"Microsoft Windows 11 Pro","Version":"10.0.26200",'
            '"BuildNumber":"26200","OperatingSystemSKU":48,"OSArchitecture":"64-bit"}',
            stderr="",
        )

    monkeypatch.setattr(local_state.subprocess, "run", fake_run)

    result = local_state._read_wmi_operating_system()

    assert called.get("ran") is True
    assert result["OSArchitecture"] == "64-bit"


def test_native_and_powershell_wmi_shapes_are_indistinguishable_downstream(monkeypatch):
    """Whichever probe supplied `wmi`, get_local_windows_state must not be able to tell."""

    def build_state_with_wmi(wmi_dict):
        monkeypatch.setattr(local_state.os, "name", "nt")
        monkeypatch.setattr(
            local_state,
            "_read_registry_current_version",
            lambda: {
                "CurrentBuildNumber": "26200",
                "CurrentBuild": "26200",
                "UBR": 8457,
                "DisplayVersion": "25H2",
                "EditionID": "Professional",
                "InstallationType": "Client",
                "ProductName": "Windows 11 Pro",
            },
        )
        monkeypatch.setattr(
            local_state,
            "_read_rtl_get_version",
            lambda: {"major": 10, "minor": 0, "build": 26200, "version": "10.0.26200"},
        )
        monkeypatch.setattr(local_state, "_read_wmi_operating_system", lambda **kwargs: wmi_dict)
        monkeypatch.setattr(local_state, "_read_dism_current_edition", lambda **kwargs: None)
        monkeypatch.setattr(local_state, "_read_product_info", lambda major, minor: 48)
        monkeypatch.setattr(local_state, "_read_kernel_file_version", lambda: "10.0.26200.8457")
        return local_state.get_local_windows_state()

    shared_fields = {
        "Caption": "Microsoft Windows 11 Pro",
        "Version": "10.0.26200",
        "BuildNumber": "26200",
        "OperatingSystemSKU": 48,
        "OSArchitecture": "64-bit",
    }

    native_state = build_state_with_wmi(dict(shared_fields))
    powershell_state = build_state_with_wmi(dict(shared_fields))

    assert native_state.to_dict() == powershell_state.to_dict()
    assert native_state.caption == "Microsoft Windows 11 Pro"
    assert native_state.architecture == "64-bit"
    assert native_state.operating_system_sku == 48


def test_read_file_tail_bounds_huge_panther_file(tmp_path):
    log = tmp_path / "setupact.log"
    log.write_bytes(b"a" * (6 * 1024 * 1024) + b"TAIL")

    tail = local_state._read_file_tail(log, max_bytes=5 * 1024 * 1024)

    assert tail.endswith("TAIL")
    assert len(tail.encode("utf-8")) == 5 * 1024 * 1024


def test_read_panther_logs_include_tail_metadata(tmp_path):
    log = tmp_path / "setupact.log"
    log.write_bytes(b"SetupPlatform.exe\n")

    logs = local_state._read_panther_logs(paths=(str(log),), max_bytes=4096)

    entry = logs[str(log)]
    assert entry["content"] == "SetupPlatform.exe\n"
    assert entry["file_size_bytes"] == log.stat().st_size
    assert entry["tail_start_offset"] == 0
    assert entry["tail_truncated"] is False
    assert entry["encoding_detected"] == "utf-8"
    assert entry["decode_errors_replaced"] is False
    assert entry["privacy_scan_completed"] is True
    assert entry["privacy_findings_count"] == 0


def test_read_panther_logs_accepts_missing_sources_without_errors(tmp_path):
    missing = tmp_path / "missing" / "setupact.log"
    errors: list[str] = []

    logs = local_state._read_panther_logs(paths=(str(missing),), errors=errors)

    assert logs == {}
    assert errors == []


def test_default_panther_total_cap_is_generous_for_known_path_set():
    assert DEFAULT_PANTHER_TOTAL_MAX_BYTES >= DEFAULT_PANTHER_TAIL_MAX_BYTES * len(local_state.PANTHER_LOG_PATHS)
    assert DEFAULT_PANTHER_TOTAL_MAX_BYTES >= DEFAULT_PANTHER_TAIL_MAX_BYTES * len(audit_probes.PANTHER_SETUP_LOG_PATHS)


def test_read_panther_logs_applies_total_cap_across_multiple_large_files(tmp_path):
    first = tmp_path / "setupact.log"
    second = tmp_path / "setuperr.log"
    third = tmp_path / "rollback.log"
    first.write_bytes(b"A" * 10)
    second.write_bytes(b"B" * 10)
    third.write_bytes(b"C" * 10)
    errors: list[str] = []

    logs = local_state._read_panther_logs(
        paths=(str(first), str(second), str(third)),
        max_bytes=10,
        total_max_bytes=15,
        errors=errors,
    )

    assert set(logs) == {str(first), str(second)}
    assert logs[str(first)]["content"] == "A" * 10
    assert logs[str(second)]["content"] == "B" * 5
    assert sum(int(entry["tail_bytes"]) for entry in logs.values()) == 15
    assert all(entry["collection_total_cap_reached"] is True for entry in logs.values())
    assert all(entry["collection_total_cap_bytes"] == 15 for entry in logs.values())
    assert any(str(third) in error and "total cap of 15 bytes reached" in error for error in errors)


def test_read_panther_logs_marks_total_cap_when_single_large_file_is_clipped(tmp_path):
    log = tmp_path / "setupact.log"
    log.write_bytes(b"A" * 20)

    logs = local_state._read_panther_logs(
        paths=(str(log),),
        max_bytes=20,
        total_max_bytes=7,
    )

    entry = logs[str(log)]
    assert entry["content"] == "A" * 7
    assert entry["tail_bytes"] == 7
    assert entry["tail_truncated"] is True
    assert entry["collection_total_cap_reached"] is True
    assert entry["collection_total_cap_bytes"] == 7


def test_read_panther_logs_reports_privacy_findings_without_values(tmp_path):
    log = tmp_path / "setupact.log"
    log.write_text(
        "Password: never-print-this\n"
        "Authorization: Bearer short\n"
        "ProductKey: never-print-this-either\n",
        encoding="utf-8",
    )

    logs = local_state._read_panther_logs(paths=(str(log),), max_bytes=4096)

    entry = logs[str(log)]
    findings = entry["privacy_findings"]
    marker_names = {str(finding["marker"]) for finding in findings}
    serialized_findings = json.dumps(findings, sort_keys=True)
    assert entry["privacy_scan_completed"] is True
    assert entry["privacy_findings_count"] == 3
    assert marker_names == {"password", "authorization_header", "product_key"}
    assert "never-print-this" in entry["content"]
    assert "never-print-this" not in serialized_findings
    assert "short" not in serialized_findings


def test_read_panther_logs_continues_after_unreadable_path(monkeypatch, tmp_path):
    blocked = tmp_path / "blocked-setupact.log"
    readable = tmp_path / "setupact.log"
    blocked.write_bytes(b"blocked")
    readable.write_bytes(b"SetupPlatform.exe\n")

    def fake_tail(path, *, max_bytes):
        if Path(path) == blocked:
            raise PermissionError("access denied")
        return DiagnosticTail(
            content="SetupPlatform.exe\n",
            file_size_bytes=18,
            tail_start_offset=0,
            tail_truncated=False,
            tail_bytes=18,
            encoding_detected="utf-8",
            decode_errors_replaced=False,
        )

    monkeypatch.setattr(local_state, "read_diagnostic_tail", fake_tail)
    errors: list[str] = []

    logs = local_state._read_panther_logs(
        paths=(str(blocked), str(readable)),
        max_bytes=4096,
        errors=errors,
    )

    assert str(readable) in logs
    assert str(blocked) not in logs
    assert errors
    assert "access denied" in errors[0]


def test_audit_panther_logs_include_tail_metadata(tmp_path):
    log = tmp_path / "setuperr.log"
    log.write_bytes(b"SetupPlatform.exe failed\n")

    result = audit_probes.read_panther_logs(paths=(str(log),), max_bytes=4096)

    entry = result["logs"][0]
    assert entry["content"] == "SetupPlatform.exe failed\n"
    assert entry["tail_bytes"] == log.stat().st_size
    assert entry["file_size_bytes"] == log.stat().st_size
    assert entry["tail_start_offset"] == 0
    assert entry["tail_truncated"] is False
    assert entry["encoding_detected"] == "utf-8"
    assert entry["decode_errors_replaced"] is False
    assert entry["privacy_scan_completed"] is True
    assert entry["privacy_findings_count"] == 0
    assert result["privacy_findings"] is None


def test_audit_panther_logs_accepts_missing_sources_without_errors(tmp_path):
    missing = tmp_path / "missing" / "setuperr.log"

    result = audit_probes.read_panther_logs(paths=(str(missing),))

    assert result["available"] is False
    assert result["logs"] == []
    assert result["setup_failure_evidence"] == []
    assert result["privacy_findings"] is None
    assert result["errors"] == []


def test_audit_panther_logs_applies_total_cap_across_multiple_large_files(tmp_path):
    first = tmp_path / "setupact.log"
    second = tmp_path / "setuperr.log"
    third = tmp_path / "rollback.log"
    first.write_bytes(b"A" * 10)
    second.write_bytes(b"B" * 10)
    third.write_bytes(b"C" * 10)

    result = audit_probes.read_panther_logs(
        paths=(str(first), str(second), str(third)),
        max_bytes=10,
        total_max_bytes=15,
    )

    logs = result["logs"]
    assert [entry["path"] for entry in logs] == [str(first), str(second)]
    assert logs[0]["content"] == "A" * 10
    assert logs[1]["content"] == "B" * 5
    assert sum(int(entry["tail_bytes"]) for entry in logs) == 15
    assert all(entry["collection_total_cap_reached"] is True for entry in logs)
    assert all(entry["collection_total_cap_bytes"] == 15 for entry in logs)
    assert any(str(third) in error and "total cap of 15 bytes reached" in error for error in result["errors"])


def test_audit_panther_logs_report_privacy_findings_without_values(tmp_path):
    log = tmp_path / "setuperr.log"
    log.write_text(
        "client_secret: never-print-this\n"
        "connection_string=server=db;uid=admin;password=never-print-this\n",
        encoding="utf-8",
    )

    result = audit_probes.read_panther_logs(paths=(str(log),), max_bytes=4096)

    entry = result["logs"][0]
    findings = entry["privacy_findings"]
    marker_names = {str(finding["marker"]) for finding in findings}
    serialized_findings = json.dumps(findings, sort_keys=True)
    assert entry["privacy_scan_completed"] is True
    assert entry["privacy_findings_count"] == 3
    assert marker_names == {"secret_assignment", "connection_string", "password"}
    assert "never-print-this" in entry["content"]
    assert "never-print-this" not in serialized_findings
    assert result["privacy_findings"]["privacy_findings_count"] == 3
    assert "uploading or sharing" in result["privacy_findings"]["notice"]
    assert "never-print-this" not in json.dumps(result["privacy_findings"], sort_keys=True)


def test_panther_path_sets_include_setup_compatibility_locations():
    local_paths = set(local_state.PANTHER_LOG_PATHS)
    audit_paths = set(audit_probes.PANTHER_SETUP_LOG_PATHS)

    assert r"C:\$Windows.~BT\Sources\Panther\setuperr.log" in local_paths
    assert r"C:\$Windows.~BT\Sources\Rollback\setuperr.log" in local_paths
    assert r"C:\$Windows.~BT\NewOS\Windows\Panther\setupact.log" in local_paths
    assert r"C:\Windows\Panther\UnattendGC\setuperr.log" in local_paths
    assert r"C:\$Windows.~BT\Sources\Panther\setuperr.log" in audit_paths
    assert r"C:\$Windows.~BT\Sources\Rollback\setuperr.log" in audit_paths
    assert r"C:\$Windows.~BT\NewOS\Windows\Panther\setupact.log" in audit_paths
    assert r"%WINDIR%\Panther\UnattendGC\setuperr.log" in audit_paths
