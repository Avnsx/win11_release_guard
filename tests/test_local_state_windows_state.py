from __future__ import annotations

import subprocess
from win11_release_guard import local_state
from win11_release_guard.models import EditionScope, ServicingChannel


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
