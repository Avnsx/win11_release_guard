import subprocess

from win11_release_guard import local_state
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

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="powershell.exe", timeout=8)

    monkeypatch.setattr(local_state.subprocess, "run", fake_run)

    state = local_state.get_local_windows_state()

    assert state.available is True
    assert any("WMI/CIM read failed" in error and "timed out" in error for error in state.errors)
    assert "timed out" in state.raw["wmi_error"]


def test_read_file_tail_bounds_huge_panther_file(tmp_path):
    log = tmp_path / "setupact.log"
    log.write_bytes(b"a" * (6 * 1024 * 1024) + b"TAIL")

    tail = local_state._read_file_tail(log, max_bytes=5 * 1024 * 1024)

    assert tail.endswith("TAIL")
    assert len(tail.encode("utf-8")) == 5 * 1024 * 1024
