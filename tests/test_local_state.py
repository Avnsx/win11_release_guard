from __future__ import annotations

from pathlib import Path
from win11_release_guard import local_state
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
