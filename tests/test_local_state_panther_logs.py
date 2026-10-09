from __future__ import annotations

import json
from win11_release_guard import local_state


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
