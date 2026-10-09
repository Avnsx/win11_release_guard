from __future__ import annotations

import json
from win11_release_guard import audit_probes, local_state
from win11_release_guard.config import DEFAULT_PANTHER_TAIL_MAX_BYTES, DEFAULT_PANTHER_TOTAL_MAX_BYTES


def test_default_panther_total_cap_is_generous_for_known_path_set():
    assert DEFAULT_PANTHER_TOTAL_MAX_BYTES >= DEFAULT_PANTHER_TAIL_MAX_BYTES * len(local_state.PANTHER_LOG_PATHS)
    assert DEFAULT_PANTHER_TOTAL_MAX_BYTES >= DEFAULT_PANTHER_TAIL_MAX_BYTES * len(audit_probes.PANTHER_SETUP_LOG_PATHS)


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
