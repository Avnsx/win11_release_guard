from __future__ import annotations

import io
import json
import os
import site
import subprocess
import sys
from pathlib import Path
from tools import sync_source_diagnostics_issues as sync_tool
from tests.support.source_diagnostics_issue_sync_helpers import (
    FakeGitHubClient,
    _event,
    _marker,
    _policy,
)


def test_script_help_runs_from_source_checkout_without_editable_install() -> None:
    script = Path(__file__).resolve().parents[1] / "tools" / "sync_source_diagnostics_issues.py"
    dependency_paths = [Path(path) for path in site.getsitepackages()]
    dependency_paths.append(Path(site.getusersitepackages()))
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        str(path) for path in dependency_paths if path.exists()
    )

    result = subprocess.run(
        [sys.executable, "-S", str(script), "--help"],
        cwd=script.parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Sync source diagnostics to GitHub Issues." in result.stdout
    assert "--policy-file" in result.stdout
    assert "--dry-run-report-output" in result.stdout
    assert "--dry-run-report-format" in result.stdout


def test_include_notices_cli_flag_does_not_create_notice_issues(tmp_path: Path) -> None:
    notice_id = "wrg-source-diagnostic-v1:9999999999999999"
    warning_id = "wrg-source-diagnostic-v1:aaaaaaaaaaaaaaaa"
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            _policy(
                [
                    _event(notice_id, severity="notice"),
                    _event(warning_id, severity="warning"),
                ]
            )
        )
        + "\n",
        encoding="utf-8",
    )
    client = FakeGitHubClient()
    stdout = io.StringIO()
    stderr = io.StringIO()

    code = sync_tool.main(
        [
            "--policy-file",
            str(policy_path),
            "--repository",
            "Avnsx/win11_release_guard",
            "--include-notices",
            "--request-delay-seconds",
            "0",
        ],
        client=client,
        environ={"GITHUB_TOKEN": "safe-test-token-value-that-must-not-print"},
        stdout=stdout,
        stderr=stderr,
    )

    assert code == 0
    assert [payload["labels"] for _, payload in client.created] == [["internals: warning"]]
    assert notice_id not in "\n".join(payload["body"] for _, payload in client.created)
    assert "Notice diagnostics are dashboard-only; --include-notices is ignored" in stdout.getvalue()
    assert "skipped_notices=1" in stdout.getvalue()
    assert stderr.getvalue() == ""


def test_issue_sync_closes_stale_open_managed_issue() -> None:
    active_id = "wrg-source-diagnostic-v1:1212121212121212"
    stale_id = "wrg-source-diagnostic-v1:3434343434343434"
    client = FakeGitHubClient(
        open_managed_issues=[
            {
                "number": 77,
                "state": "open",
                "body": _marker(stale_id),
                "labels": [{"name": "internals: notices"}],
            },
            {
                "number": 78,
                "state": "open",
                "body": _marker(active_id),
                "labels": [{"name": "internals: warning"}],
            },
        ]
    )
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(active_id)]))

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        create_limit=0,
        request_delay_seconds=0,
    )

    assert summary.closed == 1
    assert client.closed == [("Avnsx/win11_release_guard", 77, "completed")]
    assert stale_id in client.comments[0][2]
    assert client.listed == [("Avnsx/win11_release_guard", tuple(sync_tool.MANAGED_LABELS))]


def test_issue_sync_does_not_close_labeled_stale_issue_without_marker() -> None:
    active_id = "wrg-source-diagnostic-v1:5656565656565656"
    stale_id = "wrg-source-diagnostic-v1:7878787878787878"
    client = FakeGitHubClient(
        open_managed_issues=[
            {
                "number": 79,
                "state": "open",
                "body": f"Manual note mentions {stale_id} without the managed marker.",
                "labels": [{"name": "internals: notices"}],
            },
            {
                "number": 80,
                "state": "open",
                "title": f"Manual title mentions {stale_id}",
                "body": "No managed marker here.",
                "labels": [{"name": "internals: warning"}],
            },
        ]
    )
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(active_id)]))

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        create_limit=0,
        request_delay_seconds=0,
    )

    assert summary.closed == 0
    assert summary.commented == 0
    assert client.closed == []
    assert client.comments == []


def test_dry_run_does_not_mutate_or_print_token(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(_policy([_event("wrg-source-diagnostic-v1:aaaaaaaaaaaaaaaa")])) + "\n",
        encoding="utf-8",
    )
    client = FakeGitHubClient()
    stdout = io.StringIO()
    stderr = io.StringIO()
    secret_token = "safe-test-token-value-that-must-not-print"

    code = sync_tool.main(
        [
            "--policy-file",
            str(policy_path),
            "--repository",
            "Avnsx/win11_release_guard",
            "--dry-run",
            "--request-delay-seconds",
            "0",
        ],
        client=client,
        environ={"GITHUB_TOKEN": secret_token, "GITHUB_REPOSITORY": "Avnsx/win11_release_guard"},
        stdout=stdout,
        stderr=stderr,
    )

    assert code == 0
    assert client.created == []
    assert client.updated == []
    assert client.comments == []
    output = stdout.getvalue() + stderr.getvalue()
    assert "Would create issue for wrg-source-diagnostic-v1:aaaaaaaaaaaaaaaa." in output
    assert secret_token not in output
    assert "GITHUB_TOKEN" not in output


def test_end_to_end_dry_run_writes_json_and_markdown_without_mutation_or_token(tmp_path: Path) -> None:
    notice_id = "wrg-source-diagnostic-v1:1111111111111111"
    warning_id = "wrg-source-diagnostic-v1:2222222222222222"
    error_id = "wrg-source-diagnostic-v1:3333333333333333"
    stale_id = "wrg-source-diagnostic-v1:4444444444444444"
    manual_id = "wrg-source-diagnostic-v1:5555555555555555"
    policy_path = tmp_path / "policy.json"
    json_report = tmp_path / "dry-run.json"
    markdown_report = tmp_path / "dry-run.md"
    events = [
        _event(notice_id, severity="notice", kind="notice_probe", message="Notice diagnostic still exists."),
        _event(warning_id, severity="warning", kind="warning_probe", message="Warning diagnostic reappeared."),
        _event(error_id, severity="error", kind="error_probe", message="Error diagnostic requires tracking."),
        _event(error_id, severity="error", kind="error_probe", message="Duplicate event should dedupe."),
    ]
    policy_path.write_text(json.dumps(_policy(events)) + "\n", encoding="utf-8")
    diagnostics = sync_tool.diagnostics_from_policy(_policy(events))
    notice_issue = {
        "number": 90,
        "state": "open",
        "body": _marker(notice_id),
        "labels": [{"name": sync_tool.LEGACY_NOTICE_LABEL}],
    }
    closed_warning_issue = {
        "number": 91,
        "state": "closed",
        "body": _marker(warning_id),
        "labels": [{"name": "internals: warning"}],
    }
    manual_error_issue = {
        "number": 92,
        "state": "open",
        "body": f"Manual issue mentions {error_id} without the managed marker.",
        "labels": [{"name": "internals: error"}],
    }
    stale_issue = {
        "number": 93,
        "state": "open",
        "body": _marker(stale_id),
        "labels": [{"name": "internals: notices"}],
    }
    manual_stale_issue = {
        "number": 94,
        "state": "open",
        "body": f"Manual issue mentions {manual_id} without the managed marker.",
        "labels": [{"name": "internals: warning"}],
    }
    secret_token = "safe-test-token-value-that-must-not-print"

    def run_report(path: Path, report_format: str) -> FakeGitHubClient:
        client = FakeGitHubClient(
            {
                notice_id: [notice_issue],
                warning_id: [closed_warning_issue],
                error_id: [manual_error_issue],
            },
            open_managed_issues=[notice_issue, stale_issue, manual_stale_issue],
        )
        stdout = io.StringIO()
        stderr = io.StringIO()

        code = sync_tool.main(
            [
                "--policy-file",
                str(policy_path),
                "--repository",
                "Avnsx/win11_release_guard",
                "--dry-run",
                "--dry-run-report-output",
                str(path),
                "--dry-run-report-format",
                report_format,
                "--request-delay-seconds",
                "0",
            ],
            client=client,
            environ={"GITHUB_TOKEN": secret_token, "GITHUB_REPOSITORY": "Avnsx/win11_release_guard"},
            stdout=stdout,
            stderr=stderr,
        )

        assert code == 0
        assert client.created == []
        assert client.updated == []
        assert client.comments == []
        assert client.closed == []
        combined_output = stdout.getvalue() + stderr.getvalue() + path.read_text(encoding="utf-8")
        assert secret_token not in combined_output
        assert "GITHUB_TOKEN" not in combined_output
        return client

    json_client = run_report(json_report, "json")
    run_report(markdown_report, "markdown")

    payload = json.loads(json_report.read_text(encoding="utf-8"))
    assert payload["dry_run"] is True
    assert payload["repository"] == "Avnsx/win11_release_guard"
    assert payload["summary"]["considered"] == 2
    assert payload["summary"]["skipped_notices"] == 1
    assert payload["summary"]["dry_run_creates"] == 1
    assert payload["summary"]["dry_run_reopens"] == 1
    assert payload["summary"]["dry_run_closes"] == 2
    assert payload["diagnostics"] == [
        {
            "diagnostic_id": warning_id,
            "severity": "warning",
            "label": "internals: warning",
            "kind": "warning_probe",
            "title": "Warning Probe",
        },
        {
            "diagnostic_id": error_id,
            "severity": "error",
            "label": "internals: error",
            "kind": "error_probe",
            "title": "Error Probe",
        },
    ]
    assert [
        (action["action"], action["diagnostic_id"], action.get("label"), action.get("issue_number"))
        for action in payload["actions"]
    ] == [
        ("reopen", warning_id, "internals: warning", 91),
        ("create", error_id, "internals: error", None),
        ("close", notice_id, None, 90),
        ("close", stale_id, None, 93),
    ]
    assert payload["issue_status"] == {}
    assert json_client.searches == [
        ("Avnsx/win11_release_guard", warning_id),
        ("Avnsx/win11_release_guard", error_id),
    ]
    assert json_client.listed == [("Avnsx/win11_release_guard", tuple(sync_tool.MANAGED_LABELS))]

    markdown = markdown_report.read_text(encoding="utf-8")
    assert "# Source Diagnostics Issue Sync Dry Run" in markdown
    assert "| create | wrg-source-diagnostic-v1:3333333333333333 | error | internals: error | - | - |" in markdown
    assert "| close | wrg-source-diagnostic-v1:1111111111111111 | - | - | #90 | stale |" in markdown
    assert "| close | wrg-source-diagnostic-v1:4444444444444444 | - | - | #93 | stale |" in markdown
    assert manual_id not in markdown


def test_dry_run_report_requires_dry_run(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.json"
    report_path = tmp_path / "dry-run.json"
    policy_path.write_text(
        json.dumps(_policy([_event("wrg-source-diagnostic-v1:bbbbbbbbbbbbbbbb")])) + "\n",
        encoding="utf-8",
    )
    stderr = io.StringIO()

    code = sync_tool.main(
        [
            "--policy-file",
            str(policy_path),
            "--repository",
            "Avnsx/win11_release_guard",
            "--dry-run-report-output",
            str(report_path),
        ],
        client=FakeGitHubClient(),
        environ={},
        stderr=stderr,
    )

    assert code == 1
    assert "--dry-run-report-output requires --dry-run" in stderr.getvalue()
    assert not report_path.exists()
