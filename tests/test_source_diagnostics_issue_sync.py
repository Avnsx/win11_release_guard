from __future__ import annotations

import io
import json
import os
import site
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tools import sync_source_diagnostics_issues as sync_tool


ATOM_SOURCE_DIAGNOSTIC_ID = "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480"


class FakeGitHubClient:
    def __init__(
        self,
        search_results: dict[str, list[dict[str, Any]]] | None = None,
        *,
        open_managed_issues: list[dict[str, Any]] | None = None,
    ) -> None:
        self.search_results = search_results or {}
        self.open_managed_issues = open_managed_issues or []
        self.searches: list[tuple[str, str]] = []
        self.listed: list[tuple[str, tuple[str, ...]]] = []
        self.created: list[tuple[str, dict[str, Any]]] = []
        self.updated: list[tuple[str, int, dict[str, Any]]] = []
        self.comments: list[tuple[str, int, str]] = []
        self.closed: list[tuple[str, int, str]] = []

    def search_issues(self, repository: str, diagnostic_id: str) -> list[dict[str, Any]]:
        self.searches.append((repository, diagnostic_id))
        return [dict(item) for item in self.search_results.get(diagnostic_id, [])]

    def list_open_managed_issues(self, repository: str, labels: list[str]) -> list[dict[str, Any]]:
        self.listed.append((repository, tuple(labels)))
        return [dict(item) for item in self.open_managed_issues]

    def create_issue(self, repository: str, *, title: str, body: str, labels: list[str]) -> dict[str, Any]:
        self.created.append((repository, {"title": title, "body": body, "labels": labels}))
        return {"number": len(self.created), "state": "open"}

    def update_issue(
        self,
        repository: str,
        issue_number: int,
        *,
        title: str,
        body: str,
        labels: list[str],
        state: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"title": title, "body": body, "labels": labels}
        if state is not None:
            payload["state"] = state
        self.updated.append((repository, issue_number, payload))
        return {"number": issue_number, "state": "open"}

    def comment_issue(self, repository: str, issue_number: int, *, body: str) -> dict[str, Any]:
        self.comments.append((repository, issue_number, body))
        return {"id": len(self.comments)}

    def close_issue(self, repository: str, issue_number: int, *, state_reason: str = "completed") -> dict[str, Any]:
        self.closed.append((repository, issue_number, state_reason))
        return {"number": issue_number, "state": "closed"}


def _event(
    diagnostic_id: str,
    *,
    severity: str = "warning",
    kind: str = "atom_newer_than_release_history",
    message: str = "Atom feed reports a newer baseline build.",
    **extra: Any,
) -> dict[str, Any]:
    event = {
        "id": diagnostic_id,
        "severity": severity,
        "kind": kind,
        "release": "25H2",
        "build_family": 26200,
        "build": "26200.8461",
        "kb_article": "KB5089600",
        "affects_broad_target": True,
        "affects_required_baseline": severity == "warning",
        "message": message,
    }
    event.update(extra)
    return event


def _policy(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {"source_diagnostics": {"events": events}}


def _marker(diagnostic_id: str) -> str:
    return f"<!-- {sync_tool.DIAGNOSTIC_ID_COMMENT_PREFIX}: {diagnostic_id} -->"


def _managed_issue(diagnostic: sync_tool.DiagnosticIssue, *, number: int = 42, state: str = "open") -> dict[str, Any]:
    return {
        "number": number,
        "state": state,
        "title": sync_tool.issue_title(diagnostic),
        "body": sync_tool.issue_body(diagnostic),
        "labels": [{"name": diagnostic.label}],
    }


def test_issue_sync_label_contract_names_active_and_legacy_severities() -> None:
    assert sync_tool.LABEL_BY_SEVERITY == {
        "warning": "internals: warning",
        "error": "internals: error",
    }
    assert sync_tool.LEGACY_NOTICE_LABEL == "internals: notices"
    assert sync_tool.MANAGED_LABELS == (
        "internals: warning",
        "internals: error",
        "internals: notices",
    )
    assert "notice" not in sync_tool.LABEL_BY_SEVERITY


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


def test_issue_sync_deduplicates_by_diagnostic_id_before_creating() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:1111111111111111"
    diagnostics = sync_tool.diagnostics_from_policy(
        _policy([_event(diagnostic_id), _event(diagnostic_id)])
    )
    client = FakeGitHubClient()

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert summary.created == 1
    assert len(client.created) == 1
    repository, payload = client.created[0]
    assert repository == "Avnsx/win11_release_guard"
    assert payload["labels"] == ["internals: warning"]
    assert f"<!-- wrg-source-diagnostic-id: {diagnostic_id} -->" in payload["body"]
    assert f"Source diagnostic ID: `{diagnostic_id}`" in payload["body"]


def test_issue_sync_accepts_atom_source_diagnostic_id_for_events_and_markers() -> None:
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(ATOM_SOURCE_DIAGNOSTIC_ID)]))
    client = FakeGitHubClient(
        {
            ATOM_SOURCE_DIAGNOSTIC_ID: [
                {
                    "number": 42,
                    "state": "open",
                    "title": sync_tool.issue_title(diagnostics[0]),
                    "body": sync_tool.issue_body(diagnostics[0]),
                    "labels": [{"name": "internals: warning"}],
                }
            ]
        }
    )

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert [diagnostic.diagnostic_id for diagnostic in diagnostics] == [ATOM_SOURCE_DIAGNOSTIC_ID]
    assert sync_tool.issue_title(diagnostics[0]).endswith("[id=968480]")
    assert f"Source diagnostic ID: `{ATOM_SOURCE_DIAGNOSTIC_ID}`" in sync_tool.issue_body(diagnostics[0])
    assert _marker(ATOM_SOURCE_DIAGNOSTIC_ID) in sync_tool.issue_body(diagnostics[0])
    assert summary.created == 0
    assert summary.issue_status[ATOM_SOURCE_DIAGNOSTIC_ID] == {
        "number": 42,
        "state": "open",
        "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
    }
    assert client.searches == [("Avnsx/win11_release_guard", ATOM_SOURCE_DIAGNOSTIC_ID)]
    assert client.created == []
    assert client.updated == []
    assert client.comments == []


def test_issue_title_keeps_hash_diagnostic_id_out_of_title_suffix() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:1111111111111111"
    diagnostic = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id)]))[0]

    assert sync_tool.issue_title(diagnostic) == "[Source diagnostics][warning] Atom Newer Than Release History"


def test_issue_title_uses_atom_support_article_id_event_field_for_hash_fallback() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:1111111111111111"
    diagnostic = sync_tool.diagnostics_from_policy(
        _policy([_event(diagnostic_id, atom_support_article_id="968480")])
    )[0]

    assert sync_tool.issue_title(diagnostic).endswith("[id=968480]")


def test_issue_sync_ignores_atom_notice_sibling_but_keeps_warning_title_suffix() -> None:
    notice_id = "wrg-source-diagnostic-v1:2222222222222222"
    events = [
        _event(
            notice_id,
            severity="notice",
            release="24H2",
            build_family=26100,
            build="26100.8655",
            atom_entry_id="uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480",
            atom_support_article_id="968480",
            support_article_validation_status="mismatch",
            support_article_validation_reasons=["applies_to_mismatch"],
        ),
        _event(
            ATOM_SOURCE_DIAGNOSTIC_ID,
            severity="warning",
            release="25H2",
            build_family=26200,
            build="26200.8655",
            atom_entry_id="uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480",
            atom_support_article_id="968480",
            support_article_validation_status="ok",
        ),
    ]

    diagnostics = sync_tool.diagnostics_from_policy(_policy(events))

    assert [diagnostic.diagnostic_id for diagnostic in diagnostics] == [ATOM_SOURCE_DIAGNOSTIC_ID]
    assert sync_tool.issue_title(diagnostics[0]).endswith("[id=968480]")


def test_issue_title_trims_base_title_without_corrupting_atom_suffix() -> None:
    diagnostic = sync_tool.diagnostics_from_policy(
        _policy([_event(ATOM_SOURCE_DIAGNOSTIC_ID, title="A" * 300)])
    )[0]

    title = sync_tool.issue_title(diagnostic)

    assert len(title) <= 220
    assert title.endswith("[id=968480]")
    assert title[: -len(" [id=968480]")].endswith("...")


def test_issue_sync_creates_atom_issue_with_title_suffix_and_full_body_id() -> None:
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(ATOM_SOURCE_DIAGNOSTIC_ID)]))
    client = FakeGitHubClient()

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert summary.created == 1
    assert summary.updated == 0
    assert client.searches == [("Avnsx/win11_release_guard", ATOM_SOURCE_DIAGNOSTIC_ID)]
    repository, payload = client.created[0]
    assert repository == "Avnsx/win11_release_guard"
    assert payload["title"].endswith("[id=968480]")
    assert _marker(ATOM_SOURCE_DIAGNOSTIC_ID) in payload["body"]
    assert f"Source diagnostic ID: `{ATOM_SOURCE_DIAGNOSTIC_ID}`" in payload["body"]
    assert summary.issue_status[ATOM_SOURCE_DIAGNOSTIC_ID] == {
        "number": 1,
        "state": "open",
        "url": "https://github.com/Avnsx/win11_release_guard/issues/1",
    }
    assert summary.actions[0]["diagnostic_id"] == ATOM_SOURCE_DIAGNOSTIC_ID


def test_issue_sync_updates_open_atom_issue_to_title_suffix() -> None:
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(ATOM_SOURCE_DIAGNOSTIC_ID)]))
    old_issue = {
        "number": 42,
        "state": "open",
        "title": "[Source diagnostics][warning] Atom Newer Than Release History",
        "body": sync_tool.issue_body(diagnostics[0]),
        "labels": [{"name": "internals: warning"}],
    }
    client = FakeGitHubClient({ATOM_SOURCE_DIAGNOSTIC_ID: [old_issue]})

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert summary.created == 0
    assert summary.updated == 1
    assert client.searches == [("Avnsx/win11_release_guard", ATOM_SOURCE_DIAGNOSTIC_ID)]
    assert client.updated[0][1] == 42
    assert client.updated[0][2]["title"].endswith("[id=968480]")
    assert _marker(ATOM_SOURCE_DIAGNOSTIC_ID) in client.updated[0][2]["body"]
    assert f"Source diagnostic ID: `{ATOM_SOURCE_DIAGNOSTIC_ID}`" in client.updated[0][2]["body"]
    assert client.comments == []


def test_issue_sync_reopens_atom_issue_with_suffix_and_full_comment_id() -> None:
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(ATOM_SOURCE_DIAGNOSTIC_ID)]))
    client = FakeGitHubClient(
        {
            ATOM_SOURCE_DIAGNOSTIC_ID: [
                {
                    "number": 52,
                    "state": "closed",
                    "title": "Closed atom diagnostic",
                    "body": _marker(ATOM_SOURCE_DIAGNOSTIC_ID),
                    "labels": [{"name": "internals: warning"}],
                }
            ]
        }
    )

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert summary.reopened == 1
    assert summary.commented == 1
    assert client.updated[0][1] == 52
    assert client.updated[0][2]["state"] == "open"
    assert client.updated[0][2]["title"].endswith("[id=968480]")
    assert _marker(ATOM_SOURCE_DIAGNOSTIC_ID) in client.updated[0][2]["body"]
    assert ATOM_SOURCE_DIAGNOSTIC_ID in client.comments[0][2]


def test_issue_sync_closes_stale_atom_issue_with_full_id_comment() -> None:
    active_id = "wrg-source-diagnostic-v1:2222222222222222"
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(active_id)]))
    stale_issue = {
        "number": 92,
        "state": "open",
        "title": "Stale atom diagnostic",
        "body": _marker(ATOM_SOURCE_DIAGNOSTIC_ID),
        "labels": [{"name": "internals: warning"}],
    }
    client = FakeGitHubClient(open_managed_issues=[stale_issue])

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert summary.closed == 1
    assert client.closed == [("Avnsx/win11_release_guard", 92, "completed")]
    assert ATOM_SOURCE_DIAGNOSTIC_ID in client.comments[0][2]


def test_issue_sync_dry_run_report_preserves_full_atom_id(tmp_path: Path) -> None:
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(ATOM_SOURCE_DIAGNOSTIC_ID)]))
    stdout = io.StringIO()
    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=None,
        dry_run=True,
        request_delay_seconds=0,
        stdout=stdout,
    )
    report = tmp_path / "dry-run.md"

    sync_tool.write_dry_run_report_output(
        report,
        report_format="markdown",
        repository="Avnsx/win11_release_guard",
        diagnostics=diagnostics,
        summary=summary,
        include_notices=False,
    )

    assert ATOM_SOURCE_DIAGNOSTIC_ID in stdout.getvalue()
    assert summary.actions[0]["diagnostic_id"] == ATOM_SOURCE_DIAGNOSTIC_ID
    assert ATOM_SOURCE_DIAGNOSTIC_ID in report.read_text(encoding="utf-8")


def test_issue_sync_skips_malformed_atom_event_id_before_sync() -> None:
    stdout = io.StringIO()
    diagnostics = sync_tool.diagnostics_from_policy(
        _policy(
            [
                _event(
                    "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=0"
                )
            ]
        ),
        stdout=stdout,
    )

    assert diagnostics == []
    assert "Skipping source diagnostic without a valid deterministic ID." in stdout.getvalue()


def test_issue_sync_skips_atom_notice_events() -> None:
    notice = _event(ATOM_SOURCE_DIAGNOSTIC_ID, severity="notice")

    assert sync_tool.diagnostics_from_policy(_policy([notice])) == []


@pytest.mark.parametrize(
    "body",
    (
        _marker("wrg-source-diagnostic-v1:1111111111111111"),
        _marker(ATOM_SOURCE_DIAGNOSTIC_ID),
    ),
)
def test_issue_diagnostic_id_extracts_supported_marker_forms(body: str) -> None:
    expected = body.split(": ", 1)[1].split(" -->", 1)[0]

    assert sync_tool._issue_diagnostic_id({"body": body}) == expected


@pytest.mark.parametrize(
    "diagnostic_id",
    (
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af;id=968480",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=0",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=-1",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=notnumeric",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1C3E09919AF3;id=968480",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3 ;id=968480",
        "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480-extra",
        "arbitrary-string-id",
    ),
)
def test_issue_diagnostic_id_ignores_malformed_atom_marker_ids(diagnostic_id: str) -> None:
    assert sync_tool._issue_diagnostic_id({"body": _marker(diagnostic_id)}) is None


def test_issue_diagnostic_id_ignores_body_without_exactly_one_valid_marker() -> None:
    assert sync_tool._issue_diagnostic_id({"body": "Manual issue without a marker."}) is None
    assert sync_tool._issue_diagnostic_id(
        {
            "body": (
                f"{_marker(ATOM_SOURCE_DIAGNOSTIC_ID)}\n"
                f"{_marker('wrg-source-diagnostic-v1:1111111111111111')}"
            )
        }
    ) is None


def test_issue_sync_reads_only_source_diagnostics_events_not_display_rows() -> None:
    event_id = "wrg-source-diagnostic-v1:1111111111111111"
    derived_id = "wrg-source-diagnostic-v1:2222222222222222"
    policy = {
        "source_diagnostics": {
            "event_counts": {"notice": 2, "warning": 1, "error": 0},
            "events": [_event(event_id)],
            "notices": [
                "No source issues reported",
                "26H1 excluded for existing devices",
            ],
            "display_rows": [
                {
                    "id": derived_id,
                    "severity": "notice",
                    "title": "No source issues reported",
                    "message": "Derived dashboard-only row.",
                }
            ],
            "issue_status": {
                derived_id: {
                    "number": 70,
                    "state": "open",
                    "url": "https://github.com/Avnsx/win11_release_guard/issues/70",
                }
            },
        }
    }

    diagnostics = sync_tool.diagnostics_from_policy(policy)
    client = FakeGitHubClient()
    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert [diagnostic.diagnostic_id for diagnostic in diagnostics] == [event_id]
    assert summary.considered == 1
    assert client.searches == [("Avnsx/win11_release_guard", event_id)]
    assert len(client.created) == 1
    assert client.created[0][1]["labels"] == ["internals: warning"]
    assert derived_id not in client.created[0][1]["body"]


def test_issue_sync_maps_exact_labels_for_warning_and_error_only() -> None:
    events = [
        _event("wrg-source-diagnostic-v1:1111111111111111", severity="notice"),
        _event("wrg-source-diagnostic-v1:2222222222222222", severity="warning"),
        _event("wrg-source-diagnostic-v1:3333333333333333", severity="error"),
    ]
    diagnostics = sync_tool.diagnostics_from_policy(_policy(events))
    client = FakeGitHubClient()

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        create_limit=10,
        request_delay_seconds=0,
    )

    assert summary.created == 2
    assert [payload["labels"] for _, payload in client.created] == [
        ["internals: warning"],
        ["internals: error"],
    ]


def test_issue_body_adds_broad_target_atom_tip_at_bottom() -> None:
    diagnostic = sync_tool.diagnostics_from_policy(
        _policy(
            [
                _event(
                    "wrg-source-diagnostic-v1:1111111111111111",
                    severity="warning",
                    kind="atom_newer_than_release_history",
                    message="Atom feed shows a newer broad-target baseline build.",
                )
            ]
        )
    )[0]

    body = sync_tool.issue_body(diagnostic)

    assert "> [!TIP]" in body
    assert "new broad-target, non-preview build" in body
    assert "keep WUA as read-only local context" in body
    assert body.rstrip().endswith(
        "> See [follow-up documentation](https://avnsx.github.io/win11_release_guard/wiki/Source-Diagnostics/#common-issues)."
    )


def test_issue_body_adds_atom_enrichment_tip_for_feed_failures() -> None:
    diagnostic = sync_tool.diagnostics_from_policy(
        _policy(
            [
                _event(
                    "wrg-source-diagnostic-v1:2222222222222222",
                    severity="warning",
                    kind="atom_feed_parse_failed",
                    message="Atom feed could not be parsed.",
                )
            ]
        )
    )[0]

    body = sync_tool.issue_body(diagnostic)

    assert "Servicing index enrichment is unavailable or unusable" in body
    assert "Release Health remains the primary policy source" in body
    assert body.rstrip().endswith(
        "> See [follow-up documentation](https://avnsx.github.io/win11_release_guard/wiki/Source-Diagnostics/#diagnostic-sources)."
    )


def test_issue_body_adds_freshness_tip_for_unresolved_source_drift() -> None:
    diagnostic = sync_tool.diagnostics_from_policy(
        _policy(
            [
                _event(
                    "wrg-source-diagnostic-v1:3333333333333333",
                    severity="warning",
                    kind="source_drift_unresolved_after_24h",
                    message="Policy was generated after source drift remained unresolved.",
                )
            ]
        )
    )[0]

    body = sync_tool.issue_body(diagnostic)

    assert "Unresolved source drift older than 24 hours" in body
    assert "publish workflow and source timestamps" in body
    assert body.rstrip().endswith(
        "> See [follow-up documentation](https://avnsx.github.io/win11_release_guard/wiki/Anti-Static-Freshness/)."
    )


def test_issue_body_adds_publish_gate_tip_for_source_errors() -> None:
    diagnostic = sync_tool.diagnostics_from_policy(
        _policy(
            [
                _event(
                    "wrg-source-diagnostic-v1:4444444444444444",
                    severity="error",
                    kind="release_health_parser_failed",
                    message="Release Health table could not be parsed safely.",
                )
            ]
        )
    )[0]

    body = sync_tool.issue_body(diagnostic)

    assert "source diagnostic error is publish-blocking" in body
    assert "instead of bypassing the gate" in body
    assert body.rstrip().endswith(
        "> See [follow-up documentation](https://avnsx.github.io/win11_release_guard/wiki/Source-Diagnostics/#publish-gate)."
    )


def test_repeated_issue_sync_leaves_current_open_issue_unchanged_without_comment() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:4444444444444444"
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id)]))
    client = FakeGitHubClient({diagnostic_id: [_managed_issue(diagnostics[0])]})

    for _ in range(2):
        summary = sync_tool.sync_diagnostics(
            diagnostics,
            repository="Avnsx/win11_release_guard",
            client=client,
            request_delay_seconds=0,
        )

        assert summary.created == 0
        assert summary.updated == 0
        assert summary.commented == 0
        assert summary.issue_status[diagnostic_id] == {
            "number": 42,
            "state": "open",
            "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
        }
    assert client.created == []
    assert client.updated == []
    assert client.comments == []


def test_issue_sync_search_finding_managed_issue_prevents_duplicate() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:1010101010101010"
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id)]))
    client = FakeGitHubClient({diagnostic_id: [_managed_issue(diagnostics[0], number=101)]})

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert summary.created == 0
    assert summary.updated == 0
    assert summary.commented == 0
    assert summary.issue_status[diagnostic_id] == {
        "number": 101,
        "state": "open",
        "url": "https://github.com/Avnsx/win11_release_guard/issues/101",
    }
    assert client.searches == [("Avnsx/win11_release_guard", diagnostic_id)]
    assert client.created == []
    assert client.updated == []
    assert client.comments == []


def test_issue_sync_label_list_fallback_prevents_duplicate_when_search_misses() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:2020202020202020"
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id)]))
    client = FakeGitHubClient(open_managed_issues=[_managed_issue(diagnostics[0], number=202)])

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert summary.created == 0
    assert summary.updated == 0
    assert summary.commented == 0
    assert summary.issue_status[diagnostic_id] == {
        "number": 202,
        "state": "open",
        "url": "https://github.com/Avnsx/win11_release_guard/issues/202",
    }
    assert client.searches == [("Avnsx/win11_release_guard", diagnostic_id)]
    assert client.listed == [("Avnsx/win11_release_guard", tuple(sync_tool.MANAGED_LABELS))]
    assert client.created == []
    assert client.updated == []
    assert client.comments == []


def test_issue_sync_creates_when_search_and_label_list_find_no_managed_issue() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:3030303030303030"
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id)]))
    client = FakeGitHubClient()

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert summary.created == 1
    assert summary.updated == 0
    assert summary.commented == 0
    assert client.searches == [("Avnsx/win11_release_guard", diagnostic_id)]
    assert client.listed == [("Avnsx/win11_release_guard", tuple(sync_tool.MANAGED_LABELS))]
    assert len(client.created) == 1
    assert _marker(diagnostic_id) in client.created[0][1]["body"]


def test_issue_sync_label_list_issue_without_exact_marker_does_not_block_create() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:4040404040404040"
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id)]))
    client = FakeGitHubClient(
        open_managed_issues=[
            {
                "number": 204,
                "state": "open",
                "title": f"Manual tracking for {diagnostic_id}",
                "body": f"Manual note mentions {diagnostic_id} without the managed marker.",
                "labels": [{"name": "internals: warning"}],
            }
        ]
    )

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert summary.created == 1
    assert summary.updated == 0
    assert summary.commented == 0
    assert client.updated == []
    assert client.comments == []
    assert client.closed == []
    assert _marker(diagnostic_id) in client.created[0][1]["body"]


def test_repeated_issue_sync_with_label_list_fallback_stays_idempotent() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:5050505050505050"
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id)]))
    client = FakeGitHubClient(open_managed_issues=[_managed_issue(diagnostics[0], number=205)])

    for _ in range(2):
        summary = sync_tool.sync_diagnostics(
            diagnostics,
            repository="Avnsx/win11_release_guard",
            client=client,
            request_delay_seconds=0,
        )

        assert summary.created == 0
        assert summary.updated == 0
        assert summary.commented == 0
        assert summary.issue_status[diagnostic_id] == {
            "number": 205,
            "state": "open",
            "url": "https://github.com/Avnsx/win11_release_guard/issues/205",
        }
    assert client.created == []
    assert client.updated == []
    assert client.comments == []


def test_issue_sync_updates_changed_open_issue_without_still_present_comment() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:4444444444444444"
    previous_diagnostic = sync_tool.diagnostics_from_policy(
        _policy([_event(diagnostic_id, severity="warning")])
    )[0]
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id, severity="error")]))
    client = FakeGitHubClient({diagnostic_id: [_managed_issue(previous_diagnostic)]})

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert summary.created == 0
    assert summary.updated == 1
    assert summary.commented == 0
    assert client.created == []
    assert client.comments == []
    assert client.updated[0][1] == 42
    assert client.updated[0][2]["labels"] == ["internals: error"]
    assert "[Source diagnostics][error]" in client.updated[0][2]["title"]
    assert "Severity: `error`" in client.updated[0][2]["body"]
    assert diagnostic_id in client.updated[0][2]["body"]


def test_issue_sync_ignores_open_issue_with_label_but_no_marker() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:4a4a4a4a4a4a4a4a"
    client = FakeGitHubClient(
        {
            diagnostic_id: [
                {
                    "number": 43,
                    "state": "open",
                    "body": "Manual tracking issue without the managed marker.",
                    "labels": [{"name": "internals: warning"}],
                }
            ]
        }
    )
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id)]))

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert summary.created == 1
    assert summary.updated == 0
    assert summary.commented == 0
    assert client.updated == []
    assert client.comments == []
    assert client.closed == []
    assert client.created[0][1]["labels"] == ["internals: warning"]


def test_issue_sync_ignores_open_issue_with_plaintext_diagnostic_id_but_no_marker() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:4b4b4b4b4b4b4b4b"
    client = FakeGitHubClient(
        {
            diagnostic_id: [
                {
                    "number": 44,
                    "state": "open",
                    "body": f"Manual note mentions {diagnostic_id} without an HTML marker.",
                }
            ]
        }
    )
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id)]))

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert summary.created == 1
    assert summary.updated == 0
    assert summary.commented == 0
    assert client.updated == []
    assert client.comments == []
    assert client.closed == []


def test_issue_sync_ignores_open_issue_with_title_diagnostic_id_but_no_marker() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:4c4c4c4c4c4c4c4c"
    client = FakeGitHubClient(
        {
            diagnostic_id: [
                {
                    "number": 45,
                    "state": "open",
                    "title": f"Manual investigation for {diagnostic_id}",
                    "body": "No managed marker here.",
                }
            ]
        }
    )
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id)]))

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert summary.created == 1
    assert summary.updated == 0
    assert summary.commented == 0
    assert client.updated == []
    assert client.comments == []
    assert client.closed == []


def test_issue_sync_ignores_open_issue_with_multiple_managed_markers() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:4d4d4d4d4d4d4d4d"
    other_id = "wrg-source-diagnostic-v1:4e4e4e4e4e4e4e4e"
    client = FakeGitHubClient(
        {
            diagnostic_id: [
                {
                    "number": 46,
                    "state": "open",
                    "body": f"{_marker(diagnostic_id)}\n{_marker(other_id)}",
                }
            ]
        }
    )
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id)]))

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert summary.created == 1
    assert summary.updated == 0
    assert summary.commented == 0
    assert client.updated == []
    assert client.comments == []
    assert client.closed == []


def test_issue_sync_does_not_reopen_closed_issue_without_marker() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:4f4f4f4f4f4f4f4f"
    client = FakeGitHubClient(
        {
            diagnostic_id: [
                {
                    "number": 47,
                    "state": "closed",
                    "body": f"Closed manual issue mentions {diagnostic_id} without marker.",
                    "labels": [{"name": "internals: warning"}],
                }
            ]
        }
    )
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id)]))

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        create_limit=0,
        request_delay_seconds=0,
    )

    assert summary.reopened == 0
    assert summary.commented == 0
    assert client.updated == []
    assert client.comments == []
    assert client.closed == []


def test_issue_sync_reopens_matching_closed_issue_by_default() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:5555555555555555"
    client = FakeGitHubClient(
        {diagnostic_id: [{"number": 51, "state": "closed", "body": _marker(diagnostic_id)}]}
    )
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id)]))

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
    )

    assert summary.reopened == 1
    assert summary.commented == 1
    assert client.created == []
    assert client.updated[0][1] == 51
    assert client.updated[0][2]["state"] == "open"
    assert diagnostic_id in client.comments[0][2]
    assert summary.issue_status[diagnostic_id] == {
        "number": 51,
        "state": "open",
        "url": "https://github.com/Avnsx/win11_release_guard/issues/51",
    }


def test_issue_sync_can_skip_matching_closed_issue_when_reopen_disabled() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:5555555555555555"
    client = FakeGitHubClient(
        {diagnostic_id: [{"number": 51, "state": "closed", "body": _marker(diagnostic_id)}]}
    )
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id)]))

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        request_delay_seconds=0,
        reopen_closed=False,
    )

    assert summary.skipped_closed == 1
    assert client.created == []
    assert client.updated == []
    assert client.comments == []


def test_issue_sync_caps_new_issue_creation_per_run() -> None:
    diagnostics = sync_tool.diagnostics_from_policy(
        _policy(
            [
                _event("wrg-source-diagnostic-v1:6666666666666666"),
                _event("wrg-source-diagnostic-v1:7777777777777777"),
                _event("wrg-source-diagnostic-v1:8888888888888888"),
            ]
        )
    )
    client = FakeGitHubClient()

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        create_limit=2,
        request_delay_seconds=0,
    )

    assert summary.created == 2
    assert summary.skipped_cap == 1
    assert len(client.created) == 2


def test_notice_diagnostics_are_dashboard_only_even_with_legacy_flags() -> None:
    notice = _event("wrg-source-diagnostic-v1:9999999999999999", severity="notice")

    assert sync_tool.diagnostics_from_policy(_policy([notice])) == []
    assert sync_tool.diagnostics_from_policy(_policy([notice]), include_notices=True) == []
    assert sync_tool.diagnostics_from_policy(_policy([notice]), include_notices=False) == []


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


def test_notice_managed_issue_closes_as_stale_even_while_notice_exists() -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:9090909090909090"
    diagnostics = sync_tool.diagnostics_from_policy(_policy([_event(diagnostic_id, severity="notice")]))
    notice_issue = {
        "number": 90,
        "state": "open",
        "body": _marker(diagnostic_id),
        "labels": [{"name": sync_tool.LEGACY_NOTICE_LABEL}],
    }
    client = FakeGitHubClient(
        {diagnostic_id: [notice_issue]},
        open_managed_issues=[notice_issue],
    )

    summary = sync_tool.sync_diagnostics(
        diagnostics,
        repository="Avnsx/win11_release_guard",
        client=client,
        create_limit=0,
        request_delay_seconds=0,
    )

    assert diagnostics == []
    assert summary.updated == 0
    assert summary.commented == 1
    assert summary.closed == 1
    assert client.updated == []
    assert client.comments[0][1] == 90
    assert client.closed == [("Avnsx/win11_release_guard", 90, "completed")]


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


def test_issue_sync_writes_static_issue_status_output(tmp_path: Path) -> None:
    diagnostic_id = "wrg-source-diagnostic-v1:abababababababab"
    client = FakeGitHubClient(
        {diagnostic_id: [{"number": 42, "state": "open", "body": _marker(diagnostic_id)}]}
    )
    policy_path = tmp_path / "policy.json"
    status_path = tmp_path / "issue-status.json"
    policy_path.write_text(json.dumps(_policy([_event(diagnostic_id)])) + "\n", encoding="utf-8")
    stdout = io.StringIO()

    code = sync_tool.main(
        [
            "--policy-file",
            str(policy_path),
            "--repository",
            "Avnsx/win11_release_guard",
            "--issue-status-output",
            str(status_path),
            "--request-delay-seconds",
            "0",
            "--no-close-stale",
        ],
        client=client,
        environ={"GITHUB_TOKEN": "safe-test-token-value-that-must-not-print"},
        stdout=stdout,
    )

    assert code == 0
    payload = json.loads(status_path.read_text(encoding="utf-8"))
    assert payload == {
        "issue_status": {
            diagnostic_id: {
                "number": 42,
                "state": "open",
                "url": "https://github.com/Avnsx/win11_release_guard/issues/42",
            }
        }
    }


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
