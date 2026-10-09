from __future__ import annotations

import io
from pathlib import Path
import pytest
from tools import sync_source_diagnostics_issues as sync_tool
from tests.support.source_diagnostics_issue_sync_helpers import (
    ATOM_SOURCE_DIAGNOSTIC_ID,
    FakeGitHubClient,
    _event,
    _managed_issue,
    _marker,
    _policy,
)


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
