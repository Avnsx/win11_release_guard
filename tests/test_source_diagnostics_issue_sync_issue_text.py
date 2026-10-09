from __future__ import annotations

import io
import json
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
                    kind="servicing_toc_parse_failed",
                    message="Servicing TOC could not be parsed.",
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
