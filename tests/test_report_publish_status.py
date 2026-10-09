from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from typing import Any

import pytest

from tools import report_publish_status as report_tool
from tools import sync_source_diagnostics_issues as sync_tool

REPOSITORY = "Avnsx/win11_release_guard"
RUN_URL = "https://github.com/Avnsx/win11_release_guard/actions/runs/101"
SECOND_RUN_URL = "https://github.com/Avnsx/win11_release_guard/actions/runs/102"
NOW = datetime(2026, 10, 8, 6, 23, tzinfo=timezone.utc)
LATER = datetime(2026, 10, 8, 18, 23, tzinfo=timezone.utc)
GENERATION_ERROR = (
    "Policy generation failed: Could not select B-release required baseline for "
    "broad_target_existing_devices 26H2/26300 from Release Health release_history."
)
FAILED_NEEDS = {
    "sync-source-diagnostics-issues": {"result": "failure", "outputs": {}},
    "build": {"result": "skipped", "outputs": {}},
    "deploy": {"result": "skipped", "outputs": {}},
    "verify-live-pages": {"result": "skipped", "outputs": {}},
}
PASSED_NEEDS = {name: {"result": "success", "outputs": {}} for name in FAILED_NEEDS}


class FakeClient:
    def __init__(self, issues: list[dict[str, Any]] | None = None, *, label_error: Exception | None = None) -> None:
        self.issues = list(issues or [])
        self.label_error = label_error
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def ensure_label(self, repository: str, *, name: str, color: str, description: str) -> None:
        self.calls.append(("ensure_label", {"name": name, "color": color, "description": description}))
        if self.label_error is not None:
            raise self.label_error

    def list_open_issues_by_creator(self, repository: str, *, creator: str) -> list[dict[str, Any]]:
        self.calls.append(("list", {"creator": creator}))
        return [dict(issue) for issue in self.issues]

    def create_issue(self, repository: str, *, title: str, body: str, labels: list[str]) -> dict[str, Any]:
        self.calls.append(("create", {"title": title, "body": body, "labels": labels}))
        self.issues.append({"number": 7, "title": title, "body": body, "labels": [{"name": name} for name in labels]})
        return {"number": 7, "title": title, "body": body}

    def update_issue(self, repository: str, issue_number: int, *, title: str, body: str, labels: list[str], state: str | None = None) -> dict[str, Any]:
        self.calls.append(("update", {"number": issue_number, "title": title, "body": body, "labels": labels}))
        return {"number": issue_number}

    def comment_issue(self, repository: str, issue_number: int, *, body: str) -> dict[str, Any]:
        self.calls.append(("comment", {"number": issue_number, "body": body}))
        return {}

    def close_issue(self, repository: str, issue_number: int, *, state_reason: str = "completed") -> dict[str, Any]:
        self.calls.append(("close", {"number": issue_number, "state_reason": state_reason}))
        return {}

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]

    def call(self, name: str) -> dict[str, Any]:
        return next(payload for call_name, payload in self.calls if call_name == name)


def _report(client: FakeClient, *, needs: dict[str, Any], log: str | None = GENERATION_ERROR, run_url: str = RUN_URL, now: datetime = NOW) -> str:
    return report_tool.report_publish_status(
        client,
        repository=REPOSITORY,
        needs=needs,
        run_url=run_url,
        generation_log=log,
        now=now,
    )


def _open_issue_from_first_failure() -> dict[str, Any]:
    client = FakeClient()
    _report(client, needs=FAILED_NEEDS)
    created = client.call("create")
    return {"number": 7, "title": created["title"], "body": created["body"], "labels": [{"name": report_tool.ISSUE_LABEL}]}


@pytest.mark.parametrize(
    ("results", "outcome"),
    [
        (("success", "success", "success", "success"), "success"),
        (("failure", "skipped", "skipped", "skipped"), "failure"),
        (("success", "success", "success", "failure"), "failure"),
        (("success", "cancelled", "skipped", "skipped"), "inconclusive"),
        (("success", "skipped", "skipped", "skipped"), "inconclusive"),
    ],
)
def test_outcome_from_needs(results: tuple[str, ...], outcome: str) -> None:
    needs = {name: {"result": result} for name, result in zip(FAILED_NEEDS, results)}

    assert report_tool.outcome_from_needs(needs) == outcome


def test_outcome_from_needs_treats_empty_needs_as_inconclusive() -> None:
    assert report_tool.outcome_from_needs({}) == "inconclusive"


def test_first_failure_creates_one_labelled_managed_issue() -> None:
    client = FakeClient()

    action = _report(client, needs=FAILED_NEEDS)

    assert action == "created"
    assert client.names() == ["list", "ensure_label", "create"]
    created = client.call("create")
    assert created["title"] == report_tool.ISSUE_TITLE
    assert created["labels"] == [report_tool.ISSUE_LABEL]
    body = created["body"]
    assert report_tool.ISSUE_MARKER in body
    assert RUN_URL in body
    assert "`sync-source-diagnostics-issues`" in body
    assert GENERATION_ERROR in body
    assert "| Consecutive failed runs | 1 |" in body
    assert "closes itself" in body


def test_repeated_failure_with_same_error_updates_body_without_comment() -> None:
    client = FakeClient([_open_issue_from_first_failure()])

    action = _report(client, needs=FAILED_NEEDS, run_url=SECOND_RUN_URL, now=LATER)

    assert action == "updated"
    assert client.names() == ["list", "update"]
    body = client.call("update")["body"]
    assert "| Consecutive failed runs | 2 |" in body
    assert RUN_URL in body and SECOND_RUN_URL in body
    assert client.call("update")["labels"] == [report_tool.ISSUE_LABEL]


def test_failure_with_new_error_comments_once_and_updates_body() -> None:
    client = FakeClient([_open_issue_from_first_failure()])

    action = _report(client, needs=FAILED_NEEDS, log="Policy generation failed: signing key is invalid.", run_url=SECOND_RUN_URL, now=LATER)

    assert action == "commented"
    assert client.names() == ["list", "comment", "update"]
    assert "signing key is invalid" in client.call("comment")["body"]
    assert SECOND_RUN_URL in client.call("comment")["body"]
    assert "signing key is invalid" in client.call("update")["body"]


def test_success_comments_and_closes_open_managed_issue() -> None:
    client = FakeClient([_open_issue_from_first_failure()])

    action = _report(client, needs=PASSED_NEEDS, log=None, run_url=SECOND_RUN_URL, now=LATER)

    assert action == "closed"
    assert client.names() == ["list", "comment", "close"]
    assert SECOND_RUN_URL in client.call("comment")["body"]
    assert client.call("close") == {"number": 7, "state_reason": "completed"}


def test_success_without_open_issue_changes_nothing() -> None:
    client = FakeClient()

    assert _report(client, needs=PASSED_NEEDS, log=None) == "noop"
    assert client.names() == ["list"]


def test_inconclusive_run_never_touches_github() -> None:
    client = FakeClient([_open_issue_from_first_failure()])
    needs = {"sync-source-diagnostics-issues": {"result": "cancelled"}, "build": {"result": "skipped"}}

    assert _report(client, needs=needs) == "noop"
    assert client.calls == []


def test_labelled_issues_without_marker_are_left_alone() -> None:
    human_issue = {"number": 3, "title": "Publish policy is failing", "body": "Reported by hand.", "labels": []}
    client = FakeClient([human_issue])

    assert _report(client, needs=FAILED_NEEDS) == "created"
    assert "update" not in client.names() and "close" not in client.names()


def test_label_failure_still_creates_the_issue_without_labels() -> None:
    client = FakeClient(label_error=sync_tool.GitHubApiError("GitHub API request failed: HTTP 403 Forbidden", status=403))

    assert _report(client, needs=FAILED_NEEDS) == "created"
    assert client.call("create")["labels"] == []


def test_unlabelled_managed_issue_is_found_again_instead_of_duplicated() -> None:
    client = FakeClient(label_error=sync_tool.GitHubApiError("GitHub API request failed: HTTP 403 Forbidden", status=403))
    _report(client, needs=FAILED_NEEDS)

    action = _report(client, needs=FAILED_NEEDS, run_url=SECOND_RUN_URL, now=LATER)

    assert action == "updated"
    assert client.names().count("create") == 1
    assert client.call("list") == {"creator": "github-actions[bot]"}


def test_failure_without_generation_log_lists_failed_jobs() -> None:
    needs = dict(PASSED_NEEDS, **{"verify-live-pages": {"result": "failure"}})
    client = FakeClient()

    _report(client, needs=needs, log=None)

    body = client.call("create")["body"]
    assert "`verify-live-pages`" in body
    assert "No policy generation error was captured" in body


def test_error_excerpt_prefers_generator_failure_line_and_strips_ansi() -> None:
    log = "\x1b[36;1mpython tools/generate_policy.py\x1b[0m\nnoise\n" + GENERATION_ERROR + "\n"

    assert report_tool.error_excerpt(log) == GENERATION_ERROR


def test_error_excerpt_keeps_bounded_tail_when_no_failure_line() -> None:
    log = "\n".join(f"line {index}" for index in range(200))

    excerpt = report_tool.error_excerpt(log)

    assert excerpt.splitlines()[-1] == "line 199"
    assert len(excerpt.splitlines()) == report_tool.MAX_LOG_TAIL_LINES


def test_error_fence_outgrows_backticks_in_the_log() -> None:
    client = FakeClient()

    _report(client, needs=FAILED_NEEDS, log="Policy generation failed: odd ```` text")

    assert "\n`````text\n" in client.call("create")["body"]


def test_publish_failure_label_is_never_managed_by_source_diagnostics_sync() -> None:
    assert report_tool.ISSUE_LABEL not in sync_tool.MANAGED_LABELS
    assert report_tool.ISSUE_MARKER not in sync_tool.DIAGNOSTIC_ID_COMMENT_PREFIX


def test_main_reads_needs_from_environment_and_tolerates_missing_log(tmp_path) -> None:
    client = FakeClient()
    stdout = io.StringIO()

    exit_code = report_tool.main(
        ["--repository", REPOSITORY, "--run-url", RUN_URL, "--generation-log", str(tmp_path / "missing.log")],
        client=client,
        environ={"NEEDS_JSON": json.dumps(FAILED_NEEDS)},
        stdout=stdout,
        now=NOW,
    )

    assert exit_code == 0
    assert "Publish status report: created" in stdout.getvalue()


def test_main_requires_token_without_injected_client() -> None:
    stderr = io.StringIO()

    exit_code = report_tool.main(
        ["--repository", REPOSITORY, "--run-url", RUN_URL],
        environ={"NEEDS_JSON": json.dumps(FAILED_NEEDS)},
        stderr=stderr,
        now=NOW,
    )

    assert exit_code == 2
    assert "GITHUB_TOKEN" in stderr.getvalue()


def test_main_reports_github_api_errors_as_warning_annotation() -> None:
    class BrokenClient(FakeClient):
        def list_open_issues_by_creator(self, repository: str, *, creator: str) -> list[dict[str, Any]]:
            raise sync_tool.GitHubApiError("GitHub API request failed: HTTP 502 Bad Gateway", status=502)

    stdout = io.StringIO()

    exit_code = report_tool.main(
        ["--repository", REPOSITORY, "--run-url", RUN_URL],
        client=BrokenClient(),
        environ={"NEEDS_JSON": json.dumps(FAILED_NEEDS)},
        stdout=stdout,
        now=NOW,
    )

    assert exit_code == 1
    assert "::warning::Publish failure issue could not be updated" in stdout.getvalue()


class _RecordingRestClient(sync_tool.RestGitHubClient):
    def __init__(self, responses: list[Any]) -> None:
        super().__init__("token")
        self.responses = list(responses)
        self.requests: list[tuple[str, str]] = []
        self.queries: list[dict[str, str]] = []

    def _request(self, method: str, path: str, *, query=None, payload=None) -> dict[str, Any]:
        self.requests.append((method, path))
        self.queries.append(dict(query or {}))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def test_rest_client_ensure_label_creates_missing_label() -> None:
    client = _RecordingRestClient([sync_tool.GitHubApiError("HTTP 404", status=404), {"name": "x"}])

    client.ensure_label(REPOSITORY, name="internals: publish failure", color="b60205", description="d")

    assert client.requests == [
        ("GET", f"/repos/{REPOSITORY}/labels/internals%3A%20publish%20failure"),
        ("POST", f"/repos/{REPOSITORY}/labels"),
    ]


def test_rest_client_ensure_label_keeps_existing_label() -> None:
    client = _RecordingRestClient([{"name": "internals: publish failure"}])

    client.ensure_label(REPOSITORY, name="internals: publish failure", color="b60205", description="d")

    assert [method for method, _ in client.requests] == ["GET"]


def test_rest_client_ensure_label_tolerates_concurrent_creation() -> None:
    client = _RecordingRestClient(
        [sync_tool.GitHubApiError("HTTP 404", status=404), sync_tool.GitHubApiError("HTTP 422", status=422)]
    )

    client.ensure_label(REPOSITORY, name="internals: publish failure", color="b60205", description="d")


def test_rest_client_ensure_label_propagates_other_errors() -> None:
    client = _RecordingRestClient([sync_tool.GitHubApiError("HTTP 403", status=403)])

    with pytest.raises(sync_tool.GitHubApiError):
        client.ensure_label(REPOSITORY, name="internals: publish failure", color="b60205", description="d")


def test_rest_client_lists_open_issues_by_creator_and_skips_pull_requests() -> None:
    page = [{"number": 1, "body": "a"}, {"number": 2, "body": "b", "pull_request": {}}]
    client = _RecordingRestClient([{"items": page}])

    issues = client.list_open_issues_by_creator(REPOSITORY, creator="github-actions[bot]")

    assert [issue["number"] for issue in issues] == [1]
    assert client.requests == [("GET", f"/repos/{REPOSITORY}/issues")]
    assert client.queries[0]["creator"] == "github-actions[bot]"
    assert client.queries[0]["state"] == "open"


def test_main_reports_errors_from_every_generation_log(tmp_path) -> None:
    client = FakeClient()
    preview_log = tmp_path / "policy-generation.log"
    build_log = tmp_path / "build.log"
    preview_log.write_text("Policy generation failed: preview boom\n", encoding="utf-8")
    build_log.write_text("Policy generation failed: signed boom\n", encoding="utf-8")

    exit_code = report_tool.main(
        [
            "--repository", REPOSITORY, "--run-url", RUN_URL,
            "--generation-log", str(preview_log), "--generation-log", str(build_log),
        ],
        client=client,
        environ={"NEEDS_JSON": json.dumps(FAILED_NEEDS)},
        stdout=io.StringIO(),
        now=NOW,
    )

    body = client.call("create")["body"]
    assert exit_code == 0
    assert "preview boom" in body
    assert "signed boom" in body
