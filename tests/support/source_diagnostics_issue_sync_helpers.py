"""Helpers shared by the test_source_diagnostics_issue_sync test modules."""

from __future__ import annotations

from typing import Any
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
