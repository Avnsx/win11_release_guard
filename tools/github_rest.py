"""Minimal GitHub REST client for issue automation, using only the built-in Actions token."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping, Protocol, Sequence


class GitHubClient(Protocol):
    def search_issues(self, repository: str, diagnostic_id: str) -> list[dict[str, Any]]:
        ...

    def list_open_managed_issues(self, repository: str, labels: Sequence[str]) -> list[dict[str, Any]]:
        ...

    def create_issue(self, repository: str, *, title: str, body: str, labels: list[str]) -> dict[str, Any]:
        ...

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
        ...

    def comment_issue(self, repository: str, issue_number: int, *, body: str) -> dict[str, Any]:
        ...

    def close_issue(self, repository: str, issue_number: int, *, state_reason: str = "completed") -> dict[str, Any]:
        ...


class GitHubApiError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class RestGitHubClient:
    def __init__(self, token: str, *, api_url: str = "https://api.github.com") -> None:
        if not token:
            raise ValueError("GitHub token is required.")
        self._token = token
        self._api_url = api_url.rstrip("/")

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{self._api_url}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": "win11_release_guard-source-diagnostics-sync",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise GitHubApiError(
                f"GitHub API request failed: HTTP {exc.code} {exc.reason}: {detail}",
                status=exc.code,
            ) from exc
        except urllib.error.URLError as exc:
            raise GitHubApiError(f"GitHub API request failed: {exc.reason}") from exc
        if not body:
            return {}
        value = json.loads(body)
        return value if isinstance(value, dict) else {"items": value}

    def search_issues(self, repository: str, diagnostic_id: str) -> list[dict[str, Any]]:
        query = f'repo:{repository} is:issue in:body "{diagnostic_id}"'
        payload = self._request("GET", "/search/issues", query={"q": query, "per_page": "20"})
        items = payload.get("items")
        return [dict(item) for item in items] if isinstance(items, list) else []

    def list_open_managed_issues(self, repository: str, labels: Sequence[str]) -> list[dict[str, Any]]:
        issues: dict[int, dict[str, Any]] = {}
        for label in labels:
            for page in range(1, 11):
                payload = self._request(
                    "GET",
                    f"/repos/{repository}/issues",
                    query={
                        "state": "open",
                        "labels": label,
                        "per_page": "100",
                        "page": str(page),
                    },
                )
                items = payload.get("items")
                if not isinstance(items, list) or not items:
                    break
                for item in items:
                    if not isinstance(item, Mapping) or "pull_request" in item:
                        continue
                    number = _issue_number(item)
                    if number is not None:
                        issues[number] = dict(item)
                if len(items) < 100:
                    break
        return list(issues.values())

    def list_open_issues_by_creator(self, repository: str, *, creator: str) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        for page in range(1, 11):
            payload = self._request(
                "GET",
                f"/repos/{repository}/issues",
                query={"state": "open", "creator": creator, "per_page": "100", "page": str(page)},
            )
            items = payload.get("items")
            if not isinstance(items, list) or not items:
                break
            issues.extend(
                dict(item) for item in items if isinstance(item, Mapping) and "pull_request" not in item
            )
            if len(items) < 100:
                break
        return issues

    def create_issue(self, repository: str, *, title: str, body: str, labels: list[str]) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/repos/{repository}/issues",
            payload={"title": title, "body": body, "labels": labels},
        )

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
        return self._request(
            "PATCH",
            f"/repos/{repository}/issues/{issue_number}",
            payload=payload,
        )

    def comment_issue(self, repository: str, issue_number: int, *, body: str) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/repos/{repository}/issues/{issue_number}/comments",
            payload={"body": body},
        )

    def close_issue(self, repository: str, issue_number: int, *, state_reason: str = "completed") -> dict[str, Any]:
        return self._request(
            "PATCH",
            f"/repos/{repository}/issues/{issue_number}",
            payload={"state": "closed", "state_reason": state_reason},
        )

    def ensure_label(self, repository: str, *, name: str, color: str, description: str) -> None:
        """Create the label unless it exists; GitHub does not document creating labels on issue creation."""
        try:
            self._request("GET", f"/repos/{repository}/labels/{urllib.parse.quote(name, safe='')}")
            return
        except GitHubApiError as exc:
            if exc.status != 404:
                raise
        try:
            self._request(
                "POST",
                f"/repos/{repository}/labels",
                payload={"name": name, "color": color, "description": description},
            )
        except GitHubApiError as exc:
            # 422 means another run created the label first.
            if exc.status != 422:
                raise


def _issue_number(issue: Mapping[str, Any]) -> int | None:
    try:
        number = int(issue.get("number"))
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None
