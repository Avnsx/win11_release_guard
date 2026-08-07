from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence, TextIO

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from win11_release_guard.config import DEFAULT_PAGES_BASE_URL, DEFAULT_POLICY_URL
from win11_release_guard.policy_schema import SOURCE_DIAGNOSTIC_ID_PATTERN_TEXT, is_source_diagnostic_id


DIAGNOSTIC_ID_COMMENT_PREFIX = "wrg-source-diagnostic-id"
DIAGNOSTIC_ID_COMMENT_RE = re.compile(
    r"<!--\s*"
    + re.escape(DIAGNOSTIC_ID_COMMENT_PREFIX)
    + r":\s*("
    + SOURCE_DIAGNOSTIC_ID_PATTERN_TEXT
    + r")\s*-->"
)
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
LEGACY_NOTICE_LABEL = "internals: notices"
LABEL_BY_SEVERITY = {
    "warning": "internals: warning",
    "error": "internals: error",
}
MANAGED_LABELS = (*LABEL_BY_SEVERITY.values(), LEGACY_NOTICE_LABEL)
DEFAULT_CREATE_LIMIT = 10
DEFAULT_REQUEST_DELAY_SECONDS = 1.0
ATOM_DIAGNOSTIC_ID_PREFIX = "wrg-source-diagnostic-v1:uuid:"
ATOM_PUBLIC_ID_RE = re.compile(r"^[1-9][0-9]*$")


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


@dataclass(frozen=True)
class DiagnosticIssue:
    diagnostic_id: str
    severity: str
    kind: str
    title: str
    message: str
    event: Mapping[str, Any]

    @property
    def label(self) -> str:
        return LABEL_BY_SEVERITY[self.severity]


@dataclass
class SyncSummary:
    considered: int = 0
    created: int = 0
    updated: int = 0
    reopened: int = 0
    commented: int = 0
    closed: int = 0
    skipped_closed: int = 0
    skipped_cap: int = 0
    skipped_missing_id: int = 0
    skipped_notices: int = 0
    skipped_unsupported_severity: int = 0
    dry_run_creates: int = 0
    dry_run_updates: int = 0
    dry_run_reopens: int = 0
    dry_run_closes: int = 0
    issue_status: dict[str, dict[str, Any]] = field(default_factory=dict)
    actions: list[dict[str, Any]] = field(default_factory=list)


class GitHubApiError(RuntimeError):
    pass


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
            raise GitHubApiError(f"GitHub API request failed: HTTP {exc.code} {exc.reason}: {detail}") from exc
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


def _normalized_text(value: Any, *, fallback: str = "") -> str:
    if value in (None, ""):
        return fallback
    try:
        text = str(value)
    except Exception:
        return fallback
    text = re.sub(r"\s+", " ", text).strip()
    return text or fallback


def _event_title(kind: str) -> str:
    text = re.sub(r"[_-]+", " ", kind).strip()
    if not text:
        return "Source diagnostic"
    acronyms = {"kb", "oob", "esu", "lcu"}
    return " ".join(part.upper() if part.lower() in acronyms else part.capitalize() for part in text.split())


def _diagnostic_from_event(event: Mapping[str, Any]) -> DiagnosticIssue | None:
    diagnostic_id = _normalized_text(event.get("id"))
    if not is_source_diagnostic_id(diagnostic_id):
        return None
    severity = _normalized_text(event.get("severity")).lower()
    if severity not in LABEL_BY_SEVERITY:
        return None
    kind = _normalized_text(event.get("kind"), fallback="source_diagnostic")
    title = _normalized_text(event.get("title"), fallback=_event_title(kind))
    message = _normalized_text(event.get("message"), fallback=title)
    return DiagnosticIssue(
        diagnostic_id=diagnostic_id,
        severity=severity,
        kind=kind,
        title=title,
        message=message,
        event=dict(event),
    )


def _policy_events(policy: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    source_diagnostics = policy.get("source_diagnostics")
    if not isinstance(source_diagnostics, Mapping):
        return []
    events = source_diagnostics.get("events")
    if not isinstance(events, list):
        return []
    return [event for event in events if isinstance(event, Mapping)]


def diagnostics_from_policy(
    policy: Mapping[str, Any],
    *,
    include_notices: bool = False,
    stdout: TextIO | None = None,
) -> list[DiagnosticIssue]:
    # Source Diagnostic ``notice`` events are dashboard-only and must never become
    # GitHub Issues (AGENTS.md). ``include_notices`` is retained only for CLI
    # backward compatibility and is intentionally inert here: notices are always
    # skipped below regardless of its value, so no caller can opt notices into sync.
    del include_notices
    diagnostics: list[DiagnosticIssue] = []
    seen_ids: set[str] = set()
    for event in _policy_events(policy):
        severity = _normalized_text(event.get("severity")).lower()
        if severity == "notice":
            continue
        diagnostic = _diagnostic_from_event(event)
        if diagnostic is None:
            if stdout is not None:
                print("Skipping source diagnostic without a valid deterministic ID.", file=stdout)
            continue
        if diagnostic.diagnostic_id in seen_ids:
            continue
        seen_ids.add(diagnostic.diagnostic_id)
        diagnostics.append(diagnostic)
    return diagnostics


def _count_sync_skipped_notices(events: Sequence[Mapping[str, Any]]) -> int:
    return sum(
        1
        for event in events
        if _normalized_text(event.get("severity")).lower() == "notice"
        and is_source_diagnostic_id(_normalized_text(event.get("id")))
    )


def _load_policy_from_file(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Policy JSON must be an object.")
    return value


def _load_policy_from_url(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "win11_release_guard-source-diagnostics-sync"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Policy JSON must be an object.")
    return value


def load_policy(*, policy_file: Path | None = None, policy_url: str | None = None) -> dict[str, Any]:
    if policy_file is not None:
        return _load_policy_from_file(policy_file)
    return _load_policy_from_url(policy_url or DEFAULT_POLICY_URL)


def _atom_public_id_from_diagnostic_id(diagnostic_id: str) -> str | None:
    if not is_source_diagnostic_id(diagnostic_id):
        return None
    marker = ";id="
    if not diagnostic_id.startswith(ATOM_DIAGNOSTIC_ID_PREFIX) or marker not in diagnostic_id:
        return None
    public_id = diagnostic_id.rsplit(marker, 1)[1]
    return public_id if ATOM_PUBLIC_ID_RE.fullmatch(public_id) else None


def _atom_public_id_from_event(event: Mapping[str, Any]) -> str | None:
    for key in ("atom_support_article_id", "support_article_id"):
        public_id = _normalized_text(event.get(key))
        if ATOM_PUBLIC_ID_RE.fullmatch(public_id):
            return public_id
    return None


def _diagnostic_atom_public_id(diagnostic: DiagnosticIssue) -> str | None:
    return _atom_public_id_from_diagnostic_id(diagnostic.diagnostic_id) or _atom_public_id_from_event(
        diagnostic.event
    )


def _diagnostic_public_id_suffix(diagnostic: DiagnosticIssue) -> str:
    public_id = _diagnostic_atom_public_id(diagnostic)
    if public_id is None:
        return ""
    suffix = f" [id={public_id}]"
    return suffix if len(suffix) < 220 else ""


def issue_title(diagnostic: DiagnosticIssue) -> str:
    suffix = _diagnostic_public_id_suffix(diagnostic)
    title = f"[Source diagnostics][{diagnostic.severity}] {diagnostic.title}"
    limit = 220 - len(suffix)
    if len(title) > limit:
        title = title[: max(0, limit - 3)].rstrip(" .:-") + "..."
    return title + suffix


def _wiki_url(page: str, fragment: str | None = None) -> str:
    page_slug = page.strip("/")
    url = f"{DEFAULT_PAGES_BASE_URL}/wiki/{page_slug}/"
    return f"{url}#{fragment.strip('#')}" if fragment else url


def _diagnostic_issue_tip(diagnostic: DiagnosticIssue) -> tuple[str, str]:
    kind = diagnostic.kind.strip().lower()
    severity = diagnostic.severity.strip().lower()
    affects_required_baseline = bool(diagnostic.event.get("affects_required_baseline"))
    affects_broad_target = bool(diagnostic.event.get("affects_broad_target"))

    if kind == "atom_newer_than_release_history":
        if affects_required_baseline:
            return (
                "Servicing index data can surface a new broad-target, non-preview build before "
                "Release Health release history catches up. Verify the KB/build against "
                "Microsoft source tables and keep WUA as read-only local context; do not "
                "promote a required baseline from display labels alone.",
                _wiki_url("Source-Diagnostics", "common-issues"),
            )
        return (
            "Servicing index drift outside the required baseline is usually preview, out-of-band, "
            "or non-target context. Keep the row visible for source awareness, but only "
            "treat it as release-policy work after confirming it affects the broad fleet target.",
            _wiki_url("Source-Diagnostics", "common-issues"),
        )
    if kind == "current_versions_lag_release_history":
        return (
            "Release History can move ahead of the Current Versions table during Microsoft "
            "publication lag. Compare both public tables before changing parser behavior, and "
            "preserve the build-first policy model when future Windows releases add new rows.",
            _wiki_url("Source-Diagnostics", "common-issues"),
        )
    if kind in {
        "atom_feed_missing",
        "atom_feed_parse_failed",
        "atom_feed_no_usable_entries",
        "atom_diagnostics_unavailable",
        "servicing_toc_missing",
        "servicing_toc_parse_failed",
        "servicing_toc_no_usable_entries",
    }:
        return (
            "Servicing index enrichment is unavailable or unusable for this run. Release Health "
            "remains the primary policy source, but preview/OOB classification and drift context "
            "may be incomplete until the public servicing index or parser path is healthy again.",
            _wiki_url("Source-Diagnostics", "diagnostic-sources"),
        )
    if kind == "source_drift_unresolved_after_24h":
        return (
            "Unresolved source drift older than 24 hours points at automation freshness or "
            "upstream publication lag. Check the publish workflow and source timestamps before "
            "trusting the feed as operationally current.",
            _wiki_url("Anti-Static-Freshness"),
        )
    if severity == "error":
        return (
            "A source diagnostic error is publish-blocking because the generator could not "
            "derive policy safely. Fix the source/parser contract and rerun the focused tests "
            "instead of bypassing the gate.",
            _wiki_url("Source-Diagnostics", "publish-gate"),
        )
    if affects_broad_target:
        return (
            "This warning touches the current broad-fleet target. Verify the source evidence "
            "and affected build fields before changing the signed policy feed or release "
            "targeting assumptions.",
            _wiki_url("Policy-Feed-and-Trust-Model"),
        )
    return (
        "This warning is source-health context, not a runtime compliance verdict. Use the "
        "deterministic ID and fields above to compare source data across runs before changing "
        "policy generation logic.",
        _wiki_url("Source-Diagnostics"),
    )


def issue_tip_markdown(diagnostic: DiagnosticIssue) -> str:
    message, url = _diagnostic_issue_tip(diagnostic)
    return (
        "> [!TIP]\n"
        f"> {message}\n"
        f"> See [follow-up documentation]({url})."
    )


def issue_body(diagnostic: DiagnosticIssue) -> str:
    lines = [
        f"<!-- {DIAGNOSTIC_ID_COMMENT_PREFIX}: {diagnostic.diagnostic_id} -->",
        f"Source diagnostic ID: `{diagnostic.diagnostic_id}`",
        "",
        f"Severity: `{diagnostic.severity}`",
        f"Label: `{diagnostic.label}`",
        f"Kind: `{diagnostic.kind}`",
        f"Title: {diagnostic.title}",
        "",
        "Message:",
        diagnostic.message,
    ]
    for field in ("release", "build_family", "build", "kb_article"):
        value = diagnostic.event.get(field)
        if value not in (None, ""):
            lines.append(f"{field}: `{value}`")
    for field in ("affects_broad_target", "affects_required_baseline"):
        value = diagnostic.event.get(field)
        if isinstance(value, bool):
            lines.append(f"{field}: `{str(value).lower()}`")
    lines.extend(("", issue_tip_markdown(diagnostic)))
    return "\n".join(lines).rstrip() + "\n"


def _issue_payload(diagnostic: DiagnosticIssue) -> dict[str, Any]:
    return {
        "title": issue_title(diagnostic),
        "body": issue_body(diagnostic),
        "labels": [diagnostic.label],
    }


def comment_body(diagnostic: DiagnosticIssue) -> str:
    return (
        f"Source diagnostic `{diagnostic.diagnostic_id}` is still present in the latest sync run.\n\n"
        f"Current severity: `{diagnostic.severity}`\n\n"
        f"Message: {diagnostic.message}\n"
    )


def stale_comment_body(diagnostic_id: str) -> str:
    return (
        f"Source diagnostic `{diagnostic_id}` is no longer present in the latest sync run.\n\n"
        "Closing this managed issue because the deterministic diagnostic ID disappeared from "
        "the public policy source diagnostics."
    )


def _issue_number(issue: Mapping[str, Any]) -> int | None:
    try:
        number = int(issue.get("number"))
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _issue_label_names(issue: Mapping[str, Any]) -> set[str]:
    labels = issue.get("labels")
    if not isinstance(labels, Sequence) or isinstance(labels, (str, bytes)):
        return set()
    names: set[str] = set()
    for label in labels:
        if isinstance(label, Mapping):
            value = label.get("name")
        else:
            value = label
        text = _normalized_text(value)
        if text:
            names.add(text)
    return names


def _normalized_issue_body(value: Any) -> str:
    if value in (None, ""):
        return ""
    return str(value).replace("\r\n", "\n").replace("\r", "\n")


def _issue_matches_payload(issue: Mapping[str, Any], payload: Mapping[str, Any]) -> bool:
    return (
        str(issue.get("title") or "") == str(payload.get("title") or "")
        and _normalized_issue_body(issue.get("body")) == _normalized_issue_body(payload.get("body"))
        and _issue_label_names(issue) == set(payload.get("labels") or [])
    )


def _issue_diagnostic_id(issue: Mapping[str, Any]) -> str | None:
    value = issue.get("body")
    if value in (None, ""):
        return None
    matches = DIAGNOSTIC_ID_COMMENT_RE.findall(str(value))
    if len(matches) != 1:
        return None
    diagnostic_id = matches[0]
    return diagnostic_id if is_source_diagnostic_id(diagnostic_id) else None


def _issue_status_record(repository: str, number: int, *, state: str = "open") -> dict[str, Any]:
    if not REPOSITORY_RE.fullmatch(repository):
        raise ValueError("Repository must be in owner/name form.")
    return {
        "number": int(number),
        "state": state,
        "url": f"https://github.com/{repository}/issues/{int(number)}",
    }


def _summary_action(
    action: str,
    diagnostic_id: str,
    *,
    diagnostic: DiagnosticIssue | None = None,
    issue_number: int | None = None,
    state: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "action": action,
        "diagnostic_id": diagnostic_id,
    }
    if diagnostic is not None:
        record.update(
            {
                "severity": diagnostic.severity,
                "label": diagnostic.label,
                "kind": diagnostic.kind,
                "title": diagnostic.title,
            }
        )
    if issue_number is not None:
        record["issue_number"] = int(issue_number)
    if state:
        record["state"] = state
    if reason:
        record["reason"] = reason
    return record


def _matching_issue(
    items: Sequence[Mapping[str, Any]],
    state: str,
    diagnostic_id: str,
) -> Mapping[str, Any] | None:
    for item in items:
        if str(item.get("state") or "").lower() == state and _issue_diagnostic_id(item) == diagnostic_id:
            return item
    return None


def sync_diagnostics(
    diagnostics: Sequence[DiagnosticIssue],
    *,
    repository: str,
    client: GitHubClient | None,
    dry_run: bool = False,
    create_limit: int = DEFAULT_CREATE_LIMIT,
    request_delay_seconds: float = DEFAULT_REQUEST_DELAY_SECONDS,
    reopen_closed: bool = True,
    close_stale: bool = True,
    stdout: TextIO = sys.stdout,
) -> SyncSummary:
    if create_limit < 0:
        raise ValueError("create_limit must be non-negative.")
    if not REPOSITORY_RE.fullmatch(repository):
        raise ValueError("repository must be in owner/name form.")
    summary = SyncSummary(considered=len(diagnostics))
    created_this_run = 0
    active_ids = {diagnostic.diagnostic_id for diagnostic in diagnostics}
    open_label_issues: list[dict[str, Any]] | None = None

    def open_managed_issues_by_label() -> list[dict[str, Any]]:
        nonlocal open_label_issues
        if client is None:
            return []
        if open_label_issues is None:
            open_label_issues = client.list_open_managed_issues(repository, MANAGED_LABELS)
        return open_label_issues

    for diagnostic in diagnostics:
        matches = client.search_issues(repository, diagnostic.diagnostic_id) if client is not None else []
        open_issue = _matching_issue(matches, "open", diagnostic.diagnostic_id)
        if open_issue is None:
            open_issue = _matching_issue(open_managed_issues_by_label(), "open", diagnostic.diagnostic_id)
        closed_issue = _matching_issue(matches, "closed", diagnostic.diagnostic_id)
        if open_issue is not None:
            number = _issue_number(open_issue)
            if number is None:
                continue
            payload = _issue_payload(diagnostic)
            if _issue_matches_payload(open_issue, payload):
                summary.issue_status[diagnostic.diagnostic_id] = _issue_status_record(repository, number)
                summary.actions.append(
                    _summary_action("current", diagnostic.diagnostic_id, diagnostic=diagnostic, issue_number=number)
                )
                print(f"Open issue #{number} for {diagnostic.diagnostic_id} is already current.", file=stdout)
                continue
            if dry_run:
                summary.dry_run_updates += 1
                summary.actions.append(
                    _summary_action("update", diagnostic.diagnostic_id, diagnostic=diagnostic, issue_number=number)
                )
                print(f"Would update open issue #{number} for {diagnostic.diagnostic_id}.", file=stdout)
                continue
            if client is None:
                raise GitHubApiError("GitHub client is required to update issues.")
            client.update_issue(
                repository,
                number,
                title=str(payload["title"]),
                body=str(payload["body"]),
                labels=list(payload["labels"]),
            )
            if request_delay_seconds:
                time.sleep(request_delay_seconds)
            summary.updated += 1
            summary.issue_status[diagnostic.diagnostic_id] = _issue_status_record(repository, number)
            summary.actions.append(
                _summary_action("updated", diagnostic.diagnostic_id, diagnostic=diagnostic, issue_number=number)
            )
            print(f"Updated open issue #{number} for {diagnostic.diagnostic_id}.", file=stdout)
            continue
        if closed_issue is not None:
            number = _issue_number(closed_issue)
            if number is None:
                continue
            if not reopen_closed:
                summary.skipped_closed += 1
                summary.actions.append(
                    _summary_action(
                        "skipped_closed",
                        diagnostic.diagnostic_id,
                        diagnostic=diagnostic,
                        issue_number=number,
                        reason="reopen_disabled",
                    )
                )
                print(
                    f"Skipping closed issue #{number} for {diagnostic.diagnostic_id}; automatic reopen is disabled.",
                    file=stdout,
                )
                continue
            if dry_run:
                summary.dry_run_reopens += 1
                summary.actions.append(
                    _summary_action("reopen", diagnostic.diagnostic_id, diagnostic=diagnostic, issue_number=number)
                )
                print(f"Would reopen closed issue #{number} for {diagnostic.diagnostic_id}.", file=stdout)
                continue
            if client is None:
                raise GitHubApiError("GitHub client is required to reopen issues.")
            client.update_issue(
                repository,
                number,
                title=issue_title(diagnostic),
                body=issue_body(diagnostic),
                labels=[diagnostic.label],
                state="open",
            )
            if request_delay_seconds:
                time.sleep(request_delay_seconds)
            client.comment_issue(repository, number, body=comment_body(diagnostic))
            if request_delay_seconds:
                time.sleep(request_delay_seconds)
            summary.reopened += 1
            summary.commented += 1
            summary.issue_status[diagnostic.diagnostic_id] = _issue_status_record(repository, number)
            summary.actions.append(
                _summary_action("reopened", diagnostic.diagnostic_id, diagnostic=diagnostic, issue_number=number)
            )
            print(f"Reopened issue #{number} for {diagnostic.diagnostic_id}.", file=stdout)
            continue
        if created_this_run >= create_limit:
            summary.skipped_cap += 1
            summary.actions.append(
                _summary_action(
                    "skipped_create",
                    diagnostic.diagnostic_id,
                    diagnostic=diagnostic,
                    reason="create_limit_reached",
                )
            )
            print(f"Skipping {diagnostic.diagnostic_id}; issue creation cap reached.", file=stdout)
            continue
        if dry_run:
            summary.dry_run_creates += 1
            created_this_run += 1
            summary.actions.append(_summary_action("create", diagnostic.diagnostic_id, diagnostic=diagnostic))
            print(f"Would create issue for {diagnostic.diagnostic_id}.", file=stdout)
            continue
        if client is None:
            raise GitHubApiError("GitHub client is required to create issues.")
        created = client.create_issue(
            repository,
            title=issue_title(diagnostic),
            body=issue_body(diagnostic),
            labels=[diagnostic.label],
        )
        created_this_run += 1
        summary.created += 1
        number = _issue_number(created)
        suffix = f" #{number}" if number is not None else ""
        if number is not None:
            summary.issue_status[diagnostic.diagnostic_id] = _issue_status_record(repository, number)
        summary.actions.append(
            _summary_action("created", diagnostic.diagnostic_id, diagnostic=diagnostic, issue_number=number)
        )
        print(f"Created issue{suffix} for {diagnostic.diagnostic_id}.", file=stdout)
        if request_delay_seconds:
            time.sleep(request_delay_seconds)
    if close_stale and client is not None:
        stale_seen: set[int] = set()
        for issue in open_managed_issues_by_label():
            number = _issue_number(issue)
            if number is None or number in stale_seen:
                continue
            stale_seen.add(number)
            diagnostic_id = _issue_diagnostic_id(issue)
            if diagnostic_id is None or diagnostic_id in active_ids:
                continue
            if dry_run:
                summary.dry_run_closes += 1
                summary.actions.append(
                    _summary_action("close", diagnostic_id, issue_number=number, state="closed", reason="stale")
                )
                print(f"Would close stale issue #{number} for {diagnostic_id}.", file=stdout)
                continue
            client.comment_issue(repository, number, body=stale_comment_body(diagnostic_id))
            if request_delay_seconds:
                time.sleep(request_delay_seconds)
            client.close_issue(repository, number, state_reason="completed")
            if request_delay_seconds:
                time.sleep(request_delay_seconds)
            summary.closed += 1
            summary.commented += 1
            summary.actions.append(
                _summary_action("closed", diagnostic_id, issue_number=number, state="closed", reason="stale")
            )
            print(f"Closed stale issue #{number} for {diagnostic_id}.", file=stdout)
    return summary


def _repository_from_env(environ: Mapping[str, str]) -> str:
    repository = environ.get("GITHUB_REPOSITORY", "").strip()
    if not repository or "/" not in repository:
        raise ValueError("Repository must be supplied with --repository or GITHUB_REPOSITORY.")
    return repository


def _client_from_env(environ: Mapping[str, str], *, dry_run: bool) -> RestGitHubClient | None:
    token = environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        if dry_run:
            return None
        raise ValueError("GITHUB_TOKEN is required unless --dry-run is used.")
    return RestGitHubClient(token)


def _print_summary(summary: SyncSummary, *, stdout: TextIO) -> None:
    print(
        "Source diagnostics issue sync summary: "
        f"considered={summary.considered} "
        f"created={summary.created} "
        f"updated={summary.updated} "
        f"reopened={summary.reopened} "
        f"commented={summary.commented} "
        f"closed={summary.closed} "
        f"skipped_closed={summary.skipped_closed} "
        f"skipped_cap={summary.skipped_cap} "
        f"skipped_notices={summary.skipped_notices} "
        f"dry_run_creates={summary.dry_run_creates} "
        f"dry_run_updates={summary.dry_run_updates}",
        f"dry_run_reopens={summary.dry_run_reopens} "
        f"dry_run_closes={summary.dry_run_closes}",
        file=stdout,
    )


def _summary_counts(summary: SyncSummary) -> dict[str, int]:
    return {
        "considered": summary.considered,
        "created": summary.created,
        "updated": summary.updated,
        "reopened": summary.reopened,
        "commented": summary.commented,
        "closed": summary.closed,
        "skipped_closed": summary.skipped_closed,
        "skipped_cap": summary.skipped_cap,
        "skipped_missing_id": summary.skipped_missing_id,
        "skipped_notices": summary.skipped_notices,
        "skipped_unsupported_severity": summary.skipped_unsupported_severity,
        "dry_run_creates": summary.dry_run_creates,
        "dry_run_updates": summary.dry_run_updates,
        "dry_run_reopens": summary.dry_run_reopens,
        "dry_run_closes": summary.dry_run_closes,
    }


def _diagnostic_report_item(diagnostic: DiagnosticIssue) -> dict[str, str]:
    return {
        "diagnostic_id": diagnostic.diagnostic_id,
        "severity": diagnostic.severity,
        "label": diagnostic.label,
        "kind": diagnostic.kind,
        "title": diagnostic.title,
    }


def _dry_run_report_payload(
    *,
    repository: str,
    diagnostics: Sequence[DiagnosticIssue],
    summary: SyncSummary,
    include_notices: bool,
) -> dict[str, Any]:
    return {
        "dry_run": True,
        "repository": repository,
        "include_notices": bool(include_notices),
        "diagnostics": [_diagnostic_report_item(diagnostic) for diagnostic in diagnostics],
        "summary": _summary_counts(summary),
        "actions": [dict(action) for action in summary.actions],
        "issue_status": dict(summary.issue_status),
    }


def _markdown_cell(value: Any) -> str:
    text = _normalized_text(value, fallback="-")
    return text.replace("|", "\\|")


def _dry_run_report_markdown(payload: Mapping[str, Any]) -> str:
    summary = payload.get("summary") if isinstance(payload.get("summary"), Mapping) else {}
    lines = [
        "# Source Diagnostics Issue Sync Dry Run",
        "",
        f"- Repository: `{_markdown_cell(payload.get('repository'))}`",
        f"- Include notices: `{str(bool(payload.get('include_notices'))).lower()}`",
        f"- Diagnostics considered: `{_markdown_cell(summary.get('considered'))}`",
        f"- Planned creates: `{_markdown_cell(summary.get('dry_run_creates'))}`",
        f"- Planned updates: `{_markdown_cell(summary.get('dry_run_updates'))}`",
        f"- Planned reopens: `{_markdown_cell(summary.get('dry_run_reopens'))}`",
        f"- Planned stale closes: `{_markdown_cell(summary.get('dry_run_closes'))}`",
        "",
        "| Action | Diagnostic ID | Severity | Label | Issue | Reason |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    actions = payload.get("actions")
    if isinstance(actions, list) and actions:
        for action in actions:
            if not isinstance(action, Mapping):
                continue
            issue = action.get("issue_number")
            lines.append(
                "| "
                + " | ".join(
                    (
                        _markdown_cell(action.get("action")),
                        _markdown_cell(action.get("diagnostic_id")),
                        _markdown_cell(action.get("severity")),
                        _markdown_cell(action.get("label")),
                        _markdown_cell(f"#{issue}" if issue is not None else "-"),
                        _markdown_cell(action.get("reason")),
                    )
                )
                + " |"
            )
    else:
        lines.append("| none | - | - | - | - | - |")
    return "\n".join(lines).rstrip() + "\n"


def write_dry_run_report_output(
    path: Path,
    *,
    report_format: str,
    repository: str,
    diagnostics: Sequence[DiagnosticIssue],
    summary: SyncSummary,
    include_notices: bool,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _dry_run_report_payload(
        repository=repository,
        diagnostics=diagnostics,
        summary=summary,
        include_notices=include_notices,
    )
    if report_format == "json":
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    elif report_format == "markdown":
        text = _dry_run_report_markdown(payload)
    else:
        raise ValueError("dry-run report format must be json or markdown.")
    path.write_text(text, encoding="utf-8", newline="\n")


def write_issue_status_output(path: Path, issue_status: Mapping[str, Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"issue_status": dict(issue_status)}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def main(
    argv: Sequence[str] | None = None,
    *,
    client: GitHubClient | None = None,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    parser = argparse.ArgumentParser(description="Sync source diagnostics to GitHub Issues.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--policy-file", type=Path, help="Read source diagnostics from a local policy JSON file.")
    source.add_argument("--policy-url", default=None, help="Read source diagnostics from a public policy JSON URL.")
    parser.add_argument("--repository", help="GitHub repository in owner/name form. Defaults to GITHUB_REPOSITORY.")
    notice_group = parser.add_mutually_exclusive_group()
    notice_group.add_argument(
        "--include-notices",
        action="store_true",
        help="Deprecated no-op; notice diagnostics are dashboard-only and are not synced.",
    )
    notice_group.add_argument(
        "--exclude-notices",
        action="store_true",
        help="Deprecated no-op; notice diagnostics are always excluded from issue sync.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print planned changes without mutating GitHub Issues.")
    parser.add_argument("--create-limit", type=int, default=DEFAULT_CREATE_LIMIT, help="Maximum new issues per run.")
    parser.add_argument(
        "--issue-status-output",
        type=Path,
        default=None,
        help="Write static issue metadata for generated Pages diagnostics links.",
    )
    parser.add_argument(
        "--dry-run-report-output",
        type=Path,
        default=None,
        help="Write a no-mutation dry-run report artifact. Requires --dry-run.",
    )
    parser.add_argument(
        "--dry-run-report-format",
        choices=("json", "markdown"),
        default="json",
        help="Format for --dry-run-report-output.",
    )
    parser.add_argument(
        "--no-reopen-closed",
        action="store_true",
        help="Do not reopen matching closed issues when a diagnostic is still present.",
    )
    parser.add_argument(
        "--no-close-stale",
        action="store_true",
        help="Do not close open managed issues whose diagnostic ID is absent from the current policy.",
    )
    parser.add_argument(
        "--request-delay-seconds",
        type=float,
        default=DEFAULT_REQUEST_DELAY_SECONDS,
        help="Delay after issue mutation requests to reduce write burst rate.",
    )
    args = parser.parse_args(argv)

    env = dict(os.environ if environ is None else environ)
    try:
        if args.dry_run_report_output is not None and not args.dry_run:
            raise ValueError("--dry-run-report-output requires --dry-run.")
        repository = args.repository or _repository_from_env(env)
        policy = load_policy(policy_file=args.policy_file, policy_url=args.policy_url)
        raw_events = _policy_events(policy)
        include_notices = False
        if args.include_notices:
            print(
                "Notice diagnostics are dashboard-only; --include-notices is ignored for GitHub Issue sync.",
                file=stdout,
            )
        diagnostics = diagnostics_from_policy(policy)
        skipped_notices = _count_sync_skipped_notices(raw_events)
        if skipped_notices:
            print(
                f"Skipping {skipped_notices} notice diagnostic(s); notices are dashboard-only and not synced to GitHub Issues.",
                file=stdout,
            )
        github_client = client if client is not None else _client_from_env(env, dry_run=args.dry_run)
        summary = sync_diagnostics(
            diagnostics,
            repository=repository,
            client=github_client,
            dry_run=args.dry_run,
            create_limit=args.create_limit,
            request_delay_seconds=max(0.0, args.request_delay_seconds),
            reopen_closed=not args.no_reopen_closed,
            close_stale=not args.no_close_stale,
            stdout=stdout,
        )
        summary.skipped_notices = skipped_notices
        if args.issue_status_output is not None:
            write_issue_status_output(args.issue_status_output, summary.issue_status)
        if args.dry_run_report_output is not None:
            write_dry_run_report_output(
                args.dry_run_report_output,
                report_format=args.dry_run_report_format,
                repository=repository,
                diagnostics=diagnostics,
                summary=summary,
                include_notices=include_notices,
            )
        _print_summary(summary, stdout=stdout)
    except Exception as exc:
        print(f"Source diagnostics issue sync failed: {exc}", file=stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
