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
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from win11_release_guard.config import DEFAULT_POLICY_URL
from win11_release_guard.policy_schema import SOURCE_DIAGNOSTIC_ID_PATTERN_TEXT, is_source_diagnostic_id
from tools.diagnostic_issue_report import write_dry_run_report_output, write_issue_status_output
from tools.diagnostic_issue_text import (
    DIAGNOSTIC_ID_COMMENT_PREFIX,
    DiagnosticIssue,
    LABEL_BY_SEVERITY,
    SyncSummary,
    _diagnostic_from_event,
    _issue_payload,
    _normalized_text,
    comment_body,
    issue_body,
    issue_title,
    stale_comment_body,
)
from tools.github_rest import (
    GitHubApiError,
    GitHubClient,
    RestGitHubClient,
    _issue_number,
)
# Public names this module defined before the v0.6.0 split stay importable from it.
# pylint: disable=unused-import
from tools.diagnostic_issue_text import (
    ATOM_DIAGNOSTIC_ID_PREFIX,
    ATOM_PUBLIC_ID_RE,
    issue_tip_markdown,
)
# pylint: enable=unused-import


DIAGNOSTIC_ID_COMMENT_RE = re.compile(
    r"<!--\s*"
    + re.escape(DIAGNOSTIC_ID_COMMENT_PREFIX)
    + r":\s*("
    + SOURCE_DIAGNOSTIC_ID_PATTERN_TEXT
    + r")\s*-->"
)


REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


LEGACY_NOTICE_LABEL = "internals: notices"


MANAGED_LABELS = (*LABEL_BY_SEVERITY.values(), LEGACY_NOTICE_LABEL)


DEFAULT_CREATE_LIMIT = 10


DEFAULT_REQUEST_DELAY_SECONDS = 1.0


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
