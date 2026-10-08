"""Open, update, or close the managed "Publish policy is failing" issue.

This runs as the last job of ``.github/workflows/publish-policy.yml``. Source
Diagnostic issue sync only reports drift inside a policy that was generated, so a
run that fails before or after generation would otherwise leave no trace outside
the Actions log. The issue is found by its creator and a body marker, never by
label, so it is not duplicated when the label cannot be created. Its label is
deliberately outside the Source Diagnostic labels, so issue sync never touches it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence, TextIO

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.sync_source_diagnostics_issues import GitHubApiError, RestGitHubClient
from win11_release_guard.config import DEFAULT_POLICY_WARNING_AGE_DAYS

ISSUE_TITLE = "Publish policy is failing"
ISSUE_LABEL = "internals: publish failure"
ISSUE_MARKER = "<!-- wrg-publish-policy-failure -->"
ISSUE_CREATOR = "github-actions[bot]"
LABEL_COLOR = "b60205"
LABEL_DESCRIPTION = "Managed by publish-policy.yml: the signed policy feed is not being refreshed."
GENERATION_FAILURE_PREFIX = "Policy generation failed:"
MAX_LOG_TAIL_LINES = 40
MAX_EXCERPT_CHARS = 4000

_STATE_RE = re.compile(r"<!-- wrg-publish-policy-failure-state (\{.*?\}) -->")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class PublishIssueClient(Protocol):
    def list_open_issues_by_creator(self, repository: str, *, creator: str) -> list[dict[str, Any]]:
        ...

    def ensure_label(self, repository: str, *, name: str, color: str, description: str) -> None:
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


def _job_results(needs: Mapping[str, Any]) -> dict[str, str]:
    results: dict[str, str] = {}
    for name, job in needs.items():
        result = job.get("result") if isinstance(job, Mapping) else None
        results[str(name)] = str(result or "")
    return results


def outcome_from_needs(needs: Mapping[str, Any]) -> str:
    """Return ``failure``, ``success``, or ``inconclusive`` for the run's upstream jobs."""

    results = list(_job_results(needs).values())
    if not results:
        return "inconclusive"
    if "failure" in results:
        return "failure"
    if all(result == "success" for result in results):
        return "success"
    return "inconclusive"


def failed_jobs(needs: Mapping[str, Any]) -> list[str]:
    return [name for name, result in _job_results(needs).items() if result == "failure"]


def error_excerpt(log_text: str | None) -> str:
    lines = [_ANSI_RE.sub("", line).rstrip() for line in str(log_text or "").splitlines()]
    lines = [line for line in lines if line.strip()]
    failure_lines = [line for line in lines if GENERATION_FAILURE_PREFIX in line]
    selected = failure_lines[-3:] if failure_lines else lines[-MAX_LOG_TAIL_LINES:]
    excerpt = "\n".join(selected).strip()
    return excerpt[-MAX_EXCERPT_CHARS:]


def _fenced(text: str) -> str:
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _state_from_body(body: str) -> dict[str, Any]:
    match = _STATE_RE.search(body)
    if not match:
        return {}
    try:
        state = json.loads(match.group(1))
    except ValueError:
        return {}
    return state if isinstance(state, dict) else {}


def _issue_body(state: Mapping[str, Any], *, jobs: Sequence[str], excerpt: str) -> str:
    state_json = json.dumps(dict(state), sort_keys=True).replace("-->", "--\\u003e")
    jobs_text = ", ".join(f"`{job}`" for job in jobs) or "not reported"
    error_text = (
        _fenced(excerpt)
        if excerpt
        else "No policy generation error was captured; open the latest failed run for the job log."
    )
    return "\n".join(
        [
            ISSUE_MARKER,
            f"<!-- wrg-publish-policy-failure-state {state_json} -->",
            "The **Publish policy** workflow is failing, so the signed policy feed and the GitHub Pages "
            "dashboard are not being refreshed. Clients keep using the last published feed and report a "
            f"freshness warning once it is {DEFAULT_POLICY_WARNING_AGE_DAYS} days old.",
            "",
            "| | |",
            "| --- | --- |",
            f"| First failed run | [{state['first_failed_at_utc']}]({state['first_failed_run_url']}) |",
            f"| Latest failed run | [{state['latest_failed_at_utc']}]({state['latest_failed_run_url']}) |",
            f"| Consecutive failed runs | {state['failure_count']} |",
            f"| Failed jobs | {jobs_text} |",
            "",
            "### Error",
            "",
            error_text,
            "",
            "This issue is managed by the `report-publish-status` job in `.github/workflows/publish-policy.yml`. "
            "It is updated on every failed run and closes itself after the next successful run. Closing it by "
            "hand while runs still fail opens a new issue on the next failed run.",
            "",
        ]
    )


def _issue_number(issue: Mapping[str, Any]) -> int | None:
    number = issue.get("number")
    return number if isinstance(number, int) and not isinstance(number, bool) else None


def _open_managed_issue(client: PublishIssueClient, repository: str) -> dict[str, Any] | None:
    managed = [
        issue
        for issue in client.list_open_issues_by_creator(repository, creator=ISSUE_CREATOR)
        if ISSUE_MARKER in str(issue.get("body") or "") and _issue_number(issue) is not None
    ]
    return min(managed, key=lambda issue: _issue_number(issue) or 0) if managed else None


def report_publish_status(
    client: PublishIssueClient,
    *,
    repository: str,
    needs: Mapping[str, Any],
    run_url: str,
    generation_log: str | None,
    now: datetime,
) -> str:
    """Apply this run's outcome to the managed issue and return the action taken."""

    outcome = outcome_from_needs(needs)
    if outcome == "inconclusive":
        return "noop"
    issue = _open_managed_issue(client, repository)
    if outcome == "success":
        if issue is None:
            return "noop"
        number = _issue_number(issue)
        count = _state_from_body(str(issue.get("body") or "")).get("failure_count")
        failures = f" after {count} failed run{'s' if count != 1 else ''}" if isinstance(count, int) else ""
        client.comment_issue(
            repository,
            number,
            body=f"Publishing succeeded again in [this run]({run_url}){failures}. Closing.",
        )
        client.close_issue(repository, number, state_reason="completed")
        return "closed"

    jobs = failed_jobs(needs)
    excerpt = error_excerpt(generation_log)
    signature = excerpt.splitlines()[0] if excerpt else "failed jobs: " + ", ".join(jobs)
    latest = {"latest_failed_at_utc": _timestamp(now), "latest_failed_run_url": run_url, "error_signature": signature}
    if issue is None:
        state = {"first_failed_at_utc": _timestamp(now), "first_failed_run_url": run_url, "failure_count": 1, **latest}
        labels = [ISSUE_LABEL]
        try:
            client.ensure_label(repository, name=ISSUE_LABEL, color=LABEL_COLOR, description=LABEL_DESCRIPTION)
        except GitHubApiError:
            labels = []
        client.create_issue(
            repository,
            title=ISSUE_TITLE,
            body=_issue_body(state, jobs=jobs, excerpt=excerpt),
            labels=labels,
        )
        return "created"

    number = _issue_number(issue)
    previous = _state_from_body(str(issue.get("body") or ""))
    previous_count = previous.get("failure_count")
    state = {
        "first_failed_at_utc": previous.get("first_failed_at_utc") or _timestamp(now),
        "first_failed_run_url": previous.get("first_failed_run_url") or run_url,
        "failure_count": (previous_count if isinstance(previous_count, int) else 0) + 1,
        **latest,
    }
    action = "updated"
    if previous.get("error_signature") != signature:
        error_text = _fenced(excerpt) if excerpt else f"Failed jobs: {', '.join(jobs) or 'not reported'}."
        client.comment_issue(repository, number, body=f"The failure changed in [this run]({run_url}):\n\n{error_text}")
        action = "commented"
    labels = [
        str(label.get("name"))
        for label in issue.get("labels") or []
        if isinstance(label, Mapping) and label.get("name")
    ]
    client.update_issue(
        repository,
        number,
        title=ISSUE_TITLE,
        body=_issue_body(state, jobs=jobs, excerpt=excerpt),
        labels=labels,
    )
    return action


def main(
    argv: Sequence[str] | None = None,
    *,
    client: PublishIssueClient | None = None,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    now: datetime | None = None,
) -> int:
    parser = argparse.ArgumentParser(description="Report the publish-policy run outcome on a managed GitHub issue.")
    parser.add_argument("--repository", help="GitHub repository in owner/name form. Defaults to GITHUB_REPOSITORY.")
    parser.add_argument("--run-url", required=True, help="URL of the workflow run being reported.")
    parser.add_argument("--generation-log", type=Path, default=None, help="Captured policy generation output.")
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ

    repository = (args.repository or env.get("GITHUB_REPOSITORY", "")).strip()
    try:
        needs = json.loads(env.get("NEEDS_JSON") or "{}")
    except ValueError:
        needs = {}
    if not isinstance(needs, Mapping):
        needs = {}
    if client is None:
        token = env.get("GITHUB_TOKEN", "").strip()
        if not token:
            print("GITHUB_TOKEN is required to report the publish status.", file=stderr)
            return 2
        client = RestGitHubClient(token)
    generation_log = None
    if args.generation_log is not None and args.generation_log.is_file():
        generation_log = args.generation_log.read_text(encoding="utf-8", errors="replace")

    try:
        action = report_publish_status(
            client,
            repository=repository,
            needs=needs,
            run_url=args.run_url,
            generation_log=generation_log,
            now=now or datetime.now(timezone.utc),
        )
    except GitHubApiError as exc:
        print(f"::warning::Publish failure issue could not be updated: {exc}", file=stdout)
        return 1
    print(f"Publish status report: {action} (outcome: {outcome_from_needs(needs)})", file=stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
