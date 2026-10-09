"""Dry-run reports for Source Diagnostic issue sync."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence
from tools.diagnostic_issue_text import DiagnosticIssue, SyncSummary, _normalized_text


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
