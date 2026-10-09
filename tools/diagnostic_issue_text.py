"""Titles, bodies, tips, and comments for Source Diagnostic GitHub Issues."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping
from win11_release_guard.config import DEFAULT_PAGES_BASE_URL
from win11_release_guard.policy_schema import is_source_diagnostic_id


DIAGNOSTIC_ID_COMMENT_PREFIX = "wrg-source-diagnostic-id"


LABEL_BY_SEVERITY = {
    "warning": "internals: warning",
    "error": "internals: error",
}


ATOM_DIAGNOSTIC_ID_PREFIX = "wrg-source-diagnostic-v1:uuid:"


ATOM_PUBLIC_ID_RE = re.compile(r"^[1-9][0-9]*$")


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
