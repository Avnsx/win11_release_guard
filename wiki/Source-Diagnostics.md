# Source Diagnostics

Use this when investigating generator/parser drift, Microsoft source changes, Atom feed enrichment, or publish blocks.

---

## Diagnostic Sources

Source diagnostics explain the health of the policy inputs and generator
interpretation, not the final compliance verdict by themselves. They collect
Release Health, Atom feed, Atom-linked Support article, unauthenticated MSRC
CVRF, parser, and drift signals so an administrator can see whether the public
Microsoft source data changed, whether enrichment arrived late, or whether a
parser assumption needs attention. These signals never override the signed
policy verdict or required baseline semantics.

The dashboard severity tiles are filters over those generated events. Notices
are visibility-only, warnings call out non-blocking drift or missing enrichment,
and errors are publish-blocking because an error means the generated policy
could not be safely derived. This keeps source problems visible without letting
browser JavaScript mutate GitHub, hide parser failures, or turn diagnostics into
verdict authority.

| Source | Captured data |
| --- | --- |
| Microsoft Release Health HTML | Bytes, fetch time, newest current-version revision, newest release-history date. |
| Microsoft Update History Atom feed | Bytes, newest Atom build, newest published/updated timestamps. |
| Atom-linked Microsoft Support articles | Public release-note href evidence and deterministic article enrichment when available. |
| Public MSRC CVRF data | Unauthenticated security-update evidence and compact CVE context when available. |
| Parser | Structured events for missing/changed headers and table anomalies. |
| Drift checks | Current table lag, Atom newer rows, generated-after-source age. |

## Event Severity

| Severity | Meaning |
| --- | --- |
| `notice` | Informational; visible in policy output and the dashboard, but not synced to GitHub Issues. |
| `warning` | Non-blocking drift or missing enrichment; verify before trusting manually. |
| `error` | Publish-blocking source or parser failure. |

Atom drift keeps Preview and out-of-band rows at `notice` severity even when the
build number is newer than Release History. A newer non-preview build for the
current broad target can become `warning` when it has a KB and safe
Atom-provided `support.microsoft.com` article href. That warning is source
context; it does not promote the build to `required_baseline_build`.
Missing or malformed Atom input is also `warning`; it is visible source-health
degradation, not a silent condition.

Microsoft's public sources can arrive out of order. The Atom/Update History feed
can expose a KB or build before the Release Health HTML Current Versions or
release-history tables are manually refreshed. That race is normal for Preview,
out-of-band, unknown-family, non-broad-target, or incomplete Atom rows, so those
rows stay `notice`. Missing KB metadata is an uncertainty marker, not permanent
proof that a row is harmless.

Atom is discovery for public Support article hrefs. The generator fetches only
safe Atom `alternate` links to `https://support.microsoft.com` article paths.
It ignores `self` links, feed/API/search/download/static paths, non-support
hosts, userinfo, fragments, traversal patterns, and overlong URLs. Accepted
evidence URLs are canonicalized without tracking query strings. Legacy
`/help/<digits>` paths remain valid only when Atom provided them directly; the
generator does not synthesize `/help/<KB>` fallbacks. If an Atom KB row lacks a
usable support href, the generator records `atom_support_article_href_missing`
evidence. Support article text can provide human-readable KB context and
explicit security wording only after validation confirms that the article URL,
KB, expected build, and parseable applicability match the Atom record. Empty or
unknown `Applies to` values are degraded, not mismatch proof by themselves.
Public MSRC CVRF data provides higher-confidence exact-KB-token security
classification and compact CVE context when available; substring values such as
`KB50941260`, `15094126`, or `5094126a` do not match `KB5094126`. Atom title
buckets remain low-confidence labels; generic `OS Build(s)` wording is not
security evidence. If validation is `mismatch`, the technical Atom diagnostic
remains visible and the mismatch reasons are recorded, but article
KB/title/build facts and Support-derived security wording are not trusted for
the dashboard summary or `Security patch` tag. If validation is `degraded`,
summaries stay Atom-grounded and include the compact degradation reason. The
`source_drift_unresolved_after_24h` event is reserved for warning/error drift
that remains unresolved after the newest source timestamp, not for normal
notice-only feed lag.

## Diagnostic IDs

Source diagnostic IDs use stable event identity fields: severity, source,
event kind/category, release, build family, build, KB article, affected target
flags, and the source URL host/path when present. Generated timestamps, fetched
timestamps, exact message wording, tag order, and display-only prose are not part
of the normal hash-ID basis.

Supported ID forms are:

| Form | Used for |
| --- | --- |
| `wrg-source-diagnostic-v1:<16 lowercase hex>` | Older and non-Atom diagnostics with deterministic hash identity. |
| `wrg-source-diagnostic-v1:uuid:<canonical uuid>;id=<positive decimal>` | Atom-derived diagnostics when the Atom entry ID is a valid UUID plus public article ID. |

Malformed, duplicate, missing, or legacy Atom IDs do not break generation; they
fall back to the deterministic hash form.

## Publish Gate

`publish-policy.yml` rejects generated policy output when `source_diagnostics.events` contains `severity: error`. This keeps stale or structurally broken upstream parsing from silently publishing.

## GitHub Issue Sync

Issue sync is workflow-side only and uses the built-in GitHub Actions token.
Its input is deliberately limited to real `source_diagnostics.events` entries
from the generated policy. Dashboard-only rows such as `No source issues
reported`, `26H1 excluded for existing devices`, freshness notices, or other
derived display rows may remain visible and filterable in the Pages UI, but they
do not automatically create or maintain GitHub Issues.
The sync treats an issue as managed only when the body contains exactly one
internal marker:

```text
<!-- wrg-source-diagnostic-id: <full source diagnostic ID> -->
```

Labels, titles, and normal text that merely mention a diagnostic ID are ignored
for mutation. Manual issues without that marker are not updated, commented,
reopened, or closed by the sync. The body also contains
`Source diagnostic ID: <full source diagnostic ID>` for human review. For
Atom-derived diagnostics, the issue title appends the public article suffix,
for example `[id=968480]`, while the marker and body keep the exact full ID.

For managed open issues, the sync compares the current title, body, and labels
with the desired diagnostic state. If they already match, the issue is left
unchanged and no "still present" comment is posted. Reopened managed issues and
stale managed issue closes still receive a short workflow comment. New or
updated managed warning/error issues include a compact Markdown tip at the
bottom of the issue body. The tip is selected from the diagnostic kind, severity,
and target flags, and links to the relevant Pages Wiki follow-up page for Atom
drift, parser/source failures, freshness drift, or publish-gate behavior.

Issue-sync labels are fixed as:

| Severity | GitHub label |
| --- | --- |
| `warning` | `internals: warning` |
| `error` | `internals: error` |

Notice events do not create, update, reopen, or keep GitHub Issues current. The
legacy `internals: notices` label may still be searched only so older managed
Notice issues with the exact body marker can be closed as stale. Labels alone do
not make an issue managed; the internal body marker is required.

In the publish workflow, a GitHub Issues API, label, or permission failure in the
sync step is published as static degraded metadata instead of blocking signed
Pages output. The dashboard displays `Issue sync unavailable` from
`source_diagnostics.issue_sync`; source-diagnostic `error` events from the
generator still block publishing.

The dashboard Source Diagnostics tiles are filters. Select Notices, Warnings, or
Errors to show only that severity; select `View all` to reset the feed. Static
`#Ticket <number>` links appear on a row only on hover or keyboard focus and only
when workflow-generated issue metadata provides a canonical repository issue URL
for a real synced event. Not every visible Notice, Warning, or Error row has an
issue.

The small copy button above the diagnostic feed exports the rows visible at the
time of the click as JSON to the local clipboard. The export includes severity,
deterministic diagnostic ID, title, source, technical message, tags, optional
static issue URL, the active filter, visible counts, and a short neutral context
note. When present, row export also includes additive enrichment fields such as
`user_message`, `kb_update_bucket`, `is_security`,
`security_evidence_source`, `support_article_url`,
`support_article_validation_status`, `support_article_validation_reasons`,
`support_article_expected_kb`, `support_article_expected_build`,
`support_article_expected_release`, `atom_entry_id`, and
`atom_support_article_id`. It is meant for technical lookup and handoff of the
current dashboard state; it does not call GitHub, write browser-side data back
to the repository, or change the signed policy verdict.

For rehearsal runs, use `tools/sync_source_diagnostics_issues.py --dry-run` with
`--dry-run-report-output` and `--dry-run-report-format json` or `markdown`.
Dry-run reports list deterministic IDs, severities, labels, skipped Notice
counts, and planned create/update/reopen/close actions without mutating GitHub
Issues or writing tokens.

## Common Issues

| Symptom | Check | Action |
| --- | --- | --- |
| Current Versions parser fails. | Release Health table headers changed. | Update parser tests and code together. |
| Atom feed has newer build than Release Health. | `atom_newer_than_release_history` event. | Inspect the KB, Support article href, build family, and whether latest observed remains informational. |
| Atom KB row has no Support article href. | `atom_support_article_href_missing` event. | Treat as source evidence gap; do not add a `/help/<KB>` resolver. |
| Atom row links only to feed/API/search/download/static, non-support, or traversal URL. | `atom_support_article_href_missing` event with no latest-observed advancement. | Treat as unsafe or non-article evidence; use only a safe Atom `alternate` Support article URL. |
| Support article KB/build/applies-to disagrees with Atom. | `support_article_enrichment_mismatch` event and validation reason codes. | Trust Atom KB/build/release and MSRC exact-KB evidence; do not use the mismatched article for summaries or Support-derived security labels. |
| Source diagnostics warning appears on dashboard. | Event kind and affected release/build. | Keep visible; only block if severity is error. |

## Verify

```powershell
pytest -q tests/test_remote_policy.py tests/test_policy_generator.py tests/test_publish_policy_workflow.py
pytest -q tests/test_source_diagnostics_issue_sync.py tests/test_source_diagnostics_issue_metadata.py
python tools/generate_policy.py --release-health-html tests/fixtures/windows11-release-health.html --atom-feed tests/fixtures/windows11-atom.xml --output-dir site --write-index --write-manifest
```

## Related Pages

[Home](Home) | [Policy Feed and Trust Model](Policy-Feed-and-Trust-Model) | [GitHub Pages Dashboard](GitHub-Pages-Dashboard)
