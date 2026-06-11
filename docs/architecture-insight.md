# Architecture Insight

Purpose: document the current implementation boundaries that future maintainers must preserve. This is technical context, not a substitute for code, tests, workflows, and `AGENTS.md`.

Related links: [maintainer guide](maintainer-guide.md) | [wiki architecture](../wiki/Architecture.md) | [local detection](../wiki/Local-Windows-Detection.md) | [policy trust](../wiki/Policy-Feed-and-Trust-Model.md)

## Runtime Flow

| Step | Module | Contract |
| --- | --- | --- |
| Build config and CLI options | `__main__.py`, `config.py` | CLI flags and env vars become `ReleaseCheckerConfig`. |
| Fetch policy source | `api.py`, `remote_policy.py`, `cache.py` | Prefer live signed JSON; degrade visibly to cache or bundled policy. |
| Verify trust | `signing.py`, `json_utils.py`, `policy_schema.py` | Verify Ed25519 signature, strict JSON, schema, size bounds. |
| Probe local state | `local_state.py` | Build-first evidence with raw admin-facing diagnostics preserved. |
| Evaluate verdict | `evaluator.py`, `models.py` | Signed policy target drives status; local evidence describes installed state. |
| Optional diagnostics | `wua_probe.py`, `audit_probes.py`, `policy_diagnostics.py` | Read-only secondary context for update offers, logs, and likely blockers. |

## Source Hierarchy

| Rank | Evidence | Use |
| --- | --- | --- |
| 1 | Live public policy JSON plus `.sig` | Preferred runtime policy source. |
| 2 | Verified fresh cache | Degraded fallback when live fetch fails. |
| 3 | Verified stale cache | Degraded fallback with stronger warning. |
| 4 | Bundled signed policy | Last-known-good fallback; not production green in strict mode. |
| 5 | Local build and edition probes | Installed-state detection only. |
| 6 | WUA, Panther, DISM packages, event logs | Explanatory context only. |

Source Diagnostics and workflow-synced GitHub Issues are publish/source
troubleshooting evidence. They can expose parser drift, source freshness, static
ticket links, or an issue-sync outage, but they do not replace signed policy
trust or runtime evaluator verdicts.

The production generator may use public Microsoft Release Health HTML, public
Microsoft Update History Atom feed data, Atom-linked public Microsoft Support
articles, and unauthenticated public MSRC CVRF data for source diagnostics and
informational enrichment. These enrichment sources can explain observed builds,
KB classification, and source lag, but they do not override signed policy
verdicts or required baseline semantics. Authenticated Microsoft metadata API
research remains historical context only and is not active production
architecture.

`latest_build` remains the Current Versions table value from Microsoft Release
Health. `latest_observed_build` is the newest official Microsoft-observed build
the generator can prove from supported public evidence, including Atom-linked
Support articles, and can be newer than `latest_build`. `required_baseline_build`
remains selected by the existing signed quality-baseline rules; Source
Diagnostics, Support articles, and MSRC CVRF enrichment do not promote a build
to the required baseline by themselves. When Release Health has caught up and
baseline rules select the same build, all three fields can legitimately report
the same build.

Atom is discovery for Support article hrefs, not a fallback URL resolver. The
generator does not synthesize `/help/<KB>` when Atom lacks a usable support
href. Atom-linked Support article facts must match the selected Atom URL, KB,
expected build, and parseable release/applicability before they are trusted for
summaries or Support-derived security labels. MSRC CVRF enrichment requires an
exact KB-token match; unavailable or malformed CVRF data remains unknown rather
than becoming proof that a KB is non-security.

## Release Targeting

| Rule | Reason |
| --- | --- |
| Prefer supported GA H2 release for existing devices. | Broad-fleet policy should not chase every upstream release string. |
| Exclude special/new-devices-only releases from existing-device target selection. | Current 26H1 semantics are explicit in policy/tests. |
| Keep LTSC and GA rows separate. | Enterprise LTSC and IoT Enterprise LTSC have different servicing paths. |
| Use `latest_build` for the Release Health Current Versions table value and `required_baseline_build` for the required quality baseline. | Keeps table reporting and compliance floor semantics separate. |
| Use `latest_observed_build` for newer official observed-build context. | Newer Atom/support observations can be useful without becoming baseline authority. |

## Do / Do Not

| Do | Do not |
| --- | --- |
| Keep runtime JSON-first and signed by default. | Re-enable Microsoft HTML parsing in normal runtime paths. |
| Preserve raw local diagnostic values behind explicit opt-ins when default JSON compacts bulky Panther/setup log tails; keep Panther reads fixed-path, tail-bounded, and guarded by a generous total collection cap. | Treat marketing/display labels as decisive identity evidence. |
| Keep WUA optional, bounded, and read-only. | Use WUA offers/history to replace the signed policy verdict. |
| Keep Source Diagnostics and GitHub Issues as troubleshooting evidence. | Let issue state, labels, or dashboard diagnostics override compliance verdicts. |
| Keep Atom/support/MSRC enrichment informational unless baseline rules select it. | Treat a newer latest-observed build as the required baseline by itself. |
| Add fields compatibly to public `/api/v1`. | Remove or rename v1 fields/paths casually. |

## Verify

```powershell
python -m compileall -q win11_release_guard tools
pytest -q tests/test_evaluator.py tests/test_runtime_policy_sources.py tests/test_remote_policy.py
pytest -q tests/test_local_state.py tests/test_policy_generator.py
python tools/check_project_identity.py
```
