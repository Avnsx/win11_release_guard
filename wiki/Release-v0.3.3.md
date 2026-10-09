# Release v0.3.3

Release notes for `0.3.3`, the corrective source-evidence hardening release.

---

## Pick Your Path

| You are | Read | Why |
| --- | --- | --- |
| User | [Quick Start](Quick-Start) | Run the guard and understand output/exit codes. |
| Admin / RMM owner | [CLI and RMM Usage](CLI-and-RMM-Usage) | Integrate JSON output and strict-production checks. |
| Maintainer | [Build, Test and Release](Build-Test-and-Release) | Reproduce local gates and release checks. |
| Release manager | [Tagged Release Lane](Tagged-Release-Lane) | Publish a validated source archive and understand the separate PyPI lane. |
| Contributor | [Regression Chokepoints](Regression-Chokepoints) | Avoid known regression traps. |

## Highlights

| Area | 0.3.3 state |
| --- | --- |
| Versioning | Package/runtime/generator/WUA identity is centralized at `win11_release_guard/0.3.3`. |
| Build semantics | `latest_build` is Release Health Current Versions, `latest_observed_build` is newest supported public Microsoft evidence, and `required_baseline_build` is the signed baseline floor. |
| Atom diagnostics | Multi-build Atom entries keep unique diagnostic IDs; canonical warnings can keep Atom-form IDs while sibling rows use deterministic hash-form IDs. |
| Support validation | Support article URL, KB, build, and parseable applicability are validated before article facts enrich summaries or Support-derived security labels. |
| MSRC joins | CVRF matching requires exact KB tokens; unavailable or malformed CVRF stays unknown/unavailable, and context lists are capped. |
| Baseline notice | Caught-up real B-release baselines can show a 14-day dashboard-only notice without changing verdicts or issue sync. |
| Dashboard | Static Pages keeps unique row IDs, visible validation status, copy/export JSON, no raw Support HTML, no tokens, no CDN, and no external JS/CSS/fonts. |
| Change rules | Local patch files are only hints; a change counts once it is committed with its tests and docs. |
| PyPI lane | `pypi-publish.yml` builds wheel/sdist and publishes through Trusted Publishing / GitHub OIDC only after tag or published-release gates. |

## Source Evidence Semantics

Microsoft public sources can arrive out of order. Release Health Current
Versions remains the `latest_build` source. Atom-linked Support article evidence
can move `latest_observed_build` ahead, but that observation is administrator
context only until baseline rules select the same build as
`required_baseline_build`. When Release Health has caught up and the baseline
rules select that same build, all three build fields can legitimately match.

Atom discovers Support article hrefs; it is not a synthesized `/help/<KB>`
resolver. The generator prefers safe Atom `alternate` links to
`https://support.microsoft.com` article paths and records a Source Diagnostic
when no usable support href exists. Otherwise safe article URLs have tracking
queries and fragments stripped; unsafe ports, userinfo, traversal, overlong
paths, and non-support hosts still reject. Direct or fixture-provided Atom
entries are revalidated before their links can become release-history URLs,
support metadata, manifest evidence, dashboard hrefs, or copied diagnostics
JSON. Release History enrichment prefers Atom entries that match both KB and
build, then build-only entries, and skips ambiguous KB-only fallbacks.

Support article enrichment is trusted only after URL, KB, expected build, and
parseable `Applies to` evidence are compatible with the Atom record. Mismatch
and degraded statuses stay visible without dumping raw article HTML or treating
mismatched article text as summary/security truth. The parser records bounded
`applies_to` text and `applies_to_releases` when release values can be parsed.
If those parsed releases explicitly exclude the expected release, the article
is a visible mismatch and is untrusted for summaries or Support-derived
security wording for that event.

MSRC CVRF exact-KB-token evidence can still classify a KB as security when the
Support article is bad. Larger tokens such as `KB50941260`, `15094126`, and
`5094126a` do not match `KB5094126`, and malformed/unavailable CVRF data does
not silently become non-security proof. Exact-KB remediation evidence remains
security evidence even without optional CVE/severity/product fields. Dashboard
and visible JSON exports publish the classification and evidence source, not
CVE lists or counts.

When a real non-preview, non-OOB Release Health B-release row becomes the
required baseline and matches the broad target's latest observed build, the
dashboard can show an informational blue/white baseline-update notice for 14
days from the source-derived official baseline date. It labels date-only
Release Health precision explicitly and uses deterministic local facts from
Release Health, Atom, validated Support, and exact MSRC data. It does not call
an LLM or cloud API, and it does not change signed verdicts, baseline
selection, Source Diagnostics issue sync, runtime behavior, or `/api/v1`
aliases. Expired or inactive notice metadata does not trigger optional
Support/MSRC enrichment fetches solely for stale notice data. If an already
published static page becomes stale, inline local JavaScript hides the expired
notice and removes the `has-baseline-notice` grid class so the operational
panels reflow; invalid expiry data leaves the notice visible instead of
crashing the page.

## Generated Output Coverage

Generated-output regressions exercise the policy JSON, policy manifest,
dashboard HTML, `/api/v1` aliases, visible Source Diagnostics JSON export, and
remote parser acceptance. They cover the KB5094126 latest-observed case, the
caught-up Release Health case, unique diagnostic IDs, Support mismatch/degraded
states, MSRC unavailable/malformed states, no raw Support HTML leakage, and no
synthesized `/help/5094126` fallback. Additional coverage guards unsafe direct
Atom links, build-aware Atom matching, explicit release/applicability
mismatches, expired-notice no-fetch behavior, stale-notice grid reflow, and
static dashboard constraints.

## Release Gate Result

The local `0.3.3` release gate passed compileall, the full pytest suite, fixture
Pages generation, generated-output sanity inspection, secret scanning, clean
archive export/validation, identity/version/action audits, `--self-test`, live
public policy/pages checks, and the Windows Panther JSON regression harness.
Generated archive validation reported 153 clean source entries.

## Packaging And PyPI

| Item | State |
| --- | --- |
| PyPI project | [win11_release_guard](https://pypi.org/project/win11-release-guard/) |
| End-user install | `python -m pip install win11_release_guard` |
| Package metadata | `pyproject.toml` defines `win11_release_guard` version `0.3.3`, GPL-3.0-only license, console script, project URLs, and package data. |
| Build artifacts | wheel and sdist are generated in `dist/`, checked with `python -m twine check dist/*`, and never committed. |
| Publishing | `.github/workflows/pypi-publish.yml` uses PyPI Trusted Publishing / GitHub OIDC with environment `pypi`. |
| First publish | Pending Trusted Publisher setup is required if the project is absent; a PyPI 404 is not a name reservation. |

## Signed Policy Note

The local version bump does not regenerate the signed bundled production policy
or detached signature. Release packaging and Pages publishing must use the
existing secure signing workflow with the real policy signing key.

## Unchanged Boundaries

| Boundary | Rule |
| --- | --- |
| Verdict | Signed public policy remains the authority. |
| WUA | Optional read-only secondary probe; never decides the policy verdict. |
| Panther/setup logs | Administrator troubleshooting evidence only. |
| Source Diagnostics | Source-health evidence only; notices are dashboard-only and not issue-syncable. |
| Baseline notice | Informational dashboard output only. |
| 26H1 | New-devices-only / excluded for existing devices. |
| `/api/v1` | Existing public aliases remain compatible. |

## Verify Commands

```powershell
python -m compileall -q win11_release_guard tools tests
python tools/check_version_consistency.py
python tools/check_project_identity.py
python tools/check_github_action_versions.py
pytest -q
python -m win11_release_guard --self-test
python tools/scan_for_secret_material.py README.md CHANGELOG.md AGENTS.md docs wiki win11_release_guard tests tools pyproject.toml .github
python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip
python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip
python -m build
python -m twine check dist/*
```

## Full Change Notes

The complete change list recorded for v0.3.3.

### Summary

Version 0.3.3 is the corrective source-evidence hardening release. It bumps the package/runtime/generator/WUA identity to `0.3.3`, keeps the signed policy verdict model unchanged, and documents the implemented split between Microsoft Release Health `latest_build`, informational `latest_observed_build`, and the signed `required_baseline_build`. Release Health Current Versions remains the `latest_build` source; Atom-linked Support evidence can advance latest-observed context; baseline rules alone select the compliance floor; when Microsoft sources catch up all three build fields can legitimately match.

### Changed

* Added a dashboard-only required-baseline catch-up notice for the case where a real Release Health B-release baseline now matches the broad target's latest observed Microsoft build. The notice is informational, expires after the 14-day source-date window, labels date-only Release Health precision honestly, and does not change signed verdicts, baseline selection, issue sync, or runtime client behavior.
* Documented the split between Release Health `latest_build`, informational `latest_observed_build`, and signed `required_baseline_build`; Atom-linked Support article evidence can advance latest-observed context without changing the required fleet baseline.
* Documented Source Diagnostics enrichment from Atom-linked Microsoft Support articles and unauthenticated MSRC CVRF data, including no `/help/<KB>` fallback when Atom lacks a support href, Atom-form diagnostic IDs, and GitHub Issue title suffixes such as `[id=968480]`.
* Aligned repository docs and Wiki pages with the caught-up build case, validated Support/MSRC enrichment, unique hash-form or Atom-form Source Diagnostic IDs, dashboard-only notices, static dashboard constraints, and the rule that local patch files are not finished changes.
* Updated current release navigation and generated Pages changelog expectations for `/wiki/changelog/v0.3.3/` while preserving historical `v0.3.2` and `v0.3.1` sections and routes.

### Fixed

* Ensured unique multi-build Atom diagnostic IDs when one Atom entry produces multiple release/build events. The canonical broad-target warning can retain the public Atom-form ID, while sibling events use deterministic hash-form IDs and retain Atom entry, support article, support URL, source URL, and article-id metadata for triage.
* Tightened support and MSRC enrichment edge cases: safe Support URLs with explicit `:443`, tracking queries, and fragments canonicalize to scheme/host/path; unsafe ports and paths still reject. Support article `Applies to` extraction now handles heading/list and heading/paragraph layouts without swallowing following sections, and exposes `applies_to_releases` for compatibility checks.
* Exact MSRC CVRF KB remediation matches now classify a KB as security even when optional CVE, severity, or product fields are absent.
* Removed CVE lists and counts from baseline notices, Source Diagnostic dashboard rows, and copied visible JSON; administrators still get deterministic security/non-security/unknown labeling with the evidence source.
* Hardened backend source-evidence paths so direct or fixture-provided Atom links are still revalidated before they can become release-history `kb_url`, support metadata, manifest evidence, dashboard links, or copied Source Diagnostics JSON.
* Improved Atom row matching to prefer KB-and-build matches, then build matches, and to skip ambiguous KB-only fallbacks when source URL, preview/OOB, or update-bucket evidence would be unclear.
* Treated explicit `applies_to_releases` exclusions as untrusted article mismatches for summaries and Support-derived security wording while preserving exact MSRC KB evidence as an independent security signal.
* Prevented expired or inactive baseline-update notices from fetching optional Support/MSRC enrichment solely for stale historical notice data.
* Fixed stale static dashboard reflow so client-side expiry hides the baseline notice and removes the `has-baseline-notice` grid class, avoiding a blank first operations row.
* Validated Atom-linked Microsoft Support article URL, KB, build, and applicability evidence before using article facts for Source Diagnostics summaries or Support-derived security labels; mismatches now remain visible as compact validation metadata without trusting the mismatched article text.
* Hardened Microsoft source matching so Atom enrichment uses only safe alternate Support article links, Support URLs reject unsafe hosts, paths, ports, and traversal while stripping tracking queries and fragments from otherwise safe article URLs, MSRC CVRF joins require exact KB tokens, and unknown applies-to evidence degrades instead of silently passing.
* Kept security classification honest when enrichment is incomplete: exact MSRC CVRF KB-token evidence can still classify a KB as security, malformed or unavailable CVRF remains unknown/unavailable, and title-only `OS Build(s)` wording or mismatched Support article text is not treated as security proof.
* Added contributor and archive rules: local patch files are hints only, and a change needs committed code, passing tests, and updated docs. Raw worktree ZIPs remain disallowed release artifacts.

### Tests

* Added generated-output regressions for KB5094126 latest-observed behavior, caught-up Release Health behavior, diagnostic ID uniqueness, Support article mismatch/degraded states, MSRC unavailable/malformed states, API aliases, manifests, and raw Support HTML leakage.
* Added local regression coverage for the baseline-update notice payload, rendering order, dashboard-only issue-sync behavior, degraded evidence wording, Support URL canonicalization, bounded `Applies to` extraction, exact MSRC KB matching, and no raw Support HTML leakage.
* Added generated-output and browser-backed dashboard checks for unsafe Atom URL leakage, expired-notice no-fetch behavior, stale notice class removal, static-page constraints, mobile/desktop layout, and no raw Support article body leakage.
* Added regression coverage for safe Atom `alternate` link selection, support.microsoft.com URL canonicalization/rejection, exact MSRC KB-token joins, applies-to compatibility parsing, visible dashboard/copy JSON diagnostic IDs, and clean archive exclusion of temporary artifacts.
* Final local release gates for the `0.3.3` cut passed compileall, the full pytest suite, fixture Pages generation, generated-output sanity inspection, secret scanning, clean archive export/validation, identity/version/action audits, self-test, live public policy/pages checks, and the Windows Panther JSON regression harness.

### Packaging And Release

* Program/package version is `0.3.3`; runtime user-agent, generator identity, and WUA client application ID continue to derive from the shared version helper instead of hardcoded per-module strings.
* Release documentation now includes `docs/releases/v0.3.3.md` and `wiki/Release-v0.3.3.md`. Clean archives require the new release-note files while keeping historical `v0.3.2` and `v0.3.1` material available.
* PyPI publishing remains handled by `.github/workflows/pypi-publish.yml` through Trusted Publishing / GitHub OIDC. The workflow builds wheel and sdist artifacts, runs `python -m twine check dist/*`, and still requires Pending Trusted Publisher setup if the project is absent; no PyPI tokens, usernames, passwords, or credentialed repository URLs are introduced.
* The signed bundled production policy and detached signature are not regenerated by this local version bump. Production release packaging must use the existing secure signing workflow with the real policy signing key.

## Related Pages

[Home](Home) | [Architecture](Architecture) | [Policy Feed and Trust Model](Policy-Feed-and-Trust-Model) | [Source Diagnostics](Source-Diagnostics) | [Tagged Release Lane](Tagged-Release-Lane) | [Build, Test and Release](Build-Test-and-Release)
