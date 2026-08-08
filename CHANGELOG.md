# Changelog

## [Unreleased]

No unreleased changes yet.

## v0.5.0 - 2026-08-08

### Summary

Windows 11 Release Guard no longer leaves a permanent folder behind on the
machines it runs on. Its policy cache is now a single compact file in the
user's temp directory, written in one atomic step, so an interrupted run cannot
leave a half-written file or an empty folder behind, and new switches let an
administrator keep that state in a directory of their choosing, show it, purge
it, or turn it off entirely. Compliance results are unchanged: cached state is
only a speed optimisation and never affects the signed verdict or the exit
code.

### Changed

* The client runtime now keeps its default policy cache as one compact,
  atomically written record in the operating-system temp directory instead of a
  permanent JSON file under `%LOCALAPPDATA%\win11_release_guard\`. On-disk state
  is an optimisation only: it never changes the signed compliance verdict or the
  exit code.
* `--diagnose-config` now reports `cache_file` as the effective runtime state
  location, or a configured `--cache-file`, instead of the legacy default cache
  path. It is `null` when the run is stateless.
* `--output` now writes atomically through a staging file and `os.replace`,
  keeping a single in-place fallback for a report file another process holds
  open; its failure message names the path and the underlying reason, and the
  exit code stays `2`.
* The optional Windows Update cookie cache and the embedder-only
  `cache.save_policy_cache` helper serialise their JSON and write the bytes
  through the atomic write primitive, so on Windows both files are now LF
  instead of CRLF. A `--cache-file` legacy pair is not affected: it holds the
  publisher's exact policy and signature bytes, as it already did.
* `cache.save_policy_cache` and `wu_offer_probe.store_cached_cookie` no longer
  raise when the destination cannot be written; they return without writing.
* A `--cache-file` under a missing parent directory now records one
  `cache_write_failed` source problem and caches nothing instead of creating a
  directory tree.

### Added

* Operator and embedder state controls: the `--state-dir`, `--stateless`,
  `--purge-state`, and `--show-state` flags; the matching
  `WIN11_RELEASE_GUARD_STATE_DIR` and `WIN11_RELEASE_GUARD_STATELESS`
  environment variables; the `WIN11_RELEASE_GUARD_CACHE_FILE` environment
  variable, which now supplies the runtime `--cache-file` default; and the
  `purge_state`, `describe_state`, and `read_state_bytes` embedder API.

### Fixed

* A verified remote policy is no longer discarded from memory when its cache
  write fails; the run proceeds on the verified policy and records one
  `cache_write_failed` source problem.
* An unusable state record now self-heals instead of failing every run, and an
  interrupted write no longer leaves a permanent empty cache directory behind.

## v0.4.0 - 2026-08-07

### Summary

Windows 11 Release Guard now reads update history from Microsoft's Windows 11
servicing index and the servicing support articles it references, covering
every serviced Windows 11 lane in a single small request. Support-article
validation and MSRC security classification work again, with security
evidence now naming the affected Microsoft products directly instead of
opaque identifiers. Local system checks are faster because Windows details
are read natively instead of launching PowerShell, and administrators can
optionally enable a Windows Update offer probe for additional corroborating
evidence without affecting the signed verdict.

### Changed

* Release history, preview and out-of-band detection, and support article
  discovery are now derived from Microsoft's Windows 11 servicing index
  instead of the retired Update History feed.
* Support article validation resolves current Microsoft article URLs again,
  so stale or dead support links are caught before publishing.
* MSRC CVRF security enrichment reports the affected Microsoft product names
  alongside exact-KB security evidence, instead of opaque numeric product
  identifiers.
* Outbound requests to Microsoft sources now share one HTTP client with
  consistent headers, transparent response decompression, bounded response
  reads, retry with backoff, and conditional requests, improving resilience
  to transient network and server issues.
* Local Windows build/edition details are now read natively on Windows
  instead of starting a PowerShell process, removing a slow step from the
  common local-check path.
* A servicing index entry that carries a build but no KB article is now
  reported as an informational diagnostic instead of being skipped.

### Added

* Optional, off-by-default Windows Update offer probe that can add
  corroborating current-offer evidence at notice severity. It never affects
  the signed compliance verdict.

### Removed

* Removed the retired Windows Update History Atom feed source path; policy
  generation no longer depends on it or carries its dead source metadata.

## v0.3.6 - 2026-07-18

### Summary

Windows 11 Release Guard 0.3.6 keeps the dashboard's security classification
working even when Microsoft's Update History feed lags Patch Tuesday: the
baseline-update notice now checks MSRC security data directly using the Release
Health date, so administrators see a confirmed security label instead of a
neutral placeholder during Microsoft-side feed delays. Enrichment problems now
surface as visible warnings instead of staying silent, and the audited GitHub
Actions checkout pin moved to v7. Device compliance is unchanged: signed policy
verdicts, baseline selection, and the public API behave exactly as before.

### Fixed

* Kept the active baseline-update notice's security classification working when
  Microsoft's Update History Atom feed lags Patch Tuesday. When the feed has no
  entry for the new baseline KB, the notice now derives the MSRC month from the
  Release Health baseline date (for example `2026-06-09` to `2026-Jun`), fetches
  MSRC CVRF for that month, and joins the baseline KB exactly, so security is
  credited to MSRC without waiting for Microsoft's Atom entry. No Support article
  is fetched or synthesized in that case, so support validation stays
  `unavailable`, and the neutral "classification unavailable" wording now shows
  only when MSRC is also unavailable.
* Stopped silently swallowing baseline-record enrichment failures. If the MSRC
  fallback fetch fails, the standard `msrc_cvrf_enrichment_unavailable` warning
  now fires for that month, and a baseline record whose Atom-linked Support
  article fetch fails now emits the standard support-enrichment event instead of
  being suppressed. Baseline records with no support URL stay quiet as before.

### Changed

* Moved the audited first-party GitHub Actions pin for `actions/checkout` to
  `v7` across all workflows, with the action-version audit tool, its tests, and
  the AGENTS.md audited list updated in the same change (Dependabot PR #10).

### Tests

* Pinned the Atom-feed-lag baseline-notice behavior: MSRC month fallback with a
  trusted classification when MSRC responds, honest `unavailable`/`unknown`
  plus a `msrc_cvrf_enrichment_unavailable` warning when it fails, and no
  Support article fetch in either case. Also pinned that a baseline record with
  a real Atom-linked article whose fetch fails surfaces the standard
  support-enrichment event.

## v0.3.5 - 2026-06-15

### Summary

Windows 11 Release Guard 0.3.5 hides the short-lived console helper windows the
library spawns on Windows, so GUI consumers such as a PySide6 admin app no longer
see PowerShell and DISM windows flash on screen when a system check runs. It also
folds in the earlier dashboard tooltip and Pages freshness-fixture fixes. Device
compliance is unchanged: the same commands run with the same timeouts and parsing,
and the signed policy verdict behaves exactly as before.

### Fixed

* Hid the internal console helper windows on Windows. When a GUI process (for
  example a PySide6 admin app) called `check_current_system(...)`, the library's
  short-lived `powershell.exe` and `dism.exe` helper processes each briefly
  popped a black console window and stole focus. The library now creates those
  children with `CREATE_NO_WINDOW` and a hidden `STARTUPINFO` (`SW_HIDE`) by
  default on Windows, so no console windows appear. This is a window-visibility
  change only: the commands, criteria, timeouts, encodings, parsed output, exit
  codes, and the resulting verdict are unchanged, and non-Windows platforms get a
  no-op so Linux/macOS behavior is unaffected. There is no opt-out flag.
* Restored the dashboard info-icon hover tooltips. The bubble that holds the
  explanation text was `position: fixed`, but the dashboard `<main>` uses
  `backdrop-filter`, which makes a fixed descendant resolve against `<main>`
  instead of the viewport; its `bottom` offset then landed far below the fold, so
  only the small caret showed on hover. The tooltip is now `position: absolute`,
  anchored directly under its icon (connected to the caret) and contained within
  the viewport, so the full explanation panel shows again on hover/focus.
* Stabilized generated Pages freshness rendering in fixed-date tests. The
  polished dashboard fixture used `2026-05-31T14:11:50+00:00`; once scheduled CI
  reached June 14, 2026, that fixture crossed the 14-day refresh threshold and
  correctly rendered `Policy feed refresh due` instead of the expected
  `No source issues reported` notice. `render_policy_index()` and
  `write_policy_outputs()` now accept an optional render-age reference used only
  by tests and fixture helpers, while production output still computes freshness
  from the real current UTC time.

### Tests

* Pinned the fixed-date Pages and policy-generator fixture renders to a stable
  fresh reference time so the Unreleased dashboard expectations keep testing the
  intended notice-only path. The regression was reproduced from the failed
  `publish-policy` `sync-source-diagnostics-issues` job and verified locally with
  the exact failing test, the workflow's source-diagnostics test selection, the
  Pages landing tests, the full pytest suite, fixture Pages generation, secret
  scanning, clean archive validation, and live public Pages checks.

## v0.3.4 - 2026-06-13

### Summary

Windows 11 Release Guard 0.3.4 is a polish and reliability release on top of 0.3.3.
It makes the dashboard's security wording match the evidence it actually has, reads
Microsoft's source dates and update links more defensively so unusual data degrades
gracefully instead of breaking, and gives the public wiki and changelog the same
comfortable, readable scale as the dashboard. Device compliance results are
unchanged: the signed policy verdict and required-baseline rules behave exactly as
before.

### Fixed

* Made the dashboard baseline-update notice security wording source-aware and
  punctuation-clean. The user-facing summary previously asserted "MSRC confirms
  it as a security update" whenever the baseline was security-classified, even
  when the only evidence was a validated Microsoft Support article (for example
  when MSRC CVRF was unavailable). It now credits MSRC only for exact MSRC CVRF
  evidence, attributes Support article evidence to Microsoft Support, uses
  neutral wording when evidence is unavailable or unknown, and uses clear
  non-alarmist wording when checked evidence does not classify the update as
  security. The summary is assembled from complete sentences, so it no longer
  emits the `B.;` punctuation artifact or leaks raw status enums such as
  `not_security` into human-facing copy; machine JSON fields still carry the
  structured `security_evidence_source`/`security_evidence_status` values.
* Hardened baseline-notice date parsing so impossible or malformed ISO-shaped
  source dates such as `2026-02-30` degrade to no active notice instead of
  raising `ValueError` and aborting policy, dashboard, and manifest generation.
  Non-zero-padded calendar dates such as `2026-6-9` are now accepted and
  normalized to `2026-06-09`; date-only precision is preserved and no time of
  day is invented.
* Rebalanced the KB-only Atom fallback so it keeps legitimate build-agnostic
  article evidence without attaching wrong-build metadata. It runs only after
  exact KB+build and build-only matching fail, and then attaches a build-agnostic
  candidate only when the candidate KB matches, the candidate has a safe
  canonical Atom support URL, it is not Preview/Out-of-band for a normal broad
  target, it is unambiguous, and no same-release-family explicit candidate
  contradicts the row build. An explicit candidate for a different build family
  no longer blocks an otherwise-safe build-agnostic fallback, while wrong-build,
  unsafe-URL, Preview/OOB, and ambiguous candidates are still rejected. Exact
  KB+build matches (including the KB5094126 multi-build case) are unaffected.
* Removed an unreachable `release_unmatched` support-article validation branch;
  applies-to compatibility only ever produces `compatible`, `incompatible`, or
  `unknown`.
* Guarded repo-controlled Markdown reads in Wiki and changelog Pages generation
  so invalid UTF-8 in a source file degrades to replacement characters instead
  of crashing the generator; valid Markdown rendering and links are unchanged.

### Changed

* Made clean-archive validation deterministic and resistant to ambient pytest
  configuration. `tools/export_clean_archive.py --validate` builds an isolated
  environment for its inner extracted-archive pytest gate: it sets
  `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, removes inherited `PYTEST_ADDOPTS` and
  `PYTEST_PLUGINS` (which otherwise inject options or force plugin imports even
  with autoload disabled), and preserves the recursion guard and required Python
  runtime variables. A developer shell exporting `--cov=...` via `PYTEST_ADDOPTS`
  or a stale `PYTEST_PLUGINS` can no longer change, fail, or hang validation. The
  project declares no required pytest plugins, so coverage is unchanged, and CI
  still runs the full suite separately and validates with `--skip-test-run`, so
  no duplicate full run is introduced.
* Added `docs/releases/v0.3.1.md` to the required clean-archive entries (alongside
  the existing `v0.3.2` and `v0.3.3` release notes) so release history stays
  protected by archive validation.
* Clarified that the Source Diagnostics issue-sync `include_notices` flag is
  retained only for CLI backward compatibility and is intentionally inert:
  `notice` events stay dashboard-only and are never synced as GitHub Issues
  regardless of the flag.
* Unified the generated Pages Wiki visual scale and layout width with the
  dashboard. The wiki and changelog theme is rem-based but had no explicit root
  size and a narrow content cap, so it rendered noticeably smaller and denser
  than the dashboard at normal browser zoom while wide gutters sat empty. The
  shared wiki shell now sets a responsive root `font-size`
  (`clamp(1.0625rem, 1rem + 0.45vw, 1.25rem)`) so `/wiki/`, every wiki subpage,
  and the generated changelog pages scale their typography, spacing, and gutters
  to the dashboard's reading size without any CSS/browser zoom, transform-scale,
  or viewport tricks, and stay responsive (smaller on narrow screens, capped on
  wide desktops). The content column now uses the available horizontal space (up
  to a generous cap) so tables get room without shrinking their text, and long
  code blocks wrap at argument/whitespace boundaries (`white-space: pre-wrap`)
  so commands stay fully visible instead of being clipped behind a horizontal
  scrollbar. Prose paragraphs stay readable at ~74ch, content wraps long
  words/URLs, narrow screens still stack cleanly, and `overflow-x: clip` contains
  any stray overflow without breaking the sticky sidebar. The dashboard scale is
  unchanged and the Pages output remains static with no external JS, CSS, fonts,
  CDNs, tokens, or runtime API calls.

### Tests

* Added regression coverage for source-aware and punctuation-clean baseline-notice
  wording (MSRC vs Microsoft Support vs neutral vs non-security, no `B.;`, no raw
  enums), impossible/malformed and non-zero-padded baseline dates, the rebalanced
  KB-only Atom fallback (safe build-agnostic accepted; wrong-build/unsafe/Preview/
  ambiguous rejected; multi-build KB enrichment intact), the applies-to
  compatibility status set, guarded Markdown reads, archive-validation isolation
  from `PYTEST_ADDOPTS`/`PYTEST_PLUGINS` plus autoload determinism, archive
  failure on a real test failure, `--skip-test-run` content validation, and
  required historical release-doc entries.
* Added Pages visual-scale coverage: wiki home, wiki subpages, and changelog
  pages carry the shared responsive root scale; the dashboard and wiki share the
  Segoe UI font stack and clamp-based scale system; no generated Pages HTML uses
  zoom/transform-scale/viewport hacks or external assets; and wiki code blocks,
  tables, and long links stay responsive.

### Packaging And Release

* Program/package version is `0.3.4`; runtime user-agent, generator identity, and
  WUA client application ID continue to derive from the shared version helper
  instead of hardcoded per-module strings.
* Release documentation now includes `docs/releases/v0.3.4.md` and
  `wiki/Release-v0.3.4.md`; clean archives require the new release-note files while
  keeping historical `v0.3.1`, `v0.3.2`, and `v0.3.3` material available.
* PyPI publishing remains handled by `.github/workflows/pypi-publish.yml` through
  Trusted Publishing / GitHub OIDC: it builds wheel and sdist artifacts, runs
  `python -m twine check dist/*`, and still requires Pending Trusted Publisher
  setup if the project is absent; no PyPI tokens, usernames, passwords, or
  credentialed repository URLs are introduced.
* The signed bundled production policy and detached signature are not regenerated
  by this local version bump; production packaging uses the existing secure signing
  workflow with the real policy signing key.

## v0.3.3 - 2026-06-11

### Summary

Version 0.3.3 is the corrective source-evidence hardening release. It bumps the package/runtime/generator/WUA identity to `0.3.3`, keeps the signed policy verdict model unchanged, and documents the implemented split between Microsoft Release Health `latest_build`, informational `latest_observed_build`, and the signed `required_baseline_build`. Release Health Current Versions remains the `latest_build` source; Atom-linked Support evidence can advance latest-observed context; baseline rules alone select the compliance floor; when Microsoft sources catch up all three build fields can legitimately match.

### Changed

* Added a dashboard-only required-baseline catch-up notice for the case where a real Release Health B-release baseline now matches the broad target's latest observed Microsoft build. The notice is informational, expires after the 14-day source-date window, labels date-only Release Health precision honestly, and does not change signed verdicts, baseline selection, issue sync, or runtime client behavior.
* Documented the split between Release Health `latest_build`, informational `latest_observed_build`, and signed `required_baseline_build`; Atom-linked Support article evidence can advance latest-observed context without changing the required fleet baseline.
* Documented Source Diagnostics enrichment from Atom-linked Microsoft Support articles and unauthenticated MSRC CVRF data, including no `/help/<KB>` fallback when Atom lacks a support href, Atom-form diagnostic IDs, and GitHub Issue title suffixes such as `[id=968480]`.
* Aligned repository docs and Wiki pages with the caught-up build case, validated Support/MSRC enrichment, unique hash-form or Atom-form Source Diagnostic IDs, dashboard-only notices, static dashboard constraints, and anti patch-only handoff rules.
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
* Added AGENTS.md and archive-handoff guardrails that `.tmp/prompt-chain/*.patch` files are local hints only; implementation requires tracked edits, passing tests, required documentation updates, and logical commits. Raw worktree ZIPs remain disallowed release artifacts.

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

## v0.3.2 - 2026-06-10

### Summary

Version 0.3.2 is the compatibility and documentation-alignment release for the current `win11_release_guard` codebase. It bumps the package/runtime/generator/WUA identity to `0.3.2`, extends declared and CI-tested Python support through 3.14, keeps Source Diagnostics as source-health evidence only, and preserves the signed public policy as the device compliance verdict authority. Windows release semantics are unchanged: existing broad-fleet devices target Windows 11 `25H2`; `26H1` remains excluded for existing-device targeting; local build evidence outranks display labels; WUA, Panther/setup logs, DISM, Event Logs, and Source Diagnostics remain diagnostic evidence only.

### Added

* GitHub internal Wiki sync workflow and first-party `tools/sync_github_wiki.py` helper for mirroring `wiki/*.md` source Markdown to the same repository's `.wiki.git` remote with the built-in Actions token, plus dry-run Markdown artifact fallback.
* First-party static Pages Wiki generation from `wiki/*.md`, including `wiki/Home.md` to `/wiki/`, all regular wiki pages to `/wiki/<slug>/`, Markdown-compatible `_Sidebar.md` / `_Footer.md` navigation, stable heading anchors, duplicate-safe heading slugs, and GitHub Wiki link conversion for `[[Home]]`, `[[Page Name]]`, and `[[Label|Page-Name]]`.
* First-party static Pages changelog generation from `CHANGELOG.md`, including `/wiki/changelog/`, per-version Pages routes, version sidebar links, GitHub Release links, canonical metadata, sitemap entries, and no external JS/CSS/CDN dependencies.
* Visible generator warnings for silent-error cases such as missing `wiki/Home.md`, missing `_Sidebar.md` or `_Footer.md`, empty Wiki sources, empty Wiki pages, broken internal Wiki links, empty changelogs, non-standard changelog headings, and duplicate changelog version headings.
* Windows-11-style generated Wiki/changelog layout with breadcrumbs, skip-to-content link, left sidebar navigation, in-page table of contents, active page/group/section highlighting, reduced-motion-aware sidebar alignment, local-only inline SVG topic icons, and inline SVG favicon.
* Dashboard top-bar PyPI download image link copied into generated Pages assets and linked to the PyPI project without external runtime dependencies.
* Source Diagnostics dashboard controls for expanding the diagnostics panel and copying the currently visible diagnostic rows as local JSON for technical triage.
* Tests for Wiki/changelog rendering edge cases, sidebar and TOC behavior, raw HTML escaping, no external asset dependencies, PyPI-safe README media links, package metadata, workflow boundaries, and generated Pages sitemap/changelog routes.
* Python 3.13 and 3.14 are added to package compatibility metadata and CI coverage so PyPI users see the same supported interpreter range that repository automation exercises.

### Changed

* Package metadata now declares maintainer email `AvnDev@protonmail.com`; runtime dependencies remain limited to the code-backed `cryptography>=41` requirement.
* Program/package version is `0.3.2`; runtime user-agent, generator identity, and WUA client application ID continue to derive from the shared version helper instead of hardcoded per-module strings.
* README media and repository documentation links now use PyPI-safe absolute URLs, PyPI project metadata points `Documentation` at the Pages Wiki, and package metadata declares Python 3.10, 3.11, 3.12, 3.13, and 3.14 classifiers for PyPI/Shields rendering.
* CI now covers Ubuntu and Windows runners across Python 3.10, 3.11, 3.12, 3.13, and 3.14 instead of only the previously visible 3.11/3.12 jobs.
* README now shows the dashboard hero image from `assets/images/windows-11-release-guard-hero-dashboard.png` through the raw GitHub URL and keeps the PyPI download image as a direct clickable image rather than a nested UI bubble.
* Quick Start now prioritizes released-package installation and administrator usage, while source-checkout and release-candidate validation guidance stays in maintainer-oriented build/release documentation.
* Generated Wiki spacing now separates short sections, headings, tables, and paragraphs more clearly while keeping image-plus-text pairs visually related.
* Changelog sidebar/action labels are now compact but descriptive: section links, version pages, and GitHub release links no longer render as vague `Pages` or `Page` labels.
* Wiki sidebar behavior no longer uses the previous translucent pinned overlay; source navigation stays readable and scrollable without text disappearing behind a glass panel.
* The Pages Wiki renderer adds topic icons only in article content, not in the sidebar or TOC, and limits icon density so the visual layer stays useful instead of decorative noise.
* Dashboard info affordances now link directly to relevant Pages Wiki sections for build semantics, freshness, source diagnostics, signature trust, and API routes.
* `publish-policy.yml` now avoids tag-triggered Pages deploys because the protected `github-pages` environment rejects tag-sourced deployments; release tags rely on the main Pages publish lane or manual `workflow_dispatch` from `main`.
* `release.yml` now checks for matching `CHANGELOG.md`, `docs/releases/vX.Y.Z.md`, and `wiki/Release-vX.Y.Z.md` release material, and links Pages Wiki/changelog routes in GitHub Release notes.

### Fixed

* Fixed broken README image rendering on PyPI by replacing relative README media paths with absolute raw GitHub URLs.
* Fixed missing Python-version metadata for PyPI/Shields by declaring supported Python classifiers in `pyproject.toml`.
* Fixed generated Wiki/changelog sidebar overlay regressions where pinned header effects could obscure source navigation headings and active entries.
* Fixed changelog sidebar text clustering between `Changelog` and `Release history` with a structured two-column label layout and nowrap handling.
* Fixed duplicate horizontal separator effects by suppressing a second heading border when a Markdown horizontal rule already separates sections.
* Fixed changelog action injection for icon-bearing headings by matching heading elements more robustly instead of replacing only exact plain `<h2>` strings.
* Fixed generated Wiki TOC duplication by excluding the current page title from in-page section navigation.
* Fixed documentation drift that implied tag pushes deploy Pages; the docs now state that tag pushes trigger the separate Wiki sync lane only, while Pages publishing remains in `publish-policy.yml`.
* Fixed Source Diagnostics GitHub Issue sync so Notice events remain dashboard-only; automatic issue creation, update, and reopen now applies only to Warning and Error events, while legacy managed Notice issues can be closed as stale.
* Fixed dashboard Source Diagnostics rows so closed managed issue metadata suppresses stale rows, real warning/error issue links remain static hover/focus links, and derived display rows stay filterable without ticket links.
* Fixed project identity scans so allowed normalized PyPI and Shields endpoints are not mistaken for legacy hyphenated project identity drift.
* Fixed source-tree version resolution so clean source archives and source checkouts prefer their own `pyproject.toml` version over stale installed distribution metadata.
* Added compact Markdown tips with Pages Wiki follow-up links to managed Source Diagnostics warning/error GitHub Issues.
* Excluded GitHub Wiki helper files `_Sidebar.md` and `_Footer.md` from standalone Pages Wiki page and sitemap generation while preserving them as navigation/footer inputs.

### Removed

* Removed user-facing package-index staging-lane wording from release and security docs because the current implementation does not provide that lane.
* Removed source-checkout and local release-candidate validation commands from the user-facing README/Quick Start flow so end users are directed to the released package path first.
* Removed the generated Wiki sidebar glass overlay styling that made navigation text appear clipped or hidden.

### Documentation

* Documented that `sync-wiki.yml` is the only non-release workflow allowed to request `contents: write`, scoped only to GitHub internal Wiki Markdown sync.
* Added the AGENTS.md rule that future agents must keep historical `CHANGELOG.md` version sections and add newer entries at the top.
* Added AGENTS.md guardrails that preserve the README dashboard-first layout, right-aligned 96x96 PyPI image button, no-license-badge Markdown policy, and dashboard-only Notice issue-sync rule.
* Clarified Source Diagnostics wording for Microsoft Release Health vs Atom/Update-History drift, including missing-KB Atom rows as notices until reliable required-baseline evidence exists.
* Updated README, `docs/dashboard-and-pages.md`, `docs/security-automation.md`, `docs/tagged-release-lane.md`, `docs/releases/v0.3.2.md`, `docs/maintainer-guide.md`, and Wiki pages so the text reflects current code, tests, workflows, package metadata, Pages generation, changelog routes, and Wiki sync behavior.
* Added Wiki-side build/release validation guidance for regenerating Pages and running focused Wiki/generator tests after `wiki/*.md`, `CHANGELOG.md`, or Pages documentation changes.

## v0.3.1 - 2026-06-05

### Summary

Version 0.3.1 documents and hardens the current `win11_release_guard` worktree: package/runtime version identity, signed public policy feed handling, static GitHub Pages output, strict JSON trust boundaries, tagged source releases, and the PyPI Trusted Publishing lane. Windows release semantics are unchanged: existing broad-fleet devices target Windows 11 `25H2`; `26H1` remains excluded for existing-device targeting; local build evidence outranks display labels; WUA remains optional secondary evidence; policy `schema_version` and public `api_version` are not program versions.

Comparison basis: no local `v*` tags are present in this checkout. These notes are based on the current worktree at `main` `56915c9` plus uncommitted worktree files, not on earlier handover text or old release-note drafts.

### Added

* Central version helpers in `win11_release_guard/version.py`: `package_version()`, `versioned_product_id()`, `runtime_user_agent()`, `generator_version()`, and `client_application_id()`.
* Static feed freshness helpers in `win11_release_guard/freshness.py` for UTC parsing, epoch timestamps, 14-day warning metadata, and 45-day strict-stale metadata.
* Tagged GitHub Release workflow in `.github/workflows/release.yml` for `vX.Y.Z` tag validation, version parity, tests, live checks, dependency freshness, clean archive creation, and draft release publication.
* PyPI Trusted Publishing workflow in `.github/workflows/pypi-publish.yml` with build-only manual dispatch, existing-tag publish, published GitHub Release publish, package name and tag/version checks, wheel/sdist build, Twine check, dist artifact handoff, GitHub Environment `pypi`, and OIDC publishing.
* Local `wiki/` source tree and `docs/releases/v0.3.1.md` release notes for staged GitHub Wiki, rendered Pages Wiki, and maintainer documentation.
* GPL-3.0-only packaging metadata and `LICENSE.txt` inclusion in validated clean archives.
* Panther JSON support tooling: a Windows live regression harness, a developer leak debugger, and a dedicated `docs/panther-support.md` implementation/operations guide.

### Changed

* Program/package version is `0.3.1` in `pyproject.toml`; runtime user-agent, generator identity, and WUA client application ID derive from the shared version helper.
* `ReleasePolicyEntry` rendering keeps `latest_observed_build` separate from `required_baseline_build`, so preview/current-table observations do not become mandatory B-release compliance floors.
* The static Pages dashboard now exposes program version, release link, public endpoint links, source tiles, Source Diagnostics severity filters, feed currency, target build details, optional static issue links, and signature/hash state.
* `wiki/*.md` now renders into a first-party static Pages Wiki under `site/wiki/` without changing GitHub internal Wiki Markdown compatibility.
* `render_policy_manifest()` carries manifest/API metadata, freshness epochs, source diagnostics, hashes, published URLs, and broad-target build fields used by public checks.
* `publish-policy.yml` path filters include `pyproject.toml`, version/identity tools, secret scanning, generator inputs, `win11_release_guard/**`, and `wiki/**` because generated Pages output includes program metadata, runtime policy artifacts, and rendered Wiki HTML.

### Fixed

* Build-first local truth is preserved through `get_local_windows_state()`, `derive_local_consensus()`, `evaluate_windows_update_state()`, and `check_current_system()`: `ProductName`, WMI `Caption`, and `DisplayVersion` remain diagnostics.
* `query_wua_secondary()` remains read-only and secondary; WUA offers/history can explain behavior but never override the signed policy verdict.
* Strict-production mode returns production-green only from fresh live signed remote JSON. Cache and bundled fallback remain visible degraded evidence.
* Public Pages checks validate policy/signature/manifest/API aliases and fail stale feed timestamps instead of treating HTTP reachability as enough.

### Hardened

* `win11_release_guard/json_utils.py` rejects duplicate JSON keys, non-finite numbers, invalid UTF-8, wrong object top-level shapes where objects are required, and oversized trust-boundary payloads.
* Strict JSON and byte caps are applied to policy JSON, manifest JSON, signature JSON, trusted public-key JSON, cache JSON, public endpoint checks, and Microsoft source payload reads.
* Default JSON output compacts bulky local Panther/setup log tails; raw bounded local diagnostics remain available with `--include-raw-local-diagnostics`.
* The live Panther JSON harness treats missing readable Panther/setup sources as a normal clean-machine pass condition and reports `no_panther_source_present` instead of requiring an affected machine.
* Panther/setup logs remain administrator troubleshooting evidence only; they do not decide compliance or override signed public policy.
* Ed25519 verification and key-rotation windows remain enforced in `win11_release_guard/signing.py`; retired or retiring keys need bounded `verify_not_after_utc`.
* Source Diagnostics validation is structured across generator, schema, dashboard, CLI checks, GitHub Actions issue sync, and the publish workflow; `severity: error` blocks Pages publishing while issue state remains diagnostic.
* Panther/setup collection uses bounded, encoding-aware tail reads across current, UnattendGC, NewOS, `$Windows.~BT`, and rollback locations, with per-path read-error isolation and a deliberately generous global collection cap.
* Panther privacy diagnostics report category, finding type, marker, path, line number, line length, safe hint, count, truncation, and notice metadata only; matched password/token/key/secret values are not copied into privacy findings.

### Documentation

* Rebuilt root release documentation around current code, tests, workflows, `pyproject.toml`, README, docs, and local wiki source.
* Documented the v0.3.1 state that local `wiki/` is source for rendered Pages Wiki HTML and required a separate live GitHub internal Wiki sync at that time.
* Documented that local `site/` is generated output; Pages is regenerated by `.github/workflows/publish-policy.yml` and can be refreshed manually with workflow_dispatch.
* Clarified that wiki changes require a Pages rebuild because they render to `site/wiki/`; docs-only changes still require a rebuild only when they affect dashboard-rendered content, generated metadata, public URLs, or workflow path filters.
* Added `docs/panther-support.md` to describe Panther entry points, supported paths, default/opt-in JSON behavior, privacy notices, useful troubleshooting scenarios, limits, and safe extension rules.

### Workflows

* `.github/workflows/release.yml` requests `contents: write` only for explicit GitHub Release publication; `.github/workflows/sync-wiki.yml` requests it only for GitHub internal Wiki Markdown sync from `wiki/*.md`.
* GitHub Release bodies link the root changelog, detailed `docs/releases/vX.Y.Z.md` notes, Pages dashboard, Pages Wiki/changelog routes, public feed, GitHub internal Wiki sync lane, and the separate PyPI Trusted Publishing lane.
* `.github/workflows/publish-policy.yml` uses `contents: read`, `pages: write`, and `id-token: write`; it generates signed static Pages artifacts, scans them, uploads a Pages artifact, deploys Pages, and runs post-deploy live verification.
* `.github/workflows/pypi-publish.yml` uses `contents: read` globally and `id-token: write` only in `publish-to-pypi`.
* `tools/check_github_action_versions.py` allows `pypa/gh-action-pypi-publish` only in `pypi-publish.yml`, pinned to `cef221092ed1bacb1cc03d23a2d87d1d172e277b`.

### Packaging And PyPI

* `pyproject.toml` package name is `win11_release_guard`, version is `0.3.1`, readme is `README.md`, license is `GPL-3.0-only`, license file is `LICENSE.txt`, author metadata is `Mikail ("Avnsx") C.`, runtime dependency is `cryptography>=41`, and test extras are `packaging>=24` plus `pytest>=8`.
* PyPI project URL is `https://pypi.org/project/win11-release-guard/`; end users install released packages with `python -m pip install win11_release_guard`.
* Console script remains `win11_release_guard = "win11_release_guard.__main__:main"`.
* Package data includes `win11_release_guard/data/*.json` and `win11_release_guard/data/*.sig`.
* Project URLs cover Homepage, Repository, Documentation, Changelog, Bug Tracker, Public Feed, and Pages Dashboard.
* `.github/workflows/pypi-publish.yml` builds wheel and sdist artifacts in generated `dist/`, uploads/downloads that workflow artifact between jobs, and runs `python -m twine check dist/*` before publication.
* PyPI publishing is Trusted Publishing / GitHub OIDC only: project `win11_release_guard`, owner `Avnsx`.
* First publish requires PyPI Pending Trusted Publisher setup if the project is not already live.

### Tests

* Added or updated tests for PyPI publishing workflow guarantees, action pinning, project/package identity, version consistency, clean archive contents, release workflow gates, publish-policy path filters, no-secret scanning, and documentation contracts.
* Prompt-specific verification commands and results are reported in the final task handoff; release notes avoid claiming live or destructive validation that was not rerun in the current context.
