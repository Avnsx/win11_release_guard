# Changelog

## [Unreleased]

### Added

* Added a dashboard-only required-baseline catch-up notice for the case where a real Release Health B-release baseline now matches the broad target's latest observed Microsoft build. The notice is informational, expires after the 21-day source-date window, labels date-only Release Health precision honestly, and does not change signed verdicts, baseline selection, issue sync, or runtime client behavior.

### Fixed

* Tightened support and MSRC enrichment edge cases: safe Support URLs with explicit `:443`, tracking queries, and fragments canonicalize to scheme/host/path; unsafe ports and paths still reject. Support article `Applies to` extraction now handles heading/list and heading/paragraph layouts without swallowing following sections, and exposes `applies_to_releases` for compatibility checks.
* Exact MSRC CVRF KB remediation matches now classify a KB as security even when optional CVE, severity, or product fields are absent.
* Removed CVE lists and counts from baseline notices, Source Diagnostic dashboard rows, and copied visible JSON; administrators still get deterministic security/non-security/unknown labeling with the evidence source.

### Tests

* Added local regression coverage for the baseline-update notice payload, rendering order, dashboard-only issue-sync behavior, degraded evidence wording, Support URL canonicalization, bounded `Applies to` extraction, exact MSRC KB matching, and no raw Support HTML leakage.

## v0.3.3 - 2026-06-11

### Summary

Version 0.3.3 is the corrective source-evidence hardening release. It bumps the package/runtime/generator/WUA identity to `0.3.3`, keeps the signed policy verdict model unchanged, and documents the implemented split between Microsoft Release Health `latest_build`, informational `latest_observed_build`, and the signed `required_baseline_build`. Release Health Current Versions remains the `latest_build` source; Atom-linked Support evidence can advance latest-observed context; baseline rules alone select the compliance floor; when Microsoft sources catch up all three build fields can legitimately match.

### Changed

* Documented the split between Release Health `latest_build`, informational `latest_observed_build`, and signed `required_baseline_build`; Atom-linked Support article evidence can advance latest-observed context without changing the required fleet baseline.
* Documented Source Diagnostics enrichment from Atom-linked Microsoft Support articles and unauthenticated MSRC CVRF data, including no `/help/<KB>` fallback when Atom lacks a support href, Atom-form diagnostic IDs, and GitHub Issue title suffixes such as `[id=968480]`.
* Aligned repository docs and Wiki pages with the caught-up build case, validated Support/MSRC enrichment, unique hash-form or Atom-form Source Diagnostic IDs, dashboard-only notices, static dashboard constraints, and anti patch-only handoff rules.
* Updated current release navigation and generated Pages changelog expectations for `/wiki/changelog/v0.3.3/` while preserving historical `v0.3.2` and `v0.3.1` sections and routes.

### Fixed

* Ensured unique multi-build Atom diagnostic IDs when one Atom entry produces multiple release/build events. The canonical broad-target warning can retain the public Atom-form ID, while sibling events use deterministic hash-form IDs and retain Atom entry, support article, support URL, source URL, and article-id metadata for triage.
* Validated Atom-linked Microsoft Support article URL, KB, build, and applicability evidence before using article facts for Source Diagnostics summaries or Support-derived security labels; mismatches now remain visible as compact validation metadata without trusting the mismatched article text.
* Hardened Microsoft source matching so Atom enrichment uses only safe alternate Support article links, Support URLs reject unsafe hosts, paths, ports, and traversal while stripping tracking queries and fragments from otherwise safe article URLs, MSRC CVRF joins require exact KB tokens, and unknown applies-to evidence degrades instead of silently passing.
* Kept security classification honest when enrichment is incomplete: exact MSRC CVRF KB-token evidence can still classify a KB as security, malformed or unavailable CVRF remains unknown/unavailable, and title-only `OS Build(s)` wording or mismatched Support article text is not treated as security proof.
* Added AGENTS.md and archive-handoff guardrails that `.tmp/prompt-chain/*.patch` files are local hints only; implementation requires tracked edits, passing tests, required documentation updates, and logical commits. Raw worktree ZIPs remain disallowed release artifacts.

### Tests

* Added generated-output regressions for KB5094126 latest-observed behavior, caught-up Release Health behavior, diagnostic ID uniqueness, Support article mismatch/degraded states, MSRC unavailable/malformed states, API aliases, manifests, and raw Support HTML leakage.
* Added regression coverage for safe Atom `alternate` link selection, support.microsoft.com URL canonicalization/rejection, exact MSRC KB-token joins, applies-to compatibility parsing, visible dashboard/copy JSON diagnostic IDs, and clean archive exclusion of temporary artifacts.

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
