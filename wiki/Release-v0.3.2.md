# Release v0.3.2

Compact human summary of the `0.3.2` compatibility and documentation-alignment release. Code, tests, workflows, `pyproject.toml`, README, docs, local wiki source, and `AGENTS.md` remain source truth.

---

## Pick Your Path

| You are | Read | Why |
| --- | --- | --- |
| User | [Quick Start](Quick-Start) | Run the guard and understand output/exit codes. |
| Admin / RMM owner | [CLI and RMM Usage](CLI-and-RMM-Usage) | Integrate JSON output and strict-production checks. |
| Maintainer | [Build, Test and Release](Build-Test-and-Release) | Reproduce local gates and release checks. |
| Release manager | [Tagged Release Lane](Tagged-Release-Lane) | Publish a validated source archive and understand the separate PyPI lane. |
| Future agent | [Agent Chokepoints](Agent-Chokepoints) | Avoid known regression traps. |

## Highlights

| Area | 0.3.2 state |
| --- | --- |
| Versioning | Package/runtime/generator/WUA identity is centralized at `win11_release_guard/0.3.2`. |
| Python support | Package metadata declares Python 3.10, 3.11, 3.12, 3.13, and 3.14. |
| CI | Ubuntu and Windows matrix covers Python 3.10 through 3.14 without allowed-failure jobs. |
| Packaging | Runtime dependency remains `cryptography>=41`; test/tooling extras add `tomli` only for Python before 3.11. |
| Trust | Runtime uses public policy JSON plus detached Ed25519 signature; clients do not authenticate to GitHub. |
| Dashboard | Static Pages shows trust, Source Diagnostics filters, target builds, feed currency, optional static issue links for real warning/error events, and API links. |
| Source Diagnostics | Source-health evidence only; no event changes device compliance verdicts. |
| PyPI lane | `pypi-publish.yml` builds wheel/sdist and publishes through Trusted Publishing / GitHub OIDC only after tag or published-release gates. |

## Compatibility

CI is the active interpreter compatibility gate:

- `ubuntu-latest`: Python 3.10, 3.11, 3.12, 3.13, and 3.14.
- `windows-latest`: Python 3.10, 3.11, 3.12, 3.13, and 3.14.

Release, Pages, PyPI, dependency, and Wiki workflows keep Python 3.12 as their automation toolchain. The package artifacts are universal wheel/sdist outputs; interpreter compatibility is covered by CI and package metadata.

## Source Diagnostics

Source Diagnostics are source-health evidence, not compliance verdict authority. Release Health and Atom/Update History can be temporarily out of step. Preview, OOB, non-broad-target, unknown-family, and missing-KB Atom drift stays `notice` until reliable required-baseline evidence exists. Non-preview broad-target drift with an extracted KB and matching build/release evidence can be `warning`; notice-only drift does not trigger `source_drift_unresolved_after_24h`.

GitHub Issue sync remains workflow-only with `github.token` / `GITHUB_TOKEN`. It tracks real warning/error `source_diagnostics.events` only. Browser JavaScript renders static issue metadata and never writes to GitHub.

## Packaging And PyPI

| Item | State |
| --- | --- |
| PyPI project | [win11_release_guard](https://pypi.org/project/win11-release-guard/) |
| End-user install | `python -m pip install win11_release_guard` |
| Package metadata | `pyproject.toml` defines `win11_release_guard` version `0.3.2`, GPL-3.0-only license, console script, project URLs, and package data. |
| Build artifacts | Wheel and sdist are generated in `dist/`, checked with `python -m twine check dist/*`, and never committed. |
| Publishing | `.github/workflows/pypi-publish.yml` uses PyPI Trusted Publishing / GitHub OIDC with environment `pypi`. |
| First publish | Pending Trusted Publisher setup is required if the project is absent; a PyPI 404 is not a name reservation. |

## Unchanged Boundaries

| Boundary | Rule |
| --- | --- |
| Verdict | Signed public policy remains the authority. |
| WUA | Optional read-only secondary probe; never decides the policy verdict. |
| Panther/setup logs | Administrator troubleshooting evidence only. |
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
python -m build
python -m twine check dist/*
```

## Full Change Notes

The complete change list recorded for v0.3.2.

### Summary

Version 0.3.2 is the compatibility and documentation-alignment release for the current `win11_release_guard` codebase. It bumps the package/runtime/generator/WUA identity to `0.3.2`, extends declared and CI-tested Python support through 3.14, keeps Source Diagnostics as source-health evidence only, and preserves the signed public policy as the device compliance verdict authority. Windows release semantics are unchanged: existing broad-fleet devices target Windows 11 `25H2`; `26H1` remains excluded for existing-device targeting; local build evidence outranks display labels; WUA, Panther/setup logs, DISM, Event Logs, and Source Diagnostics remain diagnostic evidence only.

### Added

* GitHub internal Wiki sync workflow and first-party `tools/sync_github_wiki.py` helper for mirroring `wiki/*.md` source Markdown to the same repository's `.wiki.git` remote with the built-in Actions token, plus dry-run Markdown artifact fallback.
* First-party static Pages Wiki generation from `wiki/*.md`, including `wiki/Home.md` to `/wiki/`, all regular wiki pages to `/wiki/<slug>/`, Markdown-compatible `_Sidebar.md` / `_Footer.md` navigation, stable heading anchors, duplicate-safe heading slugs, and GitHub Wiki double-bracket link conversion (plain, named-page, and labelled forms).
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

## Related Pages

[Home](Home) | [Architecture](Architecture) | [Policy Feed and Trust Model](Policy-Feed-and-Trust-Model) | [Source Diagnostics](Source-Diagnostics) | [Tagged Release Lane](Tagged-Release-Lane) | [Build, Test and Release](Build-Test-and-Release)
