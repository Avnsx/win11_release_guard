# Release v0.3.1

Release notes for `0.3.1`, the hardening and packaging release.

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

| Area | 0.3.1 state |
| --- | --- |
| Versioning | Package/runtime/generator/WUA identity is centralized at `win11_release_guard/0.3.1`. |
| Packaging | `pyproject.toml` defines GPL-3.0-only metadata, `LICENSE.txt`, project URLs, console script, dependencies, test extras, and package data. |
| Trust | Runtime uses public policy JSON plus detached Ed25519 signature; clients do not authenticate to GitHub. |
| Freshness | Manifest/dashboard carry epoch freshness fields; browser age uses `Date.now()` and CLI checks enforce 14/45-day gates. |
| Dashboard | Static Pages shows trust, Source Diagnostics filters, target builds, feed currency, optional static issue links for real warning/error events, and API links. |
| JSON hardening | Strict JSON rejects duplicate keys, non-finite numbers, invalid UTF-8, wrong object top-level shape, and oversized payloads. |
| Local truth | Build evidence beats `ProductName`, WMI `Caption`, and `DisplayVersion`; those values remain raw diagnostics. |
| Local diagnostic output | Default JSON compacts bulky Panther/setup log tails; `--include-raw-local-diagnostics` restores raw bounded local log tails; Panther reads use fixed known paths, 5 MiB per-file tails, and a generous 512 MiB total guard. |
| WUA | Optional read-only secondary probe; never decides the policy verdict. |
| Panther/setup logs | Administrator troubleshooting evidence only; never overrides signed public policy; collection is narrow, tail-bounded, and globally guarded. |
| Release lane | `release.yml` validates `vX.Y.Z` tag/version parity, links changelog/release notes/Pages Wiki/changelog/feed in the release body, and attaches only a validated clean source archive. |
| PyPI lane | `pypi-publish.yml` builds wheel/sdist and publishes through Trusted Publishing / GitHub OIDC only after tag or published-release gates. |

## Packaging And PyPI

| Item | State |
| --- | --- |
| PyPI project | [win11_release_guard](https://pypi.org/project/win11-release-guard/) |
| End-user install | `python -m pip install win11_release_guard` |
| Package metadata | `pyproject.toml` defines `win11_release_guard` version `0.3.1`, GPL-3.0-only license, console script, project URLs, and package data. |
| Build artifacts | Wheel and sdist are generated in `dist/`, checked with `python -m twine check dist/*`, and never committed. |
| Publishing | `.github/workflows/pypi-publish.yml` uses PyPI Trusted Publishing / GitHub OIDC with environment `pypi`. |
| First publish | Pending Trusted Publisher setup is required if the project is absent; a PyPI 404 is not a name reservation. |

## What Changed By Area

| Area | Files / functions |
| --- | --- |
| Versioning | `version.py`, `package_version()`, `runtime_user_agent()`, `generator_version()`, `client_application_id()`, `tools/check_version_consistency.py` |
| Policy feed | `ReleasePolicy`, `ReleasePolicyEntry`, `generate_policy()`, `render_policy_manifest()` |
| Pages dashboard | `render_policy_index()`, `_render_source_diagnostics_panel()`, `_safe_json_script_payload()` |
| Freshness | `freshness.py`, `freshness_policy_metadata()`, `freshness_thresholds()`, `_public_pages_freshness_check()` |
| Runtime loading | `check_current_system()`, `_load_runtime_policy()`, `_load_cache_policy()`, `decide_source_degradation()` |
| Local detection | `get_local_windows_state()`, `derive_local_consensus()`, `evaluate_windows_update_state()`, `query_wua_secondary()` |
| Local diagnostic output | `--include-raw-local-diagnostics`, compact markers such as `content_omitted`, `content_chars`, and `content_bytes_utf8` |
| JSON/signature/cache | `strict_json_loads()`, `strict_json_object()`, `verify_policy_signature()`, `load_trusted_policy()` |
| Workflows | `publish-policy.yml`, `sync-wiki.yml`, `release.yml`, `pypi-publish.yml`, `ci.yml`, action/dependency workflows |
| PyPI publishing | Project `win11_release_guard`, owner `Avnsx`, repository `win11_release_guard`, workflow `pypi-publish.yml`, environment `pypi`, no PyPI token |
| Documentation | `README.md`, `CHANGELOG.md`, `docs/releases/v0.3.1.md`, `docs/`, `wiki/` |

## PyPI Lane

| Check | Rule |
| --- | --- |
| Manual without tag | Build/test/scan/build distributions/Twine check only; publish job is skipped. |
| Manual with tag | Tag must already exist, match `vX.Y.Z`, and match `pyproject.toml` version. |
| Published GitHub Release | Triggers the separate PyPI workflow from the release tag. |
| Package name | Must be `win11_release_guard`. |
| Artifact path | Workflow-generated `dist/`, uploaded/downloaded between jobs. |
| Publish job | GitHub Environment `pypi`; `id-token: write` only in that job. |
| Credentials | No PyPI API token, Twine password, username, or credentialed repository URL. |

## Pages And Wiki

| Topic | Rule |
| --- | --- |
| Local `site/` | Generated output only; do not commit. |
| Pages refresh | `.github/workflows/publish-policy.yml` regenerates and deploys Pages; `workflow_dispatch` can refresh manually. |
| Wiki changes | Pages rebuild because `wiki/*.md` renders to `site/wiki/`. |
| Changelog changes | Pages rebuild because `CHANGELOG.md` renders to `site/wiki/changelog/`. |
| Pages renderer | First-party Python escapes raw HTML, converts GitHub Wiki links, warns on broken or missing Wiki inputs, and may add local-only inline SVG topic icons without changing Markdown source. |
| Docs-only changes | No Pages rebuild unless dashboard-rendered content, generated metadata, public URLs, or workflow path filters change. |
| Local `wiki/` | Source for the static Pages Wiki and source/staging for the live GitHub internal Wiki. |
| Live wiki | `.github/workflows/sync-wiki.yml` can mirror `wiki/*.md` with the built-in Actions token or produce a dry-run artifact for manual fallback. |
| Changelog history | Newer entries are added at the top; older version sections stay visible for Pages changelog, release history, SEO, and auditability. |

## Source Diagnostics

Source Diagnostics are source-health evidence, not compliance verdict authority.
Release Health and Atom/Update History can be temporarily out of step. Preview,
OOB, non-broad-target, unknown-family, and missing-KB Atom drift stays `notice`
until reliable required-baseline evidence exists. Non-preview broad-target drift
with an extracted KB and matching build/release evidence can be `warning`;
notice-only drift does not trigger `source_drift_unresolved_after_24h`.

## Verify Commands

```powershell
python -m compileall -q win11_release_guard tools tests
python tools/check_version_consistency.py
python tools/check_project_identity.py
python tools/check_github_action_versions.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -q tests/test_pypi_publish_workflow.py tests/test_repository_automation.py tests/test_agents_contract.py tests/test_branding_contract.py tests/test_project_identity.py tests/test_import_contract.py -k "pypi or release or changelog or docs or wiki or readme or version or workflow"
python tools/scan_for_secret_material.py README.md CHANGELOG.md AGENTS.md docs wiki win11_release_guard tests tools pyproject.toml .github
python -m build
python -m twine check dist/*
```

## Common Mistakes

| Mistake | Correct behavior |
| --- | --- |
| Treat `schema_version` or `api_version` as the package version. | Use `pyproject.toml` and `package_version()` for program version. |
| Treat `ProductName` or WMI `Caption` as OS authority. | Use build-first evidence and signed policy mapping. |
| Let WUA offers override the policy target. | Keep WUA optional, read-only, and diagnostic. |
| Target existing devices at 26H1. | Keep 26H1 new-devices-only / excluded for existing devices. |
| Commit local `site/` or `dist/`. | Regenerate those as workflow/local build output only. |
| Publish raw worktree ZIPs. | Use `tools/export_clean_archive.py` and validate the archive. |
| Add PyPI credentials to Actions. | Use Trusted Publishing with GitHub OIDC. |
| Create GitHub Issues from dashboard JavaScript. | Keep issue sync workflow-side with the built-in Actions token and static dashboard links only. |
| Assume the Pages publish job also updates the GitHub internal Wiki. | Use the separate `sync-wiki.yml` workflow or its dry-run artifact fallback. |

## Full Change Notes

The complete change list recorded for v0.3.1.

### Summary

Version 0.3.1 documents and hardens the current `win11_release_guard` worktree: package/runtime version identity, signed public policy feed handling, static GitHub Pages output, strict JSON trust boundaries, tagged source releases, and the PyPI Trusted Publishing lane. Windows release semantics are unchanged: existing broad-fleet devices target Windows 11 `25H2`; `26H1` remains excluded for existing-device targeting; local build evidence outranks display labels; WUA remains optional secondary evidence; policy `schema_version` and public `api_version` are not program versions.

These notes describe the code at `main` `56915c9`; there was no earlier release tag to compare against.

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
* These notes claim only validation that was actually run for the release.

## Related Pages

[Home](Home) | [Architecture](Architecture) | [Policy Feed and Trust Model](Policy-Feed-and-Trust-Model) | [Anti-Static Freshness](Anti-Static-Freshness) | [Tagged Release Lane](Tagged-Release-Lane) | [Build, Test and Release](Build-Test-and-Release)
