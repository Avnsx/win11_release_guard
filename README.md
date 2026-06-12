![Windows 11 Release Guard dashboard preview](https://raw.githubusercontent.com/Avnsx/win11_release_guard/main/assets/images/windows-11-release-guard-hero-dashboard.png)

<a href="https://pypi.org/project/win11-release-guard/" aria-label="Download win11_release_guard from PyPI">
  <img align="right"
       src="https://raw.githubusercontent.com/Avnsx/win11_release_guard/main/assets/images/download_from_pypi.png"
       alt="Download from PyPI"
       width="96"
       height="96">
</a>

# Windows 11 Release Guard

[![Python](https://img.shields.io/pypi/pyversions/win11-release-guard?logo=python&label=Python)](https://pypi.org/project/win11-release-guard/)
[![PyPI downloads](https://img.shields.io/pypi/dm/win11-release-guard?label=PyPI%20downloads)](https://pypi.org/project/win11-release-guard/)
[![GitHub Release](https://img.shields.io/github/v/release/Avnsx/win11_release_guard?label=release)](https://github.com/Avnsx/win11_release_guard/releases)
[![Stars](https://img.shields.io/github/stars/Avnsx/win11_release_guard?label=%E2%AD%90%20Stars&color=ffc83d)](https://github.com/Avnsx/win11_release_guard/stargazers)

[![CI](https://github.com/Avnsx/win11_release_guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Avnsx/win11_release_guard/actions/workflows/ci.yml)
[![Publish policy](https://github.com/Avnsx/win11_release_guard/actions/workflows/publish-policy.yml/badge.svg)](https://github.com/Avnsx/win11_release_guard/actions/workflows/publish-policy.yml)
[![Publish Python package](https://github.com/Avnsx/win11_release_guard/actions/workflows/pypi-publish.yml/badge.svg)](https://github.com/Avnsx/win11_release_guard/actions/workflows/pypi-publish.yml)
[![CodeQL](https://github.com/Avnsx/win11_release_guard/actions/workflows/codeql.yml/badge.svg)](https://github.com/Avnsx/win11_release_guard/actions/workflows/codeql.yml)

[![Pylint](https://github.com/Avnsx/win11_release_guard/actions/workflows/pylint.yml/badge.svg)](https://github.com/Avnsx/win11_release_guard/actions/workflows/pylint.yml)
[![Dependency audit](https://github.com/Avnsx/win11_release_guard/actions/workflows/dependency-audit.yml/badge.svg)](https://github.com/Avnsx/win11_release_guard/actions/workflows/dependency-audit.yml)
[![Dependency freshness](https://github.com/Avnsx/win11_release_guard/actions/workflows/dependency-freshness.yml/badge.svg)](https://github.com/Avnsx/win11_release_guard/actions/workflows/dependency-freshness.yml)

Windows release policy guard for broad-fleet Windows 11 version checks.

Windows 11 Release Guard tells administrators whether an existing Windows 11 device is on the current fleet release and quality baseline, using a signed JSON feed, build-first local evidence, a static GitHub Pages dashboard/API, and a PyPI package for sysadmin/RMM automation. The repository, distribution package, installed console command, and Python import package use the same `win11_release_guard` name.

> [!IMPORTANT]
> Compliance trust comes from the signed public policy JSON plus detached signature, not from display labels or badge state. Start with [Policy Feed and Trust Model](https://avnsx.github.io/win11_release_guard/wiki/Policy-Feed-and-Trust-Model/) and [Local Windows Detection](https://avnsx.github.io/win11_release_guard/wiki/Local-Windows-Detection/).

| Fact | Value |
| --- | --- |
| Project / package | `win11_release_guard` |
| Version | `0.3.3` |
| Console script | `win11_release_guard` |
| Python entry point | `python -m win11_release_guard` |
| Repository | `https://github.com/Avnsx/win11_release_guard` |
| PyPI | `https://pypi.org/project/win11-release-guard/` |
| Public feed | `https://avnsx.github.io/win11_release_guard/windows-release-policy.json` |

## What This Does

- Checks Windows 11 release/build/baseline compliance from a signed public JSON release policy feed.
- Uses build-first local evidence; `ProductName`, WMI `Caption`, and `DisplayVersion` stay diagnostic.
- Keeps Windows Update Agent data optional and secondary; WUA diagnostics never override the policy verdict.
- Compacts local Panther/setup log tails in JSON by default while keeping raw bounded local diagnostics available through an explicit CLI opt-in.
- Keeps Panther reads narrow and fast with fixed known paths, per-file tail reads, and a generous global collection guard.
- Treats Panther/setup logs as administrator troubleshooting evidence only; they never decide compliance or override signed public policy.
- Shows Source Diagnostics as Notice, Warning, and Error categories on the static dashboard; these are troubleshooting signals, not fleet verdict authority.
- Shows GitHub Issue ticket links only from workflow-generated static metadata; browser JavaScript never creates or syncs issues.
- Shows a dashboard-only baseline-update notice when a real Release Health B-release required baseline has caught up to the broad target's latest observed Microsoft build.
- Treats existing devices as targeting 25H2 while 26H1 remains excluded for existing-device targeting.
- Emits human output, JSON, JSON-pretty, file output, and stable exit codes for RMM/fleet checks.
- Publishes a static GitHub Pages dashboard, Pages Wiki, and `/api/v1` policy, signature, and manifest aliases.

## Quick Start

Install the released package:

```powershell
python -m pip install win11_release_guard
win11_release_guard --pretty
win11_release_guard --json-pretty --no-wua
win11_release_guard --json-pretty --include-raw-local-diagnostics
```

Production compliance jobs normally use:

```powershell
win11_release_guard --strict-production --json-pretty --no-wua
```

> [!TIP]
> RMM jobs normally want stable JSON and exit codes first; keep WUA as secondary read-only context unless you explicitly need local update-offer evidence. See [CLI and RMM Usage](https://avnsx.github.io/win11_release_guard/wiki/CLI-and-RMM-Usage/).

Deep dive: [Quick Start](https://avnsx.github.io/win11_release_guard/wiki/Quick-Start/), [CLI and RMM Usage](https://avnsx.github.io/win11_release_guard/wiki/CLI-and-RMM-Usage/), [Configuration](https://avnsx.github.io/win11_release_guard/wiki/Configuration/).

## Public Feed And Dashboard

| Artifact | URL |
| --- | --- |
| Pages dashboard | https://avnsx.github.io/win11_release_guard/ |
| Pages Wiki | https://avnsx.github.io/win11_release_guard/wiki/ |
| Pages changelog | https://avnsx.github.io/win11_release_guard/wiki/changelog/ |
| Signed policy JSON | https://avnsx.github.io/win11_release_guard/windows-release-policy.json |
| Detached signature | https://avnsx.github.io/win11_release_guard/windows-release-policy.json.sig |
| Policy manifest | https://avnsx.github.io/win11_release_guard/policy-manifest.json |
| API v1 policy | https://avnsx.github.io/win11_release_guard/api/v1/policy.json |
| API v1 signature | https://avnsx.github.io/win11_release_guard/api/v1/policy.sig |
| API v1 manifest | https://avnsx.github.io/win11_release_guard/api/v1/manifest.json |

Public `/api/v1` aliases and signing-key overlap rules are maintained for at least 24 months unless a documented last-resort trust break is required. GitHub Pages is static; feed freshness is recomputed from generated timestamps in the browser and CLI. Source Diagnostics tiles filter Notices, Warnings, and Errors; `View all` resets the feed. Optional `#Ticket` links are hover/focus-only static links to repository issues when workflow-generated metadata exists for real warning/error source-diagnostic events.

`latest_build` stays the value Microsoft Release Health publishes in the Current Versions table. `latest_observed_build` can be newer when the generator sees a newer official build through the public Atom feed and its linked Microsoft Support article. That value is context for administrators; it does not become `required_baseline_build` unless the normal signed baseline rules select it. When Release Health has caught up and the baseline rules select the same build, `latest_build`, `latest_observed_build`, and `required_baseline_build` can legitimately be identical.

When that caught-up build comes from a real non-preview, non-OOB Release Health B-release row, the dashboard can show an informational baseline-update notice for 14 days from the source-derived official baseline date. The notice uses deterministic local summarization from Release Health, Atom, validated Support article facts, and exact MSRC KB evidence. It does not call an LLM, cloud API, GitHub runtime API, or external script, and it does not change policy verdicts, required-baseline selection, issue sync, or runtime client behavior.

> [!NOTE]
> `Policy Feed Currency` is the latest compilation timestamp for the parsed policy results. If it looks old, check the [publish-policy workflow](https://github.com/Avnsx/win11_release_guard/actions/workflows/publish-policy.yml) and the [Anti-Static Freshness](https://avnsx.github.io/win11_release_guard/wiki/Anti-Static-Freshness/) notes.

Deep dive: [GitHub Pages Dashboard](https://avnsx.github.io/win11_release_guard/wiki/GitHub-Pages-Dashboard/), [Anti-Static Freshness](https://avnsx.github.io/win11_release_guard/wiki/Anti-Static-Freshness/), [dashboard docs](https://github.com/Avnsx/win11_release_guard/blob/main/docs/dashboard-and-pages.md).

## Support The Project

If Windows 11 Release Guard saves you time or helps your fleet checks, please star the repository. Stars make the project easier for other Windows administrators to discover and help justify continued testing, documentation, release automation, and dashboard work.

[![Stargazers repo roster for @Avnsx/win11_release_guard](https://reporoster.com/stars/dark/Avnsx/win11_release_guard)](https://github.com/Avnsx/win11_release_guard/stargazers)

## Common User Paths

| You are | Start here |
| --- | --- |
| New user | [Quick Start](https://avnsx.github.io/win11_release_guard/wiki/Quick-Start/) |
| Admin / RMM user | [CLI and RMM Usage](https://avnsx.github.io/win11_release_guard/wiki/CLI-and-RMM-Usage/) |
| Maintainer | [Build, Test and Release](https://avnsx.github.io/win11_release_guard/wiki/Build-Test-and-Release/) |
| Release manager | [Tagged release lane](https://github.com/Avnsx/win11_release_guard/blob/main/docs/tagged-release-lane.md) |
| Package maintainer | [PyPI Trusted Publishing lane](https://github.com/Avnsx/win11_release_guard/blob/main/docs/tagged-release-lane.md#pypi-trusted-publishing-lane) |
| Future agent | [Agent Chokepoints](https://avnsx.github.io/win11_release_guard/wiki/Agent-Chokepoints/) |

## Core Concepts

| Concept | Short version | Detail |
| --- | --- | --- |
| Trust source | Public JSON plus detached Ed25519 signature decides policy usability. | [Policy Feed and Trust Model](https://avnsx.github.io/win11_release_guard/wiki/Policy-Feed-and-Trust-Model/) |
| Local detection | Build and signed policy evidence are the release truth. | [Local Windows Detection](https://avnsx.github.io/win11_release_guard/wiki/Local-Windows-Detection/) |
| WUA role | Optional read-only explanation for offers/history. | [Troubleshooting](https://avnsx.github.io/win11_release_guard/wiki/Troubleshooting/) |
| Release targeting | 25H2 is the existing-device target; 26H1 is excluded for existing devices. | [Architecture Insight](https://github.com/Avnsx/win11_release_guard/blob/main/docs/architecture-insight.md) |
| Versions | Package/program version is not `schema_version` or `api_version`. | [v0.3.3 notes](https://github.com/Avnsx/win11_release_guard/blob/main/docs/releases/v0.3.3.md) |
| Source diagnostics | Notice/warning/error troubleshooting evidence stays visible; generator `error` events can block policy publishing, but diagnostics do not override runtime compliance verdicts. | [Source Diagnostics](https://avnsx.github.io/win11_release_guard/wiki/Source-Diagnostics/) |

## Maintainer Commands

```powershell
python -m compileall -q win11_release_guard tools tests
python tools/check_project_identity.py
python tools/check_version_consistency.py
python tools/check_github_action_versions.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -q
python tools/scan_for_secret_material.py README.md CHANGELOG.md AGENTS.md docs wiki win11_release_guard tests tools pyproject.toml .github
python -m win11_release_guard --check-policy-source
python -m win11_release_guard --check-public-pages
python -m build
python -m twine check dist/*
python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip
python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip
```

Deployment-affecting changes require the live Pages gate before handover. Use the full gate in [AGENTS.md](https://github.com/Avnsx/win11_release_guard/blob/main/AGENTS.md#deployment-affecting-live-verification-gate) and [Build, Test and Release](https://avnsx.github.io/win11_release_guard/wiki/Build-Test-and-Release/) when changing workflows, the policy generator, signing, Pages, manifest/API aliases, source URLs, or public-check CLI behavior.

## Safety And Trust Model

- Runtime clients fetch public JSON plus `.sig`. Runtime clients do not authenticate to GitHub and do not need GitHub tokens, private repository access, or a paid signing certificate.
- The private policy signing key lives only in the GitHub Actions secret `WIN11_RELEASE_GUARD_POLICY_SIGNING_KEY_B64`; public verification keys are committed.
- The production generator may use public Microsoft Release Health HTML, public Microsoft Update History Atom data, Atom-linked public Microsoft Support articles, and unauthenticated public MSRC CVRF data for source diagnostics and informational enrichment; it does not use Microsoft Graph or token-authenticated Microsoft APIs.
- Atom is discovery for Support article hrefs; the generator uses only safe Atom `alternate` links to `https://support.microsoft.com` article paths, accepts either no port or explicit `:443`, strips tracking query strings and fragments from otherwise safe article URLs, rejects feed/API/search/download/static/traversal URLs, and records Source Diagnostic evidence instead of resolving through `/help/<KB>` when no usable Atom article href exists. Support article facts are validated against the Atom KB, build, selected URL, and parsed release/applicability, including `applies_to_releases` when available, before they can enrich summaries or provide Support-derived security labels. Security-patch classification comes from exact MSRC CVRF KB-token evidence or validated explicit Support article wording, not the Atom title alone; public dashboard/export surfaces expose the classification and evidence source, not CVE lists or counts. Source Diagnostic IDs may be deterministic hash-form or Atom-form; sibling events from a multi-build Atom entry keep unique IDs while retaining Atom metadata for triage.
- Source Diagnostics issue sync runs only for warning/error events in GitHub Actions with the built-in `github.token` / `GITHUB_TOKEN` and minimal `issues: write`; notices stay dashboard-only, and no PAT or extra repository secret is required.
- PyPI publishing uses Trusted Publishing / GitHub OIDC in `.github/workflows/pypi-publish.yml`; no PyPI API token is required.
- GitHub scheduled workflows are best-effort automation, not guaranteed cron. Badge status is a useful signal, not an operational proof.
- Dependency freshness is checked by a scheduled workflow. `Dependency freshness` is a scheduled direct-dependency check over direct dependency specifiers; it is not an always-current dependency guarantee. The Pylint badge reports the workflow for the current `--fail-under=8.0` gate, not a permanent quality certificate.

> [!WARNING]
> Source Diagnostics explain parser/source health and can block publishing on generator `error` events, but they never override the signed runtime verdict. Review [Source Diagnostics](https://avnsx.github.io/win11_release_guard/wiki/Source-Diagnostics/) before treating a warning as fleet compliance evidence.

Deep dive: [policy signing](https://github.com/Avnsx/win11_release_guard/blob/main/docs/policy-signing.md), [security automation](https://github.com/Avnsx/win11_release_guard/blob/main/docs/security-automation.md), [Tagged release lane](https://github.com/Avnsx/win11_release_guard/blob/main/docs/tagged-release-lane.md).

## Documentation Map

| Need | Link |
| --- | --- |
| Pages Wiki home | https://avnsx.github.io/win11_release_guard/wiki/ |
| Pages changelog | https://avnsx.github.io/win11_release_guard/wiki/changelog/ |
| GitHub internal Wiki (Markdown mirror) | https://github.com/Avnsx/win11_release_guard/wiki |
| Full architecture | [Architecture](https://avnsx.github.io/win11_release_guard/wiki/Architecture/) |
| Maintainer guide | [docs/maintainer-guide.md](https://github.com/Avnsx/win11_release_guard/blob/main/docs/maintainer-guide.md) |
| Release notes | [CHANGELOG.md](https://github.com/Avnsx/win11_release_guard/blob/main/CHANGELOG.md) and [docs/releases/v0.3.3.md](https://github.com/Avnsx/win11_release_guard/blob/main/docs/releases/v0.3.3.md) |
| Safe source archives | [Safe Exports and Clean Archives](https://avnsx.github.io/win11_release_guard/wiki/Safe-Exports-and-Clean-Archives/) |
| FAQ | [FAQ](https://avnsx.github.io/win11_release_guard/wiki/FAQ/) |

The generated Pages Wiki is the primary public, indexed documentation surface. The GitHub internal Wiki remains a Markdown-compatible mirror for GitHub-native browsing. The repository `wiki/` folder is source for both. `.github/workflows/publish-policy.yml` renders it into GitHub Pages. `.github/workflows/sync-wiki.yml` can mirror the same `wiki/*.md` source Markdown to the GitHub internal Wiki with the built-in Actions token, or produce a dry-run artifact for manual sync fallback. The Pages renderer is first-party Python, escapes raw HTML, emits local-only inline SVG visuals, and uses no external JS, CSS, fonts, CDN, npm, browser GitHub write path, or browser token.

`CHANGELOG.md` remains the manually maintained changelog source of truth. Newer entries are added at the top; older version sections remain visible in the generated Pages changelog.

## Contribution, Support, License

- Issues: https://github.com/Avnsx/win11_release_guard/issues
- Releases: https://github.com/Avnsx/win11_release_guard/releases
- Changelog: [CHANGELOG.md](https://github.com/Avnsx/win11_release_guard/blob/main/CHANGELOG.md)
- License: GPL-3.0-only, see [LICENSE.txt](https://github.com/Avnsx/win11_release_guard/blob/main/LICENSE.txt)

Do not commit GitHub tokens, private signing keys, generated `site/`, generated `dist/`, `.tmp/`, `dependency-freshness.json`, package metadata folders, pycache, raw worktree archives, or private key scratch files.

This project is independent open-source software and is not affiliated with Microsoft.
