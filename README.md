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
| Version | `0.5.0` |
| Console script | `win11_release_guard` |
| Python entry point | `python -m win11_release_guard` |
| Repository | `https://github.com/Avnsx/win11_release_guard` |
| PyPI | `https://pypi.org/project/win11-release-guard/` |
| Public feed | `https://avnsx.github.io/win11_release_guard/windows-release-policy.json` |

## What This Does

- Checks Windows 11 release/build/baseline compliance from a signed public JSON release policy feed.
- Uses build-first local evidence; `ProductName`, WMI `Caption`, and `DisplayVersion` stay diagnostic.
- Keeps Windows Update Agent data optional and secondary; WUA diagnostics never override the policy verdict.
- Compacts local Panther/setup log tails in JSON by default, with fixed-path tail-bounded reads and a raw opt-in for troubleshooting.
- Shows Source Diagnostics and workflow-only GitHub Issue links on the dashboard as troubleshooting signals, never fleet verdict authority.
- Shows a dashboard-only baseline-update notice when a real Release Health B-release baseline catches up to the latest observed Microsoft build.
- Treats existing devices as targeting 25H2 while 26H1 remains excluded for existing-device targeting.
- Emits human, JSON, and JSON-pretty output with stable exit codes for RMM/fleet checks.
- Publishes a static GitHub Pages dashboard, Pages Wiki, and `/api/v1` policy, signature, and manifest aliases.

See [Architecture](https://avnsx.github.io/win11_release_guard/wiki/Architecture/), [Local Windows Detection](https://avnsx.github.io/win11_release_guard/wiki/Local-Windows-Detection/), and [Source Diagnostics](https://avnsx.github.io/win11_release_guard/wiki/Source-Diagnostics/) for the detail behind each point.

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

| Public artifact | URL |
| --- | --- |
| Signed policy JSON | https://avnsx.github.io/win11_release_guard/windows-release-policy.json |
| Detached signature | https://avnsx.github.io/win11_release_guard/windows-release-policy.json.sig |
| Policy manifest | https://avnsx.github.io/win11_release_guard/policy-manifest.json |

`/api/v1` mirrors these as stable aliases, kept backward compatible — with signing-key overlap — for at least 24 months. GitHub Pages is static, so feed freshness is recomputed from generated timestamps in the browser and CLI rather than trusted from render time.

> [!NOTE]
> `Policy Feed Currency` is the latest compilation timestamp for the parsed policy results. If it looks old, check the [publish-policy workflow](https://github.com/Avnsx/win11_release_guard/actions/workflows/publish-policy.yml) and the [Anti-Static Freshness](https://avnsx.github.io/win11_release_guard/wiki/Anti-Static-Freshness/) notes.

Deep dive: [GitHub Pages Dashboard](https://avnsx.github.io/win11_release_guard/wiki/GitHub-Pages-Dashboard/), [Policy Feed and Trust Model](https://avnsx.github.io/win11_release_guard/wiki/Policy-Feed-and-Trust-Model/), [dashboard docs](https://github.com/Avnsx/win11_release_guard/blob/main/docs/dashboard-and-pages.md).

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
| Versions | Package/program version is not `schema_version` or `api_version`. | [v0.5.0 notes](https://github.com/Avnsx/win11_release_guard/blob/main/docs/releases/v0.5.0.md) |
| Source diagnostics | Notice/warning/error evidence stays visible; generator `error` events can block publishing but never override compliance verdicts. | [Source Diagnostics](https://avnsx.github.io/win11_release_guard/wiki/Source-Diagnostics/) |

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

- Runtime clients fetch public JSON plus `.sig`. Runtime clients do not authenticate to GitHub and do not need GitHub tokens, private repository access, or a paid signing certificate. The private signing key lives only in a GitHub Actions secret; public verification keys are committed.
- The production generator may use public Microsoft Release Health HTML, the public Microsoft servicing table-of-contents JSON, public Microsoft servicing support articles, and unauthenticated public MSRC CVRF data for source diagnostics and informational enrichment; it does not use Microsoft Graph or token-authenticated Microsoft APIs. Enrichment links and article facts are revalidated before they can affect a summary or a security label.
- Source Diagnostics issue sync and PyPI publishing both run from GitHub Actions with built-in, minimally scoped tokens; neither stores a PAT or API credential.
- GitHub scheduled workflows are best-effort automation, not guaranteed cron. Badge status is a useful signal, not an operational proof.
- Dependency freshness is checked by a scheduled workflow. `Dependency freshness` is a scheduled direct-dependency check over direct dependency specifiers; it is not an always-current dependency guarantee. The Pylint badge reports the workflow for the current `--fail-under=8.0` gate, not a permanent quality certificate.

> [!WARNING]
> Source Diagnostics explain parser/source health and can block publishing on generator `error` events, but they never override the signed runtime verdict. Review [Source Diagnostics](https://avnsx.github.io/win11_release_guard/wiki/Source-Diagnostics/) before treating a warning as fleet compliance evidence.

Deep dive: [Policy Feed and Trust Model](https://avnsx.github.io/win11_release_guard/wiki/Policy-Feed-and-Trust-Model/), [security automation](https://github.com/Avnsx/win11_release_guard/blob/main/docs/security-automation.md).

## Documentation Map

| Need | Link |
| --- | --- |
| Pages Wiki home | https://avnsx.github.io/win11_release_guard/wiki/ |
| Pages changelog | https://avnsx.github.io/win11_release_guard/wiki/changelog/ |
| GitHub internal Wiki (Markdown mirror) | https://github.com/Avnsx/win11_release_guard/wiki |
| Full architecture | [Architecture](https://avnsx.github.io/win11_release_guard/wiki/Architecture/) |
| Maintainer guide | [docs/maintainer-guide.md](https://github.com/Avnsx/win11_release_guard/blob/main/docs/maintainer-guide.md) |
| Release notes | [CHANGELOG.md](https://github.com/Avnsx/win11_release_guard/blob/main/CHANGELOG.md) and [docs/releases/v0.5.0.md](https://github.com/Avnsx/win11_release_guard/blob/main/docs/releases/v0.5.0.md) |
| Safe source archives | [Safe Exports and Clean Archives](https://avnsx.github.io/win11_release_guard/wiki/Safe-Exports-and-Clean-Archives/) |
| FAQ | [FAQ](https://avnsx.github.io/win11_release_guard/wiki/FAQ/) |

The generated Pages Wiki is the primary public, indexed documentation surface. The GitHub internal Wiki is a Markdown-compatible mirror of the same `wiki/*.md` source, synced by `.github/workflows/sync-wiki.yml`. The first-party Python renderer escapes raw HTML and adds no external JS, CSS, fonts, or CDN dependencies.

`CHANGELOG.md` remains the manually maintained changelog source of truth. Newer entries are added at the top; older version sections remain visible in the generated Pages changelog.

## Contribution, Support, License

- Issues: https://github.com/Avnsx/win11_release_guard/issues
- Releases: https://github.com/Avnsx/win11_release_guard/releases
- Changelog: [CHANGELOG.md](https://github.com/Avnsx/win11_release_guard/blob/main/CHANGELOG.md)
- License: GPL-3.0-only, see [LICENSE.txt](https://github.com/Avnsx/win11_release_guard/blob/main/LICENSE.txt)

Do not commit GitHub tokens, private signing keys, generated `site/`, generated `dist/`, `.tmp/`, `dependency-freshness.json`, package metadata folders, pycache, raw worktree archives, or private key scratch files.

This project is independent open-source software and is not affiliated with Microsoft.
