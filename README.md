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
| Version | `0.6.1` |
| Console script | `win11_release_guard` |
| Python entry point | `python -m win11_release_guard` |
| Repository | `https://github.com/Avnsx/win11_release_guard` |
| PyPI | `https://pypi.org/project/win11-release-guard/` |
| Public feed | `https://avnsx.github.io/win11_release_guard/windows-release-policy.json` |
| License | MIT |

## Quick Start

```powershell
python -m pip install win11_release_guard
win11_release_guard --pretty
win11_release_guard --strict-production --json-pretty --no-wua
```

The last line is the usual production/RMM compliance job.

> [!TIP]
> RMM jobs normally want stable JSON and exit codes first; keep WUA as secondary read-only context unless you explicitly need local update-offer evidence. See [CLI and RMM Usage](https://avnsx.github.io/win11_release_guard/wiki/CLI-and-RMM-Usage/).

## What It Checks

| Check | Rule |
| --- | --- |
| Verdict source | The signed public policy decides; local WUA diagnostics never override the policy verdict. |
| Installed release | Build-first local evidence; `ProductName`, WMI `Caption`, and `DisplayVersion` stay diagnostic. |
| Fleet target | The newest H2 release once it has its first monthly security (B) release; 26H1 is excluded for existing devices. |
| Output | Human, JSON, and JSON-pretty output with stable exit codes. |

Detail: [Architecture](https://avnsx.github.io/win11_release_guard/wiki/Architecture/), [Local Windows Detection](https://avnsx.github.io/win11_release_guard/wiki/Local-Windows-Detection/), [FAQ](https://avnsx.github.io/win11_release_guard/wiki/FAQ/).

## Public Feed And Dashboard

| Public artifact | URL |
| --- | --- |
| Signed policy JSON | https://avnsx.github.io/win11_release_guard/windows-release-policy.json |
| Detached signature | https://avnsx.github.io/win11_release_guard/windows-release-policy.json.sig |
| Policy manifest | https://avnsx.github.io/win11_release_guard/policy-manifest.json |

`/api/v1` mirrors these as stable aliases, kept backward compatible, with signing-key overlap, for at least 24 months.

> [!NOTE]
> `Policy Feed Currency` is the latest compilation timestamp for the parsed policy results. If it looks old, check the [publish-policy workflow](https://github.com/Avnsx/win11_release_guard/actions/workflows/publish-policy.yml) and the [Anti-Static Freshness](https://avnsx.github.io/win11_release_guard/wiki/Anti-Static-Freshness/) notes.

Detail: [GitHub Pages Dashboard](https://avnsx.github.io/win11_release_guard/wiki/GitHub-Pages-Dashboard/), [dashboard docs](https://github.com/Avnsx/win11_release_guard/blob/main/docs/dashboard-and-pages.md).

## Safety And Trust Model

- Runtime clients do not authenticate to GitHub and do not need GitHub tokens, private repository access, or a paid signing certificate. The private signing key lives only in a GitHub Actions secret.
- The production generator may use public Microsoft Release Health HTML, the public Microsoft servicing table-of-contents JSON, public Microsoft servicing support articles, and unauthenticated public MSRC CVRF data for source diagnostics and informational enrichment; it does not use Microsoft Graph or token-authenticated Microsoft APIs.
- Badges are signals, not proof. Dependency freshness is checked by a scheduled workflow. `Dependency freshness` is a scheduled direct-dependency check over direct dependency specifiers, not an always-current dependency guarantee. The Pylint badge reports the workflow for the current `--fail-under=8.0` gate, not a permanent quality certificate.

> [!WARNING]
> Source Diagnostics explain parser/source health and can block publishing on generator `error` events, but they never override the signed runtime verdict. Review [Source Diagnostics](https://avnsx.github.io/win11_release_guard/wiki/Source-Diagnostics/) before treating a warning as fleet compliance evidence.

Detail: [Policy Feed and Trust Model](https://avnsx.github.io/win11_release_guard/wiki/Policy-Feed-and-Trust-Model/), [security automation](https://github.com/Avnsx/win11_release_guard/blob/main/docs/security-automation.md).

## Documentation

| Need | Link |
| --- | --- |
| Pages Wiki home | https://avnsx.github.io/win11_release_guard/wiki/ |
| First run | [Quick Start](https://avnsx.github.io/win11_release_guard/wiki/Quick-Start/) |
| What changed | [Pages changelog](https://avnsx.github.io/win11_release_guard/wiki/changelog/), [v0.6.1 notes](https://github.com/Avnsx/win11_release_guard/blob/main/docs/releases/v0.6.1.md), [CHANGELOG.md](https://github.com/Avnsx/win11_release_guard/blob/main/CHANGELOG.md) |
| Problems | [Troubleshooting](https://avnsx.github.io/win11_release_guard/wiki/Troubleshooting/) |
| Maintainers | [Build, Test and Release](https://avnsx.github.io/win11_release_guard/wiki/Build-Test-and-Release/), [Tagged release lane](https://github.com/Avnsx/win11_release_guard/blob/main/docs/tagged-release-lane.md) |
| Contributors | [Regression Chokepoints](https://avnsx.github.io/win11_release_guard/wiki/Regression-Chokepoints/) |
| GitHub internal Wiki (Markdown mirror) | https://github.com/Avnsx/win11_release_guard/wiki |

The generated Pages Wiki is the primary public, indexed documentation surface. The GitHub Wiki mirrors the same `wiki/*.md` source.

Deployment-affecting changes require the live Pages gate before merging. Use the full gate in [AGENTS.md](https://github.com/Avnsx/win11_release_guard/blob/main/AGENTS.md#deployment-affecting-live-verification-gate) and [Build, Test and Release](https://avnsx.github.io/win11_release_guard/wiki/Build-Test-and-Release/) when changing workflows, the policy generator, signing, Pages, manifest/API aliases, source URLs, or public-check CLI behavior.

## Support The Project

If Windows 11 Release Guard saves you time or helps your fleet checks, please star the repository. Stars make the project easier for other Windows administrators to discover and help justify continued testing, documentation, release automation, and dashboard work.

[![Stargazers repo roster for @Avnsx/win11_release_guard](https://reporoster.com/stars/dark/Avnsx/win11_release_guard)](https://github.com/Avnsx/win11_release_guard/stargazers)

## Contribution, Support, License

[Issues](https://github.com/Avnsx/win11_release_guard/issues) · [Releases](https://github.com/Avnsx/win11_release_guard/releases) · MIT license, see [LICENSE.txt](https://github.com/Avnsx/win11_release_guard/blob/main/LICENSE.txt)

This project is independent open-source software and is not affiliated with Microsoft.
