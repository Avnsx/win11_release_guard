# Windows 11 Release Guard Wiki

Windows 11 Release Guard helps administrators decide whether an existing Windows 11 device is on the current broad-fleet release and quality baseline. It uses a signed public JSON policy feed, build-first local Windows evidence, and optional read-only WUA diagnostics.

README is the quick entry. This wiki is the deep dive. Code, tests, workflows, and `AGENTS.md` remain source of truth.

![Windows 11 Release Guard GitHub Pages dashboard overview](https://raw.githubusercontent.com/Avnsx/win11_release_guard/main/assets/images/windows-11-release-guard-hero-dashboard.png)

---

## Pick Your Path

| You are | Start here | Why |
| --- | --- | --- |
| New user | [Quick Start](Quick-Start) | Install, run, and verify quickly. |
| Admin / RMM user | [CLI and RMM Usage](CLI-and-RMM-Usage) | JSON output, exit codes, strict-production mode. |
| Maintainer | [Build, Test and Release](Build-Test-and-Release) | Local gates, CI, public feed checks. |
| Release manager | [Tagged Release Lane](Tagged-Release-Lane) | Clean archive release path. |
| Package maintainer | [Tagged Release Lane](Tagged-Release-Lane) | PyPI Trusted Publishing values and tag-gated publish path. |
| Future agent | [Agent Chokepoints](Agent-Chokepoints) | Regression traps and required smoke tests. |

## What This Solves

| Problem | Guard behavior |
| --- | --- |
| Device is still on 24H2 while fleet target is 25H2. | Returns `FEATURE_UPDATE_REQUIRED`. |
| Device has current target but older quality baseline. | Returns `QUALITY_UPDATE_REQUIRED`. |
| Device reports stale display labels. | Preserves raw labels but evaluates from build/policy evidence. |
| WUA does not offer a required feature update. | Keeps policy verdict and adds read-only diagnostics. |
| Static Pages feed gets old. | Uses generated epoch fields plus live age checks. |

## Current Documentation Map

| Page | Contents |
| --- | --- |
| [Architecture](Architecture) | Runtime flow, source hierarchy, module boundaries. |
| [Policy Feed and Trust Model](Policy-Feed-and-Trust-Model) | Signed JSON, Ed25519, manifest, key rotation, JSON hardening. |
| [Local Windows Detection](Local-Windows-Detection) | Build-first detection, local signals, WUA role. |
| [GitHub Pages Dashboard](GitHub-Pages-Dashboard) | Static dashboard and public endpoint contract. |
| [Pages Changelog](https://avnsx.github.io/win11_release_guard/wiki/changelog/) | Generated release history from `CHANGELOG.md`, with historical version sections preserved. |
| [Source Diagnostics](Source-Diagnostics) | Parser/source drift events and publish gate semantics. |
| [Anti-Static Freshness](Anti-Static-Freshness) | `generated_at_epoch_s`, `Date.now()`, 14/45-day gates. |
| [Configuration](Configuration) | Recommended defaults, knobs, fallback behavior. |
| [Release v0.3.2](Release-v0.3.2) | Release highlights, changed areas, verify commands. |
| [Safe Exports and Clean Archives](Safe-Exports-and-Clean-Archives) | Source ZIP rules and validation. |
| [Troubleshooting](Troubleshooting) | Check/action tables for common failures. |
| [FAQ](FAQ) | Short answers to common questions. |

## Core Concepts In One Screen

| Concept | Rule |
| --- | --- |
| Broad target | Existing devices currently target Windows 11 25H2. |
| Special release | 26H1 is new-devices-only / excluded for existing devices. |
| Quality baseline | `required_baseline_build` is the required B-release baseline. |
| Release Health latest | `latest_build` is the Microsoft Release Health Current Versions value. |
| Latest observed | `latest_observed_build` is newest supported public Microsoft evidence and can be newer. |
| Caught-up state | `latest_build`, `latest_observed_build`, and `required_baseline_build` can all match when sources and baseline rules align. |
| Local evidence | Build signals outrank display labels. |
| WUA | Optional read-only explanatory signal. |
| Trust | Public feed plus Ed25519 signature, not repository privacy. |
| Freshness | Browser and CLI recompute age from generated epoch timestamps. |

## Good Defaults

```powershell
python -m win11_release_guard --pretty
python -m win11_release_guard --json-pretty --no-wua
python -m win11_release_guard --strict-production --json-pretty --no-wua
python -m win11_release_guard --check-policy-source
python -m win11_release_guard --check-public-pages
```

## Fast Links

| Resource | Link |
| --- | --- |
| Repository | https://github.com/Avnsx/win11_release_guard |
| README | https://github.com/Avnsx/win11_release_guard/blob/main/README.md |
| Pages dashboard | https://avnsx.github.io/win11_release_guard/ |
| Pages changelog | https://avnsx.github.io/win11_release_guard/wiki/changelog/ |
| Public policy JSON | https://avnsx.github.io/win11_release_guard/windows-release-policy.json |
| Releases | https://github.com/Avnsx/win11_release_guard/releases |
| Release v0.3.2 | [Release v0.3.2](Release-v0.3.2) |
| License | https://github.com/Avnsx/win11_release_guard/blob/main/LICENSE.txt |

The local `wiki/` folder is source for the static Pages Wiki and source/staging for GitHub internal Wiki pages. The Pages workflow renders it to `/wiki/`; `.github/workflows/sync-wiki.yml` can mirror the same `wiki/*.md` Markdown into the live GitHub internal Wiki or produce a dry-run artifact for manual sync fallback.
