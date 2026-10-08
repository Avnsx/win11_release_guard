# Release v0.6.0

Compact human summary of the `0.6.0` release-transition release. Code, tests, workflows, `pyproject.toml`, README, docs, local wiki source, and `AGENTS.md` remain source truth.

---

## Pick Your Path

| You are | Read | Why |
| --- | --- | --- |
| User | [Quick Start](Quick-Start) | Run the guard and understand output/exit codes. |
| Admin / RMM owner | [CLI and RMM Usage](CLI-and-RMM-Usage) | See what devices on a new release report while it waits for its first B release. |
| Anyone asking "why not 26H2 yet?" | [FAQ](FAQ) | How the broad target is chosen and when a new release is promoted. |
| Maintainer | [Troubleshooting](Troubleshooting) | Read a held target and the publish failure issue. |
| Release manager | [Tagged Release Lane](Tagged-Release-Lane) | Publish a validated source archive and understand the separate PyPI lane. |
| Future agent | [Agent Chokepoints](Agent-Chokepoints) | Avoid known regression traps. |

## Highlights

| Area | 0.6.0 state |
| --- | --- |
| Versioning | Package/runtime/generator/WUA identity is centralized at `win11_release_guard/0.6.0`. |
| Release transition | A new annual release becomes the broad target only after its first monthly security (B) release; until then the previous release stays the target. |
| Feed publishing | Publishing works again after Windows 11 26H2 stopped it on 2026-09-29. |
| Split-target guard | Generation fails instead of publishing a target that runtime clients would select differently. |
| 26H2 devices | Recognised by build family `26300`; reported as `ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE` while 26H2 waits for its first B release. |
| Failure visibility | A failed publish run opens one managed `Publish policy is failing` GitHub issue that closes itself after the next successful run. |
| Workflows | `actions/setup-python@v7`, `pypa/gh-action-pypi-publish` v1.14.2, and a CI run on `ubuntu-26.04`. |

## What Administrators Get

Microsoft lists a new annual Windows 11 release as General Availability during
the optional preview week, about two weeks before its first Patch Tuesday. Windows
11 26H2 did this on 2026-09-29, and because the guard requires a monthly security
(B) release as the baseline, the public feed stopped refreshing and 26H2 devices
were reported as `UNKNOWN_LOCAL_RELEASE`.

With `0.6.0` the previous release, 25H2, stays the target for existing devices
until 26H2 receives its first B release. Devices on 25H2 keep their September B
baseline, and devices already on 26H2 report
`ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE` (exit code `3`). The dashboard shows a
"Windows 11 26H2 awaits its first B release" notice that names the held target and
its required baseline. The first publish run after 26H2's first B release promotes
it automatically; no configuration change is needed. Clients on `0.5.0` already
follow the hold, because they skip releases marked `not_broad_target`.

If a publish run fails again for any reason, a GitHub issue now says so within
minutes, with the error from the run, instead of the feed silently ageing.

## Release Gate Result

Local `0.6.0` release preparation passes compileall, the project identity,
version consistency, and GitHub Actions pin audits, the full pytest suite, signed
fixture generation, secret scanning, and clean archive export and validation.
Policy generation from the live Microsoft sources succeeds with 25H2 held as the
target, and the live public policy-source and Pages checks pass.

## Packaging And PyPI

| Item | State |
| --- | --- |
| PyPI project | [win11_release_guard](https://pypi.org/project/win11-release-guard/) |
| End-user install | `python -m pip install win11_release_guard` |
| Package metadata | `pyproject.toml` defines `win11_release_guard` version `0.6.0`, GPL-3.0-only license, console script, project URLs, and package data. |
| Build artifacts | wheel and sdist are generated in `dist/`, checked with `python -m twine check dist/*`, and never committed. |
| Publishing | `.github/workflows/pypi-publish.yml` uses PyPI Trusted Publishing / GitHub OIDC with environment `pypi`. |

## Signed Policy Note

The version bump does not regenerate the signed bundled production policy or
detached signature. The public feed is regenerated and signed by
`publish-policy.yml` with the real policy signing key.

## Unchanged Boundaries

| Boundary | Rule |
| --- | --- |
| Verdict | Signed public policy remains the authority. |
| Required baseline | Selected only from a real Release Health B release. |
| WUA | Optional read-only secondary probe; never decides the policy verdict. |
| Source Diagnostics | Source-health evidence only; notices are dashboard-only and not issue-syncable. |
| Baseline notice | Informational dashboard output only, visible for 14 days. |
| 26H1 | New-devices-only / excluded for existing devices. |
| `/api/v1` | Existing public aliases remain compatible; new fields are additive. |

## Verify Commands

```powershell
python -m compileall -q win11_release_guard tools tests
python tools/check_version_consistency.py
python tools/check_project_identity.py
python tools/check_github_action_versions.py
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"; python -m pytest -q
python -m win11_release_guard --self-test
python -m win11_release_guard --check-policy-source
python tools/scan_for_secret_material.py README.md CHANGELOG.md AGENTS.md docs wiki win11_release_guard tests tools pyproject.toml .github
python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip
python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip
python -m build
python -m twine check dist/*
```

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q
```

## Related Pages

[Home](Home) | [FAQ](FAQ) | [Source Diagnostics](Source-Diagnostics) | [Policy Feed and Trust Model](Policy-Feed-and-Trust-Model) | [Troubleshooting](Troubleshooting) | [Tagged Release Lane](Tagged-Release-Lane) | [Build, Test and Release](Build-Test-and-Release)
