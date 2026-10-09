# Release v0.3.5

Compact human summary of the `0.3.5` client-experience release. Code, tests, workflows, `pyproject.toml`, README, docs, local wiki source, and `AGENTS.md` remain source truth.

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

| Area | 0.3.5 state |
| --- | --- |
| Versioning | Package/runtime/generator/WUA identity is centralized at `win11_release_guard/0.3.5`. |
| Console helpers | The library's short-lived `powershell.exe` and `dism.exe` helpers are spawned with `CREATE_NO_WINDOW` and a hidden `STARTUPINFO` on Windows, so GUI consumers see no console flashes. |
| Verdict | Unchanged: same commands, timeouts, parsing, and signed-policy authority as 0.3.4. |
| Cross-platform | Window hiding is a no-op off Windows, so Linux/macOS and CI behavior is unaffected. |
| Folded-in fixes | Restored dashboard info-icon tooltips and stabilized fixed-date Pages freshness rendering. |

## What Changed

The library reads local Windows state through short-lived console helpers:
`powershell.exe` for `Get-CimInstance Win32_OperatingSystem` and `Get-WinEvent`,
`dism.exe` for `/Get-CurrentEdition` and `/Get-Packages`, and a re-exec of the
package for the secondary Windows Update Agent probe. Previously these spawned
with no window-hiding parameters, so a GUI host (for example a PySide6 admin app
calling `check_current_system(...)`) saw each child briefly pop a black console
window and steal focus.

A new private helper, `win11_release_guard._subprocess_util.hidden_console_kwargs()`,
returns Windows console-hiding `subprocess` keyword arguments — `CREATE_NO_WINDOW`
plus a `STARTUPINFO` with `STARTF_USESHOWWINDOW` and `wShowWindow = SW_HIDE` — and
is merged into every internal `subprocess.run` call without changing any existing
argument. Both Microsoft-documented mechanisms are applied together so any
intermediate shell is hidden as well. Off Windows the helper is a no-op.

This is a window-visibility change only. Commands, search criteria, timeouts,
encodings, parsed output, exit codes, and the signed compliance verdict are
identical to `0.3.4`. The behavior is default-on with no opt-out flag.

`0.3.5` also publishes the earlier staged fixes: the dashboard info-icon hover
tooltips are restored (the tooltip is now `position: absolute` and contained in
the viewport instead of resolving against a `backdrop-filter` ancestor), and the
fixed-date Pages freshness fixtures render against a stable reference time while
production still computes freshness from the real current UTC time.

## Release Gate Result

Local `0.3.5` gates passed `compileall` and the full pytest suite. The tagged
release lane runs the full deployment gate; this release is prepared but not yet
published.

## Packaging And PyPI

| Item | State |
| --- | --- |
| PyPI project | [win11_release_guard](https://pypi.org/project/win11-release-guard/) |
| End-user install | `python -m pip install win11_release_guard` |
| Package metadata | `pyproject.toml` defines `win11_release_guard` version `0.3.5`, GPL-3.0-only license, console script, project URLs, and package data. |
| Build artifacts | wheel and sdist are generated in `dist/`, checked with `python -m twine check dist/*`, and never committed. |
| Publishing | `.github/workflows/pypi-publish.yml` uses PyPI Trusted Publishing / GitHub OIDC with environment `pypi`. |
| First publish | Pending Trusted Publisher setup is required if the project is absent; a PyPI 404 is not a name reservation. |

## Signed Policy Note

The version bump does not regenerate the signed bundled production policy or
detached signature. Release packaging and Pages publishing must use the existing
secure signing workflow with the real policy signing key.

## Unchanged Boundaries

| Boundary | Rule |
| --- | --- |
| Verdict | Signed public policy remains the authority. |
| WUA | Optional read-only secondary probe; never decides the policy verdict. |
| Panther/setup logs | Administrator troubleshooting evidence only. |
| Source Diagnostics | Source-health evidence only; notices are dashboard-only and not issue-syncable. |
| Baseline notice | Informational dashboard output only, visible for 14 days. |
| 26H1 | New-devices-only / excluded for existing devices. |
| `/api/v1` | Existing public aliases remain compatible. |

## Verify Commands

```powershell
python -m compileall -q win11_release_guard tools tests
python tools/check_version_consistency.py
python tools/check_project_identity.py
python tools/check_github_action_versions.py
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"; python -m pytest -q
python -m win11_release_guard --self-test
python tools/scan_for_secret_material.py README.md CHANGELOG.md AGENTS.md docs wiki win11_release_guard tests tools pyproject.toml .github
python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip
python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip
python -m build
python -m twine check dist/*
```

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q
```

## Full Change Notes

The complete change list recorded for v0.3.5.

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

## Related Pages

[Home](Home) | [Architecture](Architecture) | [Local Windows Detection](Local-Windows-Detection) | [Policy Feed and Trust Model](Policy-Feed-and-Trust-Model) | [Tagged Release Lane](Tagged-Release-Lane) | [Build, Test and Release](Build-Test-and-Release)
