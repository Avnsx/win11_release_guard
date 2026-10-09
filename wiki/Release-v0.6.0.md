# Release v0.6.0

Release notes for `0.6.0`, the release-transition release.

---

## Pick Your Path

| You are | Read | Why |
| --- | --- | --- |
| User | [Quick Start](Quick-Start) | Run the guard and understand output/exit codes. |
| Admin / RMM owner | [CLI and RMM Usage](CLI-and-RMM-Usage) | See what devices on a new release report while it waits for its first B release. |
| Anyone asking "why not 26H2 yet?" | [FAQ](FAQ) | How the broad target is chosen and when a new release is promoted. |
| Maintainer | [Troubleshooting](Troubleshooting) | Read a held target and the publish failure issue. |
| Release manager | [Tagged Release Lane](Tagged-Release-Lane) | Publish a validated source archive and understand the separate PyPI lane. |
| Contributor | [Regression Chokepoints](Regression-Chokepoints) | Avoid known regression traps. |

## Highlights

| Area | 0.6.0 state |
| --- | --- |
| Versioning | Package/runtime/generator/WUA identity is centralized at `win11_release_guard/0.6.0`. |
| Release transition | A new annual release becomes the broad target only after its first monthly security (B) release; until then the previous release stays the target. |
| Feed publishing | Publishing works again after Windows 11 26H2 stopped it on 2026-09-29. |
| Split-target guard | Generation fails instead of publishing a target that runtime clients would select differently. |
| 26H2 devices | Recognised by build family `26300`; reported as `ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE` while 26H2 waits for its first B release. |
| Failure visibility | A failed publish run opens one managed `Publish policy is failing` GitHub issue that closes itself after the next successful run. |
| License | MIT, previously GPL-3.0-only. |
| Workflows | `actions/setup-python@v7`, `pypa/gh-action-pypi-publish` v1.14.2, and a CI run on `ubuntu-26.04`. |
| Code layout | Smaller single-purpose modules; dashboard and wiki HTML/CSS/JS in static asset files; output unchanged. |

## What Administrators Get

Microsoft lists a new annual Windows 11 release as General Availability during
the optional preview week, about two weeks before its first Patch Tuesday. Windows
11 26H2 did this on 2026-09-29 with only an optional preview (D) update. The
generator picked the newest H2 release as the broad target, could not select a
B-release baseline for it, and every scheduled `publish-policy.yml` run failed
from 2026-09-29 22:21 UTC, so the public feed stopped refreshing and 26H2 devices
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

## Scope

| Item | Current state |
| --- | --- |
| Package/program version | `0.6.0` from `pyproject.toml` and `win11_release_guard.version.package_version()` |
| Package name | `win11_release_guard` |
| Runtime identity | `win11_release_guard/0.6.0` for runtime user-agent, generator identity, and WUA client application ID |
| Python support | `>=3.10` with classifiers for 3.10, 3.11, 3.12, 3.13, and 3.14 |
| CI compatibility gate | `ci.yml` tests Ubuntu and Windows across Python 3.10–3.14, plus Python 3.12 on `ubuntu-26.04`, without `continue-on-error` |
| API compatibility | Policy `schema_version` remains `1`; public `api_version` remains `v1`; new metadata keys and the new notice kind are additive |
| Verdict model | Signed public policy JSON plus detached signature remains the compliance authority; broad-target selection now also requires a monthly security (B) release |
| Source layout | Modules under 800 lines; Pages HTML/CSS/JS in package-data assets; import graph acyclic |
| License | MIT (`LICENSE.txt`, `license = "MIT"` in `pyproject.toml`); releases before `0.6.0` remain GPL-3.0-only |

## Broad Target Hold For New Releases

`broad_target_existing_devices` is the newest supported General Availability H2
release that is not new-devices-only and has a B release in Release Health. A
newer release without one is held only while the held release's newest B
release is dated before the new release became available. Patch Tuesday ships a
B release for every supported version on the same day, so a later B release for
the held release means Release Health is inconsistent. When that is not provable, because a
Patch Tuesday passed without a B release for the new release, its dates are
missing, or the only fallback is a newer release, generation still fails closed.

The pending release stays in `current_versions` with `not_broad_target`,
`not_broad_target_existing_devices`, `pending_first_b_release`, and
`broad_target_hold_reason` metadata. Runtime clients already skip
`not_broad_target` entries, so `0.5.0` clients apply the hold without an update.
A dashboard-only `broad_target_pending_b_release` notice names the held release
and its required baseline; it is never synced to GitHub Issues. The first publish
run after the new release's first B release promotes it automatically.

## Split-Target Guard

Runtime clients choose their target from `current_versions` per edition scope
instead of reading `broad_target_existing_devices`. Generation now runs that
client selection for unknown, Home/Pro, and Enterprise/Education General
Availability devices and fails when any of them would differ from the signed
target, so a policy whose signed target and client verdict disagree cannot be
published.

## Client Changes

- Build family `26300` maps to `26H2` in the offline build-family table, so 26H2
  devices are identified even without a policy.
- Under the B-release-only quality policy, a target with release-history rows but
  no B release no longer uses a preview or out-of-band build as the required
  baseline. No quality baseline is enforced in that case and the result warnings
  say so. This is reachable only through `--explicit-target-release` for a
  release that has not had its first Patch Tuesday.
- `remote_policy` defined `_build_key` twice; the strict validator helper is now
  `_validated_build_key`, and a test rejects any module that redefines a
  top-level name.

## Publish Failure Issue

Source-diagnostic issue sync only reports drift in a policy that was generated,
so the 26H2 failure produced no issue for more than a week of scheduled runs. A final
`report-publish-status` job in `publish-policy.yml` runs after every job unless
the run was cancelled. A failed run opens one `Publish policy is failing` issue
with the captured `Policy generation failed:` line, later failures update it and
comment only when the error changes, and the next successful run closes it. The
issue is found by creator and a body marker rather than by label, its
`internals: publish failure` label stays outside the source-diagnostic labels,
and the report job cannot fail a publish run.

## Workflow Maintenance

| Change | Detail |
| --- | --- |
| `actions/setup-python` | `v7` in every workflow; the removed `pip-install` input was never used. |
| `pypa/gh-action-pypi-publish` | `v1.14.2` at `dc37677b2e1c63e2034f94d8a5b11f265b73ba33`; dependency updates only (Twine 7, sigstore fix for publishes that outlive the GitHub OIDC token). A test pins the reviewed commit. |
| Ubuntu 26.04 | GitHub moves `ubuntu-latest` to Ubuntu 26.04 between 2026-10-19 and 2026-11-19, so CI also runs Python 3.12, the publish lane's version, on `ubuntu-26.04`. |

## Code Layout

Large modules are split into single-purpose modules. The original modules
(`remote_policy`, `evaluator`, `models`, `local_state`, `api`, `__main__`, and the
`policy_generator` package) stay as facades: every public name they defined
before the split is still importable from them, and a test pins that list.
Private helpers are imported from the module that now defines them. The dashboard
and wiki HTML, CSS, and JavaScript live in
`win11_release_guard/policy_generator/pages/assets/` and ship as package data.
Tests patch seams where callers look them up: `policy_generator.clock.utc_now`,
`policy_generator.sources.fetch_url`,
`policy_generator.support_articles.default_support_article_fetcher`, and
`policy_generator.msrc_cvrf.default_msrc_cvrf_fetcher`. Generated output is
byte-identical to the unsplit code.

## Release Gate Result

Local `0.6.0` release preparation passes `compileall`, the project identity,
version consistency, and GitHub Actions pin audits, the full pytest suite, signed
fixture generation, secret scanning, and clean archive export and validation.
Policy generation from the live Microsoft sources succeeds with 25H2 held as the
target and no warning or error events, and the live `--check-policy-source` and
`--check-public-pages` checks pass. The tagged release in the
[Tagged Release Lane](Tagged-Release-Lane) reruns the full deployment gate.

## Packaging And PyPI

| Item | State |
| --- | --- |
| PyPI project | [win11_release_guard](https://pypi.org/project/win11-release-guard/) |
| End-user install | `python -m pip install win11_release_guard` |
| Package metadata | `pyproject.toml` defines `win11_release_guard` version `0.6.0`, MIT license (previously GPL-3.0-only), console script, project URLs, and package data. |
| Console script | `win11_release_guard = "win11_release_guard.__main__:main"` |
| Package data | `win11_release_guard = ["data/*.json", "data/*.sig"]`; `"win11_release_guard.policy_generator.pages" = ["assets/*.css", "assets/*.html", "assets/*.js"]` |
| Build artifacts | wheel and sdist are generated in `dist/`, checked with `python -m twine check dist/*`, and never committed. |
| Publishing | `.github/workflows/pypi-publish.yml` uses PyPI Trusted Publishing / GitHub OIDC with environment `pypi`, no PyPI API token. |

## Signed Policy Note

The version bump does not regenerate the signed bundled production policy or
detached signature. The public feed is regenerated and signed by
`publish-policy.yml` with the real policy signing key.

## Unchanged Boundaries

| Boundary | Rule |
| --- | --- |
| Verdict | Signed public policy remains the authority. |
| Required baseline | Selected only from a real Release Health B release. |
| Local evidence | Windows labels, WUA, Panther/setup logs, DISM, Event Logs, and Source Diagnostics remain diagnostic evidence. |
| WUA | Optional read-only secondary probe; never decides the policy verdict. |
| Source Diagnostics | Source-health evidence only; notices are dashboard-only and not issue-syncable. |
| Baseline notice | Informational dashboard output only, visible for 14 days. |
| 26H1 | New-devices-only / excluded for existing devices. |
| `/api/v1` | Existing public aliases remain compatible; new fields are additive. |
| On-disk state | An optimisation only; it never changes the verdict or the exit code. |

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

## Full Change Notes

The complete change list recorded for v0.6.0.

### Fixed

* The policy feed publishes again after Microsoft lists a new annual Windows 11
  release. Windows 11 26H2 appeared on 2026-09-29 with only an optional preview
  (D) update, and every scheduled publish since then failed with `Could not
  select B-release required baseline for broad_target_existing_devices
  26H2/26300`. The previous release now stays the broad target until the new
  release receives its first monthly security (B) release; the new release is
  published in `current_versions` with `not_broad_target` and
  `pending_first_b_release` metadata and a dashboard-only
  `broad_target_pending_b_release` notice. A missing B release after a Patch
  Tuesday, missing dates, or a newer fallback release still fail closed.
* Generation refuses to publish a policy whose runtime target selection would
  differ from `broad_target_existing_devices`, so the signed target and the
  client verdict cannot split.
* Under the B-release-only quality policy the client no longer uses a preview
  or out-of-band build as the required baseline when the target has no B release
  yet; it enforces no quality baseline and says so in the result warnings.
* `remote_policy` no longer replaces its build sort key with the strict
  validator helper of the same name.

### Added

* The client recognises build family 26300 as Windows 11 26H2 without a policy.
* A failed `publish-policy.yml` run opens one managed `Publish policy is
  failing` GitHub issue with the captured generator error; later failures update
  it and the next successful run closes it.
* CI also runs Python 3.12 on `ubuntu-26.04` ahead of the `ubuntu-latest`
  migration.

### Changed

* The project license is now MIT. `LICENSE.txt` carries GitHub's MIT template,
  `pyproject.toml` declares `license = "MIT"`, and the dashboard footer and docs
  name the MIT license. Releases before `0.6.0` remain GPL-3.0-only.
* GitHub Actions now use `actions/setup-python@v7` and
  `pypa/gh-action-pypi-publish` v1.14.2
  (`dc37677b2e1c63e2034f94d8a5b11f265b73ba33`).
* The source code is split into smaller single-purpose modules, and the Pages
  dashboard and wiki HTML, CSS, and JavaScript now live in static asset files
  shipped with the package. Behaviour and generated output are unchanged; tests
  guard the 800-line module limit, the acyclic import graph, and the absence of
  inline web code. Every public name the split modules defined before stays
  importable from them.

## Related Pages

[Home](Home) | [FAQ](FAQ) | [Source Diagnostics](Source-Diagnostics) | [Policy Feed and Trust Model](Policy-Feed-and-Trust-Model) | [Troubleshooting](Troubleshooting) | [Tagged Release Lane](Tagged-Release-Lane) | [Build, Test and Release](Build-Test-and-Release)
