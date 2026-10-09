# Release v0.6.1

Release notes for `0.6.1`, the dashboard reliability release.

---

## Pick Your Path

| You are | Read | Why |
| --- | --- | --- |
| User | [Quick Start](Quick-Start) | Run the guard and understand output/exit codes. |
| Dashboard reader | [GitHub Pages Dashboard](GitHub-Pages-Dashboard) | Expand View, the latest-update notices, and the date format. |
| Maintainer | [Troubleshooting](Troubleshooting) | Read the publish failure issue, now with the signed build's error text. |
| Release manager | [Tagged Release Lane](Tagged-Release-Lane) | Publish a validated source archive and understand the separate PyPI lane. |

## Highlights

| Area | 0.6.1 state |
| --- | --- |
| Versioning | Package/runtime/generator/WUA identity is `win11_release_guard/0.6.1`. |
| Dashboard controls | Expand View and the filters keep working after a same-tab download link or a back/forward return. |
| Latest updates | The expanded diagnostics end with one notice per Windows 11 version: latest update date, build, update kind, KB, and Microsoft's support article. |
| Dates | Every dashboard date reads like "Friday, 9 October 2026, 15:52:04 CEST"; date-only values show no invented time; explicit UTC timestamps stay UTC. |
| Failure issue | A failed signed generation or policy validation reports its error text in the managed `Publish policy is failing` issue. |
| Verdicts | Unchanged. |

## Dashboard Controls

The dashboard script used to stop all of its controls when the browser fired
`beforeunload` or `pagehide`. A same-tab link that only downloads a file, such as
the policy signature, fires `beforeunload` while the page stays open, and a page
restored from the browser's back/forward cache comes back after `pagehide`. In
both cases Expand View and the filters stopped responding until a reload. The
script now stops only on a real unload (`pagehide` that is not kept in the cache)
and refreshes the feed age when the page is restored.

## Latest Update Notices

`Expand View` now ends with one notice per version in Microsoft's Release Health
table, in Microsoft's order, for example:

> Windows 11 26H2 received its latest update on Tuesday, 29 September 2026: build 26300.9550 (2026-09 D, optional preview).

Each notice carries the release, build, update label, and KB number as tags, and
links "Read more" to Microsoft's support article for that build when release
history lists one that passes the same safe-URL check as other support links. B
means the monthly security update, D an optional preview, and OOB an out-of-band
update. LTSC and Hotpatch rows are labelled as such, and a version listed twice
for the same channel and build is shown once. The notices are derived from the signed
policy for display only: they count as notices, never become GitHub issues, and
never affect a verdict. In the collapsed view they stay inside the `+N more` group,
so real source diagnostics stay on top.

## Dates

Dashboard dates use one long format in Berlin time, for example "Friday, 9
October 2026, 15:52:04 CEST" (CET in winter). Timestamps that already state UTC,
such as the source `Fetched` times, stay in UTC, and dual-zone timestamps show
both: "Tuesday, 9 June 2026, 02:00:00 CEST / 00:00:00 UTC". Microsoft's Release
Health dates carry no time of day, so they are shown as a date only, for example
"Tuesday, 29 September 2026", instead of an invented midnight. ISO dates inside
diagnostic messages are rewritten the same way when the dashboard renders them;
the signed policy JSON keeps its ISO values.

## Publish Failure Issue

The managed `Publish policy is failing` issue already quoted errors from the
unsigned preview generation. The signed generation and the policy and signature
validation in the `build` job now also write their output to a log that is
uploaded when the job fails, and the report job passes both logs to
`tools/report_publish_status.py`, which accepts `--generation-log` more than once.
The log is quoted into a public issue and Actions log masking does not cover
files, so before the upload the job drops the log if it contains the signing key
or anything `tools/scan_for_secret_material.py` flags. Workflow command prefixes
such as `::error::` are removed from the quoted excerpt.

## Target Hold Reason

The hold reason now ends after the held target and its baseline, for example
"Windows 11 26H2 has no B release yet (available since Tuesday, 29 September
2026), so 25H2 stays the broad target with required baseline 26200.9445." It fits
the dashboard's 150-character diagnostic summary, so it is no longer cut off.

## Release Gate Result

Local `0.6.1` release preparation passes `compileall`, the project identity,
version consistency, and GitHub Actions pin audits, the full pytest suite, signed
fixture generation, secret scanning, and clean archive export and validation, and
the live `--check-policy-source` and `--check-public-pages` checks pass. The
tagged release in the [Tagged Release Lane](Tagged-Release-Lane) reruns the full
deployment gate.

## Packaging And PyPI

| Item | State |
| --- | --- |
| PyPI project | [win11_release_guard](https://pypi.org/project/win11-release-guard/) |
| End-user install | `python -m pip install win11_release_guard` |
| Package metadata | `pyproject.toml` defines `win11_release_guard` version `0.6.1`, MIT license, console script, project URLs, and package data. |
| Publishing | `.github/workflows/pypi-publish.yml` uses PyPI Trusted Publishing / GitHub OIDC with environment `pypi`. |

## Unchanged Boundaries

| Boundary | Rule |
| --- | --- |
| Verdict | Signed public policy remains the authority. |
| Required baseline | Selected only from a real Release Health B release. |
| Source Diagnostics | Source-health evidence only; notices are dashboard-only and not issue-syncable. |
| `/api/v1` | Existing public aliases remain compatible. |

## Verify Commands

```powershell
python -m compileall -q win11_release_guard tools tests
python tools/check_version_consistency.py
python tools/check_project_identity.py
python tools/check_github_action_versions.py
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"; python -m pytest -q
python -m win11_release_guard --self-test
python -m win11_release_guard --check-policy-source
python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip
python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip
```

## Full Change Notes

The complete change list recorded for v0.6.1.

### Added

* The expanded Source Diagnostics view ends with one notice per Windows 11
  version from the Release Health table: the date of its latest update, its
  build, the update label and kind, its KB number, and a "Read more" link to the
  Microsoft support article for that build when release history lists a safe one.

### Fixed

* The dashboard script stops its controls only on a real unload. A same-tab
  download link or a back/forward cache restore no longer leaves Expand View and
  the filters unresponsive until a reload, and a restored page refreshes the feed
  age.
* The `build` job of `publish-policy.yml` logs the signed generation and the
  policy and signature validation, uploads the log when it fails, and the report
  job passes it to `tools/report_publish_status.py`, so the managed issue quotes
  the error. A log that contains the signing key or other secret material is
  never uploaded.
* The target hold reason fits the dashboard's 150-character summary.

### Changed

* Dashboard dates use the long Berlin-time format, keep explicit UTC timestamps in
  UTC, and show Release Health date-only values without a time of day.

## Related Pages

[Home](Home) | [GitHub Pages Dashboard](GitHub-Pages-Dashboard) | [Troubleshooting](Troubleshooting) | [Tagged Release Lane](Tagged-Release-Lane) | [Release v0.6.0](Release-v0.6.0)
