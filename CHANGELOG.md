# Changelog

Key changes per release. Each version links to its full release notes in the [Pages wiki](https://avnsx.github.io/win11_release_guard/wiki/).

## [Unreleased]

No unreleased changes yet.

## v0.6.0 - 2026-10-09

### Summary

Windows 11 Release Guard keeps its signed policy feed current when Microsoft
releases a new annual Windows 11 version. The feed had stopped refreshing after
26H2 arrived on 2026-09-29 with only a preview update; 25H2 now stays the target
for existing devices until 26H2 receives its first monthly security update, and
devices already on 26H2 are reported as above the target. Failed publish runs
now open a GitHub issue automatically, and the project is now MIT-licensed.

### Fixed

* The feed publishes again after Microsoft lists a new annual release: the previous release stays the broad target until the new one has its first monthly security (B) release.
* Generation refuses to publish a target that runtime clients would select differently.
* Under the default B-release-only policy, a target without a B release no longer falls back to a preview baseline.

### Added

* Build family `26300` is recognised as Windows 11 26H2 without a policy.
* A failed `publish-policy.yml` run opens one managed `Publish policy is failing` issue; the next successful run closes it.
* CI also runs on `ubuntu-26.04`.

### Changed

* License: MIT (previously GPL-3.0-only).
* Source code split into smaller modules; dashboard and wiki HTML, CSS, and JavaScript ship as static asset files. Output is unchanged.
* `actions/setup-python@v7` and `pypa/gh-action-pypi-publish` v1.14.2.

Full notes: [Release v0.6.0](https://avnsx.github.io/win11_release_guard/wiki/Release-v0.6.0/)

## v0.5.0 - 2026-08-08

### Summary

Windows 11 Release Guard no longer leaves a permanent folder behind on the
machines it runs on. Its policy cache is now a single compact file in the
operating system's temp directory, written in one atomic step, so an
interrupted run cannot
leave a half-written file or an empty folder behind, and new switches let an
administrator keep that state in a directory of their choosing, show it, purge
it, or turn it off entirely. Compliance results are unchanged: cached state is
only a speed optimisation and never affects the signed verdict or the exit
code.

### Changed

* The default policy cache is one atomically written record in the OS temp directory instead of a permanent `%LOCALAPPDATA%` folder.
* `--diagnose-config` reports the effective `cache_file` (`null` when the run is stateless).
* `--output` writes atomically; a failure names the path and still exits `2`.
* `cache.save_policy_cache` and the Windows Update cookie cache write LF instead of CRLF on Windows and no longer raise on an unwritable path.
* A `--cache-file` under a missing directory records `cache_write_failed` instead of creating the directory.

### Added

* State controls: `--state-dir`, `--stateless`, `--purge-state`, `--show-state`, the `WIN11_RELEASE_GUARD_STATE_DIR`, `WIN11_RELEASE_GUARD_STATELESS`, and `WIN11_RELEASE_GUARD_CACHE_FILE` environment variables, and the `purge_state`, `describe_state`, and `read_state_bytes` embedder API.

### Fixed

* A failed cache write no longer discards a verified remote policy.
* An unusable state record self-heals instead of failing every run.

Full notes: [Release v0.5.0](https://avnsx.github.io/win11_release_guard/wiki/Release-v0.5.0/)

## v0.4.0 - 2026-08-07

### Summary

Windows 11 Release Guard now reads update history from Microsoft's Windows 11
servicing index and the servicing support articles it references, covering
every serviced Windows 11 lane in a single small request. Support-article
validation and MSRC security classification work again, with security
evidence now naming the affected Microsoft products directly instead of
opaque identifiers. Local system checks are faster because Windows details
are read natively instead of launching PowerShell, and administrators can
optionally enable a Windows Update offer probe for additional corroborating
evidence without affecting the signed verdict.

### Changed

* Release history, preview and out-of-band detection, and support articles come from Microsoft's Windows 11 servicing index instead of the retired Update History feed.
* Support article validation and MSRC security classification work again; security evidence names the affected products.
* Microsoft sources share one HTTP client with bounded reads, decompression, retry, and conditional requests.
* Local Windows details are read natively instead of through PowerShell.

### Added

* Optional, off-by-default Windows Update offer probe; it never affects the signed verdict.

### Removed

* The retired Update History Atom feed source.

Full notes: [Release v0.4.0](https://avnsx.github.io/win11_release_guard/wiki/Release-v0.4.0/)

## v0.3.6 - 2026-07-18

### Summary

Windows 11 Release Guard 0.3.6 keeps the dashboard's security classification
working even when Microsoft's Update History feed lags Patch Tuesday: the
baseline-update notice now checks MSRC security data directly using the Release
Health date, so administrators see a confirmed security label instead of a
neutral placeholder during Microsoft-side feed delays. Enrichment problems now
surface as visible warnings instead of staying silent, and the audited GitHub
Actions checkout pin moved to v7. Device compliance is unchanged: signed policy
verdicts, baseline selection, and the public API behave exactly as before.

### Fixed

* The baseline-update notice keeps its MSRC security label when the Update History feed lags Patch Tuesday.
* Baseline enrichment failures surface as warnings instead of staying silent.

### Changed

* `actions/checkout` is pinned to `v7`.

Full notes: [Release v0.3.6](https://avnsx.github.io/win11_release_guard/wiki/Release-v0.3.6/)

## v0.3.5 - 2026-06-15

### Summary

Windows 11 Release Guard 0.3.5 hides the short-lived console helper windows the
library spawns on Windows, so GUI consumers such as a PySide6 admin app no longer
see PowerShell and DISM windows flash on screen when a system check runs. It also
folds in the earlier dashboard tooltip and Pages freshness-fixture fixes. Device
compliance is unchanged: the same commands run with the same timeouts and parsing,
and the signed policy verdict behaves exactly as before.

### Fixed

* No console windows flash when a GUI app calls `check_current_system(...)` on Windows.
* Dashboard info-icon tooltips show again.
* Fixed-date Pages tests no longer cross the 14-day freshness threshold.

Full notes: [Release v0.3.5](https://avnsx.github.io/win11_release_guard/wiki/Release-v0.3.5/)

## v0.3.4 - 2026-06-13

### Summary

Windows 11 Release Guard 0.3.4 is a polish and reliability release on top of 0.3.3.
It makes the dashboard's security wording match the evidence it actually has, reads
Microsoft's source dates and update links more defensively so unusual data degrades
gracefully instead of breaking, and gives the public wiki and changelog the same
comfortable, readable scale as the dashboard. Device compliance results are
unchanged: the signed policy verdict and required-baseline rules behave exactly as
before.

### Fixed

* Baseline-notice security wording credits only the evidence it has: MSRC, Microsoft Support, or neutral.
* Malformed source dates degrade instead of aborting generation; dates such as `2026-6-9` are accepted.
* The KB-only Atom fallback keeps safe build-agnostic evidence without attaching wrong-build metadata.
* Invalid UTF-8 in wiki or changelog sources no longer crashes generation.

### Changed

* Clean-archive validation ignores ambient pytest configuration.
* The Pages wiki and changelog use the dashboard's reading scale and width.

Full notes: [Release v0.3.4](https://avnsx.github.io/win11_release_guard/wiki/Release-v0.3.4/)

## v0.3.3 - 2026-06-11

### Summary

Version 0.3.3 hardens how Microsoft source evidence is matched and validated, and
separates Release Health `latest_build`, informational `latest_observed_build`, and
the signed `required_baseline_build`. The signed policy verdict model is unchanged.

### Changed

* A dashboard-only notice appears when a real B-release baseline catches up to the latest observed build; it expires after 14 days.

### Fixed

* Multi-build Atom entries get unique Source Diagnostic IDs.
* Support and MSRC enrichment validate URL, KB, build, and applicability before their facts are used.
* Security classification stays honest when enrichment is incomplete; CVE lists are no longer shown.
* Expired baseline notices no longer fetch enrichment or leave a blank dashboard row.

Full notes: [Release v0.3.3](https://avnsx.github.io/win11_release_guard/wiki/Release-v0.3.3/)

## v0.3.2 - 2026-06-10

### Summary

Version 0.3.2 adds the first-party Pages wiki and changelog, a GitHub Wiki mirror,
and Python 3.13 and 3.14 support. Signed policy verdicts and Windows release
semantics are unchanged.

### Added

* Static Pages wiki from `wiki/*.md` and Pages changelog from `CHANGELOG.md`.
* GitHub internal Wiki sync through `sync-wiki.yml`.
* Python 3.13 and 3.14 support and CI coverage.
* Dashboard Source Diagnostics expand and copy-as-JSON controls.

### Changed

* README media and doc links use PyPI-safe absolute URLs.
* `release.yml` requires matching `CHANGELOG.md`, `docs/releases`, and wiki release material.

### Fixed

* README images render on PyPI, and Python versions show on PyPI and Shields.
* Notice events stay dashboard-only in GitHub Issue sync.

Full notes: [Release v0.3.2](https://avnsx.github.io/win11_release_guard/wiki/Release-v0.3.2/)

## v0.3.1 - 2026-06-05

### Summary

Version 0.3.1 is the first documented release: central version identity, the
signed public policy feed and static Pages dashboard, strict JSON trust
boundaries, tagged source releases, and PyPI Trusted Publishing. Existing devices
target Windows 11 `25H2`; `26H1` stays excluded for existing devices.

### Added

* Central version helpers in `win11_release_guard/version.py` and feed freshness helpers.
* Tagged GitHub Release workflow `release.yml`.
* PyPI Trusted Publishing workflow `.github/workflows/pypi-publish.yml`: builds the wheel and sdist, runs `twine check`, and publishes over OIDC; the first publish needs a Pending Trusted Publisher.
* Panther/setup JSON support tooling.

### Changed

* `latest_observed_build` stays separate from `required_baseline_build`.
* The Pages dashboard shows the program version, endpoints, source tiles, diagnostics filters, feed freshness, and signature state.

### Hardened

* Strict JSON parsing and byte caps at every trust boundary.
* Default JSON output compacts Panther/setup log tails; raw tails are opt-in.

Full notes: [Release v0.3.1](https://avnsx.github.io/win11_release_guard/wiki/Release-v0.3.1/)
