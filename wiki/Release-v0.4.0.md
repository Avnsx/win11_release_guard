# Release v0.4.0

Release notes for `0.4.0`, the servicing-index source pipeline release.

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

| Area | 0.4.0 state |
| --- | --- |
| Versioning | Package/runtime/generator/WUA identity is centralized at `win11_release_guard/0.4.0`. |
| Release history source | Release history, preview/out-of-band builds, and support article discovery come from Microsoft's Windows 11 servicing index, covering every serviced lane in one small request. |
| Support articles and MSRC | Support-article link validation is active again, and MSRC CVRF security evidence names the affected Microsoft products directly instead of opaque numeric identifiers. |
| Local checks | Local build, edition, and architecture details are read natively on Windows without starting a PowerShell process. |
| Windows Update offer probe | An optional, off-by-default probe can attach corroborating current-offer evidence at notice severity; it never affects the signed verdict. |
| Verdict | Unchanged: signed policy authority, baseline selection, `/api/v1`, and the 14-day notice window behave exactly as before. |

## What Administrators Get

Update history, preview and out-of-band build detection, and support-article
discovery are all sourced from Microsoft's Windows 11 servicing index.
Support-article links are validated against the current Microsoft article
before publishing, so a stale or dead link is caught rather than shipped.
Security evidence from MSRC CVRF names the affected Microsoft products
alongside the exact-KB match.

Local build, edition, and architecture checks read Windows details directly
through the registry and native Windows APIs, without starting a PowerShell
process, so local checks complete faster on Windows hosts. The compliance
verdict those checks feed into is unchanged.

Administrators can optionally enable a Windows Update offer probe that adds
corroborating current-offer evidence at notice severity to the dashboard.
Enabling it never changes the signed compliance verdict. Requests to
Microsoft sources share one HTTP client with consistent headers, response
decompression, bounded response reads, retry with backoff, and conditional
requests.

## Release Gate Result

Local `0.4.0` gates pass compileall, identity/version/action audits, the full
pytest suite, signed fixture generation, secret scanning, clean archive export
and validation, and the live public policy-source and Pages checks. The tagged
release lane reruns the full deployment gate.

## Packaging And PyPI

| Item | State |
| --- | --- |
| PyPI project | [win11_release_guard](https://pypi.org/project/win11-release-guard/) |
| End-user install | `python -m pip install win11_release_guard` |
| Package metadata | `pyproject.toml` defines `win11_release_guard` version `0.4.0`, GPL-3.0-only license, console script, project URLs, and package data. |
| Build artifacts | wheel and sdist are generated in `dist/`, checked with `python -m twine check dist/*`, and never committed. |
| Publishing | `.github/workflows/pypi-publish.yml` uses PyPI Trusted Publishing / GitHub OIDC with environment `pypi`. |

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

The complete change list recorded for v0.4.0.

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

* Release history, preview and out-of-band detection, and support article
  discovery are now derived from Microsoft's Windows 11 servicing index
  instead of the retired Update History feed.
* Support article validation resolves current Microsoft article URLs again,
  so stale or dead support links are caught before publishing.
* MSRC CVRF security enrichment reports the affected Microsoft product names
  alongside exact-KB security evidence, instead of opaque numeric product
  identifiers.
* Outbound requests to Microsoft sources now share one HTTP client with
  consistent headers, transparent response decompression, bounded response
  reads, retry with backoff, and conditional requests, improving resilience
  to transient network and server issues.
* Local Windows build/edition details are now read natively on Windows
  instead of starting a PowerShell process, removing a slow step from the
  common local-check path.
* A servicing index entry that carries a build but no KB article is now
  reported as an informational diagnostic instead of being skipped.

### Added

* Optional, off-by-default Windows Update offer probe that can add
  corroborating current-offer evidence at notice severity. It never affects
  the signed compliance verdict.

### Removed

* Removed the retired Windows Update History Atom feed source path; policy
  generation no longer depends on it or carries its dead source metadata.

## Related Pages

[Home](Home) | [Architecture](Architecture) | [Source Diagnostics](Source-Diagnostics) | [Policy Feed and Trust Model](Policy-Feed-and-Trust-Model) | [Tagged Release Lane](Tagged-Release-Lane) | [Build, Test and Release](Build-Test-and-Release)
