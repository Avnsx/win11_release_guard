# Release v0.3.6

Compact human summary of the `0.3.6` source-evidence resilience release. Code, tests, workflows, `pyproject.toml`, README, docs, local wiki source, and `AGENTS.md` remain source truth.

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

| Area | 0.3.6 state |
| --- | --- |
| Versioning | Package/runtime/generator/WUA identity is centralized at `win11_release_guard/0.3.6`. |
| Security classification | The active baseline-update notice derives the MSRC month from the Release Health baseline date when Microsoft's Update History Atom feed lags Patch Tuesday, so MSRC CVRF can classify the baseline KB without waiting for the Atom entry. |
| Enrichment honesty | MSRC fetch failures fire the standard `msrc_cvrf_enrichment_unavailable` warning; a baseline record with a real Atom-linked article whose fetch fails now emits the standard support-enrichment event instead of staying silent. |
| Actions pins | The audited `actions/checkout` pin moved to v7 across all workflows in lockstep with the audit tool, tests, and AGENTS.md list. |
| Verdict | Unchanged: signed policy authority, baseline selection, `/api/v1`, and the 14-day notice window behave exactly as before. |

## What Changed

In July 2026 the live dashboard showed "Security classification is unavailable
from the checked enrichment source." for the new 25H2 baseline 26200.8875 /
KB5101650. An audit confirmed the message was honest: Microsoft's Update
History Atom feed had not published the Patch-Tuesday article (it lagged more
than two weeks), and without an Atom link the generator had no Support URL or
MSRC month to check — even though MSRC CVRF data for July was already public.

`0.3.6` closes that gap. When the baseline record has no Atom dates, the
generator now derives the MSRC month from the Release Health baseline date,
fetches MSRC CVRF for that month, and joins the baseline KB with the existing
exact-KB-token rule. Security is credited to MSRC without an Atom link; no
Support article is fetched or synthesized, so support validation honestly stays
`unavailable`. The neutral wording now appears only when MSRC is also
unavailable or fails — and that failure is recorded as a visible warning event.
The fallback affects only the active baseline notice; release-history
enrichment, `latest_observed_build`, and baseline selection are untouched.

The same release stops suppressing support-enrichment failure events for a
baseline record that has a real Atom-linked article, and moves the audited
`actions/checkout` pin to v7 (Dependabot PR #10) with the audit tool, tests,
and AGENTS.md updated in lockstep.

## Release Gate Result

Local `0.3.6` gates passed compileall, identity/version/action audits, the full
pytest suite, signed fixture generation, secret scanning, clean archive export
and validation, and the live public policy-source and Pages checks. The tagged
release lane reruns the full deployment gate.

## Packaging And PyPI

| Item | State |
| --- | --- |
| PyPI project | [win11_release_guard](https://pypi.org/project/win11-release-guard/) |
| End-user install | `python -m pip install win11_release_guard` |
| Package metadata | `pyproject.toml` defines `win11_release_guard` version `0.3.6`, GPL-3.0-only license, console script, project URLs, and package data. |
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

## Related Pages

[Home](Home) | [Architecture](Architecture) | [Source Diagnostics](Source-Diagnostics) | [Policy Feed and Trust Model](Policy-Feed-and-Trust-Model) | [Tagged Release Lane](Tagged-Release-Lane) | [Build, Test and Release](Build-Test-and-Release)
