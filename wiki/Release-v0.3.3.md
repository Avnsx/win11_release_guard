# Release v0.3.3

Compact human summary of the `0.3.3` corrective source-evidence hardening release. Code, tests, workflows, `pyproject.toml`, README, docs, local wiki source, and `AGENTS.md` remain source truth.

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

| Area | 0.3.3 state |
| --- | --- |
| Versioning | Package/runtime/generator/WUA identity is centralized at `win11_release_guard/0.3.3`. |
| Build semantics | `latest_build` is Release Health Current Versions, `latest_observed_build` is newest supported public Microsoft evidence, and `required_baseline_build` is the signed baseline floor. |
| Atom diagnostics | Multi-build Atom entries keep unique diagnostic IDs; canonical warnings can keep Atom-form IDs while sibling rows use deterministic hash-form IDs. |
| Support validation | Support article URL, KB, build, and parseable applicability are validated before article facts enrich summaries or Support-derived security labels. |
| MSRC joins | CVRF matching requires exact KB tokens; unavailable or malformed CVRF stays unknown/unavailable, and context lists are capped. |
| Baseline notice | Caught-up real B-release baselines can show a 21-day dashboard-only notice without changing verdicts or issue sync. |
| Dashboard | Static Pages keeps unique row IDs, visible validation status, copy/export JSON, no raw Support HTML, no tokens, no CDN, and no external JS/CSS/fonts. |
| Handoff | `.tmp/prompt-chain/*.patch` files are local hints only; tracked edits, tests, docs where needed, and logical commits are required. |
| PyPI lane | `pypi-publish.yml` builds wheel/sdist and publishes through Trusted Publishing / GitHub OIDC only after tag or published-release gates. |

## Source Evidence Semantics

Microsoft public sources can arrive out of order. Release Health Current
Versions remains the `latest_build` source. Atom-linked Support article evidence
can move `latest_observed_build` ahead, but that observation is administrator
context only until baseline rules select the same build as
`required_baseline_build`. When Release Health has caught up and the baseline
rules select that same build, all three build fields can legitimately match.

Atom discovers Support article hrefs; it is not a synthesized `/help/<KB>`
resolver. The generator prefers safe Atom `alternate` links to
`https://support.microsoft.com` article paths and records a Source Diagnostic
when no usable support href exists. Otherwise safe article URLs have tracking
queries and fragments stripped; unsafe ports, userinfo, traversal, overlong
paths, and non-support hosts still reject.

Support article enrichment is trusted only after URL, KB, expected build, and
parseable `Applies to` evidence are compatible with the Atom record. Mismatch
and degraded statuses stay visible without dumping raw article HTML or treating
mismatched article text as summary/security truth. The parser records bounded
`applies_to` text and `applies_to_releases` when release values can be parsed.

MSRC CVRF exact-KB-token evidence can still classify a KB as security when the
Support article is bad. Larger tokens such as `KB50941260`, `15094126`, and
`5094126a` do not match `KB5094126`, and malformed/unavailable CVRF data does
not silently become non-security proof. Exact-KB remediation evidence remains
security evidence even without optional CVE/severity/product fields. Dashboard
and visible JSON exports publish the classification and evidence source, not
CVE lists or counts.

When a real non-preview, non-OOB Release Health B-release row becomes the
required baseline and matches the broad target's latest observed build, the
dashboard can show an informational blue/white baseline-update notice for 21
days from the source-derived official baseline date. It labels date-only
Release Health precision explicitly and uses deterministic local facts from
Release Health, Atom, validated Support, and exact MSRC data. It does not call
an LLM or cloud API, and it does not change signed verdicts, baseline
selection, Source Diagnostics issue sync, runtime behavior, or `/api/v1`
aliases.

## Generated Output Coverage

Generated-output regressions exercise the policy JSON, policy manifest,
dashboard HTML, `/api/v1` aliases, visible Source Diagnostics JSON export, and
remote parser acceptance. They cover the KB5094126 latest-observed case, the
caught-up Release Health case, unique diagnostic IDs, Support mismatch/degraded
states, MSRC unavailable/malformed states, no raw Support HTML leakage, and no
synthesized `/help/5094126` fallback.

## Packaging And PyPI

| Item | State |
| --- | --- |
| PyPI project | [win11_release_guard](https://pypi.org/project/win11-release-guard/) |
| End-user install | `python -m pip install win11_release_guard` |
| Package metadata | `pyproject.toml` defines `win11_release_guard` version `0.3.3`, GPL-3.0-only license, console script, project URLs, and package data. |
| Build artifacts | wheel and sdist are generated in `dist/`, checked with `python -m twine check dist/*`, and never committed. |
| Publishing | `.github/workflows/pypi-publish.yml` uses PyPI Trusted Publishing / GitHub OIDC with environment `pypi`. |
| First publish | Pending Trusted Publisher setup is required if the project is absent; a PyPI 404 is not a name reservation. |

## Signed Policy Note

The local version bump does not regenerate the signed bundled production policy
or detached signature. Release packaging and Pages publishing must use the
existing secure signing workflow with the real policy signing key.

## Unchanged Boundaries

| Boundary | Rule |
| --- | --- |
| Verdict | Signed public policy remains the authority. |
| WUA | Optional read-only secondary probe; never decides the policy verdict. |
| Panther/setup logs | Administrator troubleshooting evidence only. |
| Source Diagnostics | Source-health evidence only; notices are dashboard-only and not issue-syncable. |
| Baseline notice | Informational dashboard output only. |
| 26H1 | New-devices-only / excluded for existing devices. |
| `/api/v1` | Existing public aliases remain compatible. |

## Verify Commands

```powershell
python -m compileall -q win11_release_guard tools tests
python tools/check_version_consistency.py
python tools/check_project_identity.py
python tools/check_github_action_versions.py
pytest -q
python -m win11_release_guard --self-test
python tools/scan_for_secret_material.py README.md CHANGELOG.md AGENTS.md docs wiki win11_release_guard tests tools pyproject.toml .github
python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip
python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip
python -m build
python -m twine check dist/*
```

## Related Pages

[Home](Home) | [Architecture](Architecture) | [Policy Feed and Trust Model](Policy-Feed-and-Trust-Model) | [Source Diagnostics](Source-Diagnostics) | [Tagged Release Lane](Tagged-Release-Lane) | [Build, Test and Release](Build-Test-and-Release)
