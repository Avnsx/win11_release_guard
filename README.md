# win11_release_guard

[![CI](https://github.com/Avnsx/win11_release_guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Avnsx/win11_release_guard/actions/workflows/ci.yml)
[![Publish policy](https://github.com/Avnsx/win11_release_guard/actions/workflows/publish-policy.yml/badge.svg)](https://github.com/Avnsx/win11_release_guard/actions/workflows/publish-policy.yml)
[![CodeQL](https://github.com/Avnsx/win11_release_guard/actions/workflows/codeql.yml/badge.svg)](https://github.com/Avnsx/win11_release_guard/actions/workflows/codeql.yml)
[![Pylint](https://github.com/Avnsx/win11_release_guard/actions/workflows/pylint.yml/badge.svg)](https://github.com/Avnsx/win11_release_guard/actions/workflows/pylint.yml)
[![Dependency audit](https://github.com/Avnsx/win11_release_guard/actions/workflows/dependency-audit.yml/badge.svg)](https://github.com/Avnsx/win11_release_guard/actions/workflows/dependency-audit.yml)
[![Dependency freshness](https://github.com/Avnsx/win11_release_guard/actions/workflows/dependency-freshness.yml/badge.svg)](https://github.com/Avnsx/win11_release_guard/actions/workflows/dependency-freshness.yml)

🛡️ Windows release policy guard for broad-fleet Windows 11 version checks.

`win11_release_guard` tells administrators whether a Windows 11 device is on
the current broad-fleet target release and baseline build. The repository,
distribution package, installed console command, and Python import package use
the same `win11_release_guard` name.

## 🚦 At A Glance

| Need | Command or link |
| --- | --- |
| Run a human check | `python -m win11_release_guard --pretty` |
| Run automation JSON | `python -m win11_release_guard --json-pretty` |
| Verify public feed | `python -m win11_release_guard --check-policy-source` |
| Verify Pages/API | `python -m win11_release_guard --check-public-pages` |
| Local integrity check | `python -m win11_release_guard --self-test` |
| Full technical docs | [GitHub Wiki](https://github.com/Avnsx/win11_release_guard/wiki) |
| Public policy feed | https://avnsx.github.io/win11_release_guard/windows-release-policy.json |

## ✅ What It Does

- Detects installed Windows release/build using build-first local evidence.
- Compares the device with a signed public Windows 11 release policy.
- Handles special cases such as 26H1 being excluded for existing devices.
- Keeps WUA, setup logs, DISM, and local labels as diagnostics only.
- Returns structured results for RMM, dashboards, scripts, and WinMGT
  integration.

## ❌ What It Does Not Do

- It does not install, trigger, hide, or schedule updates.
- It does not make runtime clients authenticate to GitHub.
- It does not need GitHub tokens, private repository access, or a paid signing
  certificate.
- It does not treat WUA availability as policy truth; diagnostics never override the policy verdict.

## 📌 Project Identity

- Project name: `win11_release_guard`
- GitHub repo: `https://github.com/Avnsx/win11_release_guard`
- Public feed: `https://avnsx.github.io/win11_release_guard/windows-release-policy.json`
- Python entry point: `python -m win11_release_guard`
- Console script: `win11_release_guard`

Do not reintroduce the old prototype script named by joining `windows`,
`releases`, and `info` with underscores and adding `.py`; do not revert naming
back to the previous hyphenated project identity.

## ⚡ Quick Start

```powershell
python -m pip install -e ".[test]"
python -m win11_release_guard --pretty
python -m win11_release_guard --json-pretty
python -m win11_release_guard --no-wua --json-pretty
python -m win11_release_guard --strict-production --json-pretty
```

Useful field-debug commands:

```powershell
python -m win11_release_guard --self-test
python -m win11_release_guard --diagnose-config
python -m win11_release_guard --check-policy-source
python -m win11_release_guard --check-public-pages
```

After installation, the console command is also available:

```powershell
win11_release_guard --pretty
win11_release_guard --json
win11_release_guard --policy-url https://avnsx.github.io/win11_release_guard/windows-release-policy.json
```

For RMM or enterprise compliance jobs, use `--strict-production` or set
`WIN11_RELEASE_GUARD_STRICT_PRODUCTION=1`. Strict production keeps the normal
signed-policy trust model, disables unsigned policy acceptance, requires source
checks before returning any production result, and returns `CHECK_INCOMPLETE`
instead of the local verdict, including `OUT_OF_SCOPE`, when the verdict came
from cache, stale cache, bundled policy, local JSON, or any other non-live
remote JSON source. JSON output includes `source_status`, `policy_source_kind`,
`policy_age_hours`, `is_source_check_complete`, and `strict_production`.

Source modes:

- Normal mode: remote signed JSON is preferred; fresh cache, stale cache, and
  bundled policy may still produce a verdict, with `source_status` showing the
  degraded source.
- Strict-production mode: only a complete live signed remote JSON source can
  produce a production result; cache, stale cache, bundled policy, local JSON,
  unsigned policy, and runtime HTML fallback produce `CHECK_INCOMPLETE` and
  exit code 2.
- Offline mode: use the cache or bundled fallback for local triage when network
  access is unavailable; treat the output as degraded evidence unless
  `source_status` is `REMOTE_POLICY_OK`.

`SourceStatus` values:

| SourceStatus | Meaning | Production interpretation |
| --- | --- | --- |
| `REMOTE_POLICY_OK` | Live public JSON and detached signature verified. | Complete production source. |
| `USING_FRESH_CACHE` | Remote source failed, but cache is within fresh age. | Degraded; not strict-production green. |
| `USING_STALE_CACHE` | Cache is older than the fresh age but still within stale fallback age. | Offline/degraded evidence. |
| `USING_BUNDLED_POLICY` | Bundled last-known-good signed policy was used. | Offline triage only. |
| `POLICY_UNAVAILABLE` | No usable signed policy source was available. | `CHECK_INCOMPLETE`; fix source access. |

Exit codes:

| Exit code | Meaning |
| --- | --- |
| `0` | `COMPLIANT` or successful source/self-test check. |
| `1` | Feature update, quality update, or preview-remediation action required. |
| `2` | Unknown local release, policy/source failure, or `CHECK_INCOMPLETE`. |
| `3` | Above broad target or special release. |
| `10` | CLI argument error. |

## 🌐 Public JSON API

| Endpoint | Purpose |
| --- | --- |
| [`/windows-release-policy.json`](https://avnsx.github.io/win11_release_guard/windows-release-policy.json) | Canonical signed policy JSON |
| [`/windows-release-policy.json.sig`](https://avnsx.github.io/win11_release_guard/windows-release-policy.json.sig) | Detached Ed25519 signature |
| [`/policy-manifest.json`](https://avnsx.github.io/win11_release_guard/policy-manifest.json) | Publication manifest and hashes |
| [`/api/v1/policy.json`](https://avnsx.github.io/win11_release_guard/api/v1/policy.json) | API alias for policy JSON |
| [`/api/v1/policy.sig`](https://avnsx.github.io/win11_release_guard/api/v1/policy.sig) | API alias for signature |
| [`/api/v1/manifest.json`](https://avnsx.github.io/win11_release_guard/api/v1/manifest.json) | API alias for manifest |

Runtime clients do not authenticate to GitHub and do not need GitHub tokens.
They fetch public JSON plus the detached `.sig` file and verify the Ed25519
signature locally.

GitHub Pages is static public hosting. The policy JSON, detached signature,
manifest, landing page, and `/api/v1` aliases are static files produced by
GitHub Actions. A scheduled workflow is best-effort automation, not an SLA
cron service: GitHub may delay, skip, or batch scheduled runs. Consumers should
trust verified content, `generated_at_utc`, source diagnostics, signatures,
and manifest hashes, not the assumption that a schedule ran at an exact time.

Manual endpoint checks:

```powershell
curl -I https://avnsx.github.io/win11_release_guard/
curl -I https://avnsx.github.io/win11_release_guard/windows-release-policy.json
curl -I https://avnsx.github.io/win11_release_guard/windows-release-policy.json.sig
curl https://avnsx.github.io/win11_release_guard/robots.txt
```

## 🧠 How The Verdict Works

The evaluator does not simply choose the numerically highest Windows release.
The signed policy decides the broad-fleet target for existing devices. Local
build signals decide what is installed. WUA and event-log evidence explain what
happened locally.

Policy build fields are intentionally separate:

- `baseline_build` and `required_baseline_build` are the required B-release
  compliance floor for broad-fleet checks.
- `latest_build` and `latest_observed_build` are the newest Microsoft Current
  Versions table value observed by the generator. They may include a D Preview
  or another newer observed build.
- A device on a preview build above the B baseline can be `COMPLIANT`, but the
  result still carries preview evidence and pretty output states that preview
  is installed.

Typical result:

| Local device | Signed policy target | Verdict |
| --- | --- | --- |
| Windows 11 24H2, build `26100.x` | Windows 11 25H2, build `26200.x` | `FEATURE_UPDATE_REQUIRED` |
| Windows 11 25H2 B-release baseline | Windows 11 25H2 B-release baseline | `COMPLIANT` |
| Windows 11 25H2 preview above baseline | Windows 11 25H2 B-release baseline | `COMPLIANT` with preview evidence |
| Windows Server | Windows 11 client policy | `OUT_OF_SCOPE` |

Windows 11 Enterprise LTSC and IoT Enterprise LTSC are checked against LTSC
quality baselines instead of being flagged for the normal General Availability
feature target.

## 🔎 Local Evidence Model

Build-first signals:

- `RtlGetVersion`
- Registry build/UBR values
- Optional CIM/WMI `Win32_OperatingSystem`
- Optional `ntoskrnl.exe` file version
- Edition from DISM, `EditionID`, WMI SKU, and `GetProductInfo`

Marketing fields such as `ProductName`, WMI `Caption`, and `DisplayVersion`
are preserved as raw administrator-facing diagnostics, but they are not the
primary truth source.

When build-family signals disagree, the collector records
`raw["build_signal_decision"]` and `raw["build_signal_conflicts"]`. Selection
uses weighted trust instead of a blind majority: `RtlGetVersion` is the
strongest runtime signal, DISM image version can corroborate it, and registry
or WMI metadata cannot silently override a plausible runtime build-family.
`LocalConsensus` carries `LOCAL_BUILD_SIGNAL_CONFLICT` warnings and per-signal
trust classes for machine-readable diagnostics.

## 🔐 Trust Model

The public policy feed is static non-secret data. Trust comes from Ed25519
verification.

- Public verification keys are committed in
  `win11_release_guard/data/trusted_policy_keys.json`.
- The production signing secret is
  `WIN11_RELEASE_GUARD_POLICY_SIGNING_KEY_B64`.
- Private signing keys must never be committed.
- Generated, cached, and bundled policies must verify unless unsigned mode is
  explicitly enabled for a test/lab case.
- In strict production mode, unsigned policy acceptance is disabled even if the
  unsigned lab flag is also provided.
- The bundled policy is a signed last-known-good fallback. If the raw bundled
  JSON is still in the older schema-1 shape, tests must prove that it verifies,
  carries the current public URLs and B-release baseline, and normalizes through
  the runtime model without unknown-key warnings. Do not regenerate it with a
  test signing key.

The production generator uses public Microsoft Release Health and Atom sources only; it does not use token-authenticated Microsoft APIs.

## 🧰 Maintainer Commands

```powershell
python -m compileall -q win11_release_guard tools
python tools/check_project_identity.py
python tools/check_github_action_versions.py
python tools/check_dependency_freshness.py --output dependency-freshness.json
pylint --fail-under=8.0 win11_release_guard tools
pip-audit --local
pytest -q
python tools/scan_for_secret_material.py site win11_release_guard tests tools docs README.md AGENTS.md pyproject.toml .github
python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip
python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip
python -m win11_release_guard --self-test
python -m win11_release_guard --diagnose-config
python -m win11_release_guard --check-policy-source
python -m win11_release_guard --check-public-pages
python -m win11_release_guard --json-pretty --no-wua | python -m json.tool
```

Use the clean archive helper when sharing source snapshots:

```powershell
python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip
python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip
```

It writes `dist/win11_release_guard-source.zip` and excludes Git metadata,
caches, local `site/`, local `.tmp/`, private key files, generated ZIPs, and
other local artifacts. Do not share raw worktree ZIPs; they can include `.git/`,
`.tmp/`, `site/`, `dist/`, package metadata, pycache, and private signing-key
scratch files.

## 🚀 Policy Generator

Generate local Pages artifacts from fixtures:

```powershell
python tools/generate_policy.py `
  --release-health-html tests/fixtures/windows11-release-health.html `
  --atom-feed tests/fixtures/windows11-atom.xml `
  --output-dir site `
  --write-index `
  --write-robots `
  --write-sitemap `
  --write-manifest
```

Create signing keys only in ignored scratch space:

```powershell
python tools/generate_signing_key.py --out-dir .tmp/signing-key
```

Copy the generated private key value into the GitHub Actions secret named
`WIN11_RELEASE_GUARD_POLICY_SIGNING_KEY_B64`. Do not commit private key
material.

## 🧪 Live Verification Gate

Deployment-affecting changes require the live Pages gate before handover.
This includes workflow changes, policy generator changes, signing changes,
Pages landing page changes, manifest/API alias changes, source URL or published URL changes, and CLI changes to `--check-policy-source` or
`--check-public-pages`.

```powershell
python -m compileall -q win11_release_guard tools
pytest -q
python tools/generate_signing_key.py --out-dir .tmp/signing-test --key-id test-policy-key --created-at-utc 2026-06-03T00:00:00+00:00
python tools/generate_policy.py --release-health-html tests/fixtures/windows11-release-health.html --atom-feed tests/fixtures/windows11-atom.xml --output-dir site --write-index --write-robots --write-sitemap --write-manifest --signing-key-file .tmp/signing-test/private-key.b64
python tools/scan_for_secret_material.py site win11_release_guard tests tools docs README.md AGENTS.md pyproject.toml .github
python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip
python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip
python -m win11_release_guard --check-policy-source
python -m win11_release_guard --check-public-pages
```

If live network is unavailable, record that explicitly and do not claim live success. If a live check fails, record the exact failing URL, status, and error, fix it, and rerun the check.

## 📚 In-Depth Documentation

The README is intentionally compact. The full technical material lives in the
[GitHub Wiki](https://github.com/Avnsx/win11_release_guard/wiki):

- [Quick Start](https://github.com/Avnsx/win11_release_guard/wiki/Quick-Start)
- [Reference Manual](https://github.com/Avnsx/win11_release_guard/wiki/Reference-Manual)
- [Policy Feed and Signing](https://github.com/Avnsx/win11_release_guard/wiki/Policy-Feed-and-Signing)
- [Automation and Security](https://github.com/Avnsx/win11_release_guard/wiki/Automation-and-Security)
- [Architecture Insight](https://github.com/Avnsx/win11_release_guard/wiki/Architecture-Insight)
- [Operations Checklist](https://github.com/Avnsx/win11_release_guard/wiki/Operations-Checklist)

Badge notes:

- The badges above report the latest GitHub Actions workflow status only.
- `Dependency freshness` is a scheduled direct-dependency check, not an
  always-current dependency guarantee.
- Dependency freshness is checked by a scheduled workflow.
- GitHub Actions schedules are not SLA cron; GitHub-hosted scheduled runs can
  be delayed or skipped, so the signed feed timestamp and live verification
  output are the operational truth.
- A passing freshness run means direct dependency specifiers in `pyproject.toml`
  allow the latest stable PyPI releases seen by that run.
- The Pylint badge reports the workflow status for the current `--fail-under=8.0` gate, not a permanent quality guarantee.

Workflows opt into GitHub JavaScript action execution on Node 24 with
`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true`.
