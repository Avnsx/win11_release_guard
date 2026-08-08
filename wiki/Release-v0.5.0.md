# Release v0.5.0

Compact human summary of the `0.5.0` portable-state release. Code, tests, workflows, `pyproject.toml`, README, docs, local wiki source, and `AGENTS.md` remain source truth.

---

## Pick Your Path

| You are | Read | Why |
| --- | --- | --- |
| User | [Quick Start](Quick-Start) | Run the guard and understand output/exit codes. |
| Admin / RMM owner | [CLI and RMM Usage](CLI-and-RMM-Usage) | Integrate JSON output and strict-production checks. |
| Operator tuning state | [Configuration](Configuration) | Choose where on-disk state lives, or turn it off. |
| Maintainer | [Build, Test and Release](Build-Test-and-Release) | Reproduce local gates and release checks. |
| Release manager | [Tagged Release Lane](Tagged-Release-Lane) | Publish a validated source archive and understand the separate PyPI lane. |
| Future agent | [Agent Chokepoints](Agent-Chokepoints) | Avoid known regression traps. |

## Highlights

| Area | 0.5.0 state |
| --- | --- |
| Versioning | Package/runtime/generator/WUA identity is centralized at `win11_release_guard/0.5.0`. |
| Default cache location | One compact record in the operating-system temp directory instead of a permanent file under `%LOCALAPPDATA%\win11_release_guard\`. |
| State controls | New `--state-dir`, `--stateless`, `--purge-state`, and `--show-state` flags, plus `WIN11_RELEASE_GUARD_STATE_DIR`, `WIN11_RELEASE_GUARD_STATELESS`, and `WIN11_RELEASE_GUARD_CACHE_FILE`. |
| Embedder API | `describe_state`, `purge_state`, and `read_state_bytes` expose the same controls without the CLI. |
| Atomic writes | State, the optional Windows Update cookie cache, the legacy JSON cache pair, and `--output` all write through a staging file and `os.replace`. |
| Resilience | A failed cache write no longer discards a verified policy; an unusable record self-heals on the next run. |
| Verdict | Unchanged: signed policy authority, baseline selection, `/api/v1`, and the 14-day notice window behave exactly as before. |

## What Administrators Get

A run no longer leaves a permanent directory behind on a managed machine. The
default policy cache is one compact, atomically written record in the
operating-system temp directory rather than a permanent JSON file under
`%LOCALAPPDATA%\win11_release_guard\`. On-disk state is an optimisation only: it
never changes the signed compliance verdict and never changes the exit code, and
a verified remote policy is used even when the state write is skipped or fails.

Operators who want a different location, or none at all, have explicit controls.
`--state-dir` moves the record, `--stateless` runs the compliance check with no
state read or write, `--show-state` reports the resolved location, and
`--purge-state` clears it. `--purge-state` and `--show-state` deliberately ignore
`--stateless`, so a fleet that normally runs stateless can still inspect and
clear what an earlier stateful run left behind. `--diagnose-config` now reports
`cache_file` as the effective runtime state location and `null` when the run is
stateless. `--cache-file` keeps its transparent `policy.json` plus `.sig` pair.

Writes are atomic. State, the optional Windows Update cookie cache, the legacy
JSON cache pair, and `--output` all go through a staging file and `os.replace`,
so an interrupted run cannot leave a half-written file or an empty cache
directory behind. A cache write that fails records one `cache_write_failed`
source problem instead of losing the verified policy.

Two files changed their line endings. The Windows Update cookie cache and the
embedder-only `cache.save_policy_cache` helper now serialise their JSON and write
the bytes, so on Windows those two contain LF instead of the previous CRLF. A
`--cache-file` legacy pair is not one of them: it still holds the publisher's
exact policy bytes beside the detached signature, exactly as it always has, so a
cached policy still verifies against its signature.

## Release Gate Result

Local `0.5.0` release preparation passes compileall, the project identity and
version consistency audits, and the full pytest suite. The tagged release lane
reruns the full deployment gate, including signed fixture generation, secret
scanning, clean archive export and validation, and the live public policy-source
and Pages checks.

## Packaging And PyPI

| Item | State |
| --- | --- |
| PyPI project | [win11_release_guard](https://pypi.org/project/win11-release-guard/) |
| End-user install | `python -m pip install win11_release_guard` |
| Package metadata | `pyproject.toml` defines `win11_release_guard` version `0.5.0`, GPL-3.0-only license, console script, project URLs, and package data. |
| Build artifacts | wheel and sdist are generated in `dist/`, checked with `python -m twine check dist/*`, and never committed. |
| Publishing | `.github/workflows/pypi-publish.yml` uses PyPI Trusted Publishing / GitHub OIDC with environment `pypi`. |

## Signed Policy Note

The version bump does not regenerate the signed bundled production policy or
detached signature. The stored policy and signature bytes round-trip
byte-identically through the new state record, so a cached policy still verifies
against its detached signature. Release packaging and Pages publishing must use
the existing secure signing workflow with the real policy signing key.

## Unchanged Boundaries

| Boundary | Rule |
| --- | --- |
| Verdict | Signed public policy remains the authority. |
| On-disk state | Optimisation only; never changes the verdict or the exit code. |
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
python -m win11_release_guard --show-state
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

[Home](Home) | [Configuration](Configuration) | [Architecture](Architecture) | [Source Diagnostics](Source-Diagnostics) | [Policy Feed and Trust Model](Policy-Feed-and-Trust-Model) | [Tagged Release Lane](Tagged-Release-Lane) | [Build, Test and Release](Build-Test-and-Release)
