# Agent Chokepoints

Use this before future agents change docs, runtime, generator, signing, workflow, or release behavior.

---

## 1. Technical Identity Drift

| Field | Content |
| --- | --- |
| Symptom | Package/feed/CLI names drift away from `win11_release_guard`. |
| History / what went wrong | Previous identities and prototype entrypoints can be accidentally reintroduced. |
| Resolution / keep it this way | Technical identifiers stay `win11_release_guard`; display name is prose-only. |
| Do not | Rename import package, feed paths, console script, JSON identity, or workflow identifiers. |
| Verify | `python tools/check_project_identity.py` |

## 2. Local Display Labels Overriding Build Evidence

| Field | Content |
| --- | --- |
| Symptom | Local marketing labels decide installed Windows identity. |
| History / what went wrong | Some Windows 11 machines can expose stale labels while build family is current. |
| Resolution / keep it this way | Build-family and signed policy mapping drive evaluation; raw labels stay visible. |
| Do not | Let display labels override `RtlGetVersion`, DISM, kernel, registry, WMI/CIM build signals. |
| Verify | `pytest -q tests/test_local_state*.py tests/test_evaluator*.py tests/test_edge_cases.py` |

## 3. WUA Treated As Verdict Authority

| Field | Content |
| --- | --- |
| Symptom | WUA offer/history changes the target or baseline decision. |
| History / what went wrong | WUA is localized, policy-managed, staged, and noisy. |
| Resolution / keep it this way | WUA stays read-only diagnostic context. |
| Do not | Replace signed policy target with WUA offers or history. |
| Verify | `pytest -q tests/test_wua_probe.py tests/test_wua_diagnostics.py tests/test_evaluator*.py` |

## 4. Special Release Becomes Existing-Device Target

| Field | Content |
| --- | --- |
| Symptom | 26H1 is selected for existing 24H2/25H2 devices. |
| History / what went wrong | Highest release string is not always the broad-fleet target. |
| Resolution / keep it this way | Existing-device target selection excludes special/new-devices-only releases. |
| Do not | Pick target by highest version string alone. |
| Verify | `pytest -q tests/test_remote_policy*.py tests/test_policy_generator*.py tests/test_evaluator*.py` |

## 5. Strict Production Goes Green From Fallback

| Field | Content |
| --- | --- |
| Symptom | Cache or bundled policy returns production-green in strict mode. |
| History / what went wrong | Fallbacks are useful but degraded. |
| Resolution / keep it this way | Strict mode needs fresh live signed remote JSON. |
| Do not | Hide fallback source status or candidate status. |
| Verify | `pytest -q tests/test_runtime_policy_sources*.py tests/test_cli*.py` |

## 6. Public API Alias Break

| Field | Content |
| --- | --- |
| Symptom | `/api/v1` files are missing, mismatched, or undocumented. |
| History / what went wrong | Integrations rely on stable public aliases. |
| Resolution / keep it this way | Keep v1 paths and add fields compatibly. |
| Do not | Remove v1 aliases without documented last-resort trust break. |
| Verify | `python -m win11_release_guard --check-public-pages` |

## Common Agent Mistakes Checklist

| Check |
| --- |
| Did not edit code when asked for docs only. |
| Did not use handover files as source truth. |
| Did not hide raw admin diagnostic values. |
| Did not weaken tests to match a preferred narrative. |
| Did not add external dashboard dependencies. |
| Did not claim live checks without running them. |

## Required Smoke Tests

```powershell
python -m compileall -q win11_release_guard tools
pytest -q
python tools/check_project_identity.py
python tools/check_version_consistency.py
python -m win11_release_guard --self-test
```

## Related Pages

[Home](Home) | [Troubleshooting](Troubleshooting) | [Build, Test and Release](Build-Test-and-Release)
