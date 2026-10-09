# Agent Chokepoints

Purpose: list the narrow areas where future documentation or implementation agents most often regress product safety or project identity.

Related links: [maintainer guide](maintainer-guide.md) | [wiki agent chokepoints](../wiki/Agent-Chokepoints.md)

## Chokepoints

| Symptom | Resolution | Verify |
| --- | --- | --- |
| Product/package identity drifts from `win11_release_guard`. | Preserve technical identity; use display name only in prose headings. | `python tools/check_project_identity.py` |
| Display labels are treated as installed OS authority. | Keep build-first local evidence and preserve raw labels as diagnostics. | `pytest -q tests/test_local_state*.py tests/test_evaluator*.py` |
| Fallback cache/bundled policy appears production-green in strict mode. | Strict mode needs live signed remote JSON. | `pytest -q tests/test_runtime_policy_sources*.py` |
| 26H1 becomes existing-device target. | Keep special/new-devices-only exclusion semantics. | `pytest -q tests/test_remote_policy*.py tests/test_policy_generator*.py` |
| Public API aliases break. | Preserve `/api/v1` compatibility. | `python -m win11_release_guard --check-public-pages` |
| Private material enters source or generated Pages. | Keep private keys in GitHub secret / ignored scratch only. | `python tools/scan_for_secret_material.py site win11_release_guard tests tools docs wiki README.md CHANGELOG.md AGENTS.md pyproject.toml .github` |

## Do Not

| Rule |
| --- |
| Do not reintroduce the removed root prototype entrypoint. |
| Do not make runtime clients authenticate to GitHub. |
| Do not use authenticated Microsoft APIs in production generator architecture. |
| Do not weaken tests to make documentation or implementation changes pass. |
| Do not publish raw worktree archives. |

## Required Smoke Tests

```powershell
python -m compileall -q win11_release_guard tools
pytest -q
python tools/check_project_identity.py
python tools/check_version_consistency.py
python -m win11_release_guard --self-test
```
