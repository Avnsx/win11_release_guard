# Build, Test And Release

Use this when preparing implementation changes, documentation releases, or deployment-affecting updates.

---

## Prerequisites

| Need | Command |
| --- | --- |
| Editable install | `python -m pip install -e ".[test]"` |
| Compile check | `python -m compileall -q win11_release_guard tools` |
| Full tests | `pytest -q` |

## Important Scripts

| Script | Purpose |
| --- | --- |
| `tools/check_project_identity.py` | Technical identity and legacy path guard. |
| `tools/check_version_consistency.py` | Version parity across package/runtime markers. |
| `tools/check_github_action_versions.py` | Action version and third-party action audit. |
| `tools/scan_for_secret_material.py` | Source and generated artifact secret scan. |
| `tools/export_clean_archive.py` | Create and validate clean source ZIP. |
| `tools/generate_policy.py` | Generate signed/static Pages policy artifacts. |
| `.github/workflows/pypi-publish.yml` | Build and publish wheel/sdist through PyPI Trusted Publishing when explicitly run. |

## Critical Smoke Tests

```powershell
python -m compileall -q win11_release_guard tools
python tools/check_project_identity.py
python tools/check_version_consistency.py
python tools/check_github_action_versions.py
pytest -q
python -m win11_release_guard --self-test
```

## Package Build Check

Use this before enabling PyPI publication or handing off a release candidate:

```powershell
python -m pip install -e ".[test]"
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
```

`python -m build` creates wheel and sdist artifacts under generated `dist/`. Do not commit `dist/`.

## Deployment-Affecting Gate

Run this after workflow, generator, signing, Pages, manifest/API, published URL, or public-check CLI changes:

```powershell
python -m compileall -q win11_release_guard tools
pytest -q
python tools/generate_signing_key.py --out-dir .tmp/signing-test --key-id test-policy-key --created-at-utc 2026-06-03T00:00:00+00:00
python tools/generate_policy.py --release-health-html tests/fixtures/windows11-release-health.html --servicing-toc tests/fixtures/windows11-servicing-toc.json --output-dir site --write-index --write-robots --write-sitemap --write-manifest --signing-key-file .tmp/signing-test/private-key.b64
python tools/scan_for_secret_material.py site win11_release_guard tests tools docs wiki README.md CHANGELOG.md AGENTS.md pyproject.toml .github
python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip
python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip
python -m win11_release_guard --check-policy-source
python -m win11_release_guard --check-public-pages
```

If live network is unavailable, say so and do not claim live success.

## Documentation Release Check

```powershell
git diff --name-only
```

Also run the prompt-specific Markdown stale-wording scans before handoff and resolve every hit instead of explaining it away.

For `wiki/*.md`, `CHANGELOG.md`, or Pages documentation changes, regenerate the static Pages output and run the focused Wiki/generator tests:

```powershell
python tools/generate_policy.py --release-health-html tests/fixtures/windows11-release-health.html --servicing-toc tests/fixtures/windows11-servicing-toc.json --output-dir site --write-index --write-robots --write-sitemap --write-manifest
pytest -q tests/test_wiki_markdown_links.py tests/test_policy_generator.py tests/test_pages_landing.py
```

The repository `wiki/` folder is source for the static Pages Wiki and GitHub Wiki source/staging. `publish-policy.yml` renders it to Pages under `/wiki/`; `.github/workflows/sync-wiki.yml` mirrors the same `wiki/*.md` Markdown to the live GitHub internal Wiki when explicitly run as a non-dry-run or triggered by a `vX.Y.Z` tag. Manual dry-runs upload a Markdown artifact for fallback sync. If the live Wiki push fails, the Wiki sync workflow must stay visibly failed while the clean Markdown artifact remains available for manual application.

## PyPI Publishing Check

| Check | Rule |
| --- | --- |
| Trusted Publisher values | Project `win11_release_guard`, owner `Avnsx`, repository `win11_release_guard`, workflow `pypi-publish.yml`, environment `pypi`. |
| PyPI project | `https://pypi.org/project/win11-release-guard/` |
| Trigger | Manual dispatch without a tag is build-only; manual dispatch with an existing `vX.Y.Z` tag, or a published GitHub Release, can publish. No normal push. |
| Publishing model | PyPI Trusted Publishing / GitHub OIDC. |
| Permission | `id-token: write` in the publish job only. |
| Credential rule | No PyPI API token, Twine password, username, or credentialed URL. |
| Package artifacts | Wheel and sdist from generated `dist/`, checked by Twine before publish. |
| Name availability | If PyPI already owns the name under another owner, stop and report. |

## Related Pages

[Home](Home) | [Tagged Release Lane](Tagged-Release-Lane) | [Safe Exports and Clean Archives](Safe-Exports-and-Clean-Archives)
