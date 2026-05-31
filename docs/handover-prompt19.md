# Handover Prompt 19

## Scope

This handover records the real current repository state for `Avnsx/win-release-guard` after Prompt 1 of the new prompt set.

I did not inspect `.git` credentials, credentialed remotes, tokens, private signing keys, or secret values. Source truth used here is the tracked code, workflows, tests, docs, tools, and bundled public policy artifacts.

## Verification commands run

```powershell
python -m compileall -q win11_release_guard tools
pytest -q
python -m win11_release_guard --self-test
python -m win11_release_guard --diagnose-config
python -m win11_release_guard --check-policy-source --policy-url https://avnsx.github.io/win-release-guard/windows-release-policy.json
```

Results:

- `python -m compileall -q win11_release_guard tools`: passed.
- `pytest -q`: passed, `195 passed in 1.10s`.
- `--self-test`: passed with `ok: true`.
- `--diagnose-config`: passed without live remote fetch.
- Production policy source check: passed with `Policy source: OK` and `Signature: valid`.

## Current worktree note

Before this prompt started, the worktree already had:

- Modified: `tools/export_clean_archive.py`
- Modified: `tests/test_export_clean_archive.py`
- Ignored generated artifact: `dist/`

This prompt adds:

- `docs/handover-prompt19.md`

## CLI and package state

Self-test output showed:

- package version: `0.2.0`
- package import: `ok`
- bundled policy loaded: `ok`
- bundled policy signature: `valid`
- policy schema: `ok`
- remote fetch performed: `false`
- WUA probe performed: `false`

Diagnose-config output showed:

- effective policy URL: `https://avnsx.github.io/win-release-guard/windows-release-policy.json`
- policy URL source: `default`
- cache file: `C:\Users\canmi\AppData\Local\win-release-guard\windows-release-policy.json`
- bundled policy present: `true`
- bundled policy signature present: `true`
- bundled policy signature status: `valid`
- bundled policy generated at UTC: `2026-05-28T18:17:50+00:00`
- trusted public key fingerprint: `sha256:cd72e2581e95d9e99205e3b7e0215edc26873dd61d8b19d1927cc34bca13d298`
- WUA default enabled: `false`
- runtime HTML fallback enabled: `false`
- source check required for green: `false`
- live remote fetch performed by diagnose-config: `false`

## Production policy endpoint

Production policy URL is configured in `win11_release_guard/config.py` as:

```text
https://avnsx.github.io/win-release-guard/windows-release-policy.json
```

Live check result:

- Policy source: `OK`
- Signature URL: `https://avnsx.github.io/win-release-guard/windows-release-policy.json.sig`
- Signature: `valid`
- Generated at UTC: `2026-05-31T14:11:50+00:00`
- Broad target: `25H2 / 26200 / 26200.8457`
- Baseline: `26200.8457`
- Excluded release: `26H1 / 28000`

Remaining known warning:

```text
Loaded policy URL is not listed in source_urls.
```

This means the hosted signed artifact is valid and usable, but policy metadata still lists only upstream source URLs, not the hosted policy URL itself.

## Inspected files and findings

### `.github/workflows/ci.yml`

- Exists.
- Runs on `push` and `pull_request`.
- Uses `windows-latest` and Python `3.11`.
- Installs with `python -m pip install -e ".[test]"`.
- Runs compileall, validates console command help, runs `pytest -q`.
- Generates policy from fixtures into `site`.
- Validates generated policy schema.
- Validates CLI JSON using the checked-in bundled policy.

### `.github/workflows/publish-policy.yml`

- Exists.
- Runs on workflow dispatch, schedule, and selected pushes to `main`.
- Schedule is `17 */6 * * *`, every six hours at minute 17.
- Publishes through GitHub Pages.
- Generates signed policy when `WIN11_RELEASE_GUARD_SIGNING_KEY` is configured.
- Falls back to checked-in signed last-known-good policy when the signing key is not configured.
- Validates policy schema and signature before upload.
- I inspected only the workflow logic and secret name reference, not any secret value.

### `README.md`

- Documents policy sources and production URL.
- Documents readiness checks:
  - library readiness via `python -m win11_release_guard --self-test`
  - policy feed readiness via `python -m win11_release_guard --check-policy-source --policy-url ...`
- Documents clean source archive creation via `python tools/export_clean_archive.py`.
- Documents source-tree entry point as `python -m win11_release_guard`.

### `docs/source-learnings.md`

- Exists.
- Still contains historical research and implementation plan text.
- Some `What Must Change` items are now completed in code, including signed JSON runtime policy, generator path ownership, preview/OOB handling, WUA evidence, and audit probes. Treat that section as historical planning unless refreshed in a later prompt.

### `docs/handover-prompt18.md`

- Missing from the current working tree.
- `Test-Path docs\handover-prompt18.md` returned `False`.
- `git ls-files docs/handover-prompt18.md` returned no tracked file.
- Do not trust any previous handover content for Prompt 18 unless it is recovered from another source.

### `tools/generate_policy.py`

- Exists.
- CLI entry point is `python tools/generate_policy.py`.
- Supports live sources, local fixture files, output directory, index generation, signing key from environment variable name, and signing key from file.
- Does not contain private key material.

### `tools/export_clean_archive.py`

- Exists in the working tree.
- Creates `dist/win-release-guard-source.zip`.
- Uses an explicit include list:
  - `win11_release_guard/`
  - `tests/`
  - `tools/`
  - `README.md`
  - `pyproject.toml`
  - `.github/workflows/ci.yml`
  - `docs/`
- Excludes Git metadata, pytest cache, Python bytecode caches, `.cache/`, build/dist internals, local temp output, local JSON outputs, and the legacy prototype script name.
- The current implementation constructs the legacy prototype filename instead of storing the stale old path as a literal, so repo-wide legacy-string searches can remain clean.

### `win11_release_guard/config.py`

- Production default policy URL is correct:
  `https://avnsx.github.io/win-release-guard/windows-release-policy.json`
- Environment override is `WIN11_RELEASE_GUARD_POLICY_URL`.
- `ReleaseCheckerConfig.policy_url` defaults to `None`.
- `resolve_policy_url()` chooses configured URL, then environment URL, then production default.
- `policy_url_source()` returns `config`, `env`, `default`, or `none`.
- WUA is disabled by default.
- Runtime HTML fallback is disabled by default.

### `win11_release_guard/policy_generator.py`

- Owns Release Health and Atom feed policy generation.
- Default Atom feed URL is:
  `https://support.microsoft.com/en-us/feed/atom/4ec863cc-2ecd-e187-6cb3-b50c6545db92`
- Enriches release history with Atom metadata for preview/out-of-band classification.
- Builds quality baselines, preview build lists, out-of-band build lists, known notes, and source fetch status.
- `write_policy_outputs()` writes `windows-release-policy.json`, optional `.sig`, and optional `index.html`.

### `win11_release_guard/signing.py`

- Implements Ed25519 policy signing and verification.
- Supports raw base64 key material and PEM for keys.
- Public-key verification path rejects invalid signatures.
- Missing signatures are rejected when required.
- No private key values are present in this source file.

### `win11_release_guard/data/windows-release-policy.json`

Bundled policy metadata:

- file size: `26078` bytes
- schema version: `1`
- generated at UTC: `2026-05-28T18:17:50+00:00`
- generator version: `win-release-guard/0.2`
- source URLs:
  - `https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information`
  - `https://support.microsoft.com/en-us/feed/atom/4ec863cc-2ecd-e187-6cb3-b50c6545db92`
- source fetch status keys:
  - `atom_feed`
  - `release_health_html`
- broad target:
  - version: `25H2`
  - build family: `26200`
  - latest build: `26200.8457`
  - baseline build: `26200.8457`
- excluded release:
  - `26H1`, build family `28000`
- preview build count: `1`
- out-of-band build count: `0`
- validation warnings: `[]`

### `win11_release_guard/data/windows-release-policy.json.sig`

- Exists.
- file size: `136` bytes
- SHA-256: `2b66d66788e49ec6a18b5a19edd904889d8f4d9a23daaae47202de022656f85e`
- Format is JSON with `algorithm: ed25519` and a signature field.
- Local verification with the trusted public key returned `True`.

## Current mismatch to known-state expectations

Expected/current matches:

- Full test suite is around `195 passed`; actual: `195 passed`.
- `.github/workflows/ci.yml` exists.
- `.github/workflows/publish-policy.yml` exists.
- Production policy URL is `https://avnsx.github.io/win-release-guard/windows-release-policy.json`.
- Remaining live production warning is `Loaded policy URL is not listed in source_urls.`

Mismatch:

- `docs/handover-prompt18.md` was requested for inspection but is not present in the current tree.

## Immediate recommendations

- Decide whether `source_urls` should include the hosted policy artifact URL. If yes, update policy generation so the production URL is listed and the live warning goes away.
- Refresh `docs/source-learnings.md` if it should describe current implementation rather than historical planning.
- Decide whether to restore or intentionally omit `docs/handover-prompt18.md`.

## Prompt 3 Signing Update

Prompt 3 superseded the signing-secret details above. Current signing
management uses:

- private key secret: `WIN_RELEASE_GUARD_POLICY_SIGNING_KEY_B64`
- committed trusted public-key file:
  `win11_release_guard/data/trusted_policy_keys.json`
- new signature field: `key_id`
- local key-generation helper: `python tools/generate_signing_key.py --out-dir .tmp/signing-key`

Any earlier reference in this handover to `WIN11_RELEASE_GUARD_SIGNING_KEY` is
historical Prompt 1 state, not the current workflow contract.

## Prompt 5 Publish Workflow Update

Prompt 5 superseded the publish-workflow details above. Current
`.github/workflows/publish-policy.yml` uses same-repo GitHub Pages artifact
deployment, Python `3.12`, `contents: read`, `pages: write`, and
`id-token: write`.

Production publishing now fails if
`WIN_RELEASE_GUARD_POLICY_SIGNING_KEY_B64` is missing. It no longer falls back
to publishing checked-in bundled policy, does not commit generated files to a
branch, does not use PATs, and does not use `gh-pages` branch mode.
