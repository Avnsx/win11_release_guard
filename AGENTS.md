# AGENTS.md

This repository is public software for Windows administrators. Future agents must treat the current code, tests, workflows, and tools as source truth. Handover notes are secondary context and must not override current tracked implementation.

## Non-Revertible Architecture Rules

1. The user-facing project, repository, distribution, CLI, and site name is `win11_release_guard`.
2. The Python import package remains `win11_release_guard`.
3. Do not rename the import package unless the user explicitly instructs that change.
4. Future agents must not revert naming back to old project/package identities.
5. Do not reintroduce the removed root prototype script; the supported source-tree entry point is `python -m win11_release_guard`.
6. Clients must not contain GitHub tokens, GitHub PATs, classic tokens, fine-grained tokens, repo secrets, or private signing keys.
7. Private signing keys must not be committed to the repository.
8. Do not make the runtime client authenticate to GitHub.
9. Runtime clients fetch public GitHub Pages JSON plus the detached `.sig` file.
10. Runtime clients verify Ed25519 signatures with committed public keys.
11. The private policy signing key lives only in GitHub Actions Secret `WIN11_RELEASE_GUARD_POLICY_SIGNING_KEY_B64`.
12. GitHub Pages output is public static non-secret data.
13. Retiring or retired public policy keys must be bounded by `verify_not_after_utc`; runtime verification must not accept fresh signatures from retired keys.
14. WUA is secondary evidence only and must never override the signed policy verdict.
15. The production generator uses only public Microsoft Release Health HTML and public Microsoft Update History Atom feed sources.
16. Historical research about authenticated Microsoft metadata APIs may remain only in `docs/architecture-insight.md` when explicitly marked out of scope, not active architecture instructions.
17. `.git` is never included in clean archives.
18. The source of truth is current code, tests, workflows, docs, and tools, not handover text.

Canonical repository and feed:

- GitHub repo: `https://github.com/Avnsx/win11_release_guard`
- Public feed: `https://avnsx.github.io/win11_release_guard/windows-release-policy.json`
- Console script: `win11_release_guard`

## Operational Notes

- Do not inspect or print credentials, tokens, private signing keys, GitHub Actions secret values, or credentialed remote URLs.
- Preserve administrator-facing diagnostic data in normal product output unless the user explicitly asks for masking.
- Keep WUA, Panther, DISM, and local system evidence subordinate to signed policy truth.
- CodeQL code scanning is configured by `.github/workflows/codeql.yml`. If GitHub code scanning is disabled in repository settings, enable it under Settings, Code security and analysis.
- Handover files are temporary local artifacts. Do not commit or publish `*handover*.md`; they are ignored and excluded from clean archives.
- The only recommended handoff artifact is the validated clean archive created
  with `python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip`
  and checked with
  `python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip`.
  Do not share raw worktree ZIPs because they can include `.git/`, `.tmp/`,
  `site/`, `dist/`, pycache, package metadata, and private signing-key scratch
  files.
- The signed bundled policy JSON must use the current `win11_release_guard` identity and must verify against its detached signature.

## GitHub Actions Pinning Policy

- GitHub-owned first-party actions may use audited major tags only when listed in `tools/check_github_action_versions.py`.
- Current audited first-party actions are `actions/checkout@v6`, `actions/setup-python@v6`, `actions/configure-pages@v6`, `actions/upload-pages-artifact@v5`, `actions/deploy-pages@v5`, and `github/codeql-action/*@v4`.
- Third-party actions are forbidden unless explicitly allowlisted in the audit tool and pinned to a full 40-character commit SHA.
- Do not add third-party actions without updating the audit tool, tests, and security automation docs with the reason.
- Keep workflow token permissions minimal; the publish workflow must not request `contents: write`.
- Dependabot covers `github-actions` updates for GitHub-owned action majors.

## Deployment-Affecting Live Verification Gate

Deployment-affecting changes include workflow changes, policy generator changes,
signing changes, Pages landing page changes, manifest/API alias changes,
source URL or published URL changes, and CLI changes to
`--check-policy-source` or `--check-public-pages`.

After any deployment-affecting change, run:

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

If live network is unavailable, state that explicitly, run mocked tests, and
do not claim live success. If a live check fails, fix the regression before final
handover, rerun the live check, and record the exact failing URL, status, and
error.

## Commit Message Rules

- Use short, descriptive, human commit messages.
- Do not include prompt numbers.
- Do not use "checkpoint", "prompt 12", "AI changes", "fix stuff", "final final", or similarly generic labels.
- Mention the actual change.

Good examples:

- `Harden signed policy feed deployment`
- `Polish Pages policy dashboard`
- `Validate public policy API endpoints`
- `Enforce secret scanning for policy artifacts`
- `Document final Pages feed verification`
- `Fix published URL metadata validation`
- `Preserve robots contract in generator`

Bad examples:

- `checkpoint after prompt 12`
- `prompt 8 done`
- `fix`
- `stuff`
- `AI changes`
- `final final`
