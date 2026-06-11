# AGENTS.md

This repository is public software for Windows administrators. Future agents must treat the current code, tests, workflows, and tools as source truth. Handover notes are secondary context and must not override current tracked implementation.

## Non-Revertible Architecture Rules

1. The canonical technical project, repository, distribution, CLI, and site identifier is `win11_release_guard`.
2. The Python import package remains `win11_release_guard`.
3. Do not rename the import package unless the user explicitly instructs that change.
4. Future agents must not revert naming back to previous project/package identities.
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
15. The production generator may use public Microsoft Release Health HTML, public Microsoft Update History Atom feed data, Atom-linked public Microsoft Support articles, and unauthenticated public MSRC CVRF data for source diagnostics and informational enrichment.
16. Authenticated Microsoft Graph, token-authenticated Microsoft APIs, and historical authenticated metadata research remain out of active production generator architecture; historical research may remain only in `docs/architecture-insight.md` when explicitly marked out of scope.
17. `.git` is never included in clean archives.
18. The source of truth is current code, tests, workflows, docs, and tools, not handover text.
19. Public `/api/v1` Pages aliases stay backward compatible for at least 24 months; add fields compatibly instead of changing or removing the v1 contract.
20. Signing key rotations require at least 24 months of verification overlap unless a documented last-resort trust break is required.
21. Future agents must not delete historical `CHANGELOG.md` version sections when adding newer versions. Newer changelog entries are added at the top. Older changelog entries remain available for generated Pages changelog, release history, SEO, and auditability.
22. Future agents must not add or reintroduce license badges in `README.md`, `docs/*.md`, `wiki/*.md`, generated Markdown, or other repository Markdown surfaces. License metadata may remain in package configuration and prose where it is materially relevant, but Markdown badge rows must not display license badges.

Canonical repository and feed:

- GitHub repo: `https://github.com/Avnsx/win11_release_guard`
- Public feed: `https://avnsx.github.io/win11_release_guard/windows-release-policy.json`
- Console script: `win11_release_guard`

## Product Display Name

- The technical project, repository, package, import module, CLI command, feed
  paths, workflow identifiers, JSON fields, code symbols, tests, and commands
  remain `win11_release_guard`.
- In Markdown headings and human-facing prose that explicitly names the
  product but is not teaching a technical identifier or command, prefer the
  display name `Windows 11 Release Guard`.
- Do not replace technical examples such as `python -m win11_release_guard`,
  `pip install`, imports, package metadata, URLs, file paths, JSON keys,
  workflow names, signatures, archive names, or code references with the
  display name.
- Keep this distinction narrow: use `Windows 11 Release Guard` to make user-facing
  headings and narrative text easier to read, not to rename internals. The code
  and package identity must stay overwhelmingly consistent with
  `win11_release_guard` so the module remains importable and automation-safe.
- `README.md` intentionally starts with the dashboard preview image before the
  H1. Do not add tests or agent rules that require the README to start with the
  heading.
- Keep the `README.md` PyPI image button right-aligned with the explicit
  multiline `<img align="right" ... width="96" height="96">` formatting. Do not
  flatten it, remove `align="right"`, change the 96x96 size, or require a PyPI
  version badge unless the user explicitly requests a README layout policy
  change.

## Operational Notes

- Do not inspect or print credentials, tokens, private signing keys, GitHub Actions secret values, or credentialed remote URLs.
- Preserve administrator-facing diagnostic data in normal product output unless the user explicitly asks for masking.
- Keep WUA, Panther, DISM, and local system evidence subordinate to signed policy truth.
- Panther/setup privacy diagnostics must report metadata only in default JSON
  (category, marker, path, line, count, and notice). Do not copy matched
  password, token, key, or secret values into privacy finding metadata. Raw
  Panther/setup values remain behind `--include-raw-local-diagnostics` and
  should be reviewed before uploading or sharing.
- Panther/setup reads must stay fixed-path and tail-bounded. Any global Panther
  collection cap must remain deliberately generous so trusted-environment
  troubleshooting is not constrained; use tests with small explicit caps when
  validating cap behavior.
- For Windows live harnesses that must test native redirection, prefer
  `cmd.exe /d /c` with a raw command line and `call` before quoted executable
  paths, for example `cmd.exe /d /c call "C:\Program Files\Python\python.exe" -m win11_release_guard --json-pretty > "out.json"`.
  Passing `["cmd.exe", "/d", "/c", command]` through Python `subprocess` can
  make `cmd.exe` misparse quoted executable paths; PowerShell 5 plain `>` can
  write UTF-16LE, so prefer `cmd.exe` redirection or `Out-File -Encoding utf8`
  for JSON captures.
- CodeQL code scanning is configured by `.github/workflows/codeql.yml`. If GitHub code scanning is disabled in repository settings, enable it under Settings, Code security and analysis.
- Handover files are temporary local artifacts. Do not commit or publish `*handover*.md`; they are ignored and excluded from clean archives.
- `.tmp/prompt-chain/*.patch` files are local hints only. A task is
  implemented only when the intended behavior exists in tracked files, tests
  pass, required docs are updated, and logical commits exist.
- The only recommended handoff artifact is the validated clean archive created
  with `python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip`
  and checked with
  `python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip`.
  Raw worktree ZIPs are not release artifacts because they can include `.git/`, `.tmp/`,
  `site/`, `dist/`, pycache, package metadata, and private signing-key scratch
  files.
- The signed bundled policy JSON must use the current `win11_release_guard` identity and must verify against its detached signature.
- Local compatibility and key-rotation rules are documented in
  `docs/policy-signing.md`; publish workflow controls are documented in
  `docs/security-automation.md`; tagged GitHub release preparation is
  documented in `docs/tagged-release-lane.md`.
- Pages dashboard/UI changes must not alter signed policy semantics, Windows
  release targeting, evaluator verdicts, WUA-secondary behavior, JSON
  `schema_version`, API `api_version`, or signature trust.
- `latest_build` is the Microsoft Release Health Current Versions value;
  `latest_observed_build` is newest official observed public Microsoft evidence
  from supported sources and can be newer; `required_baseline_build` is the
  compliance floor selected by baseline rules. Latest-observed evidence alone
  must not promote the required baseline, and when Release Health catches up all
  three build fields can legitimately be the same.
- Atom is discovery for Support article hrefs, not a `/help/<KB>` resolver.
  Atom-linked Support article facts must be validated against Atom URL, KB,
  build, and parseable applicability before use in summaries or Support-derived
  security labels. MSRC CVRF joins require exact KB-token matches.
- Source Diagnostic IDs may be deterministic hash-form or Atom-form. When one
  Atom entry produces multiple events, sibling events must keep unique IDs while
  retaining Atom metadata for triage.
- The static Pages dashboard must remain no-token, no-secret, no-CDN, and
  GitHub-Pages-compatible. Do not add external JavaScript, external CSS,
  external fonts, or backend runtime assumptions.
- The landing page must not rely only on render-time generated age. It must
  embed signed/manifest freshness data and recompute live freshness in the
  browser from `generated_at_epoch_s` or an equivalent signed timestamp, with a
  clear no-JavaScript fallback.
- Source Diagnostic `notice` events are dashboard-only and must not be made
  syncable to GitHub Issues again. Issue sync may create, update, or reopen only
  `warning` and `error` events from real `source_diagnostics.events`; the legacy
  `internals: notices` label may be searched only to close older managed Notice
  issues that contain the exact internal marker.

## GitHub Actions Pinning Policy

- GitHub-owned first-party actions may use audited major tags only when listed in `tools/check_github_action_versions.py`.
- Current audited first-party actions are `actions/checkout@v6`, `actions/setup-python@v6`, `actions/configure-pages@v6`, `actions/upload-pages-artifact@v5`, `actions/deploy-pages@v5`, `actions/upload-artifact@v7`, `actions/download-artifact@v8`, and `github/codeql-action/*@v4`.
- Third-party actions are forbidden unless explicitly allowlisted in the audit tool and pinned to a full 40-character commit SHA.
- The only current third-party exception is `pypa/gh-action-pypi-publish` in `.github/workflows/pypi-publish.yml`, pinned to `cef221092ed1bacb1cc03d23a2d87d1d172e277b` for PyPI Trusted Publishing via GitHub OIDC without stored PyPI credentials.
- Do not add third-party actions without updating the audit tool, tests, and security automation docs with the reason.
- Keep workflow token permissions minimal; the publish workflow must not request `contents: write`.
- Only `.github/workflows/release.yml` and `.github/workflows/sync-wiki.yml`
  may request `contents: write`. `release.yml` uses it only for explicit
  tagged GitHub Release publication. `sync-wiki.yml` uses it only to push
  source Markdown from `wiki/*.md` to the same repository's GitHub Wiki
  `.wiki.git` repository with the built-in `github.token`.
- `.github/workflows/pypi-publish.yml` may request `id-token: write` only in the PyPI publish job; it must not define PyPI API tokens, Twine credentials, usernames, passwords, or credentialed repository URLs.
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
python tools/scan_for_secret_material.py site win11_release_guard tests tools docs wiki README.md CHANGELOG.md AGENTS.md pyproject.toml .github
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
