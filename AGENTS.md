# AGENTS.md

This repository is public software for Windows administrators. Future agents must treat the current code, tests, workflows, and tools as source truth. Handover notes are secondary context and must not override current tracked implementation.

## Non-Revertible Architecture Rules

1. The user-facing project, repository, distribution, CLI, and site name is `win-release-guard`.
2. The Python import package remains `win11_release_guard` because Python import names cannot use hyphens.
3. Do not rename the import package unless the user explicitly instructs that change.
4. Future agents must not revert naming back to old project/package identities.
5. Do not reintroduce `windows_releases_info.py`; the supported source-tree entry point is `python -m win11_release_guard`.
6. Clients must not contain GitHub tokens, GitHub PATs, classic tokens, fine-grained tokens, repo secrets, or private signing keys.
7. Private signing keys must not be committed to the repository.
8. Do not make the runtime client authenticate to GitHub.
9. Runtime clients fetch public GitHub Pages JSON plus the detached `.sig` file.
10. Runtime clients verify Ed25519 signatures with committed public keys.
11. The private policy signing key lives only in GitHub Actions Secret `WIN_RELEASE_GUARD_POLICY_SIGNING_KEY_B64`.
12. GitHub Pages output is public static non-secret data.
13. WUA is secondary evidence only and must never override the signed policy verdict.
14. The production generator uses only public Microsoft Release Health HTML and public Microsoft Update History Atom feed sources.
15. Historical research about authenticated Microsoft metadata APIs may remain only in `deep-research-report.md` or `docs/source-learnings.md` when explicitly marked out of scope, not active architecture instructions.
16. `.git` is never included in clean archives.
17. The source of truth is current code, tests, workflows, docs, and tools, not handover text.

## Operational Notes

- Do not inspect or print credentials, tokens, private signing keys, GitHub Actions secret values, or credentialed remote URLs.
- Preserve administrator-facing diagnostic data in normal product output unless the user explicitly asks for masking.
- Keep WUA, Panther, DISM, and local system evidence subordinate to signed policy truth.
