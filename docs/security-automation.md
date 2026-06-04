# Security Automation

Detailed automation documentation now lives in the GitHub Wiki:

https://github.com/Avnsx/win11_release_guard/wiki/Automation-and-Security

Repository invariants kept here for local agents and tests:

- Dependabot is configured in `.github/dependabot.yml`.
- CodeQL code scanning is configured by `.github/workflows/codeql.yml`.
- If GitHub code scanning is disabled, enable it under
  `Settings -> Code security and analysis -> Code scanning`.
- GitHub UI settings are not fully controlled by repository files.
- README badges are workflow status badges, not external guarantees.

## GitHub Actions Pinning

- GitHub-owned first-party actions may use audited major tags.
- Audited major tags are enforced by `tools/check_github_action_versions.py`.
- Third-party actions are forbidden unless explicitly allowlisted and pinned to
  a full 40-character commit SHA.
- Adding any third-party action requires updating the audit tool, tests, and
  this document with the reason for the exception.
- Workflow permissions stay minimal; production publishing must not request
  `contents: write`.

Current audited GitHub-owned action majors include checkout, setup-python,
configure-pages, upload-pages-artifact, deploy-pages, and CodeQL at the majors
listed in `tools/check_github_action_versions.py`. Dependabot tracks
`github-actions` updates, but the audit tool is the repository-enforced source
of truth.

## Post-Deploy Live Verification

The policy publish workflow deploys static Pages artifacts, then runs a
post-deploy `verify-live-pages` job. The job checks out the repository, installs
the package, waits briefly for Pages propagation with a shell retry loop, and
runs:

```powershell
python -m win11_release_guard --check-policy-source --check-public-pages
```

The check must fail the workflow when public Pages/API endpoints, detached
signatures, manifest hashes, or published URL metadata are inconsistent. The
signing key is scoped to the generate step only; verification never prints or
requires private signing material.

GitHub Pages remains static public hosting. Scheduled workflows are best-effort
automation and are not an SLA cron service. Operational verification should use
the signed policy timestamp, manifest hashes, and live verification output.
