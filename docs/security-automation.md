# Security Automation

This repository uses file-based automation where GitHub supports it, and keeps
GitHub UI settings explicit where they cannot be fully controlled by source
files.

## Dependabot

Dependabot version updates are configured by `.github/dependabot.yml`.

Configured ecosystems:

- `pip` for Python dependency declarations in `pyproject.toml`
- `github-actions` for workflow action versions under `.github/workflows/`

Dependabot alerts and security updates may still need to be enabled in GitHub
repository settings if they are not already active.

## Code Scanning

CodeQL code scanning is configured by `.github/workflows/codeql.yml`.

GitHub UI path:

```text
Settings -> Code security and analysis -> Code scanning
```

GitHub UI settings are not fully controlled by repository files. If code
scanning is disabled in settings, enable it there after the workflow is present.

## Workflow Badges

README badges are GitHub Actions workflow status badges. They reflect the latest
workflow status; they are not external guarantees.

The dependency freshness badge is backed by
`.github/workflows/dependency-freshness.yml`, which runs
`tools/check_dependency_freshness.py`. A passing run means direct dependency
specifiers in `pyproject.toml` allow the latest stable PyPI releases seen by
that run.

The dependency audit badge is backed by `.github/workflows/dependency-audit.yml`
and `pip-audit`.
