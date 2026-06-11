# Security Automation

Purpose: document repository automation that protects public feed generation, release publication, dependency posture, and GitHub Actions execution.

Related links: [maintainer guide](maintainer-guide.md) | [docs/tagged-release-lane.md](tagged-release-lane.md) | [wiki build/test/release](../wiki/Build-Test-and-Release.md) | [wiki tagged release lane](../wiki/Tagged-Release-Lane.md)

## Automation Configuration Files

| File | Purpose |
| --- | --- |
| `.github/dependabot.yml` | Keeps GitHub Actions and Python dependency update signals visible. |
| `.github/workflows/codeql.yml` | Runs CodeQL code scanning for the Python source tree. |
| `tools/check_github_action_versions.py` | Enforces the audited Actions allowlist and pinning rules. |

Enable or verify CodeQL in repository settings via Settings -> Code security and analysis -> Code scanning. GitHub UI settings are not fully controlled by repository files. Treat workflow status badges as public status links, not as complete security or freshness guarantees.

## Workflow Map

| Workflow | Trigger | Role |
| --- | --- | --- |
| `ci.yml` | push / pull request | Compile, audit actions, check identity, run tests, generate fixture policy, scan, export archive. |
| `publish-policy.yml` | schedule / `workflow_dispatch` / selected `main` pushes | Generate signed Pages feed and deploy static Pages artifact. |
| `sync-source-diagnostics-issues.yml` | `workflow_dispatch` | Sync source-diagnostic warning/error events to GitHub Issues using only the built-in Actions token; notices remain dashboard-only except for closing legacy managed Notice issues. |
| `sync-wiki.yml` | `workflow_dispatch` / `vX.Y.Z` tags | Sync `wiki/*.md` source Markdown to the same repository's GitHub internal Wiki. |
| `release.yml` | tags / `workflow_dispatch` | Validate version/tag parity and publish clean source archive as GitHub Release asset. |
| `pypi-publish.yml` | `workflow_dispatch` / published GitHub Release | Build wheel/sdist on manual runs; publish to PyPI through Trusted Publishing / GitHub OIDC only from an existing tag or published release. |
| `codeql.yml` | schedule / push / PR | CodeQL scan. |
| `dependency-audit.yml` | schedule / `workflow_dispatch` | `pip-audit` dependency vulnerability check. |
| `dependency-freshness.yml` | schedule / `workflow_dispatch` | Direct dependency freshness summary. |
| `pylint.yml` | push / PR | Pylint quality gate. |

## Permissions

| Lane | Required permission |
| --- | --- |
| CI / checks | Read-only repository access. |
| Pages publish | `contents: read`, `pages: write`, `id-token: write`. |
| Source diagnostics issue sync | `contents: read`, `issues: write`; uses `GITHUB_TOKEN` / `${{ github.token }}` only. |
| GitHub internal Wiki sync | `contents: write` only in `sync-wiki.yml`; uses the built-in `github.token` only for the same repository's `.wiki.git` remote. |
| Tagged releases | `contents: write` only in `release.yml`. |
| PyPI publish | `id-token: write` only in the `publish-to-pypi` job; no PyPI API token. |

Production Pages publishing must not use PATs, branch pushes, or `gh-pages` branch deployment.
`publish-policy.yml` selected push paths include `wiki/**` and `CHANGELOG.md` because the first-party generator renders `wiki/*.md` into the static Pages Wiki and `CHANGELOG.md` into the static Pages changelog.

Tagged release pushes do not trigger `publish-policy.yml` because the
repository's protected `github-pages` environment rejects tag-sourced Pages
deployments. This keeps release tags from producing red Pages deploy jobs while
still keeping Pages publishing in the Pages lane. Release managers should verify
the main-branch Pages run for the release commit or run `publish-policy.yml`
manually from `main` when the generated dashboard, Pages Wiki, or Pages
changelog needs an explicit refresh.

## GitHub Internal Wiki Sync

`wiki/*.md` is the shared source for the static Pages Wiki and GitHub's
internal Wiki. GitHub documents Wikis as cloneable Git repositories ending in
`.wiki.git`, and `sync-wiki.yml` mirrors only root `wiki/*.md` files into that
repository. Generated Pages HTML is never pushed to the internal Wiki.

`sync-wiki.yml` is separate from `publish-policy.yml` and `release.yml`.
Manual `workflow_dispatch` defaults to dry-run and uploads a clean
`github-wiki-sync-markdown` artifact that can be applied manually if the live
Wiki repository is not initialized or GitHub rejects the built-in token. Tag
runs and manual non-dry-runs attempt the push. A clone, commit, or push failure
fails only the Wiki sync workflow and remains visible in Actions; it does not
silently degrade Pages publishing.

The Markdown artifact upload uses `if: always()` so the fallback stays
available even when the live Wiki clone or push fails. Do not add
`continue-on-error` to the Wiki sync push step: a failed internal Wiki sync must
be a visible red workflow while the independent Pages publish lane remains
separate.

The workflow does not introduce a PAT or additional secret. The sync tool uses
a temporary Git askpass helper and the built-in token environment value, keeps
the remote URL as `https://github.com/<owner>/<repo>.wiki.git`, and does not
print credentialed URLs.

## GitHub Actions Pinning

| Rule | Enforcement |
| --- | --- |
| GitHub-owned first-party actions may use audited major tags. | `tools/check_github_action_versions.py` |
| Third-party actions are forbidden unless explicitly allowlisted. | Audit tool plus tests. |
| Allowlisted third-party actions must use a full 40-character commit SHA. | Audit tool plus tests. |
| `pypa/gh-action-pypi-publish` is allowed only in `pypi-publish.yml`, pinned to `cef221092ed1bacb1cc03d23a2d87d1d172e277b`. | Narrow Trusted Publishing exception; no stored PyPI credentials. |
| JavaScript actions opt into Node 24. | Workflow env and tests. |

## PyPI Trusted Publishing

| Field | Value |
| --- | --- |
| PyPI project name | Derived from `pyproject.toml` `[project].name`: `win11_release_guard` |
| PyPI project URL | `https://pypi.org/project/win11-release-guard/` |
| Owner | `Avnsx` |
| Repository | `win11_release_guard` |
| Workflow | `pypi-publish.yml` |
| Environment | `pypi` |

PyPI and GitHub exchange a short-lived OIDC publishing identity during the workflow run. Artifact transfer is workflow-initiated: the workflow builds generated wheel/sdist files in `dist/`, checks them with Twine, uploads the artifact between jobs, and actively publishes it only after an existing tag is checked out and the `pypi` environment gate approves. Manual dispatch without a tag is build-only. If the PyPI project does not exist yet, configure a Pending Trusted Publisher first; that does not reserve the name. Do not add workflow YAML that asks maintainers to paste publishing tokens, usernames, passwords, or credentialed repository URLs.

## Source Diagnostics Gate

`publish-policy.yml` blocks deployment when generated `source_diagnostics.events` contains `severity: error`. These are source-diagnostics `error` events; notice and warning events remain visible diagnostic output.

`sync-source-diagnostics-issues.yml` and the `publish-policy.yml`
`sync-source-diagnostics-issues` job use `issues: write` only for workflow-side
GitHub Issues synchronization. The deployment job does not receive issue-write
permission. The sync reads only real `source_diagnostics.events` entries,
deduplicates by the deterministic source diagnostic ID, stores the ID in the
issue body as
`<!-- wrg-source-diagnostic-id: ... -->`, and caps new issues per run. Only
warnings and errors from that event list are synced to GitHub Issues. Notice
events stay visible in policy output and the dashboard, but they are
dashboard-only for issue sync and must not create, update, or reopen GitHub
Issues. Derived dashboard-only rows such as `No source issues reported`,
existing-device exclusion notes, and freshness notices are not issue-sync
inputs. Matching open
issues are left untouched when their title, body, and labels already match the
current diagnostic. Changed open issues are patched without a recurring
still-present comment. Matching closed issues are reopened with a comment while
the diagnostic is still present, and open managed issues are closed with a
comment when their diagnostic ID disappears from the current policy. Created or
updated managed warning/error issues include a compact Markdown tip at the
bottom of the body with a Pages Wiki follow-up link chosen from the diagnostic
kind, severity, and target flags.
Before creating a new issue, the sync checks both GitHub Search results for the
diagnostic ID and open issues carrying the managed internals labels. Every
candidate is accepted only after the exact internal body marker matches the
current diagnostic ID, so labels alone still cannot block or trigger mutation.

Active issue-sync severity labels are fixed as `internals: warning` and
`internals: error`. The legacy `internals: notices` label may still be searched
only to close older managed Notice issues whose body contains the exact internal
marker; new Notice issues are not created, updated, reopened, or kept current.
Labels help filtering in GitHub, but they are not sufficient to mark an issue as
managed without the internal body marker.

During `publish-policy.yml`, GitHub Issues API, label, or permission failures in
the issue-sync mutation step are degraded rather than publish-blocking. The
workflow writes static `source_diagnostics.issue_sync.status: unavailable`
metadata into the issue-status artifact, and the signed policy, manifest, and
dashboard expose that degraded state. Generator source-diagnostic `error` events
still block publication in the build validation step.

Source diagnostic IDs are based on stable event identity fields: severity,
source, event kind/category, release, build family, build, KB article, affected
target flags, and source URL host/path when available. Generated/fetched
timestamps, exact message wording, tag order, and display-only prose are
excluded from the normal hash-ID basis to avoid duplicate issue churn. Older
and non-Atom diagnostics keep the compact form
`wrg-source-diagnostic-v1:<16 lowercase hex>`. Atom-derived diagnostics may use
the durable public Atom entry form
`wrg-source-diagnostic-v1:uuid:<canonical uuid>;id=<positive decimal>` when the
entry ID is valid; malformed or legacy Atom IDs fall back to the hash form.
If one Atom entry produces multiple release/build events, only the canonical
unambiguous event keeps the Atom-form ID; sibling events use unique
deterministic hash-form IDs while preserving Atom entry and support-article
metadata in the diagnostic payload.

An issue is considered managed only when its body contains exactly one internal
HTML comment marker of the form
`<!-- wrg-source-diagnostic-id: <full source diagnostic ID> -->`. Labels,
titles, or plain-text diagnostic ID mentions are not enough for the sync to
update, comment, reopen, or close an issue. The issue body also includes
`Source diagnostic ID: <full source diagnostic ID>` for human review. For valid
Atom-form IDs, issue titles keep the exact full ID in the body and append only
the public suffix, for example `[id=968480]`, to the title.

The standalone `sync-source-diagnostics-issues.yml` workflow supports manual
dry-runs. In dry-run mode the tool does not create, update, comment, reopen, or
close issues, and can write JSON or Markdown reports with deterministic IDs,
labels, planned actions, and static issue-status metadata. The workflow uploads
a Markdown dry-run artifact without adding any secret beyond the built-in
`GITHUB_TOKEN`.

The dashboard renders issue links only from static generated
`source_diagnostics.issue_status` metadata. Browser JavaScript must not query the
GitHub Issues API, expose workflow logs, or embed tokens.

README badges show latest workflow status only. The schedule is not the only control: workflow dispatch, source diagnostics, signature checks, public Pages checks, and live verification gates are the operational controls.

## Do / Do Not

| Do | Do not |
| --- | --- |
| Keep workflow permissions minimal. | Add `contents: write` outside the tagged release workflow and the dedicated Wiki sync workflow. |
| Keep GitHub Issues sync in Actions with the built-in token. | Add issue creation calls, tokens, or GitHub API writes to client-side Pages JavaScript. |
| Keep GitHub internal Wiki sync in `sync-wiki.yml` with `wiki/*.md` source only. | Push generated HTML or use browser JavaScript to write the GitHub Wiki. |
| Keep signed feed generation limited to public Microsoft source data and unauthenticated enrichment. | Add token-authenticated Microsoft API requirements to production generator. |
| Keep PyPI publishing on Trusted Publishing / OIDC. | Add PyPI API tokens, Twine passwords, usernames, or credentialed repository URLs. |
| Scan generated Pages output before upload. | Publish stale or unsigned artifacts silently. |
| Treat scheduled runs as best-effort. | Present schedules as guaranteed timing. |

## Verify

```powershell
python tools/check_github_action_versions.py
python tools/check_project_identity.py
python tools/check_version_consistency.py
python -m win11_release_guard --check-policy-source
python -m win11_release_guard --check-public-pages
pytest -q tests/test_repository_automation.py tests/test_publish_policy_workflow.py tests/test_workflow_node24.py
pytest -q tests/test_pypi_publish_workflow.py tests/test_github_action_versions.py
pytest -q tests/test_source_diagnostics_issue_sync.py tests/test_source_diagnostics_issue_metadata.py
```
