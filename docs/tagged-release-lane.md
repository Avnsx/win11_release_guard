# Tagged Release Lane

The GitHub Release path for clean source archives. These are distribution checkpoints for Windows 11 Release Guard source archives, separate from the twice-daily public policy feed publish workflow.

Related links: [maintainer guide](maintainer-guide.md) | [v0.3.4 release notes](releases/v0.3.4.md) | [wiki tagged release lane](../wiki/Tagged-Release-Lane.md) | [safe exports](../wiki/Safe-Exports-and-Clean-Archives.md)

## Release Contract

| Item | Rule |
| --- | --- |
| Tag format | `vX.Y.Z`, matching `pyproject.toml` and runtime identity. |
| Workflow | `.github/workflows/release.yml`. |
| Artifact | `dist/win11_release_guard-source.zip`. |
| License | Repository `LICENSE.txt` is the MIT license file and is included in the validated source archive. |
| Default release state | Draft unless explicitly changed by workflow input. |
| Release body | Links `CHANGELOG.md`, matching `docs/releases/vX.Y.Z.md`, Pages dashboard, Pages Wiki, Pages changelog, public feed, and the separate PyPI lane. |
| Token | Built-in `github.token`; no PAT. |
| Scope | Source archive release, not Pages policy deployment or direct Wiki mutation. Publishing a GitHub Release can trigger the separate PyPI workflow, which still owns its own gates and environment approval. A `vX.Y.Z` tag can also trigger the separate `sync-wiki.yml` workflow for GitHub internal Wiki Markdown sync. |

The manual workflow can create an annotated tag only when `create_tag=true` is explicitly provided. The built-in GitHub API token is used by the workflow and must never be exposed in logs, docs, or client code. Before publishing a release asset, `release.yml` checks that `CHANGELOG.md`, `docs/releases/vX.Y.Z.md`, and `wiki/Release-vX.Y.Z.md` contain the matching release material.

Tag pushes wire the release and Wiki sync lanes together without merging their permissions:

- `release.yml` validates the tag and publishes the clean source archive as a GitHub Release asset.
- `sync-wiki.yml` mirrors `wiki/*.md` to the GitHub internal Wiki when the built-in token is accepted by GitHub.

`publish-policy.yml` stays the only Pages deployment lane, but it runs from
schedule, workflow_dispatch, or selected `main` pushes rather than tag pushes.
The repository's protected `github-pages` environment rejects tag-sourced Pages
deployments, so release managers must verify the main-branch Pages run for the
release commit or manually dispatch `publish-policy.yml` from `main` before
publishing the final release.

If the GitHub internal Wiki repository is not initialized or GitHub rejects the
built-in token for `.wiki.git`, only `sync-wiki.yml` fails. The workflow still
uploads the clean Markdown artifact for manual Wiki application, and the
release and Pages lanes keep their own status and permissions.

## PyPI Trusted Publishing Lane

| Item | Rule |
| --- | --- |
| Workflow | `.github/workflows/pypi-publish.yml`. |
| Trigger | Manual `workflow_dispatch` without a tag runs build/twine/self-test only; manual dispatch with an existing `vX.Y.Z` tag or a published GitHub Release can publish. No normal push or pull request publishing. |
| PyPI project | `https://pypi.org/project/win11-release-guard/`. |
| Environment | `pypi`, intended for manual approval. |
| Permission | `id-token: write` only in the PyPI publish job. |
| Credentials | No PyPI API token, Twine password, username, or credentialed repository URL. |
| Package artifacts | Wheel and sdist built from the selected source ref into generated `dist/`, checked with `twine check`, uploaded as a workflow artifact, then published through OIDC only when publish is tag-enabled. |
| Public install | `python -m pip install win11_release_guard` after a successful PyPI release. |

PyPI Trusted Publisher setup must match these values:

| Field | Value |
| --- | --- |
| Project name | `win11_release_guard` from `pyproject.toml` `[project].name` |
| Owner | `Avnsx` |
| Repository | `win11_release_guard` |
| Workflow | `pypi-publish.yml` |
| Environment | `pypi` |

If the project does not exist on PyPI, configure a Pending Trusted Publisher first. Pending Publisher does not reserve the package name; if the name is already owned by someone else, stop and report instead of publishing. Do not synthesize a publish tag from a branch run; the workflow verifies and checks out an existing tag before publishing.

## Preflight Gates

```powershell
python -m compileall -q win11_release_guard tools
python tools/check_project_identity.py
python tools/check_github_action_versions.py
python tools/check_version_consistency.py
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"; python -m pytest -q
python -m win11_release_guard --self-test
python -m win11_release_guard --check-policy-source
python -m win11_release_guard --check-public-pages
python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip
python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip
```

Bash form for the test gate:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q
```

`export_clean_archive.py --validate` runs its inner archive test gate with
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` so ambient third-party pytest plugins cannot
change, slow, or hang validation; the project declares no required pytest
plugins, so coverage is unchanged. The validated clean archive requires the
current `docs/releases/v0.3.4.md` and preserves the historical release notes
`docs/releases/v0.3.1.md`, `docs/releases/v0.3.2.md`, and `docs/releases/v0.3.3.md`.

## Release Checklist

| Step | Action |
| --- | --- |
| 1 | Confirm worktree scope and version parity. |
| 2 | Run the preflight gates. |
| 3 | Create or select an annotated `vX.Y.Z` tag. |
| 4 | Run `release.yml` through tag push or manual dispatch; tag pushes also trigger the separate Wiki sync lane. Verify the main Pages publish run or manually dispatch `publish-policy.yml` from `main` when Pages needs a release refresh. |
| 5 | Review the draft GitHub Release and attached clean archive. |
| 6 | Publish the GitHub Release only after verification output is credible. |
| 7 | Publish to PyPI separately through `pypi-publish.yml` only when explicitly intended. |

## Do / Do Not

| Do | Do not |
| --- | --- |
| Attach only the validated clean archive. | Upload raw worktree ZIPs. |
| Keep Pages publishing in `publish-policy.yml`. | Use release workflow to mutate the policy feed. |
| Keep GitHub internal Wiki sync in `sync-wiki.yml`. | Push Wiki changes directly from `release.yml`. |
| Keep PyPI publishing in `pypi-publish.yml` with Trusted Publishing. | Add long-lived PyPI credentials to Actions. |
| Document failed live checks honestly. | Claim live verification when network or endpoint checks failed. |
| Keep commit messages descriptive. | Use "checkpoint" or "final final" style commit messages. |

## Rollback Notes

Tagged source releases are immutable audit anchors. If a release is wrong, publish a corrected tag/release with notes; do not rewrite public history casually.
