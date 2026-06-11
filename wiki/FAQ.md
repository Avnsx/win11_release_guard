# FAQ

Short answers for common administrator, maintainer, and agent questions.

---

## Does this install or trigger updates?

No. It evaluates state and emits diagnostics. It does not install, hide, schedule, download, or trigger Windows updates.

## Why is 25H2 the current target for existing devices?

The policy selects the supported broad-fleet existing-device target. Current code/tests treat 25H2 as that target and keep 26H1 out of existing-device target selection because it is new-devices-only.

## What if the local machine shows a stale Windows label?

The guard preserves the raw label for review, but build-family and signed policy mapping drive the result.

## Is WUA required?

No. WUA is optional, read-only diagnostic evidence. Default integration paths can run without it.

## Why does strict-production return `CHECK_INCOMPLETE` from cache?

Strict mode requires fresh live signed remote JSON. Cache and bundled fallback remain visible degraded evidence.

## Are public feed artifacts secret?

No. Policy JSON, signatures, manifests, dashboard files, and public keys are non-secret. Private signing keys and tokens must never be committed.

## What license does the repository use?

The repository uses GPL-3.0. The full license text lives in `LICENSE.txt` and is included in validated clean source archives.

## Do I need a PyPI API token?

No. The current publish workflow uses PyPI Trusted Publishing with GitHub Actions OIDC. Configure PyPI with project `win11_release_guard`, owner `Avnsx`, repository `win11_release_guard`, workflow `pypi-publish.yml`, and environment `pypi`. Do not paste publishing tokens, usernames, passwords, or credentialed repository URLs into workflow YAML.

## Does local wiki source publish automatically?

To GitHub Pages, yes: `publish-policy.yml` renders `wiki/*.md` into the static Pages Wiki under `/wiki/`.

To the GitHub internal Wiki repository, use `.github/workflows/sync-wiki.yml`. Manual runs default to dry-run and upload a Markdown artifact; tag runs and manual non-dry-runs attempt to push `wiki/*.md` to the same repository's `.wiki.git` remote with the built-in Actions token.

## Does a Pending Trusted Publisher reserve the package name?

No. If the PyPI name is already owned by someone else, stop and report instead of publishing.

## Can `/api/v1` change?

Fields can be added compatibly. Existing public v1 paths and contract fields should not be removed casually.

## Why is the dashboard age recalculated in the browser?

Static Pages output can become old without re-rendering. The page embeds generated epoch fields and uses browser time to show live feed age.

## Why can latest observed be newer than latest build?

`latest_build` is the Microsoft Release Health Current Versions table value.
That table can lag behind public Update History Atom entries and their linked
Microsoft Support articles. `latest_observed_build` records the newest official
build the generator found in supported public evidence. It is context only and
does not become `required_baseline_build` unless the signed baseline rules
select it. When Release Health has caught up and those rules select the same
build, all three values can legitimately match.

## Related Pages

[Home](Home) | [Quick Start](Quick-Start) | [Troubleshooting](Troubleshooting)
