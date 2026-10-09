# FAQ

Short answers to common administrator and maintainer questions.

---

## Does this install or trigger updates?

No. It evaluates state and emits diagnostics. It does not install, hide, schedule, download, or trigger Windows updates.

## Which release is the target for existing devices?

The policy selects the newest supported General Availability H2 release that has a monthly security (B) release in Release Health. 26H1 stays out of existing-device target selection because Microsoft scopes it to new devices. The dashboard's Broad target card and `broad_target_existing_devices` in the feed show the current choice.

## Why is a new Windows 11 release not the broad target yet?

Microsoft lists a new annual release as General Availability during the optional preview (D) week, so its first monthly security (B) release arrives on the next Patch Tuesday. Until then there is no B-release baseline to require, so the previous release stays the broad target. The new release still appears in `current_versions` with `not_broad_target` and `pending_first_b_release` metadata, devices already on it report `ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE` (exit code `3`), and the dashboard shows an "awaits its first B release" notice. The next publish run after its first B release promotes it automatically. If a Patch Tuesday passes and Release Health still lists no B release for it, generation fails closed instead of guessing.

## What if the local machine shows a stale Windows label?

The guard preserves the raw label for review, but build-family and signed policy mapping drive the result.

## Is WUA required?

No. WUA is optional, read-only diagnostic evidence. Default integration paths can run without it.

## Why does strict-production return `CHECK_INCOMPLETE` from cache?

Strict mode requires fresh live signed remote JSON. Cache and bundled fallback remain visible degraded evidence.

## Are public feed artifacts secret?

No. Policy JSON, signatures, manifests, dashboard files, and public keys are non-secret. Private signing keys and tokens must never be committed.

## What license does the repository use?

The project is MIT-licensed (since v0.6.0; earlier releases were GPL-3.0-only). The full license text lives in `LICENSE.txt` and is included in validated clean source archives.

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
That table can lag behind the public Microsoft servicing table-of-contents
JSON and its linked Microsoft Support articles. `latest_observed_build`
records the newest official build the generator found in supported public
evidence. It is context only and does not become `required_baseline_build`
unless the signed baseline rules select it. When Release Health has caught up
and those rules select the same build, all three values can legitimately
match.

## What is the baseline-update notice?

It is dashboard-only context shown when a real Release Health B-release
required baseline catches up to the latest observed Microsoft build. It lasts
14 days from the source-derived official date, labels date-only Microsoft
precision honestly, and does not change verdicts, baselines, issue sync,
runtime clients, signatures, or `/api/v1`.

## Why does the baseline notice say security classification is unavailable?

The notice derives its security label from exact MSRC CVRF KB evidence or a
validated Microsoft Support article linked from the servicing table-of-contents
JSON. That servicing index can lag Patch Tuesday by days or weeks. When it has
not yet published the baseline KB entry, the notice no longer waits for it: it
derives the MSRC month from the Release Health baseline date, fetches MSRC
CVRF for that month, and joins the baseline KB exactly, so security is still
credited to MSRC without a servicing-linked support article (no Support
article is fetched or synthesized, so support validation stays unavailable).
The neutral sentence "Security classification is unavailable
from the checked enrichment source." now appears only when MSRC is also
unavailable or its fetch fails; that failure is recorded as an ordinary
`msrc_cvrf_enrichment_unavailable` warning event. Either way it is honest
output, not an error, and it does not affect baseline selection or verdicts. If
MSRC was temporarily unavailable, the classification appears automatically once
a later scheduled publish run reaches it.

## How are Support and MSRC evidence trusted?

The servicing table-of-contents JSON discovers Support article links; it is
not a `/help/<KB>` resolver. Safe Support URLs are canonicalized, direct links
are revalidated before public metadata use, and article URL/KB/build/
applicability must match before article facts affect summaries or
Support-derived security labels. MSRC security classification requires exact
KB remediation evidence; malformed or unavailable CVRF stays unknown.

## Related Pages

[Home](Home) | [Quick Start](Quick-Start) | [Troubleshooting](Troubleshooting)
