# Architecture Insight

Detailed architecture context now lives in the GitHub Wiki:

https://github.com/Avnsx/win11_release_guard/wiki/Architecture-Insight

Repository invariants kept here for local agents and tests:

- Signed policy JSON is the runtime source of truth for the broad-fleet target.
- Local build and edition probes describe the installed state.
- WUA, Panther, DISM, setup logs, and package data are secondary evidence only.
- Runtime clients do not scrape Microsoft HTML in the normal path.
- Generator-owned upstream parsing produces the signed public policy feed.
- The public feed is verified with Ed25519 signatures and committed public keys.

## Runtime Trust Path

Runtime starts at the CLI or API with `ReleaseCheckerConfig`, then resolves the
policy source. The preferred path is public GitHub Pages JSON plus the detached
`.sig` file. The client verifies the Ed25519 signature against committed public
keys before evaluating local build evidence. Cache and bundled fallbacks remain
signed policy material, but they are degraded sources and must be surfaced via
`source_status`.

The runtime trust path is:

1. CLI/API builds config and strict-production settings.
2. Runtime fetches public static policy JSON and detached signature.
3. Signature verification selects a trusted public key by `key_id` and validates
   `signed_at_utc` against key lifecycle windows.
4. Fresh cache, stale cache, or bundled policy can be used only as fallback and
   must not hide source degradation.
5. In strict-production mode, fallback sources cannot produce any production
   result, including `OUT_OF_SCOPE`; the result is `CHECK_INCOMPLETE` until a
   complete live signed remote JSON source is available.
6. Local probes collect build/edition evidence; WUA and logs remain secondary.
7. Evaluator compares local state against signed policy target and B-release
   baseline.

## Generator Path

The production generator uses public Microsoft Release Health HTML and the
public Microsoft Update History Atom feed. It parses current versions, release
history, source diagnostics, 26H1 special-release notes, preview/OOB evidence,
and source freshness warnings before writing the static Pages artifacts. It
then signs the canonical policy and writes canonical plus `/api/v1` aliases and
manifest hashes.

## Required Live Verification

Deployment-affecting changes require the live verification gate. The publish
workflow generates and signs the static feed, deploys it to GitHub Pages, then
the `verify-live-pages` job polls the public Pages endpoints and runs:

```powershell
python -m win11_release_guard --check-policy-source --check-public-pages
```

That check verifies HTTP reachability, canonical/API aliases, signatures,
manifest SHA-256 values, and published URL metadata. It is a required workflow
step for deployment-affecting changes; if live network is unavailable, do not
claim live success.
