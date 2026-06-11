# Troubleshooting

Use this when a check fails, a source degrades, or a local Windows result looks surprising.

---

## `CHECK_INCOMPLETE`

| Check | What to do |
| --- | --- |
| `source_status` | Confirm whether live remote, cache, bundled, or unavailable source was used. |
| `source_problems` | Read exact fetch, parse, signature, hash, or freshness problem. |
| `policy_signature_status` | Verify signature and key trust. |
| Strict mode | Confirm live signed remote JSON is fresh enough. |

```powershell
python -m win11_release_guard --check-policy-source
python -m win11_release_guard --diagnose-config
```

## Public Pages Check Fails

| Check | What to do |
| --- | --- |
| Landing page | Verify dashboard URL returns expected static HTML. |
| Policy/signature | Verify policy bytes and signature metadata. |
| Manifest hash | Compare manifest hash with policy bytes. |
| API aliases | Confirm `/api/v1` files exist and match expected contract. |
| Freshness | Check generated epoch and 14/45-day thresholds. |

```powershell
python -m win11_release_guard --check-public-pages
```

## Local Device Label Looks Wrong

| Check | What to do |
| --- | --- |
| Build family | Trust build-family mapping over display label. |
| Raw labels | Keep raw `ProductName`, `Caption`, and `DisplayVersion` for admin review. |
| Conflict flags | Look for `LOCAL_PRODUCT_NAME_STALE`, `LOCAL_CAPTION_STALE`, or display-version conflict flags. |
| Policy map | Confirm signed policy knows the build family. |

```powershell
python -m win11_release_guard --json-pretty --no-wua
```

## WUA Does Not Offer Target Feature Update

| Check | What to do |
| --- | --- |
| Policy verdict | Keep the signed policy verdict. |
| WUA availability | Enable WUA only for diagnostics. |
| WUfB / WSUS | Check target-release pins, WSUS/SCCM source, deferrals. |
| Pending reboot | Review read-only pending reboot evidence. |
| Panther/setup logs | Review fixed-path, bounded setup diagnostic tails; collection also has a generous total guard. |

Panther/setup logs are administrator troubleshooting evidence only. They never decide compliance or override the signed public policy verdict.
Default JSON keeps raw Panther content compacted; raw bounded tails are restored only with `--include-raw-local-diagnostics`.

```powershell
python -m win11_release_guard --json-pretty --wua --include-raw-local-diagnostics
```

## Generator Fails After Microsoft Page Change

| Check | What to do |
| --- | --- |
| Parser event | Inspect `source_diagnostics.events`. |
| Headers | Compare Release Health table headings with fixtures. |
| 26H1 note | Confirm special/new-devices-only text is still detected. |
| B baseline | Confirm broad target has a B-release baseline. |
| Atom support href | Use only safe Atom `alternate` links to `https://support.microsoft.com` article paths. If an Atom KB row lacks a safe Support article href, keep the Source Diagnostic evidence; do not add a `/help/<KB>` fallback resolver. |
| Support article mismatch | If Support article KB, build, URL, or parseable `Applies to` evidence disagrees with Atom, trust Atom KB/build/release and exact MSRC KB evidence; treat Support-derived summary/security wording as untrusted. |
| Security classification | Use exact MSRC CVRF KB-token evidence or validated explicit Support article wording; do not infer security status from generic Atom title text or KB substrings embedded in larger tokens. |

```powershell
pytest -q tests/test_remote_policy.py tests/test_policy_generator.py
```

## Latest Observed Is Newer Than Latest Build

| Check | What to do |
| --- | --- |
| `latest_build` | Treat it as the Release Health Current Versions table value. |
| `latest_observed_build` | Treat it as informational public Microsoft evidence, often from Atom-linked Support articles. |
| `required_baseline_build` | Keep this as the signed quality baseline used for verdicts. |

A newer latest-observed build can explain why a local machine is ahead of the
normal fleet baseline. It does not make the device noncompliant and does not
raise the required baseline unless the policy baseline rules select that build.
When Release Health has caught up and the baseline rules select that same
build, all three fields can legitimately show the same build number.

## Related Pages

[Home](Home) | [Source Diagnostics](Source-Diagnostics) | [Agent Chokepoints](Agent-Chokepoints)
