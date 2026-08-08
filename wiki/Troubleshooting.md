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
| Servicing index missing/unparseable | `servicing_toc_missing`, `servicing_toc_parse_failed`, or `servicing_toc_no_usable_entries` warning. Release Health still drives the policy; preview/out-of-band classification and drift context stay incomplete until the servicing index is available and carries at least one titled, hrefed row (a KB in the title is not required). |
| Servicing support href | Use only safe links to `https://support.microsoft.com` article paths. Safe `:443`, query, or fragment variants canonicalize to scheme/host/path; unsafe ports, feed/API/search/download/static/traversal paths, and non-support hosts reject. If a servicing entry's KB row lacks a safe Support article href, keep the Source Diagnostic evidence (`atom_support_article_href_missing`); do not add a `/help/<KB>` fallback resolver. |
| Servicing row matching | If the same KB appears more than once, confirm Release History enrichment selected a row-build match before accepting KB-only metadata. Ambiguous KB-only fallbacks should be skipped rather than silently choosing the first entry. |
| Support article mismatch | If Support article KB, build, URL, or parseable `Applies to` evidence disagrees with the servicing entry, trust the servicing entry's KB/build/release and exact MSRC KB evidence; treat Support-derived summary/security wording as untrusted. Use `applies_to_releases` when present to see which release values were parsed. |
| Security classification | Use exact MSRC CVRF KB-token evidence or validated explicit Support article wording; do not infer security status from generic servicing entry title text or KB substrings embedded in larger tokens. Exact-KB remediations count even when optional CVE/severity/product fields are absent. |

```powershell
pytest -q tests/test_remote_policy.py tests/test_policy_generator.py
```

## Latest Observed Is Newer Than Latest Build

| Check | What to do |
| --- | --- |
| `latest_build` | Treat it as the Release Health Current Versions table value. |
| `latest_observed_build` | Treat it as informational public Microsoft evidence, often from Support articles linked in the servicing table-of-contents JSON. |
| `required_baseline_build` | Keep this as the signed quality baseline used for verdicts. |

A newer latest-observed build can explain why a local machine is ahead of the
normal fleet baseline. It does not make the device noncompliant and does not
raise the required baseline unless the policy baseline rules select that build.
When Release Health has caught up and the baseline rules select that same
build, all three fields can legitimately show the same build number.

## Baseline Update Notice Appears

| Check | What to do |
| --- | --- |
| Required baseline source | Confirm the row is a real non-preview, non-OOB Release Health B-release. |
| Notice timing | Check `official_release_date`, `official_release_precision`, `visible_from_utc`, and `visible_until_utc`; date-only Microsoft evidence is intentionally labeled date-only. |
| Evidence status | If Support or MSRC evidence is degraded/unknown, keep the notice but do not treat Support text as security proof. |
| Expired notice | Expired or inactive notice metadata should not fetch optional Support/MSRC enrichment just to decorate stale history. A stale static page hides the notice and reflows the operational panels. |
| Issue sync | Leave it dashboard-only; the `required_baseline_matched_latest_observed` notice must not create or reopen GitHub Issues. |

The notice explains that the compliance floor has caught up to already observed
public Microsoft evidence. It is informational UI generated from local policy
facts and validated public evidence; it does not change signed verdicts,
required-baseline selection, runtime client behavior, or `/api/v1` aliases.

## On-Disk State

| Check | What to do |
| --- | --- |
| `cache_write_failed` source problem | The state or `--cache-file` write was skipped or failed; the run continues on the freshly verified remote policy and the verdict and exit code are unchanged. The problem message names the path and reason. |
| Two instances at once (`WinError 32`) | First cause to rule out: two runs with the same configuration share one staging file name and one raced the other's `os.replace`. The loser records `cache_write_failed` and moves on; no data is lost. |
| `--cache-file` under a missing parent | The write primitive never creates directories, so a `--cache-file` whose parent directory does not exist is skipped, not created. The run records `cache_write_failed` and caches nothing, and the embedder-only `cache.save_policy_cache` and `wu_offer_probe.store_cached_cookie` helpers return without raising in the same situation. Create the directory once, deliberately, then rerun. |
| Legacy pair `.sig` mismatch | For a `--cache-file` legacy pair the policy and its `.sig` are written together; a stale or mismatched `.sig` reads back as `corrupt_cache` and self-heals on the next successful remote fetch. |
| Stored record shows `corrupt_cache` | A container record that fails its magic, length, stream-boundary, or digest checks is treated as unusable and retried; it is rewritten from the next verified remote policy. |
| `--show-state --output` did not write | A monitoring agent holding the output path open can refuse both the atomic swap and the one in-place fallback; the state report still prints, a top-level `detail` names the reason, and the command exits `2`. |
| `--output` did not write | The report is written atomically through a staging file and `os.replace`, with one in-place fallback. When both fail the message names the path and the underlying error, for example `Could not write JSON output to C:\reports\out.json: FileNotFoundError: [Errno 2] No such file or directory`, and the command exits `2` as before. |
| Cookie cache or `cache.save_policy_cache` file now ends lines with LF | The optional Windows Update cookie cache and the embedder-only `cache.save_policy_cache` / `save_cached_policy` helpers serialise their JSON and write the bytes through the atomic write primitive, so on Windows those two files contain LF instead of the previous CRLF. The JSON content is otherwise unchanged and every reader of them is unaffected. A `--cache-file` legacy pair is not one of them: it holds the publisher's exact policy and signature bytes and always did. |

## Related Pages

[Home](Home) | [Source Diagnostics](Source-Diagnostics) | [Agent Chokepoints](Agent-Chokepoints)
