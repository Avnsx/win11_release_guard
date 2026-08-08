# Configuration

Use this when choosing runtime defaults or documenting CLI/env knobs for fleet usage.

---

## Recommended Defaults

| Context | Default |
| --- | --- |
| Human local check | `--pretty` |
| RMM compliance | `--json --no-wua` |
| Production compliance | `--strict-production --json --no-wua` |
| Troubleshooting update offers | Add `--wua` |
| Source-only verification | `--check-policy-source` and `--check-public-pages` |

## Settings / Knobs

| Knob | Source | Meaning |
| --- | --- | --- |
| `--policy-url` | CLI | Override default policy URL or use local file. |
| `WIN11_RELEASE_GUARD_POLICY_URL` | Env | Default policy URL override. |
| `--strict-production` | CLI | Require live signed remote JSON for production-green result. |
| `WIN11_RELEASE_GUARD_STRICT_PRODUCTION` | Env | Enable strict-production preset. |
| `--cache-file` | CLI | Override cache path. |
| `--cache-max-age-hours` | CLI | Fresh cache age. |
| `--stale-cache-max-age-hours` | CLI | Stale cache allowance. |
| `--max-policy-bytes` | CLI/env | Policy fetch/parse size cap. |
| `--wua` / `--no-wua` | CLI | Enable or disable optional WUA probe. |
| `--include-raw-local-diagnostics` | CLI | Include raw bounded local Panther/setup log tails instead of default JSON compaction. |
| `--quality-policy` | CLI | Choose B-release default or broader quality policy. |
| `--state-dir DIR` | CLI | Keep the on-disk state record in `DIR` instead of the operating-system temp directory. |
| `WIN11_RELEASE_GUARD_STATE_DIR` | Env | Default state directory override. |
| `--stateless` | CLI | Read and write no on-disk state for this run. |
| `WIN11_RELEASE_GUARD_STATELESS` | Env | Enable stateless mode (`1`, `true`, `yes`, or `on`). |
| `--purge-state` | CLI | Remove every file this configuration may have written and report each path. |
| `--show-state` | CLI | Print the decoded stored policy state. |
| `WIN11_RELEASE_GUARD_CACHE_FILE` | Env | Default `--cache-file` override for the legacy JSON cache pair. |

## Runtime Clamps / Fallbacks

| Area | Default behavior |
| --- | --- |
| HTTP fetch | Shared client with consistent headers, transparent decompression, bounded timeout and byte cap, retry with backoff on transient failures, and conditional (`ETag`) requests. |
| WUA subprocess | Bounded timeout. |
| DISM / PowerShell probes | Bounded timeouts. |
| Panther logs | Fixed known paths, bounded per-file tail reads, a generous global collection guard, and default JSON compaction unless `--include-raw-local-diagnostics` is used. |
| WUA output | History and relevant OS update lists are bounded. |
| Cache fallback | Visible degraded source status. |

Panther/setup logs are administrator troubleshooting evidence only. They do not decide compliance or override the signed public policy verdict.

## On-Disk State

By default the client runtime keeps its policy cache as one compact, atomically
written record in the operating-system temp directory, not as a permanent file
under `%LOCALAPPDATA%`. On-disk state is an optimisation only: it never changes
the signed compliance verdict and never changes the exit code. A verified remote
policy is always used even when the state write is skipped or fails.

The record is a fixed 50-byte little-endian header followed by one
`zlib`-deflated body of the signed policy bytes and the detached signature:

```text
off  size  field           value / meaning
  0     8  magic           DB A7 0D 0A 53 54 52 31        (STATE_MAGIC)
  8     2  format_version  uint16, must equal 1
 10     4  policy_len      uint32, exact length of the signed policy bytes, uncompressed
 14     4  signature_len   uint32, exact length of the detached signature, 0 when absent
 18    32  body_digest     sha256(policy_bytes + signature_bytes) over the uncompressed body
 50  rest  body            zlib.compress(policy_bytes + signature_bytes, 9)
```

The tool reads a record only at a path it derived itself and removes one only
after confirming its first eight bytes match `STATE_MAGIC` and it did not yield a
signature-verified policy, so a foreign file at the same path is never deleted. An
unusable record self-heals on the next run. The record format is compact because
it stores two exact byte blobs and a digest.
It is not a confidentiality mechanism and provides no protection against
inspection of any kind.

`--stateless` applies to the compliance run: that run reads and writes no state.
`--purge-state` and `--show-state` deliberately ignore it and act on the real
location, so a fleet that normally runs stateless can still inspect and clear
what an earlier stateful run left behind. In the `--show-state` payload the
`stateless` field therefore reports the configured setting while `layout` and
`source` describe the inspected location.

`--diagnose-config` reports `cache_file` as the effective runtime location: a
configured `--cache-file` when one is set, otherwise the state record path, and
`null` when the run is stateless. `state_layout`, `state_path`, `state_dir`,
`state_dir_source`, `stateless`, `stateless_source`, `cache_file_source`, and
`state_format_version` report the rest of the resolved scope and where each
value came from.

`--cache-file` (and `WIN11_RELEASE_GUARD_CACHE_FILE`) selects the legacy JSON
cache pair instead: the write primitive never creates directories, so a
`--cache-file` under a missing parent directory is skipped with a
`cache_write_failed` source problem rather than creating a tree. The legacy pair
is written as bytes, so it uses LF line endings on every platform.

## Deprecated / Avoid

| Avoid | Reason |
| --- | --- |
| `--allow-unsigned-policy` in production | Removes signature trust requirement. |
| Runtime HTML fallback | Generator owns Microsoft HTML parsing. |
| Treating stale cache as production-green | Strict-production blocks this. |

## Verify

```powershell
python -m win11_release_guard --diagnose-config
python -m win11_release_guard --show-state
pytest -q tests/test_cache.py tests/test_cli.py tests/test_state_cli.py
```

## Related Pages

[Home](Home) | [CLI and RMM Usage](CLI-and-RMM-Usage) | [Policy Feed and Trust Model](Policy-Feed-and-Trust-Model)
