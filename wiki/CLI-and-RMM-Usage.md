# CLI And RMM Usage

Use this when integrating Windows 11 Release Guard into scripts, RMM tools, dashboards, or compliance checks.

---

## Common Commands

| Need | Command |
| --- | --- |
| Human output | `python -m win11_release_guard --pretty` |
| Compact JSON | `python -m win11_release_guard --json --no-wua` |
| Pretty JSON | `python -m win11_release_guard --json-pretty --no-wua` |
| UTF-8 console JSON | `python -m win11_release_guard --json --unicode` |
| Write output file | `python -m win11_release_guard --json --output release-check.json` |
| Include full bounded WUA history | `python -m win11_release_guard --json --include-raw-wua-history --wua` |
| Include raw local Panther/setup log tails | `python -m win11_release_guard --json-pretty --include-raw-local-diagnostics` |
| Diagnose config | `python -m win11_release_guard --diagnose-config` |
| Check source only | `python -m win11_release_guard --check-policy-source` |
| Keep state in a fixed directory | `python -m win11_release_guard --state-dir C:\ProgramData\win11_release_guard` |
| Run with no on-disk state | `python -m win11_release_guard --stateless` |
| Remove stored state | `python -m win11_release_guard --purge-state` |
| Show stored state | `python -m win11_release_guard --show-state` |

## Exit Codes

| Code | Status |
| --- | --- |
| `0` | `COMPLIANT` or source check passed. |
| `1` | `FEATURE_UPDATE_REQUIRED`, `QUALITY_UPDATE_REQUIRED`, or preview remediation when configured. |
| `2` | `UNKNOWN_LOCAL_RELEASE`, `CHECK_INCOMPLETE`, or policy/source problem. |
| `3` | `ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE`. |
| `10` | CLI argument error. |

## RMM Defaults

| Setting | Recommendation |
| --- | --- |
| Source mode | Use default public signed policy URL. |
| WUA | Keep off for fast compliance checks; enable for diagnostics. |
| Output | Use JSON or JSON-pretty. |
| Production gate | Use `--strict-production`. |
| Cache | Accept as degraded evidence, not production green in strict mode. |
| State location | Set `--state-dir` or `WIN11_RELEASE_GUARD_STATE_DIR` for a fixed, auditable path; the default is the operating-system temp directory. |
| Stateless runners | Use `--stateless` or `WIN11_RELEASE_GUARD_STATELESS=1` for read-only agents that must write nothing. |

## JSON Fields To Watch

| Field | Meaning |
| --- | --- |
| `status` | Primary verdict. |
| `candidate_status` | Local candidate verdict when strict source gating masks it. |
| `local_scope_status` | Out-of-scope candidate for Windows 10/Server in strict degraded paths. |
| `source_status` | Remote/cache/bundled/unavailable source state. |
| `is_source_check_complete` | Whether source requirements were fully satisfied. |
| `policy_signature_status` | Signature trust state. |
| `feed_age_days` | Age of live policy feed where available. |

Default JSON compacts bulky local Panther/setup log tails and emits omission markers
such as `content_omitted`, `content_chars`, and `content_bytes_utf8`. Use
`--include-raw-local-diagnostics` only when troubleshooting needs the raw bounded
local log tails. Panther/setup logs are administrator troubleshooting evidence
only; they never decide compliance or override the signed public policy verdict.
Panther reads use fixed known paths, per-file tail reads, and a deliberately
generous global collection guard to keep IO predictable without constraining
normal trusted troubleshooting.

## Verify

```powershell
python -m win11_release_guard --json-pretty --no-wua
python -m win11_release_guard --diagnose-config
pytest -q tests/test_cli.py tests/test_output_encoding.py
```

## Related Pages

[Home](Home) | [Configuration](Configuration) | [Troubleshooting](Troubleshooting)
