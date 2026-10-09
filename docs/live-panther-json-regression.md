# Live Panther JSON Regression

A repeatable, Windows-only live check that default JSON hides raw Panther/setup log tails and that `--include-raw-local-diagnostics` brings them back.

This harness is output validation only. It must not change evaluator verdict logic, signing, policy trust, WUA verdict behavior, boot configuration, BCD, BitLocker, WinRE, recovery settings, or Windows setup state.

Operational boundary:

- Panther data is an administrator troubleshooting layer, not product truth.
- Raw Panther/setup log text in default JSON is treated as an output leak, not as proof of OS damage.
- Panther reads stay fixed-path, per-file tail-bounded, and protected by a deliberately generous global collection cap.
- Compliance remains decided by the signed public policy verdict. Setup warnings and local Panther evidence must not override it.

## Command

```powershell
python tools/live_panther_json_regression.py
```

Default output directory:

```text
.tmp/live-panther-json-regression/
```

Generated files:

| File | Purpose |
| --- | --- |
| `out.json` | Strict-production default pretty JSON. |
| `out.raw.json` | Strict-production pretty JSON with `--include-raw-local-diagnostics`. |
| `report.json` | Machine-readable harness result, commands, JSON validation status, raw-string counts, marker counts, and verdict summary. |

Before each run the harness removes only its own generated `out.json` and
`out.raw.json` files. This prevents stale output from a previous successful run
from masking a failed live command.

## What It Checks

1. Runs strict-production default JSON through `cmd.exe` redirection.
2. Validates `out.json` with `python -m json.tool`.
3. Confirms these raw strings are absent from default JSON:
   - `$WINDOWS.~BT`
   - `SetupPlatform.exe`
   - `SERIALIZEVERBOSE`
   - `Set boot command`
   - `Update Boot Sector`
   These are leak signatures for default output, not mandatory strings that
   every live machine must have in its Panther logs.
4. Reports whether readable Panther/setup diagnostics were present. If no
   Panther source exists on the machine, the report records
   `no_panther_source_present` and the harness can still pass.
5. When Panther/setup diagnostics exist, confirms Panther-context compact
   markers exist in default JSON:
   - `content_omitted`
   - `content_chars`
   - `content_bytes_utf8`
   The marker check is both textual and structural: at least one JSON object
   in Panther context must have `content_omitted: true` plus numeric
   `content_chars` and `content_bytes_utf8` fields. Non-Panther diagnostic
   sections using the same marker names do not make the harness treat Panther
   source as present.
6. Runs strict-production JSON with `--include-raw-local-diagnostics` into `out.raw.json`.
7. Validates `out.raw.json` with `python -m json.tool`.
8. When default JSON proved Panther/setup diagnostics existed through
   compaction markers, confirms raw Panther/setup diagnostic `content` fields
   appear in `out.raw.json`. The harness also counts the known marker strings
   in raw output when present, but does not require every marker because live
   Panther logs differ by machine, setup path, and rollback history.
9. Confirms verdict fields remain sane:
   - `status`
   - `source_status`
   - `policy_signature_status`
   - `strict_production`
   - `installed_release`
   - `target.version`
   - `target.build_family`

The harness returns exit code `0` only when every check passes.

## PowerShell 5 Redirection Pitfall

Windows PowerShell 5 native-command redirection can write redirected command output as UTF-16LE. That can make this fail even when the CLI emitted valid JSON:

```powershell
python -m json.tool out.json
```

Preferred options:

```powershell
$env:WIN11_RELEASE_GUARD_STRICT_PRODUCTION = "1"
cmd.exe /d /c 'call python -m win11_release_guard --json-pretty > ".tmp\live-panther-json-regression\out.json"'
```

Or, when staying in PowerShell:

```powershell
$env:WIN11_RELEASE_GUARD_STRICT_PRODUCTION = "1"
python -m win11_release_guard --json-pretty | Out-File -Encoding utf8 .tmp\live-panther-json-regression\out.json
```

Do not use plain PowerShell 5 `> out.json` for this regression check.

## Expected Failure Modes

| Failure | Meaning |
| --- | --- |
| Stale output cannot be removed | One of the generated output paths is blocked or is not a file, so the harness refuses to risk reading old results. |
| JSON command exits nonzero | The live strict-production CLI run failed. Check `report.json` command stderr/stdout. |
| JSON command times out | The CLI or `json.tool` did not finish within the harness timeout; the report records return code `124`. |
| Output file missing after return code `0` | The command appeared successful but did not create a fresh capture file, so the result is rejected. |
| `json.tool` fails | The captured file is not valid JSON or was written with the wrong encoding. |
| JSON loads but is not an object | The capture is syntactically JSON but not the expected CLI object payload. |
| Raw strings found in `out.json` | Default JSON compaction missed a Panther/setup output path. |
| `no_panther_source_present` | Not a failure. The machine has no readable Panther/setup source in this run, so compaction/raw-restore checks are not required. |
| Compact markers missing or malformed while raw diagnostics exist | Default compaction did not run, or marker fields were written with the wrong types. |
| Raw Panther `content` fields missing while default compaction markers exist | Raw local diagnostics were not restored even though default JSON proved content existed. |
| Known marker counts are zero in `out.raw.json` | Not a failure by itself when raw Panther `content` fields exist; the exact strings are machine-specific. |
| `source_status` is not `REMOTE_POLICY_OK` | Strict production did not use a fresh live signed remote policy source. |

If live network access is unavailable, do not claim live harness success. Unit tests cover the harness logic, but the live regression is only proven by running the tool on the affected Windows machine.
