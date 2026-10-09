# Panther Support

Purpose: explain how Windows 11 Release Guard uses Windows Panther/setup logs, how operators and maintainers can use the feature, and where to extend it without turning Panther data into verdict authority.

Related links: [maintainer guide](maintainer-guide.md) | [architecture insight](architecture-insight.md) | [live Panther JSON regression](live-panther-json-regression.md) | [source module map](source-modules.md)

## At A Glance

| Area | Current support level | Practical meaning |
| --- | --- | --- |
| Collection | Narrow and guarded | Reads a fixed set of known Panther/setup log tail paths only. |
| Read size | Bounded | Reads the tail of each existing log instead of loading whole files; current default is 5 MiB per file. |
| Total IO guard | Very generous | A 512 MiB global Panther collection cap acts as a regression backstop without limiting the current known path set. |
| Encoding | Hardened | Handles UTF-8, UTF-8 BOM, UTF-16LE/BE BOM, BOM-less UTF-16 NUL heuristics, 2-byte tail alignment, and replacement-error metadata. |
| Default JSON | Compact | Omits raw Panther/setup content and emits size markers instead. |
| Raw troubleshooting | Explicit opt-in | Restores raw bounded log tails only with `--include-raw-local-diagnostics`. |
| Privacy notice | Metadata only | Reports likely password/token/key/secret markers without copying matched values into privacy metadata. |
| Verdict authority | None | Panther is troubleshooting evidence only. Signed public policy remains the compliance authority. |

This is good production/RMM support for safe output and repeatable debugging. It is intentionally not a complete Windows Setup parser and intentionally not an OS-damage detector.

## Product Boundary

Panther support answers questions like:

- Did Windows Setup leave local diagnostic evidence that helps explain a failed, rolled-back, or missing feature update?
- Are there setup log tails worth collecting for an admin troubleshooting run?
- Did a future JSON path start leaking raw Panther text in default output?
- Does raw opt-in output still restore the evidence an admin needs?

Panther support must not answer:

- Is this machine compliant?
- Is the signed Microsoft release policy wrong?
- Should a signed policy verdict be overridden?
- Is the OS damaged just because setup logs contain warnings, boot text, or rollback strings?

The compliance verdict continues to come from signed public policy plus the normal evaluator rules. WUA remains secondary evidence. Panther remains a local admin troubleshooting layer.

## Supported Log Locations

Runtime local-state collection reads these concrete paths when they exist and are readable:

| Family | Paths |
| --- | --- |
| Current Windows Panther | `C:\Windows\Panther\setupact.log`, `C:\Windows\Panther\setuperr.log` |
| UnattendGC | `C:\Windows\Panther\UnattendGC\setupact.log`, `C:\Windows\Panther\UnattendGC\setuperr.log` |
| NewOS Panther | `C:\Windows\Panther\NewOS\Panther\setupact.log`, `C:\Windows\Panther\NewOS\Panther\setuperr.log` |
| Upgrade staging | `C:\$Windows.~BT\Sources\Panther\setupact.log`, `C:\$Windows.~BT\Sources\Panther\setuperr.log` |
| Rollback | `C:\$Windows.~BT\Sources\Rollback\setupact.log`, `C:\$Windows.~BT\Sources\Rollback\setuperr.log` |
| NewOS staged Windows | `C:\$Windows.~BT\NewOS\Windows\Panther\setupact.log`, `C:\$Windows.~BT\NewOS\Windows\Panther\setuperr.log` |

Audit diagnostics use the same coverage, with `%WINDIR%` for the Windows directory based paths.

Missing paths are silently skipped because many healthy systems do not have every setup log family. Existing but unreadable paths are recorded as Panther read errors and do not stop the rest of the probe.

Known Panther paths also share a global collection cap. The current defaults are 5 MiB per file and 512 MiB per collection. The total default is deliberately generous: it is larger than the current per-file maximum multiplied by the full known path set. Its job is to protect against future path-list expansion mistakes or accidental broad collection, not to constrain normal trusted troubleshooting.

If the total cap is reached, collected entries expose `collection_total_cap_reached: true` and `collection_total_cap_bytes`; later existing paths are reported as Panther read-skip diagnostics instead of being silently ignored.

## Operator Entry Points

### Normal Fleet Or RMM Run

Use normal JSON or pretty JSON. This is the safe default for collection systems.

```powershell
python -m win11_release_guard --json-pretty
```

Expected Panther behavior:

- Raw Panther/setup text is omitted.
- `content_omitted`, `content_chars`, and `content_bytes_utf8` show that content existed and was compacted.
- Tail metadata can remain visible, such as byte count, file size, truncation, encoding, and decode-replacement status.
- Privacy marker summaries can remain visible without matched secret values.

### Troubleshooting Run With Raw Local Diagnostics

Use raw local diagnostics only when an admin intentionally needs the actual Panther/setup tail content.

```powershell
python -m win11_release_guard --json-pretty --include-raw-local-diagnostics
```

Expected Panther behavior:

- Raw bounded Panther/setup log tails are present.
- The same verdict/status fields keep the same meaning.
- Any privacy notice should be treated as a review-before-upload warning.

### Live Regression Harness

Use this when changing Panther output behavior or validating a Windows machine where Panther logs are known to be noisy.

```powershell
python tools/live_panther_json_regression.py
```

The harness creates:

| File | Meaning |
| --- | --- |
| `.tmp/live-panther-json-regression/out.json` | Strict-production default JSON. |
| `.tmp/live-panther-json-regression/out.raw.json` | Strict-production raw opt-in JSON. |
| `.tmp/live-panther-json-regression/report.json` | Machine-readable validation report. |

It validates JSON syntax, confirms raw Panther strings are absent by default,
confirms compaction markers exist when readable Panther diagnostics exist,
confirms raw Panther `content` fields return in opt-in output when default
compaction proved such content existed, and verifies verdict fields remain
sane. On clean machines with no readable Panther/setup source, the report uses
`no_panther_source_present` and can still pass. The known strings such as
`$WINDOWS.~BT`, `SetupPlatform.exe`, and `SERIALIZEVERBOSE` are treated as
default-output leak signatures, not as mandatory raw evidence on every machine.

PowerShell 5 note: for manual captures, prefer `cmd.exe` redirection or `Out-File -Encoding utf8`; plain PowerShell 5 `>` can write UTF-16LE and make valid CLI JSON fail `python -m json.tool`.

### Leak Debugger

Use this when default JSON unexpectedly contains raw Panther/setup strings.

```powershell
python tools/debug_panther_json_leaks.py .tmp\live-panther-json-regression\out.json --mode default
```

For raw opt-in output:

```powershell
python tools/debug_panther_json_leaks.py .tmp\live-panther-json-regression\out.raw.json --mode raw-opt-in
```

The debugger reports JSON paths, value lengths, matched marker names, short sanitized snippets, and the likely minimal fix strategy. Raw opt-in leaks are expected; default-output leaks are regressions.

## JSON Shape

Default JSON compacts raw Panther strings into marker objects:

```json
{
  "content_omitted": true,
  "content_chars": 1781351,
  "content_bytes_utf8": 1781395
}
```

Panther tail metadata can remain visible:

```json
{
  "file_size_bytes": 1781395,
  "tail_start_offset": 0,
  "tail_truncated": false,
  "tail_bytes": 1781395,
  "encoding_detected": "utf-8",
  "decode_errors_replaced": false,
  "privacy_scan_completed": true,
  "privacy_findings_count": 0
}
```

BOM-less UTF-16 Panther logs are detected with NUL-byte heuristics. When a
bounded tail starts in the middle of such a file, the reader aligns the start
back to a 2-byte code-unit boundary before decoding so the tail does not gain
avoidable replacement characters solely from an odd byte offset.

If the global collection guard was reached, Panther entries can also include:

```json
{
  "collection_total_cap_reached": true,
  "collection_total_cap_bytes": 536870912
}
```

If privacy-sensitive markers are found, default JSON reports metadata only:

```json
{
  "privacy_scan_completed": true,
  "privacy_findings_count": 1,
  "notice": "Panther/setup logs matched privacy-sensitive markers. Default JSON omits raw log content; review --include-raw-local-diagnostics output before uploading or sharing it.",
  "privacy_findings": [
    {
      "category": "license_key",
      "finding_type": "license_key:product_key",
      "marker": "product_key",
      "path": "C:\\Windows\\Panther\\setupact.log",
      "line_number": 614,
      "line_chars": 92,
      "line_bytes_utf8": 92,
      "safe_hint": "Review before sharing raw diagnostics; product key value is omitted."
    }
  ]
}
```

The finding metadata deliberately does not include the matching line or value.

## Privacy And Upload Safety

Panther/setup logs are local administrator evidence and can contain values that should not be posted to tickets, public issues, chat systems, or remote storage without review.

Current privacy hardening detects likely markers for:

| Category | Examples of marker type |
| --- | --- |
| `credential` | Password labels, authorization headers, connection-string credentials |
| `secret` | Secret assignments, SAS signatures, private key blocks |
| `token` | Token or API key assignments |
| `license_key` | Product key / GVLK-style labels |

The scanner reports only category, finding type, marker, path, line number,
line length, counts, safe hints, and a notice. It does not copy the matched
line or matched value into `privacy_findings`.

To avoid noisy Panther false positives, setup phase labels such as `Pass:
specialize` are not treated as passwords. Password findings require explicit
password-style labels such as `password`, `passwd`, or `pwd`.

Default JSON is the upload-safer output. Raw opt-in JSON is intentionally more useful for troubleshooting and therefore should be reviewed before it is uploaded or shared.

## Implementation Map

| File | Panther responsibility |
| --- | --- |
| `win11_release_guard/diagnostic_tail.py` | Bounded tail reads, encoding detection, privacy-marker summaries. |
| `win11_release_guard/local_state.py` | Main local Panther log collection under `local.raw.panther_logs`. |
| `win11_release_guard/audit_probes.py` | Read-only audit diagnostics and setup evidence extraction. |
| `win11_release_guard/__main__.py`, `win11_release_guard/cli_output.py` | Default JSON compaction and `--include-raw-local-diagnostics`. |
| `tools/live_panther_json_regression.py` | Windows live regression proving default compaction and raw opt-in restoration. |
| `tools/debug_panther_json_leaks.py` | Developer debugger for future raw Panther JSON leaks. |
| `tests/test_local_state*.py` | Tail decoding, path coverage, privacy metadata, read-error continuation. |
| `tests/test_output_encoding.py` | Default compaction, raw opt-in, nested JSON paths, privacy metadata safety. |
| `tests/test_live_panther_json_regression.py` | Harness logic and redirection command construction. |
| `tests/test_debug_panther_json_leaks.py` | Leak path reporting and minimal-fix recommendations. |

## How Well It Is Implemented

The current implementation is strongest in these areas:

| Strength | Why it matters |
| --- | --- |
| Bounded reads | Large Panther logs do not explode JSON output or memory use. |
| Global collection cap | Multiple large logs cannot grow without an upper IO/backing-memory bound if path coverage expands later; the default is intentionally generous for trusted troubleshooting. |
| Per-path failure isolation | One unreadable log does not hide other readable logs. |
| Encoding metadata | UTF-16 and invalid-byte cases are visible instead of silently misread. |
| Default compaction | Fleet/RMM JSON avoids dumping large local setup logs by default. |
| Raw opt-in | Admins can still get exact local evidence when troubleshooting. |
| Leak debugger | Future JSON path regressions can be located precisely. |
| Live harness | Real Windows redirection, JSON parsing, raw string checks, and verdict-field sanity are repeatable. |
| Privacy metadata | Default JSON can warn about likely sensitive Panther values without copying them. |

The current implementation is intentionally limited here:

| Limit | Reason |
| --- | --- |
| Not a full setup parser | The product should not infer compliance from setup logs. |
| Narrow path list | Avoids broad recursive collection of arbitrary logs. |
| Tail-only reads | Old evidence outside the bounded tail may not be captured. |
| Marker-based privacy scan | It is a best-effort warning layer, not a data loss prevention engine. |
| English/setup-token biased evidence extraction | It extracts known useful setup patterns but does not attempt every language or every setup component. |

## When It Becomes Useful

Panther support is useful when:

- The signed policy says the target release is available, but the machine did not move.
- A feature update was offered or attempted but appears to have rolled back.
- WUA evidence is unclear and an admin needs local setup context.
- A support engineer needs to know whether setupact/setuperr tails contain rollback, setup failure, target release, or target build clues.
- Default JSON unexpectedly gets huge or contains raw `$WINDOWS.~BT`, `SetupPlatform.exe`, `SERIALIZEVERBOSE`, boot command, or boot sector strings.
- A troubleshooting bundle needs to prove raw diagnostics are available only when explicitly requested.

Panther support is not useful as a sole reason to:

- Mark a release compliant or non-compliant.
- Override a valid signed public policy verdict.
- Declare Windows damaged.
- Change boot, BCD, BitLocker, WinRE, recovery, signing, policy trust, or WUA verdict behavior.

## Extending Support Safely

Use this checklist when adding Panther compatibility:

1. Add new known log paths only to `PANTHER_LOG_PATHS` and `PANTHER_SETUP_LOG_PATHS`.
2. Keep reads bounded through `read_diagnostic_tail()` and preserve the generous global collection guard.
3. Add tests for the new path or evidence shape.
4. Confirm default JSON still compacts raw strings.
5. Confirm raw opt-in still restores raw diagnostics.
6. If a new JSON path leaks raw Panther content, add a narrow compaction hook or extend the existing recursive `source == "panther"` compaction path.
7. If new privacy-sensitive patterns are found, add marker metadata only; do not copy matched values into privacy findings.
8. Rerun scoped Panther tests and the full local gate.

Recommended scoped tests:

```powershell
pytest -q tests/test_local_state*.py tests/test_output_encoding.py tests/test_debug_panther_json_leaks.py tests/test_live_panther_json_regression.py
```

Recommended full gate:

```powershell
python -m compileall -q win11_release_guard tools
pytest -q
python tools/check_project_identity.py
python tools/check_version_consistency.py
python -m win11_release_guard --self-test
python tools/scan_for_secret_material.py site win11_release_guard tests tools docs wiki README.md CHANGELOG.md AGENTS.md pyproject.toml .github
```

For live Windows verification:

```powershell
python tools/live_panther_json_regression.py
```

## Regression Definition

This is a Panther regression:

- Raw Panther/setup strings appear in default JSON.
- Raw Panther/setup `content` fields appear in default JSON, even if they do
  not contain one of the known marker strings.
- Default JSON loses compaction markers for Panther log tails that actually
  exist.
- `--include-raw-local-diagnostics` no longer restores raw bounded Panther
  tails when default compaction proves such content existed.
- Privacy findings include matched secret/password/token/key values instead of metadata only.
- The global collection cap is reduced enough to constrain the current known path set during normal trusted troubleshooting.
- Panther warnings start changing evaluator verdicts or signed-policy authority.

This is not a Panther regression by itself:

- A machine has no Panther logs.
- A log path is missing.
- A protected Panther subdirectory returns access denied while other paths continue.
- The live harness reports `no_panther_source_present`.
- Raw opt-in output contains Panther/setup strings.
- Raw opt-in output contains Panther/setup `content` but not the exact known
  marker strings counted by the live harness.
- Setup logs contain warnings that are useful for troubleshooting but not verdict authority.
