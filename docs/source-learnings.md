# Source Learnings

## Audit Scope

Reviewed local sources:

- `deep-research-report.md`
- `WindowsOSBuild/README.md`
- `WindowsOSBuild/Public/Get-LatestOSBuild.ps1`
- `WindowsOSBuild/Public/Get-CurrentOSBuild.ps1`
- `WUView/README.md`
- `WUView/WUView/ViewModels/MainViewModel.cs`
- `WUView/WUView/Models/WUpdate.cs`
- `WUView/WUView/Models/WuEventRecord.cs`
- `win11_release_guard/*.py`

## External Source Lessons

WindowsOSBuild does not reveal a hidden public Microsoft JSON API. It retrieves patch data from Microsoft Release Health / Update History pages and enriches it with Microsoft Atom feeds. Its useful ideas for this project are:

- Release Health / Update History parsing.
- Atom feed enrichment for preview and out-of-band metadata.
- Preview / out-of-band classification on each build row.
- `ExcludePreview` / `ExcludeOutOfBand` semantics, including treating unknown feed state separately from known preview/OOB rows.
- `BuildOnly`-style baseline output for automation that only needs the selected build number.

WUView is useful as a local update-evidence model, not as policy truth. Its useful ideas are:

- WUA `QueryHistory`.
- WUA `Search`.
- Capturing result code, HResult/unmapped result, and operation.
- KB extraction from update titles.
- Setup log correlation through the `Microsoft-Windows-Servicing` provider in the `Setup` event log, matched by KB.
- Noise filtering for Defender, .NET, app runtime, driver, and similar non-OS-baseline updates.

WUView's hard limitation is that it can only display what the local Windows Update Agent knows. WUA evidence must never override the policy verdict.

## Deep Report Architecture

The final architecture from the research report is:

- The runtime client should consume a generated, signed policy JSON.
- HTML parsing belongs primarily in the generator path, not normal runtime client execution.
- WUA is secondary evidence only.
- Panther logs and DISM packages are audit/conflict-resolution evidence, not primary truth.

The live output evidence reinforces the same design:

- Raw local `ProductName` can be `Windows 10 Pro` while the real build/release state is Windows 11 25H2.
- Local build `26200.8524` is above B baseline `26200.8457`, but WUA history shows it came from preview update `KB5089573`.
- WUA output can be very noisy and localized, for example German Defender, .NET, runtime, MRT, driver, and platform update titles.

## What The Current Module Does Correctly

- Uses a build-first local model and keeps `ProductName`, caption, and display fields as raw diagnostics rather than primary truth.
- Collects multiple local build signals: `RtlGetVersion`, registry build/UBR, CIM/WMI, `ntoskrnl.exe` file version, and DISM current edition.
- Has a policy-shaped model with `broad_target_existing_devices`, current versions, release history, special releases, excluded existing-device releases, supported build families, and B-release quality policy.
- Parses Microsoft Windows 11 Release Health HTML into current-version and release-history rows.
- Detects special releases such as 26H1 from page text and can exclude them from broad-fleet target selection.
- Selects GA H2 broad target and B-release baseline, matching the required "25H2 over 26H1 for existing devices" behavior.
- Keeps WUA as secondary data in evaluation and already records WUA search/history, KB IDs, categories, operation, result code, HResult, and unmapped result code.
- Import is side-effect free; active local/network/WUA work starts only through explicit APIs or CLI execution.
- Project identity is `win-release-guard` for the repository, distribution metadata, console command, cache path, user agent, and WUA `ClientApplicationID`. The Python import package remains `win11_release_guard` because import statements cannot use hyphens.

## What Must Change

- Split generator from runtime: runtime must fetch and verify a generated signed JSON policy, not parse Release Health HTML directly during normal execution.
- Move or wrap the existing Release Health HTML parser into a generator path and add WindowsOSBuild-style Atom feed enrichment for preview/OOB classification.
- Add explicit signed-policy schema fields for source URLs, generation time, expiry, broad-target policy, B baseline, preview/OOB rows, special/excluded releases, and signature metadata.
- Distinguish "above B baseline because preview installed" from "fleet baseline is higher"; `26200.8524` from `KB5089573` should be shown as preview-origin evidence while the required B baseline remains `26200.8457`.
- Improve WUA classification for localized/noisy output. Do not rely only on English title fragments such as `feature update`; use KB IDs, categories, release strings, build numbers, and allowlist/blocklist classes.
- Add WUView-style Setup/Servicing event-log correlation by KB.
- Add Panther log and DISM package collection as audit/conflict-resolution output.
- Preserve all raw admin-facing values in output. Do not hide stale `ProductName`, localized WUA titles, KBs, driver titles, or error details.
- Keep policy verdict precedence explicit in docs and tests: WUA can add notes/evidence but cannot change the release-policy verdict.

## Implementation Plan

1. Define a generated signed policy JSON contract with schema version, `generated_at_utc`, `expires_at_utc`, sources, broad target for existing devices, B baseline, release history, preview/OOB flags, excluded/special releases, supported build-family map, and signature metadata.
2. Create a generator path that owns Microsoft Release Health / Update History parsing and Atom feed enrichment. Keep existing HTML parsing logic only there or behind generator-specific APIs.
3. Change runtime policy loading to accept signed JSON, verify schema/signature/expiry, then cache last-known-good policy. Runtime should not scrape Microsoft HTML in the normal path.
4. Extend baseline evaluation so preview/OOB-installed builds above the B baseline are reported as compliant with preview/OOB evidence, not as a new required fleet baseline.
5. Strengthen WUA secondary evidence: collect `Search` and `QueryHistory`, preserve raw result fields, extract KBs/builds/release strings language-neutrally, classify common Defender/.NET/runtime/driver noise, and keep WUA non-authoritative.
6. Add Setup/Servicing event-log correlation by KB, following WUView's model, and include raw event IDs, record IDs, timestamps, provider, and descriptions.
7. Add Panther and DISM package audit probes for conflict resolution, including raw matched KBs, package identities, setup log paths checked, and parse errors.
8. Add regression fixtures for the observed live-output case: `ProductName` `Windows 10 Pro`, release `25H2`, build `26200.8524`, B baseline `26200.8457`, preview `KB5089573`, and noisy German WUA history.
9. Update README and docs to state the source hierarchy: signed policy JSON first, local build/edition signals for installed state, WUA/Panther/DISM as evidence only, and raw admin data preserved.
