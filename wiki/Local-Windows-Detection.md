# Local Windows Detection

Use this when documenting or changing installed-state detection. The evaluator must derive installed Windows state from build evidence before display labels.

![Windows 11 Release Guard local detection model showing build evidence as authoritative and labels as diagnostic](https://raw.githubusercontent.com/Avnsx/win11_release_guard/main/assets/images/windows-11-release-guard-local-detection-model.png)

---

## Signal Map

| Signal | Role |
| --- | --- |
| `RtlGetVersion` | Highest-trust running OS build signal. |
| DISM image version | Strong image/build consistency signal. |
| `ntoskrnl.exe` file version | Kernel build consistency signal. |
| Registry build / UBR | Raw diagnostic and build contributor. |
| WMI/CIM build fields | Optional local build contributor. |
| DISM current edition | Primary edition context where available. |
| Registry `EditionID` | Edition fallback / diagnostic value. |
| `GetProductInfo` | Secondary edition/SKU signal. |
| `ProductName`, WMI `Caption`, `DisplayVersion` | Display and diagnostic labels only. |

Operating system identity fields are read natively, through the registry and
Win32 APIs, with no process spawn. PowerShell `Get-CimInstance
Win32_OperatingSystem` is the fallback path: it runs automatically only when
the native read is unavailable or returns an incomplete result.

## Why Display Labels Are Not Decisive

Windows machines can expose stale marketing strings while build signals identify the real branch. For example, raw local labels may still show `Windows 10 Pro` on a Windows 11 build family. The guard preserves the raw values for admins and flags conflicts instead of letting labels override build evidence.

## Build And Policy Win

| Situation | Result |
| --- | --- |
| `DisplayVersion=25H2` but build family maps to 24H2 in policy. | Policy build-family map wins. |
| `DisplayVersion=24H2` but build family maps to 25H2 in policy. | Policy build-family map wins. |
| Unknown syntactic release label. | Report unrecognized unless policy knows it. |
| Windows 10 client. | `OUT_OF_SCOPE` unless major-upgrade recommendation is explicitly enabled. |
| Windows Server. | `OUT_OF_SCOPE` unless server evaluation is explicitly enabled. |

## WUA Role

| WUA evidence | Use |
| --- | --- |
| Available feature update titles | Explain whether target is offered. |
| Update history | Identify previews, out-of-band updates, KBs, result codes. |
| Setup / servicing event correlation | Explain likely blockers or prior failures. |
| Defender/.NET/driver noise | Count/classify separately from relevant OS updates. |

WUA is read-only, optional, bounded, and explanatory.

## Verify

```powershell
pytest -q tests/test_local_state.py tests/test_evaluator.py tests/test_edge_cases.py
pytest -q tests/test_wua_probe.py tests/test_wua_diagnostics.py
```

## Related Pages

[Home](Home) | [CLI and RMM Usage](CLI-and-RMM-Usage) | [Troubleshooting](Troubleshooting)
