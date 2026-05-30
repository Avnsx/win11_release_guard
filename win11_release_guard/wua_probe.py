from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import argparse
from collections import Counter
from typing import Any, Mapping

from .config import (
    DEFAULT_EVENT_LOG_MAX_EVENTS,
    DEFAULT_POWERSHELL_TIMEOUT_SECONDS,
    DEFAULT_WUA_MAX_HISTORY,
    DEFAULT_WUA_MAX_RELEVANT_UPDATES,
    DEFAULT_WUA_TIMEOUT_SECONDS,
)


SEARCH_CRITERIA = "IsInstalled=0 and Type='Software' and IsHidden=0"
CLIENT_APPLICATION_ID = "win-release-guard/0.2"
NOISE_CLASSIFICATIONS = {
    "defender_definition",
    "dotnet",
    "driver",
    "store_or_runtime",
    "security_platform",
}
RELEVANT_OS_CLASSIFICATIONS = {
    "feature_update",
    "quality_update",
    "quality_preview",
    "out_of_band",
}


def _empty_result() -> dict[str, Any]:
    return {
        "available": False,
        "service_enabled": None,
        "available_updates": [],
        "relevant_os_updates": [],
        "noise_counts": {},
        "history": [],
        "event_log_events": [],
        "correlated_event_logs": [],
        "target_feature_update_offered": False,
        "target_release_in_history": False,
        "search_criteria": SEARCH_CRITERIA,
        "timed_out": False,
        "warnings": [],
        "errors": [],
    }


def _collection_count(collection: Any) -> int:
    return int(getattr(collection, "Count", 0) or 0)


def _collection_item(collection: Any, index: int) -> Any:
    return collection.Item(index)


def _kb_ids_from_text(text: str | None) -> list[str]:
    return list(dict.fromkeys(match.upper() for match in re.findall(r"\bKB\d{6,8}\b", text or "", flags=re.IGNORECASE)))


def _string_collection(collection: Any, prefix: str = "") -> list[str]:
    values: list[str] = []
    try:
        for index in range(_collection_count(collection)):
            value = str(_collection_item(collection, index))
            values.append(f"{prefix}{value}" if prefix and not value.upper().startswith(prefix.upper()) else value)
    except Exception:
        return values
    return values


def _kb_ids_from_update(update: Any, title: str) -> list[str]:
    values = _string_collection(getattr(update, "KBArticleIDs", None), prefix="KB")
    values.extend(_kb_ids_from_text(title))
    return list(dict.fromkeys(value.upper() for value in values if value))


def _update_categories(update: Any) -> list[str]:
    categories: list[str] = []
    try:
        collection = update.Categories
        for index in range(_collection_count(collection)):
            category = _collection_item(collection, index)
            categories.append(str(getattr(category, "Name", category)))
    except Exception:
        return categories
    return categories


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _identity_payload(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    payload: dict[str, Any] = {}
    for attr in ("UpdateID", "RevisionNumber"):
        try:
            attr_value = getattr(value, attr)
        except Exception:
            continue
        if attr_value not in (None, ""):
            payload[attr] = attr_value
    return payload or None


def classify_update_title(title: str, categories: list[str] | None = None) -> str:
    text = title.lower()
    categories_text = " ".join(categories or []).lower()
    combined = f"{text} {categories_text}"

    if (
        "security intelligence-update" in combined
        or "security intelligence update" in combined
        or "kb2267602" in combined
        or "microsoft defender" in combined
        or "windows defender" in combined
    ):
        return "defender_definition"
    if ".net framework" in combined or ".net" in combined:
        return "dotnet"
    if (
        "driver" in combined
        or "treiber" in combined
        or re.search(r"\b(intel|nvidia|amd|realtek|dell|hp|lenovo|qualcomm|broadcom)\b.*\b(driver|treiber)\b", combined)
    ):
        return "driver"
    if (
        "microsoft store" in combined
        or "app installer" in combined
        or "visual c++" in combined
        or "runtime" in combined
        or "web experience" in combined
        or "winget" in combined
    ):
        return "store_or_runtime"
    if (
        "security platform" in combined
        or "sicherheitsplattform" in combined
        or "malicious software removal tool" in combined
        or "tool zum entfernen bösartiger software" in combined
        or "kb5007651" in combined
    ):
        return "security_platform"
    if "funktionsupdate" in combined or "feature update to windows 11, version" in combined or "feature update" in combined:
        return "feature_update"
    if (
        "out-of-band" in combined
        or "out of band" in combined
        or re.search(r"\boob\b", combined)
        or "außerplan" in combined
        or "ausserplan" in combined
    ):
        return "out_of_band"
    if "vorschauupdate" in combined or "preview" in combined:
        return "quality_preview"
    if "kumulatives update" in combined or "cumulative update" in combined or "quality update" in combined:
        return "quality_update"
    return "unknown"


def _mentions_target(title: str, target_release: str | None) -> bool:
    return bool(target_release and target_release.upper() in title.upper())


def _update_payload(update: Any, target_release: str | None) -> dict[str, Any]:
    title = str(getattr(update, "Title", ""))
    categories = _update_categories(update)
    classification = classify_update_title(title, categories)
    mentions_target = _mentions_target(title, target_release)
    return {
        "title": title,
        "kb_ids": _kb_ids_from_update(update, title),
        "categories": categories,
        "classification": classification,
        "mentions_target_release": mentions_target,
        "is_feature_update": classification == "feature_update",
        "update_identity": _identity_payload(getattr(update, "Identity", None)),
        "support_url": str(getattr(update, "SupportUrl", "") or "") or None,
    }


def _history_payload(entry: Any, target_release: str | None) -> dict[str, Any]:
    title = str(getattr(entry, "Title", ""))
    classification = classify_update_title(title)
    mentions_target = _mentions_target(title, target_release)
    return {
        "title": title,
        "kb_ids": _kb_ids_from_text(title),
        "classification": classification,
        "date": str(getattr(entry, "Date", "")),
        "operation": _safe_int(getattr(entry, "Operation", 0)),
        "result_code": _safe_int(getattr(entry, "ResultCode", 0)),
        "hresult": _safe_int(getattr(entry, "HResult", 0)),
        "unmapped_result_code": _safe_int(getattr(entry, "UnmappedResultCode", 0)),
        "update_identity": _identity_payload(getattr(entry, "UpdateIdentity", None)),
        "support_url": str(getattr(entry, "SupportUrl", "") or "") or None,
        "mentions_target_release": mentions_target,
    }


def _event_payload(raw: Mapping[str, Any]) -> dict[str, Any]:
    message = str(raw.get("message") or raw.get("Message") or "")
    title = message or str(raw.get("provider_name") or raw.get("ProviderName") or "")
    payload = {
        "log_name": raw.get("log_name") or raw.get("LogName"),
        "provider_name": raw.get("provider_name") or raw.get("ProviderName"),
        "event_id": raw.get("event_id") or raw.get("Id"),
        "time_created": raw.get("time_created") or raw.get("TimeCreated"),
        "level_display_name": raw.get("level_display_name") or raw.get("LevelDisplayName"),
        "message": message,
        "kb_ids": _kb_ids_from_text(message),
        "classification": classify_update_title(title),
    }
    return {key: value for key, value in payload.items() if value not in (None, "", [])}


def _query_event_logs(
    kb_ids: set[str],
    *,
    max_events: int = DEFAULT_EVENT_LOG_MAX_EVENTS,
    lookback_days: int = 60,
    timeout_seconds: float = DEFAULT_POWERSHELL_TIMEOUT_SECONDS,
) -> tuple[list[dict[str, Any]], list[str]]:
    if os.name != "nt":
        return [], []

    script = rf"""
$ErrorActionPreference = 'Continue'
$warnings = New-Object System.Collections.Generic.List[string]
$events = New-Object System.Collections.Generic.List[object]
$since = (Get-Date).AddDays(-{int(lookback_days)})
function Add-Events($filter, $label) {{
  try {{
    Get-WinEvent -FilterHashtable $filter -MaxEvents {int(max_events)} -ErrorAction Stop |
      Select-Object LogName,ProviderName,Id,TimeCreated,LevelDisplayName,Message |
      ForEach-Object {{ $events.Add($_) }}
  }} catch {{
    $warnings.Add("$label event log query failed: $($_.Exception.Message)")
  }}
}}
Add-Events @{{LogName='Setup'; StartTime=$since}} 'Setup'
Add-Events @{{ProviderName='Microsoft-Windows-Servicing'; StartTime=$since}} 'Microsoft-Windows-Servicing'
[pscustomobject]@{{events=$events; warnings=$warnings}} | ConvertTo-Json -Depth 5 -Compress
"""
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [], [f"Event log query timed out after {timeout_seconds:g} seconds."]
    except PermissionError as exc:
        return [], [f"Event log permission warning: {exc}"]
    except OSError as exc:
        return [], [f"Event log query unavailable: {exc}"]

    if proc.returncode != 0 and not proc.stdout.strip():
        return [], [f"Event log query failed: {(proc.stderr or '').strip()}"]
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        return [], [f"Event log query returned malformed JSON: {exc}"]
    warnings = [str(item) for item in data.get("warnings", [])]
    events = [_event_payload(item) for item in data.get("events", []) if isinstance(item, Mapping)]
    if kb_ids:
        # Preserve all bounded events for diagnostics; correlation is handled separately.
        events = events[: max(0, int(max_events))]
    return events, warnings


def _correlate_events(events: list[dict[str, Any]], kb_ids: set[str]) -> list[dict[str, Any]]:
    if not kb_ids:
        return []
    correlated = []
    for event in events:
        event_kbs = {str(kb).upper() for kb in event.get("kb_ids", [])}
        if event_kbs & kb_ids:
            correlated.append(event)
    return correlated


def _finish_update_collections(
    result: dict[str, Any],
    *,
    max_relevant_updates: int = DEFAULT_WUA_MAX_RELEVANT_UPDATES,
) -> None:
    noise = Counter()
    relevant = []
    for update in result["available_updates"]:
        classification = update.get("classification")
        if classification in NOISE_CLASSIFICATIONS:
            noise[str(classification)] += 1
        elif classification in RELEVANT_OS_CLASSIFICATIONS:
            relevant.append(update)
    result["noise_counts"] = dict(noise)
    limit = max(0, int(max_relevant_updates))
    result["relevant_os_updates"] = relevant[:limit]
    if len(relevant) > limit:
        result["warnings"].append(
            f"WUA relevant OS update output truncated from {len(relevant)} to {limit} entries."
        )


def _query_wua_secondary_unbounded(
    target_release: str | None,
    max_history: int = DEFAULT_WUA_MAX_HISTORY,
    timeout_seconds: float = DEFAULT_WUA_TIMEOUT_SECONDS,
    max_relevant_updates: int = DEFAULT_WUA_MAX_RELEVANT_UPDATES,
    event_log_max_events: int = DEFAULT_EVENT_LOG_MAX_EVENTS,
) -> dict[str, Any]:
    result = _empty_result()

    if os.name != "nt":
        result["errors"].append("WUA only available on Windows")
        return result

    try:
        import win32com.client  # type: ignore[import-not-found]
    except Exception as exc:
        result["errors"].append(f"pywin32/win32com unavailable: {exc}")
        return result

    pythoncom = None
    try:
        import pythoncom as imported_pythoncom  # type: ignore[import-not-found]

        pythoncom = imported_pythoncom
        pythoncom.CoInitialize()
    except Exception:
        pythoncom = None

    try:
        try:
            automatic_updates = win32com.client.Dispatch("Microsoft.Update.AutoUpdate")
            result["service_enabled"] = bool(automatic_updates.ServiceEnabled)
        except Exception as exc:
            result["warnings"].append(f"IAutomaticUpdates.ServiceEnabled failed: {exc}")

        try:
            session = win32com.client.Dispatch("Microsoft.Update.Session")
            session.ClientApplicationID = CLIENT_APPLICATION_ID
            searcher = session.CreateUpdateSearcher()
            search_result = searcher.Search(SEARCH_CRITERIA)
            updates = search_result.Updates

            for index in range(_collection_count(updates)):
                payload = _update_payload(_collection_item(updates, index), target_release)
                if payload["mentions_target_release"] and payload["is_feature_update"]:
                    result["target_feature_update_offered"] = True
                result["available_updates"].append(payload)

            result["available"] = True
        except Exception as exc:
            result["warnings"].append(f"WUA Search failed: {exc}")

        try:
            session = win32com.client.Dispatch("Microsoft.Update.Session")
            searcher = session.CreateUpdateSearcher()
            total = int(searcher.GetTotalHistoryCount())
            count = min(total, max(0, int(max_history)))

            if count > 0:
                entries = searcher.QueryHistory(0, count)
                for index in range(_collection_count(entries)):
                    payload = _history_payload(_collection_item(entries, index), target_release)
                    if payload["mentions_target_release"]:
                        result["target_release_in_history"] = True
                    result["history"].append(payload)
        except Exception as exc:
            result["warnings"].append(f"WUA QueryHistory failed: {exc}")

        _finish_update_collections(result, max_relevant_updates=max_relevant_updates)
        kb_ids = {
            str(kb).upper()
            for collection_name in ("available_updates", "history")
            for item in result[collection_name]
            for kb in item.get("kb_ids", [])
        }
        try:
            events, event_warnings = _query_event_logs(
                kb_ids,
                max_events=event_log_max_events,
                lookback_days=60,
                timeout_seconds=min(
                    DEFAULT_POWERSHELL_TIMEOUT_SECONDS,
                    max(1.0, float(timeout_seconds)),
                ),
            )
            result["event_log_events"] = events
            result["correlated_event_logs"] = _correlate_events(events, kb_ids)
            result["warnings"].extend(event_warnings)
        except PermissionError as exc:
            result["warnings"].append(f"Event log permission warning: {exc}")
        except Exception as exc:
            result["warnings"].append(f"Event log query failed: {exc}")
    finally:
        if pythoncom is not None:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass

    return result


def query_wua_secondary(
    target_release: str | None,
    max_history: int = DEFAULT_WUA_MAX_HISTORY,
    timeout_seconds: float = DEFAULT_WUA_TIMEOUT_SECONDS,
    max_relevant_updates: int = DEFAULT_WUA_MAX_RELEVANT_UPDATES,
    event_log_max_events: int = DEFAULT_EVENT_LOG_MAX_EVENTS,
    *,
    use_subprocess: bool = True,
) -> dict[str, Any]:
    """Read WUA offer/history and event-log diagnostics without mutating update state."""

    if os.name != "nt":
        return _query_wua_secondary_unbounded(
            target_release,
            max_history=max_history,
            timeout_seconds=timeout_seconds,
            max_relevant_updates=max_relevant_updates,
            event_log_max_events=event_log_max_events,
        )
    if not use_subprocess:
        return _query_wua_secondary_unbounded(
            target_release,
            max_history=max_history,
            timeout_seconds=timeout_seconds,
            max_relevant_updates=max_relevant_updates,
            event_log_max_events=event_log_max_events,
        )
    return _query_wua_secondary_subprocess(
        target_release,
        max_history=max_history,
        timeout_seconds=timeout_seconds,
        max_relevant_updates=max_relevant_updates,
        event_log_max_events=event_log_max_events,
    )


def _query_wua_secondary_subprocess(
    target_release: str | None,
    *,
    max_history: int,
    timeout_seconds: float,
    max_relevant_updates: int,
    event_log_max_events: int,
) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "win11_release_guard.wua_probe",
        "--child-json",
        "--target-release",
        target_release or "",
        "--max-history",
        str(max(0, int(max_history))),
        "--timeout-seconds",
        str(max(0.1, float(timeout_seconds))),
        "--max-relevant-updates",
        str(max(0, int(max_relevant_updates))),
        "--event-log-max-events",
        str(max(0, int(event_log_max_events))),
    ]
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(0.1, float(timeout_seconds)),
            check=False,
        )
    except subprocess.TimeoutExpired:
        result = _empty_result()
        result["timed_out"] = True
        result["warnings"].append(f"WUA probe timed out after {timeout_seconds:g} seconds.")
        return result
    except OSError as exc:
        result = _empty_result()
        result["warnings"].append(f"WUA subprocess failed to start: {exc}")
        return result

    if proc.returncode != 0:
        result = _empty_result()
        stderr = (proc.stderr or "").strip()
        result["warnings"].append(
            f"WUA subprocess failed with exit code {proc.returncode}: {stderr or 'no stderr'}"
        )
        return result

    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        result = _empty_result()
        result["warnings"].append(f"WUA subprocess returned malformed JSON: {exc}")
        return result
    if not isinstance(payload, dict):
        result = _empty_result()
        result["warnings"].append("WUA subprocess returned a non-object payload.")
        return result
    return payload


def _child_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--child-json", action="store_true")
    parser.add_argument("--target-release", default="")
    parser.add_argument("--max-history", type=int, default=DEFAULT_WUA_MAX_HISTORY)
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_WUA_TIMEOUT_SECONDS)
    parser.add_argument("--max-relevant-updates", type=int, default=DEFAULT_WUA_MAX_RELEVANT_UPDATES)
    parser.add_argument("--event-log-max-events", type=int, default=DEFAULT_EVENT_LOG_MAX_EVENTS)
    args = parser.parse_args(argv)
    if not args.child_json:
        return 2
    result = _query_wua_secondary_unbounded(
        args.target_release or None,
        max_history=args.max_history,
        timeout_seconds=args.timeout_seconds,
        max_relevant_updates=args.max_relevant_updates,
        event_log_max_events=args.event_log_max_events,
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0


__all__ = [
    "classify_update_title",
    "query_wua_secondary",
]


if __name__ == "__main__":
    raise SystemExit(_child_main())
