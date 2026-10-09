"""Formatting command results as JSON or human-readable text."""

from __future__ import annotations

import json
import sys
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Mapping
from . import state_store
from .exceptions import WindowsReleaseCheckerError
from .models import EvaluationResult, EvaluationStatus, InstalledBuildClassification, InstalledBuildOrigin, SourceStatus


EXIT_COMPLIANT = 0


EXIT_UPDATE_REQUIRED = 1


EXIT_UNKNOWN_OR_POLICY_ERROR = 2


EXIT_ABOVE_BROAD_TARGET = 3


def _exit_code(status: EvaluationStatus) -> int:
    if status is EvaluationStatus.COMPLIANT:
        return EXIT_COMPLIANT
    if status in {
        EvaluationStatus.FEATURE_UPDATE_REQUIRED,
        EvaluationStatus.QUALITY_UPDATE_REQUIRED,
        EvaluationStatus.PREVIEW_BUILD_INSTALLED,
    }:
        return EXIT_UPDATE_REQUIRED
    if status is EvaluationStatus.ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE:
        return EXIT_ABOVE_BROAD_TARGET
    return EXIT_UNKNOWN_OR_POLICY_ERROR


RELEVANT_WUA_CLASSIFICATIONS = {
    "feature_update",
    "quality_update",
    "quality_preview",
    "out_of_band",
}


def _compact_wua_output(wua: dict[str, object], *, target_offer_expected: bool) -> dict[str, object]:
    available_updates = [
        item for item in wua.get("available_updates", []) if isinstance(item, dict)
    ]
    history = [item for item in wua.get("history", []) if isinstance(item, dict)]
    relevant_os_updates = [
        item for item in wua.get("relevant_os_updates", []) if isinstance(item, dict)
    ]
    latest_relevant_history = [
        item
        for item in history
        if item.get("classification") in RELEVANT_WUA_CLASSIFICATIONS
    ][:3]
    available_counts = Counter(str(item.get("classification") or "unknown") for item in available_updates)
    history_counts = Counter(str(item.get("classification") or "unknown") for item in history)
    raw_truncated = bool(
        history
        or len(available_updates) != len(relevant_os_updates)
        or len(latest_relevant_history) < len(
            [item for item in history if item.get("classification") in RELEVANT_WUA_CLASSIFICATIONS]
        )
    )
    return {
        "available": wua.get("available"),
        "service_enabled": wua.get("service_enabled"),
        "target_feature_update_offered": wua.get("target_feature_update_offered"),
        "target_feature_update_offer_expected": target_offer_expected,
        "target_release_in_history": wua.get("target_release_in_history"),
        "timed_out": wua.get("timed_out", False),
        "counts_by_category": {
            "available_updates_total": len(available_updates),
            "history_total": len(history),
            "relevant_os_updates_total": len(relevant_os_updates),
            "available_update_classifications": dict(available_counts),
            "history_classifications": dict(history_counts),
            "noise_counts": dict(wua.get("noise_counts") or {}),
        },
        "relevant_os_updates": relevant_os_updates,
        "latest_relevant_history": latest_relevant_history,
        "warnings": list(wua.get("warnings") or []),
        "errors": list(wua.get("errors") or []),
        "raw_output_truncated": raw_truncated,
    }


def _omitted_local_diagnostic_string(value: str, *, field: str = "content") -> dict[str, object]:
    return {
        f"{field}_omitted": True,
        f"{field}_chars": len(value),
        f"{field}_bytes_utf8": len(value.encode("utf-8", errors="replace")),
    }


def _looks_like_panther_log_path(value: object) -> bool:
    text = str(value).lower()
    return "panther" in text and text.endswith(".log")


def _compact_local_diagnostic_value(value: object) -> object:
    if isinstance(value, str):
        return _omitted_local_diagnostic_string(value)
    if isinstance(value, list):
        return [_compact_local_diagnostic_value(item) for item in value]
    if not isinstance(value, dict):
        return value

    compacted: dict[str, object] = {}
    for key, item in value.items():
        key_text = str(key)
        if key_text in {"errors", "warnings"}:
            compacted[key_text] = item
        elif key_text == "content" and isinstance(item, str):
            compacted.update(_omitted_local_diagnostic_string(item))
        elif key_text == "line" and isinstance(item, str):
            compacted.update(_omitted_local_diagnostic_string(item, field="line"))
        elif key_text in {"path", "source_path"} and isinstance(item, str):
            compacted.update(_omitted_local_diagnostic_string(item, field=key_text))
        elif isinstance(item, str):
            compacted[key_text] = (
                _omitted_local_diagnostic_string(item)
                if _looks_like_panther_log_path(key_text)
                else item
            )
        else:
            compacted[key_text] = _compact_local_diagnostic_value(item)
    return compacted


def _compact_panther_consensus(consensus: object) -> None:
    if not isinstance(consensus, dict):
        return

    signal_set = consensus.get("signal_set")
    if not isinstance(signal_set, dict):
        return

    signals = signal_set.get("signals")
    if not isinstance(signals, list):
        return

    for signal in signals:
        if isinstance(signal, dict) and signal.get("source") == "panther":
            signal["value"] = _compact_local_diagnostic_value(signal.get("value"))


def _compact_recursive_panther_signals(value: object) -> None:
    if isinstance(value, list):
        for item in value:
            _compact_recursive_panther_signals(item)
        return
    if not isinstance(value, dict):
        return

    if value.get("source") == "panther" and "value" in value:
        value["value"] = _compact_local_diagnostic_value(value.get("value"))
        return

    for item in value.values():
        _compact_recursive_panther_signals(item)


def _compact_local_diagnostics(payload: dict[str, object]) -> dict[str, object]:
    local = payload.get("local")
    if isinstance(local, dict):
        raw = local.get("raw")
        if isinstance(raw, dict):
            for key in ("panther_logs",):
                if key in raw:
                    raw[key] = _compact_local_diagnostic_value(raw[key])

    _compact_panther_consensus(payload.get("local_consensus"))
    for key in ("details", "metadata"):
        value = payload.get(key)
        if isinstance(value, dict):
            _compact_panther_consensus(value.get("local_consensus"))

    details = payload.get("details")
    if isinstance(details, dict):
        diagnostics = details.get("silent_feature_update_missing")
        if isinstance(diagnostics, dict):
            audit = diagnostics.get("audit_diagnostics")
            if isinstance(audit, dict) and "panther_logs" in audit:
                audit["panther_logs"] = _compact_local_diagnostic_value(audit["panther_logs"])
    _compact_recursive_panther_signals(payload)
    return payload


def _output_payload(
    result: EvaluationResult,
    *,
    include_raw_wua_history: bool,
    include_raw_local_diagnostics: bool,
) -> dict[str, object]:
    payload = deepcopy(result.to_dict())
    wua = payload.get("wua_secondary")
    if isinstance(wua, dict):
        if include_raw_wua_history:
            wua["target_feature_update_offer_expected"] = result.target_feature_update_offer_expected
            wua["raw_output_truncated"] = False
        else:
            payload["wua_secondary"] = _compact_wua_output(
                wua,
                target_offer_expected=result.target_feature_update_offer_expected,
            )
    if not include_raw_local_diagnostics:
        payload = _compact_local_diagnostics(payload)
    return payload


def _json_text(
    result: EvaluationResult,
    *,
    pretty: bool,
    unicode_output: bool,
    include_raw_wua_history: bool,
    include_raw_local_diagnostics: bool,
) -> str:
    return json.dumps(
        _output_payload(
            result,
            include_raw_wua_history=include_raw_wua_history,
            include_raw_local_diagnostics=include_raw_local_diagnostics,
        ),
        indent=2 if pretty else None,
        sort_keys=True,
        ensure_ascii=not unicode_output,
        separators=None if pretty else (",", ":"),
    )


def _print_json(
    result: EvaluationResult,
    *,
    pretty: bool,
    unicode_output: bool,
    include_raw_wua_history: bool,
    include_raw_local_diagnostics: bool,
) -> None:
    print(
        _json_text(
            result,
            pretty=pretty,
            unicode_output=unicode_output,
            include_raw_wua_history=include_raw_wua_history,
            include_raw_local_diagnostics=include_raw_local_diagnostics,
        )
    )


def _atomic_write_with_inplace_fallback(path: Path, data: bytes) -> state_store.StateEvent:
    event = state_store.write_bytes_atomically(path, data)
    if event.outcome != "failed":
        return event
    try:
        path.write_bytes(data)                              # today's --output behaviour, one time, no retry loop
        return state_store.StateEvent("write", "written", str(path), None)
    except (OSError, ValueError) as exc:
        return state_store.StateEvent("write", "failed", str(path), state_store._reason(exc))


def _write_json_output(
    path: Path,
    result: EvaluationResult,
    *,
    pretty: bool,
    unicode_output: bool,
    include_raw_wua_history: bool,
    include_raw_local_diagnostics: bool,
) -> None:
    json_text = _json_text(
        result,
        pretty=pretty,
        unicode_output=unicode_output,
        include_raw_wua_history=include_raw_wua_history,
        include_raw_local_diagnostics=include_raw_local_diagnostics,
    )
    data = (json_text + "\n").encode("utf-8")
    event = _atomic_write_with_inplace_fallback(path, data)
    if event.outcome == "failed":
        raise WindowsReleaseCheckerError(f"Could not write JSON output to {path}: {event.detail}")


def _source_degradation_warning(result: EvaluationResult) -> str | None:
    source_status = result.source_status
    source_kind = result.policy_source_kind or "unknown"
    if source_status is SourceStatus.REMOTE_POLICY_OK and source_kind == "remote_json" and result.is_source_check_complete:
        return None
    if source_status is SourceStatus.USING_FRESH_CACHE:
        return "using fresh cache; live remote policy was not used for this result."
    if source_status is SourceStatus.USING_STALE_CACHE:
        return "using stale cache; treat this as degraded evidence, not production green."
    if source_status is SourceStatus.USING_BUNDLED_POLICY:
        return "using bundled last-known-good policy; live policy source is unavailable."
    if source_status is SourceStatus.POLICY_UNAVAILABLE:
        return "policy unavailable; release compliance check is incomplete."
    if source_kind != "remote_json" or not result.is_source_check_complete:
        return "live signed remote JSON policy was not fully verified."
    return None


def _source_drift_warnings(result: EvaluationResult) -> list[str]:
    warnings: list[str] = []
    for warning in result.warnings:
        if "source freshness warning" in warning.lower() or "source drift" in warning.lower():
            warnings.append(warning)
    metadata = result.metadata if isinstance(result.metadata, Mapping) else {}
    source_diagnostics = metadata.get("source_diagnostics")
    if isinstance(source_diagnostics, Mapping):
        warnings.extend(str(item) for item in source_diagnostics.get("warnings", []) if item)
    return list(dict.fromkeys(warnings))


def _local_candidate_line(result: EvaluationResult) -> str | None:
    if result.status is not EvaluationStatus.CHECK_INCOMPLETE or result.candidate_status is None:
        return None
    if result.candidate_status is result.status:
        return None
    if result.local_scope_status is EvaluationStatus.OUT_OF_SCOPE:
        return (
            f"Local candidate: {result.candidate_status.value} "
            f"(local scope: {result.local_scope_status.value}; source check incomplete)"
        )
    return f"Local candidate: {result.candidate_status.value} (source check incomplete)"


def _policy_age_line(result: EvaluationResult) -> str | None:
    if result.policy_age_hours is None:
        return None
    feed_age_days = result.feed_age_days
    if feed_age_days is None:
        feed_age_days = round(result.policy_age_hours / 24, 2)
    return f"Policy age: {feed_age_days:g} days ({result.policy_age_hours:g} hours)"


def _print_pretty(result: EvaluationResult) -> None:
    target_version = result.target.version if result.target else "unknown"
    target_build = result.baseline_build or (result.target.effective_baseline_build if result.target else None)
    latest_observed = result.target.latest_observed_build if result.target else None
    source_status = result.source_status.value if result.source_status else "unknown"
    print(f"Status: {result.status.value}")
    print(f"Local: {result.installed_release or 'unknown'} / {result.installed_build or 'unknown'}")
    if result.local_consensus:
        print(f"Display OS: {result.local_consensus.display_os_name}")
        if result.local_consensus.raw_product_name:
            print(f"Raw ProductName: {result.local_consensus.raw_product_name}")
    print(f"Target: {target_version} / {target_build or 'unknown'}")
    if result.target:
        print(f"Required baseline: {target_build or 'unknown'}")
        print(f"Latest observed: {latest_observed or 'unknown'}")
    print(f"Source: {source_status} / {result.policy_source_kind or 'unknown'}")
    policy_age_line = _policy_age_line(result)
    if policy_age_line:
        print(policy_age_line)
    local_candidate_line = _local_candidate_line(result)
    if local_candidate_line:
        print(local_candidate_line)
    source_warning = _source_degradation_warning(result)
    if source_warning:
        print(
            "Source warning: live signed remote JSON policy was not fully verified; "
            f"{source_warning}"
        )
    if result.installed_build_origin:
        print(f"Build origin: {_format_build_origin(result.installed_build_origin, result)}")
        if (
            result.status is EvaluationStatus.COMPLIANT
            and result.installed_build_origin.classification is InstalledBuildClassification.PREVIEW
        ):
            print(
                "Preview warning: COMPLIANT means the installed build is at or above the required B-release "
                "baseline, but a preview build is installed."
            )
    drift_warnings = _source_drift_warnings(result)
    if drift_warnings:
        print("Source drift warnings:")
        for warning in drift_warnings:
            print(f"- {warning}")
    print(f"Action: {result.action or 'Manual inspection required.'}")
    if result.notes:
        print("Notes:")
        for note in result.notes:
            print(f"- {note}")
    if result.errors:
        print("Errors:")
        for error in result.errors:
            print(f"- {error}")
    if result.source_problems:
        print("Source problems:")
        for problem in result.source_problems:
            print(f"- {problem}")


def _format_build_origin(origin: InstalledBuildOrigin, result: EvaluationResult) -> str:
    classification = origin.classification
    if classification is InstalledBuildClassification.UNKNOWN_NEWER_THAN_BASELINE:
        if result.policy_source_kind == "bundled":
            return "newer than bundled baseline; exact KB/origin unknown because live policy/WUA evidence was not used."
        return "newer than policy baseline; exact KB/origin unknown."
    if classification is InstalledBuildClassification.UNKNOWN_OLDER_THAN_BASELINE:
        return "older than policy baseline; exact KB/origin unknown."

    labels = {
        InstalledBuildClassification.B_RELEASE: "B release",
        InstalledBuildClassification.PREVIEW: "preview",
        InstalledBuildClassification.OUT_OF_BAND: "out-of-band",
    }
    label = labels.get(classification, classification.value if classification else "unknown")
    parts = [label, origin.evidence_source.value]
    if origin.kb_article:
        parts.append(origin.kb_article)
    return " / ".join(parts)


def _error_payload(message: str, status: str = "POLICY_ERROR") -> dict[str, object]:
    return {
        "status": status,
        "error": message,
    }


def _print_error(message: str, *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(_error_payload(message), indent=2, sort_keys=True, ensure_ascii=True), file=sys.stderr)
    else:
        print(f"Error: {message}", file=sys.stderr)
