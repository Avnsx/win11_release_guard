"""Combining local build signals into one installed build decision."""

from __future__ import annotations

import re
from typing import Any, Mapping


DEFAULT_BUILD_FAMILY_RELEASES: Mapping[int, str] = {
    22000: "21H2",
    22621: "22H2",
    22631: "23H2",
    26100: "24H2",
    26200: "25H2",
    26300: "26H2",
    28000: "26H1",
}


BUILD_SIGNAL_TRUST: Mapping[str, dict[str, int | str]] = {
    "rtl": {"trust": "runtime_truth", "weight": 120, "priority": 0},
    "dism_image": {"trust": "dism_image", "weight": 80, "priority": 1},
    "kernel": {"trust": "runtime_file", "weight": 60, "priority": 2},
    "registry": {"trust": "registry_metadata", "weight": 35, "priority": 3},
    "wmi": {"trust": "wmi_metadata", "weight": 35, "priority": 4},
}


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def extract_release(value: str | None) -> str | None:
    match = re.search(r"\b(\d{2}H[12])\b", value or "", flags=re.IGNORECASE)
    return match.group(1).upper() if match else None


def infer_release_from_build_family(
    build_family: int | None,
    build_family_map: Mapping[int, str] = DEFAULT_BUILD_FAMILY_RELEASES,
) -> str | None:
    if build_family is None:
        return None
    release = build_family_map.get(int(build_family))
    return release.upper() if release else None


def _full_build(build: int | None, ubr: int | None) -> str | None:
    if build is None:
        return None
    return f"{build}.{ubr}" if ubr is not None else str(build)


def _version_build(value: str | None) -> int | None:
    if not value:
        return None
    parts = str(value).split(".")
    try:
        if len(parts) >= 3:
            return int(parts[2])
        return int(parts[0])
    except ValueError:
        return None


def _version_ubr(value: str | None) -> int | None:
    if not value:
        return None
    parts = str(value).split(".")
    if len(parts) < 2:
        return None
    try:
        return int(parts[3] if len(parts) >= 4 else parts[1])
    except ValueError:
        return None


def _is_plausible_windows_version(value: str | None) -> bool:
    if not value:
        return False
    parts = str(value).strip().split(".")
    if len(parts) not in {3, 4}:
        return False
    try:
        numbers = [int(part) for part in parts]
    except ValueError:
        return False
    major = numbers[0]
    build = numbers[2]
    revision = numbers[3] if len(numbers) == 4 else 0
    return major >= 6 and build >= 10240 and revision >= 0


def _build_signal_metadata(source: str) -> dict[str, int | str]:
    return dict(BUILD_SIGNAL_TRUST.get(source, {"trust": "diagnostic", "weight": 10, "priority": 99}))


def _build_signal_decision(candidates: list[tuple[str, int | None]]) -> dict[str, Any]:
    signals: list[dict[str, Any]] = []
    grouped: dict[int, dict[str, Any]] = {}
    for source, value in candidates:
        if value is None:
            continue
        metadata = _build_signal_metadata(source)
        build = int(value)
        signal = {
            "source": source,
            "build": build,
            "trust": metadata["trust"],
            "weight": metadata["weight"],
            "priority": metadata["priority"],
        }
        signals.append(signal)
        group = grouped.setdefault(
            build,
            {
                "build": build,
                "sources": [],
                "trust_classes": [],
                "score": 0,
                "highest_signal_weight": 0,
                "best_priority": 99,
            },
        )
        group["sources"].append(source)
        group["trust_classes"].append(metadata["trust"])
        group["score"] += int(metadata["weight"])
        group["highest_signal_weight"] = max(int(group["highest_signal_weight"]), int(metadata["weight"]))
        group["best_priority"] = min(int(group["best_priority"]), int(metadata["priority"]))

    if not grouped:
        return {
            "selected_build": None,
            "selection_method": "weighted_trust",
            "selected_sources": [],
            "selected_trust_classes": [],
            "conflict": False,
            "signals": [],
            "conflicting_builds": {},
        }

    selected = max(
        grouped.values(),
        key=lambda group: (
            int(group["score"]),
            int(group["highest_signal_weight"]),
            -int(group["best_priority"]),
            int(group["build"]),
        ),
    )
    selected_build = int(selected["build"])
    for signal in signals:
        signal["selected"] = int(signal["build"]) == selected_build

    return {
        "selected_build": selected_build,
        "selection_method": "weighted_trust",
        "selected_sources": list(selected["sources"]),
        "selected_trust_classes": list(dict.fromkeys(str(item) for item in selected["trust_classes"])),
        "conflict": len(grouped) > 1,
        "signals": signals,
        "conflicting_builds": {
            str(build): {
                "sources": list(group["sources"]),
                "trust_classes": list(dict.fromkeys(str(item) for item in group["trust_classes"])),
                "score": int(group["score"]),
                "highest_signal_weight": int(group["highest_signal_weight"]),
            }
            for build, group in sorted(grouped.items())
        },
    }


def _choose_build(candidates: list[tuple[str, int | None]]) -> int | None:
    decision = _build_signal_decision(candidates)
    selected = decision.get("selected_build")
    return int(selected) if selected is not None else None


def _build_signal_conflicts(
    candidates: list[tuple[str, int | None]],
    *,
    selected_build: int | None,
    decision: Mapping[str, Any] | None = None,
) -> tuple[str, ...]:
    present = [(source, value) for source, value in candidates if value is not None]
    values = {value for _, value in present}
    if len(values) <= 1:
        return ()
    signals = ", ".join(f"{source}={value}" for source, value in present)
    selected_sources = ", ".join(str(source) for source in (decision or {}).get("selected_sources", []))
    selected_by = f" via weighted_trust from {selected_sources}" if selected_sources else ""
    return (
        f"LOCAL_BUILD_SIGNAL_CONFLICT: build signals disagree ({signals}); "
        f"selected current_build={selected_build}{selected_by}.",
    )
