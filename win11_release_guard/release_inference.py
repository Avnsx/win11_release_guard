"""Inferring the installed release and local consensus from local signals."""

from __future__ import annotations

import re
from typing import Mapping
from .models import EditionScope, InstalledReleaseInference, LocalConsensus, LocalSignal, LocalSignalSet, LocalWindowsState, ReleasePolicy
from .local_state import DEFAULT_BUILD_FAMILY_RELEASES, extract_release
from .evaluator_common import (
    _conflicts,
    _current_version_for_build_family,
    _display_release_hint,
    _edition_scope,
    _is_windows10_or_older_client,
    _policy_allows_future_release_pattern,
    _policy_release_catalog,
    _special_version_for_build_family,
)


def infer_installed_release(
    local_state: LocalWindowsState,
    policy: ReleasePolicy | None,
    *,
    allow_major_upgrade_recommendation: bool = False,
    allow_server_evaluation: bool = False,
) -> InstalledReleaseInference:
    """Infer installed release without letting local labels override policy."""

    reasons: list[str] = []
    display_release = _display_release_hint(local_state)

    if local_state.is_server and not allow_server_evaluation:
        return InstalledReleaseInference(
            release=None,
            confidence="out_of_scope",
            source="product_family",
            reasons=("Local OS is Windows Server; Windows 11 client release policy is out of scope.",),
            is_out_of_scope=True,
        )

    if _is_windows10_or_older_client(local_state) and not allow_major_upgrade_recommendation:
        return InstalledReleaseInference(
            release=None,
            confidence="out_of_scope",
            source="build_family",
            reasons=("Local OS is Windows 10 or older client; Windows 11 major upgrade recommendation is disabled.",),
            is_out_of_scope=True,
        )

    build_family = local_state.build_family
    if policy is None:
        static_release = DEFAULT_BUILD_FAMILY_RELEASES.get(int(build_family)) if build_family is not None else None
        release = static_release or extract_release(local_state.inferred_release) or display_release
        if release:
            return InstalledReleaseInference(
                release=release,
                confidence="fallback_static",
                source="static_local_fallback",
                reasons=("No policy was available; used static local fallback only.",),
                is_recognized_by_policy=False,
            )
        return InstalledReleaseInference(
            release=None,
            confidence="unknown",
            source="none",
            reasons=("No policy or static fallback matched local state.",),
        )

    if build_family is not None:
        release = policy.supported_build_families.get(int(build_family))
        if release:
            return InstalledReleaseInference(
                release=release,
                confidence="policy_build_family",
                source="policy.supported_build_families",
                reasons=(f"Build family {build_family} is mapped by policy to {release}.",),
                is_recognized_by_policy=True,
                conflicts=_conflicts(display_release, release, "policy build-family"),
            )

        current_entry = _current_version_for_build_family(policy, int(build_family))
        if current_entry is not None:
            return InstalledReleaseInference(
                release=current_entry.version,
                confidence="policy_current_versions",
                source="policy.current_versions",
                reasons=(f"Build family {build_family} matched policy current_versions.",),
                is_recognized_by_policy=True,
                conflicts=_conflicts(display_release, current_entry.version, "policy current_versions"),
            )

        special_entry = _special_version_for_build_family(policy, int(build_family))
        if special_entry is not None:
            return InstalledReleaseInference(
                release=special_entry.version,
                confidence="policy_special_release",
                source="policy.special_releases",
                reasons=(f"Build family {build_family} matched explicit special/excluded release policy.",),
                is_recognized_by_policy=True,
                conflicts=_conflicts(display_release, special_entry.version, "policy special-release"),
            )

    catalog = _policy_release_catalog(policy)
    if display_release:
        if display_release in catalog:
            return InstalledReleaseInference(
                release=display_release,
                confidence="display_version_policy_recognized",
                source="local.display_version",
                reasons=(f"DisplayVersion hint {display_release} exists in policy release catalog.",),
                is_recognized_by_policy=True,
            )
        if _policy_allows_future_release_pattern(policy):
            return InstalledReleaseInference(
                release=display_release,
                confidence="display_version_future_pattern",
                source="local.display_version",
                reasons=(f"DisplayVersion hint {display_release} matches release syntax and policy allows future patterns.",),
                is_recognized_by_policy=False,
            )
        if _is_windows10_or_older_client(local_state) and allow_major_upgrade_recommendation:
            return InstalledReleaseInference(
                release=display_release,
                confidence="major_upgrade_local_hint",
                source="local.display_version",
                reasons=(
                    f"DisplayVersion hint {display_release} is outside policy but major upgrade recommendation is explicitly enabled.",
                ),
                is_recognized_by_policy=False,
            )
        reasons.append(f"DisplayVersion hint {display_release} is syntactically valid but absent from policy.")

    if build_family is not None:
        reasons.append(f"Build family {build_family} is absent from policy.")
    return InstalledReleaseInference(
        release=None,
        confidence="unrecognized",
        source="policy",
        reasons=tuple(reasons or ("Local release could not be recognized by policy.",)),
        is_recognized_by_policy=False,
        conflicts=_conflicts(display_release, None, "policy"),
    )


def _raw_mapping(local_state: LocalWindowsState, key: str) -> Mapping[str, object]:
    value = local_state.raw.get(key) if isinstance(local_state.raw, Mapping) else None
    return value if isinstance(value, Mapping) else {}


def _signal_value(raw: Mapping[str, object], key: str, fallback: object = None) -> object:
    value = raw.get(key)
    return fallback if value in (None, "") else value


def _add_signal(
    signals: list[LocalSignal],
    *,
    source: str,
    name: str,
    value: object,
    kind: str,
    trust: str,
    normalized_value: str | None = None,
    diagnostic_flags: tuple[str, ...] = (),
) -> None:
    if value is None or value == "":
        return
    signals.append(
        LocalSignal(
            source=source,
            name=name,
            value=value,
            kind=kind,
            normalized_value=normalized_value,
            trust=trust,
            diagnostic_flags=diagnostic_flags,
        )
    )


def _signal_build_family(value: object) -> int | None:
    if value is None or value == "":
        return None
    text = str(value).strip()
    if not text:
        return None
    parts = text.split(".")
    try:
        if len(parts) >= 3:
            return int(parts[2])
        return int(parts[0])
    except (TypeError, ValueError):
        return None


def _build_signal_flags(local_state: LocalWindowsState, value: object) -> tuple[str, ...]:
    raw = local_state.raw if isinstance(local_state.raw, Mapping) else {}
    decision = raw.get("build_signal_decision")
    if not isinstance(decision, Mapping):
        return ()
    build = _signal_build_family(value)
    if build is None:
        return ()
    selected_build = _signal_build_family(decision.get("selected_build"))
    flags: list[str] = []
    if decision.get("conflict"):
        flags.append("build_signal_conflict")
    if selected_build is not None:
        flags.append("selected_build_signal" if build == selected_build else "conflicting_build_signal")
    return tuple(dict.fromkeys(flags))


def local_signal_set(local_state: LocalWindowsState) -> LocalSignalSet:
    registry = _raw_mapping(local_state, "registry")
    rtl = _raw_mapping(local_state, "rtl")
    wmi = _raw_mapping(local_state, "wmi")
    signals: list[LocalSignal] = []
    registry_build_value = _signal_value(
        registry,
        "CurrentBuildNumber",
        _signal_value(registry, "CurrentBuild", local_state.current_build),
    )
    rtl_build_value = _signal_value(rtl, "build")
    wmi_version_value = _signal_value(wmi, "Version", local_state.wmi_version)
    wmi_build_value = _signal_value(wmi, "BuildNumber")

    _add_signal(
        signals,
        source="registry",
        name="CurrentBuild",
        value=registry_build_value,
        kind="build",
        trust="registry_metadata",
        normalized_value=str(local_state.current_build) if local_state.current_build is not None else None,
        diagnostic_flags=_build_signal_flags(local_state, registry_build_value),
    )
    _add_signal(
        signals,
        source="registry",
        name="UBR",
        value=_signal_value(registry, "UBR", local_state.ubr),
        kind="build",
        trust="registry_metadata",
    )
    _add_signal(signals, source="registry", name="ProductName", value=local_state.product_name, kind="display_label", trust="display_only")
    _add_signal(
        signals,
        source="registry",
        name="DisplayVersion",
        value=local_state.display_version,
        kind="release_hint",
        trust="hint",
        normalized_value=_display_release_hint(local_state),
    )
    _add_signal(
        signals,
        source="registry",
        name="EditionID",
        value=local_state.edition_id,
        kind="edition",
        trust="edition_signal",
        normalized_value=local_state.edition_scope.value,
    )
    _add_signal(
        signals,
        source="rtl",
        name="RtlGetVersion.build",
        value=rtl_build_value,
        kind="build",
        trust="runtime_truth",
        diagnostic_flags=_build_signal_flags(local_state, rtl_build_value),
    )
    _add_signal(
        signals,
        source="wmi",
        name="Version",
        value=wmi_version_value,
        kind="build",
        trust="wmi_metadata",
        diagnostic_flags=_build_signal_flags(local_state, wmi_version_value),
    )
    _add_signal(
        signals,
        source="wmi",
        name="BuildNumber",
        value=wmi_build_value,
        kind="build",
        trust="wmi_metadata",
        diagnostic_flags=_build_signal_flags(local_state, wmi_build_value),
    )
    _add_signal(signals, source="wmi", name="Caption", value=local_state.caption, kind="display_label", trust="display_only")
    _add_signal(signals, source="wmi", name="OperatingSystemSKU", value=local_state.operating_system_sku, kind="edition", trust="edition_signal")
    _add_signal(
        signals,
        source="dism",
        name="CurrentEdition",
        value=local_state.dism_current_edition,
        kind="edition",
        trust="primary_edition_signal",
        normalized_value=local_state.edition_scope.value,
    )
    _add_signal(
        signals,
        source="dism",
        name="Image Version",
        value=local_state.dism_image_version,
        kind="build",
        trust="dism_image",
        diagnostic_flags=_build_signal_flags(local_state, local_state.dism_image_version),
    )
    _add_signal(
        signals,
        source="dism",
        name="DISM tool version",
        value=local_state.dism_tool_version,
        kind="tool_version",
        trust="diagnostic",
    )
    _add_signal(
        signals,
        source="get_product_info",
        name="ProductInfoCode",
        value=local_state.product_info_code,
        kind="edition",
        trust="secondary_edition_signal",
        normalized_value=local_state.edition_scope.value,
    )
    _add_signal(
        signals,
        source="kernel_file",
        name="ntoskrnl.exe version",
        value=local_state.kernel_file_version,
        kind="build",
        trust="runtime_file",
        diagnostic_flags=_build_signal_flags(local_state, local_state.kernel_file_version),
    )
    _add_signal(signals, source="dism", name="packages", value=local_state.raw.get("dism_packages"), kind="audit", trust="audit")
    _add_signal(signals, source="panther", name="logs", value=local_state.raw.get("panther_logs"), kind="audit", trust="audit")
    return LocalSignalSet(signals=tuple(signals))


def _edition_display_label(local_state: LocalWindowsState) -> str:
    scope = _edition_scope(local_state.edition_scope)
    text = " ".join(
        str(value).lower()
        for value in (
            local_state.dism_current_edition,
            local_state.edition_id,
            local_state.edition_family,
            local_state.product_name,
            local_state.caption,
        )
        if value
    )
    compact = re.sub(r"[^a-z0-9]+", "", text)
    if scope is EditionScope.UNKNOWN:
        return "unknown edition"
    if scope is EditionScope.SERVER:
        return "Server"
    if scope is EditionScope.IOT_ENTERPRISE_LTSC:
        return "IoT Enterprise LTSC"
    if scope is EditionScope.ENTERPRISE_LTSC:
        return "Enterprise LTSC"
    if scope is EditionScope.ENTERPRISE_EDUCATION:
        return "Education" if "education" in compact and "enterprise" not in compact else "Enterprise"
    if "workstation" in compact:
        return "Pro for Workstations"
    if "professionaleducation" in compact or "proeducation" in compact:
        return "Pro Education"
    if "home" in compact or "core" in compact:
        return "Home"
    return "Pro"


def derive_display_os_name(
    local_state: LocalWindowsState,
    inference: InstalledReleaseInference,
) -> str:
    build_family = local_state.build_family
    scope = _edition_scope(local_state.edition_scope)
    if scope is EditionScope.SERVER or local_state.is_server:
        base = "Windows Server"
    elif build_family is not None and build_family >= 22000:
        base = "Windows 11"
    elif build_family is not None and build_family >= 10240:
        base = "Windows 10"
    elif inference.release:
        base = "Windows 11"
    elif any("windows 11" in str(value).lower() for value in (local_state.product_name, local_state.caption) if value):
        base = "Windows 11"
    elif any("windows 10" in str(value).lower() for value in (local_state.product_name, local_state.caption) if value):
        base = "Windows 10"
    else:
        base = "Windows"

    edition = _edition_display_label(local_state)
    if base == "Windows Server":
        return base if edition == "Server" else f"{base} {edition}"
    return f"{base} {edition}"


def derive_local_consensus(
    local_state: LocalWindowsState,
    inference: InstalledReleaseInference,
) -> LocalConsensus:
    display_os_name = derive_display_os_name(local_state, inference)
    raw_product_name = local_state.product_name
    conflicts: list[str] = []
    warnings: list[str] = []
    display_release = _display_release_hint(local_state)
    build_signal_conflicts = ()
    if isinstance(local_state.raw, Mapping):
        build_signal_conflicts = tuple(
            str(item)
            for item in local_state.raw.get("build_signal_conflicts", [])
            if item
        )

    if raw_product_name and "windows 10" in raw_product_name.lower() and display_os_name.startswith("Windows 11"):
        conflicts.append("LOCAL_PRODUCT_NAME_STALE")
        warnings.append(
            f"LOCAL_PRODUCT_NAME_STALE: raw ProductName '{raw_product_name}' is display-only and was ignored because build family {local_state.build_family} maps to Windows 11 {inference.release or 'release'}."
        )
    if local_state.caption and "windows 10" in local_state.caption.lower() and display_os_name.startswith("Windows 11"):
        conflicts.append("LOCAL_CAPTION_STALE")
        warnings.append(
            f"LOCAL_CAPTION_STALE: WMI Caption '{local_state.caption}' is display-only and was ignored because build family {local_state.build_family} maps to Windows 11 {inference.release or 'release'}."
        )
    if display_release and inference.release and display_release != inference.release:
        conflicts.append("DISPLAY_VERSION_CONFLICTS_WITH_BUILD")
        warnings.append(
            f"DISPLAY_VERSION_CONFLICTS_WITH_BUILD: DisplayVersion {display_release} was ignored because build family {local_state.build_family} maps to {inference.release}."
        )
    if build_signal_conflicts:
        conflicts.append("LOCAL_BUILD_SIGNAL_CONFLICT")
        warnings.extend(build_signal_conflicts)
    if _edition_scope(local_state.edition_scope) is EditionScope.UNKNOWN:
        warnings.append("UNKNOWN_EDITION_SCOPE: unable to derive Windows edition; display name uses unknown edition.")

    return LocalConsensus(
        display_os_name=display_os_name,
        raw_product_name=raw_product_name,
        edition_scope=local_state.edition_scope,
        servicing_channel=local_state.servicing_channel,
        release=inference.release,
        build_family=local_state.build_family,
        conflicts=tuple(dict.fromkeys(conflicts)),
        warnings=tuple(dict.fromkeys(warnings)),
        signal_set=local_signal_set(local_state),
    )
