from __future__ import annotations

import re
from typing import Mapping

from .exceptions import PolicyError
from .models import (
    BuildEvidenceSource,
    EditionScope,
    EvaluationResult,
    EvaluationStatus,
    InstalledBuildClassification,
    InstalledBuildOrigin,
    InstalledReleaseInference,
    LocalConsensus,
    LocalSignal,
    LocalSignalSet,
    LocalWindowsState,
    QualityPolicy,
    ReleaseHistoryEntry,
    ReleasePolicy,
    ReleasePolicyEntry,
    ServicingChannel,
)
from .local_state import DEFAULT_BUILD_FAMILY_RELEASES, extract_release
from .policy_diagnostics import apply_silent_feature_update_diagnostics


def _release_key(release: str | None) -> tuple[int, int]:
    if not release:
        return (-1, -1)
    match = re.fullmatch(r"(\d{2})H([12])", release.upper())
    if not match:
        return (-1, -1)
    return int(match.group(1)), int(match.group(2))


def _build_key(build: str | None) -> tuple[int, int]:
    if not build:
        return (-1, -1)
    parts = str(build).split(".")
    try:
        major = int(parts[0])
        ubr = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        return (-1, -1)
    return major, ubr


def _quality_policy(value: QualityPolicy | str) -> QualityPolicy:
    if isinstance(value, QualityPolicy):
        return value
    return QualityPolicy(str(value))


def _edition_scope(value: EditionScope | str | None) -> EditionScope:
    if value is None:
        return EditionScope.UNKNOWN
    if isinstance(value, EditionScope):
        return value
    try:
        return EditionScope(str(value))
    except ValueError:
        return EditionScope.UNKNOWN


def _servicing_channel(value: ServicingChannel | str | None) -> ServicingChannel:
    if value is None:
        return ServicingChannel.UNKNOWN
    if isinstance(value, ServicingChannel):
        return value
    try:
        return ServicingChannel(str(value))
    except ValueError:
        return ServicingChannel.UNKNOWN


def _policy_release_catalog(policy: ReleasePolicy) -> set[str]:
    releases = set(policy.supported_build_families.values())
    releases.update(entry.version for entry in policy.current_versions)
    releases.update(entry.version for entry in policy.supported_releases)
    releases.update(entry.version for entry in policy.special_releases)
    releases.update(entry.version for entry in policy.excluded_for_existing_devices)
    if policy.broad_target_existing_devices:
        releases.add(policy.broad_target_existing_devices.version)
    return {release.upper() for release in releases if release}


def _current_version_for_build_family(policy: ReleasePolicy, build_family: int | None) -> ReleasePolicyEntry | None:
    if build_family is None:
        return None
    for entry in policy.current_versions:
        if entry.build_family == build_family:
            return entry
    return None


def _special_version_for_build_family(policy: ReleasePolicy, build_family: int | None) -> ReleasePolicyEntry | None:
    if build_family is None:
        return None
    for entry in (*policy.special_releases, *policy.excluded_for_existing_devices):
        if entry.build_family == build_family:
            return entry
    return None


def _policy_allows_future_release_pattern(policy: ReleasePolicy) -> bool:
    return bool(
        policy.metadata.get("allow_future_release_pattern")
        or policy.metadata.get("allow_future_recognized_pattern")
        or policy.source.get("allow_future_release_pattern")
    )


def _display_release_hint(local_state: LocalWindowsState) -> str | None:
    return extract_release(local_state.display_version) or extract_release(local_state.release_id)


def _conflicts(display_release: str | None, release: str | None, source: str) -> tuple[str, ...]:
    if display_release and release and display_release != release:
        return (f"DisplayVersion hint {display_release} conflicts with {source} release {release}.",)
    return ()


def _is_windows10_or_older_client(local_state: LocalWindowsState) -> bool:
    if local_state.is_windows_client is False or local_state.is_server:
        return False
    if local_state.is_windows_11_or_newer:
        return False
    return bool(local_state.build_family is not None and local_state.build_family < 22000)


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


def _entry_channel(entry: ReleasePolicyEntry | ReleaseHistoryEntry) -> ServicingChannel:
    channel = getattr(entry, "servicing_channel", ServicingChannel.UNKNOWN)
    parsed = _servicing_channel(channel)
    if parsed is not ServicingChannel.UNKNOWN:
        return parsed
    servicing = (entry.servicing_option or "").lower()
    if "hotpatch" in servicing or "hot patch" in servicing:
        return ServicingChannel.HOTPATCH
    if "long-term" in servicing or "long term" in servicing or "ltsc" in servicing or "ltsb" in servicing:
        return ServicingChannel.LTSC
    if "general availability" in servicing or "allgemeine" in servicing:
        return ServicingChannel.GENERAL_AVAILABILITY
    return ServicingChannel.UNKNOWN


def _entry_scopes(entry: ReleasePolicyEntry) -> set[EditionScope]:
    scopes = {_edition_scope(scope) for scope in entry.edition_scopes}
    scopes.discard(EditionScope.UNKNOWN)
    if scopes:
        return scopes
    channel = _entry_channel(entry)
    if channel is ServicingChannel.LTSC:
        return {EditionScope.ENTERPRISE_LTSC, EditionScope.IOT_ENTERPRISE_LTSC}
    if channel is ServicingChannel.GENERAL_AVAILABILITY:
        return {EditionScope.HOME_PRO, EditionScope.ENTERPRISE_EDUCATION}
    if channel is ServicingChannel.HOTPATCH:
        return {EditionScope.ENTERPRISE_EDUCATION}
    return set()


def _desired_channel_for_scope(
    edition_scope: EditionScope,
    servicing_channel: ServicingChannel,
) -> ServicingChannel:
    if servicing_channel in {ServicingChannel.LTSC, ServicingChannel.HOTPATCH}:
        return servicing_channel
    if edition_scope in {EditionScope.ENTERPRISE_LTSC, EditionScope.IOT_ENTERPRISE_LTSC}:
        return ServicingChannel.LTSC
    if edition_scope is EditionScope.SERVER:
        return ServicingChannel.UNKNOWN
    return ServicingChannel.GENERAL_AVAILABILITY


def _entry_matches_scope(
    entry: ReleasePolicyEntry,
    *,
    edition_scope: EditionScope,
    servicing_channel: ServicingChannel,
) -> bool:
    desired_channel = _desired_channel_for_scope(edition_scope, servicing_channel)
    entry_channel = _entry_channel(entry)
    if desired_channel is not ServicingChannel.UNKNOWN:
        if entry_channel is not desired_channel:
            return False
    elif entry_channel is ServicingChannel.LTSC:
        return False

    if edition_scope is EditionScope.UNKNOWN:
        return entry_channel is ServicingChannel.GENERAL_AVAILABILITY

    scopes = _entry_scopes(entry)
    return not scopes or edition_scope in scopes


def _is_general_availability(entry: ReleasePolicyEntry | ReleaseHistoryEntry) -> bool:
    return _entry_channel(entry) is ServicingChannel.GENERAL_AVAILABILITY


def _has_end_of_updates(
    entry: ReleasePolicyEntry,
    edition_scope: EditionScope = EditionScope.HOME_PRO,
) -> bool:
    if edition_scope is EditionScope.ENTERPRISE_EDUCATION:
        support_key = "enterprise_education_end"
    elif edition_scope in {EditionScope.ENTERPRISE_LTSC, EditionScope.IOT_ENTERPRISE_LTSC}:
        support_key = "ltsc_end"
    else:
        support_key = "home_pro_end"

    values = [entry.reason or "", str(entry.metadata.get(support_key) or "")]
    raw = entry.metadata.get("raw")
    if isinstance(raw, dict):
        for key, value in raw.items():
            key_l = str(key).lower()
            if edition_scope is EditionScope.HOME_PRO and "home" in key_l:
                values.append(str(value))
            elif edition_scope is EditionScope.ENTERPRISE_EDUCATION and (
                "enterprise" in key_l or "education" in key_l
            ):
                values.append(str(value))
            elif edition_scope in {EditionScope.ENTERPRISE_LTSC, EditionScope.IOT_ENTERPRISE_LTSC} and (
                "ltsc" in key_l or "long-term" in key_l or "iot" in key_l
            ):
                values.append(str(value))
    else:
        values.extend(
            str(value)
            for key, value in entry.metadata.items()
            if key not in {"raw", "home_pro_end", "enterprise_education_end", "ltsc_end"}
        )
    return any("end of updates" in value.lower() for value in values)


def _is_special_release(entry: ReleasePolicyEntry, policy: ReleasePolicy) -> bool:
    if entry.metadata.get("special_release") or entry.metadata.get("not_broad_target"):
        return True
    special_versions = {special.version.upper() for special in policy.special_releases}
    special_versions.update(excluded.version.upper() for excluded in policy.excluded_for_existing_devices)
    return entry.version.upper() in special_versions


def _policy_release_entries(policy: ReleasePolicy) -> tuple[ReleasePolicyEntry, ...]:
    if policy.current_versions:
        return policy.current_versions
    if policy.supported_releases:
        return policy.supported_releases
    if policy.broad_target_existing_devices:
        return (policy.broad_target_existing_devices,)
    return ()


def _target_selection_note(
    edition_scope: EditionScope,
    servicing_channel: ServicingChannel,
    target: ReleasePolicyEntry,
) -> str:
    channel = _desired_channel_for_scope(edition_scope, servicing_channel)
    if edition_scope is EditionScope.UNKNOWN:
        return (
            "Unknown edition scope; selected General Availability target "
            f"{target.version} conservatively."
        )
    if channel is ServicingChannel.LTSC:
        return f"Selected LTSC target {target.version} for {edition_scope.value} devices."
    if channel is ServicingChannel.HOTPATCH:
        return f"Selected hotpatch target {target.version} for {edition_scope.value} devices."
    return f"Selected General Availability target {target.version} for {edition_scope.value} devices."


def _select_broad_fleet_target_with_reason(
    policy: ReleasePolicy,
    prefer_h2_releases: bool = True,
    excluded_releases: set[str] | None = None,
    explicit_target_release: str | None = None,
) -> tuple[ReleasePolicyEntry, str]:
    return _select_broad_fleet_target_for_scope(
        policy,
        prefer_h2_releases=prefer_h2_releases,
        excluded_releases=excluded_releases,
        explicit_target_release=explicit_target_release,
        edition_scope=EditionScope.UNKNOWN,
        servicing_channel=ServicingChannel.UNKNOWN,
    )


def _select_broad_fleet_target_for_scope(
    policy: ReleasePolicy,
    prefer_h2_releases: bool = True,
    excluded_releases: set[str] | None = None,
    explicit_target_release: str | None = None,
    edition_scope: EditionScope | str | None = None,
    servicing_channel: ServicingChannel | str | None = None,
) -> tuple[ReleasePolicyEntry, str]:
    """Select the current broad-fleet target for existing devices."""

    entries = _policy_release_entries(policy)
    if not entries:
        raise PolicyError("Release policy does not contain current versions.")

    excluded = {release.upper() for release in (excluded_releases or set())}
    scope = _edition_scope(edition_scope)
    channel = _servicing_channel(servicing_channel)

    if explicit_target_release:
        target = explicit_target_release.upper()
        for entry in entries:
            if entry.version.upper() == target and _entry_matches_scope(
                entry,
                edition_scope=scope,
                servicing_channel=channel,
            ):
                return entry, f"Explicit target release {target} selected for {scope.value}."
        if scope is EditionScope.UNKNOWN:
            for entry in entries:
                if entry.version.upper() == target:
                    return entry, f"Explicit target release {target} selected."
        raise PolicyError(f"Explicit target release {target} not found in policy.")

    candidates = [
        entry
        for entry in entries
        if entry.version.upper() not in excluded
        and _entry_matches_scope(
            entry,
            edition_scope=scope,
            servicing_channel=channel,
        )
        and not _has_end_of_updates(entry, scope)
        and not _is_special_release(entry, policy)
    ]

    if not candidates:
        raise PolicyError("No supported broad-fleet target candidate found.")

    if prefer_h2_releases:
        h2_candidates = [entry for entry in candidates if entry.version.upper().endswith("H2")]
        if h2_candidates:
            candidates = h2_candidates

    target = max(candidates, key=lambda entry: _release_key(entry.version))
    return target, _target_selection_note(scope, channel, target)


def select_broad_fleet_target(
    policy: ReleasePolicy,
    prefer_h2_releases: bool = True,
    excluded_releases: set[str] | None = None,
    explicit_target_release: str | None = None,
    edition_scope: EditionScope | str | None = None,
    servicing_channel: ServicingChannel | str | None = None,
) -> ReleasePolicyEntry:
    target, _reason = _select_broad_fleet_target_for_scope(
        policy,
        prefer_h2_releases=prefer_h2_releases,
        excluded_releases=excluded_releases,
        explicit_target_release=explicit_target_release,
        edition_scope=edition_scope,
        servicing_channel=servicing_channel,
    )
    return target


def select_quality_baseline(
    policy: ReleasePolicy,
    target_release: str,
    quality_policy: QualityPolicy | str = QualityPolicy.B_RELEASE_ONLY,
    target_entry: ReleasePolicyEntry | None = None,
) -> ReleaseHistoryEntry | dict:
    """Select the required quality baseline for a target release."""

    selected_policy = _quality_policy(quality_policy)
    rows = [
        row
        for row in policy.release_history
        if row.release.upper() == target_release.upper()
    ]
    if target_entry is not None and rows:
        scoped_rows = [
            row
            for row in rows
            if row.build_family == target_entry.build_family
            and (
                _entry_channel(target_entry) is ServicingChannel.UNKNOWN
                or _entry_channel(row) is ServicingChannel.UNKNOWN
                or _entry_channel(row) is _entry_channel(target_entry)
            )
        ]
        if scoped_rows:
            rows = scoped_rows
    if not rows:
        return {}

    if selected_policy is QualityPolicy.B_RELEASE_ONLY:
        filtered = [row for row in rows if row.update_type_letter == "B"]
    elif selected_policy is QualityPolicy.LATEST_NON_PREVIEW:
        filtered = [row for row in rows if not row.preview]
    else:
        filtered = rows

    if not filtered:
        filtered = rows

    return max(
        filtered,
        key=lambda row: (
            row.availability_date or "",
            _build_key(row.build),
        ),
    )


def _kb_article(text: str | None) -> str | None:
    match = re.search(r"\bKB\d{6,8}\b", text or "", flags=re.IGNORECASE)
    return match.group(0).upper() if match else None


def _history_title_mentions_preview(title: str) -> bool:
    text = title.lower()
    return "preview" in text or "vorschau" in text


def _history_title_mentions_oob(title: str) -> bool:
    text = title.lower().replace("_", "-")
    return (
        "out-of-band" in text
        or "out of band" in text
        or re.search(r"\boob\b", text) is not None
        or "außerplan" in text
        or "ausserplan" in text
    )


def _policy_row_classification(row: ReleaseHistoryEntry) -> InstalledBuildClassification:
    if row.out_of_band or row.update_type_letter == "OOB":
        return InstalledBuildClassification.OUT_OF_BAND
    if row.preview or row.update_type_letter == "D":
        return InstalledBuildClassification.PREVIEW
    if row.update_type_letter == "B":
        return InstalledBuildClassification.B_RELEASE
    update_type = (row.update_type or "").lower()
    if "preview" in update_type or "vorschau" in update_type:
        return InstalledBuildClassification.PREVIEW
    if "out-of-band" in update_type or "out of band" in update_type:
        return InstalledBuildClassification.OUT_OF_BAND
    return InstalledBuildClassification.B_RELEASE


def _diagnostic_flag(classification: InstalledBuildClassification) -> str:
    if classification is InstalledBuildClassification.B_RELEASE:
        return "LOCAL_BUILD_IS_B_RELEASE"
    if classification is InstalledBuildClassification.PREVIEW:
        return "LOCAL_BUILD_IS_PREVIEW"
    if classification is InstalledBuildClassification.OUT_OF_BAND:
        return "LOCAL_BUILD_IS_OOB"
    if classification is InstalledBuildClassification.UNKNOWN_NEWER_THAN_BASELINE:
        return "LOCAL_BUILD_NEWER_THAN_POLICY_UNKNOWN_ORIGIN"
    return "LOCAL_BUILD_OLDER_THAN_POLICY_UNKNOWN_ORIGIN"


def _matching_policy_history_row(
    policy: ReleasePolicy,
    *,
    installed_release: str | None,
    installed_build: str | None,
    target: ReleasePolicyEntry | None,
) -> ReleaseHistoryEntry | None:
    if not installed_release or not installed_build:
        return None
    matches = [
        row
        for row in policy.release_history
        if row.release.upper() == installed_release.upper()
        and row.build == installed_build
    ]
    if not matches:
        return None
    if target is not None:
        scoped = [
            row
            for row in matches
            if row.build_family == target.build_family
            and (
                _entry_channel(target) is ServicingChannel.UNKNOWN
                or _entry_channel(row) is ServicingChannel.UNKNOWN
                or _entry_channel(row) is _entry_channel(target)
            )
        ]
        if scoped:
            matches = scoped
    return max(matches, key=lambda row: (row.availability_date or "", _build_key(row.build)))


def _origin_from_wua_history(
    wua_secondary: object,
    *,
    installed_build: str | None,
    installed_release: str | None,
) -> InstalledBuildOrigin | None:
    if not installed_build or not isinstance(wua_secondary, Mapping):
        return None
    for item in wua_secondary.get("history", []):
        if not isinstance(item, Mapping):
            continue
        title = str(item.get("title") or "")
        if installed_build not in title:
            continue
        if _history_title_mentions_oob(title):
            classification = InstalledBuildClassification.OUT_OF_BAND
        elif _history_title_mentions_preview(title):
            classification = InstalledBuildClassification.PREVIEW
        else:
            classification = InstalledBuildClassification.B_RELEASE
        return InstalledBuildOrigin(
            build=installed_build,
            release=installed_release,
            matched_policy_row=None,
            classification=classification,
            kb_article=_kb_article(title),
            availability_date=str(item.get("date") or "") or None,
            evidence_source=BuildEvidenceSource.WUA_HISTORY,
            diagnostic_flags=(_diagnostic_flag(classification),),
        )
    return None


def determine_installed_build_origin(
    *,
    local_state: LocalWindowsState,
    policy: ReleasePolicy,
    installed_release: str | None,
    installed_build: str | None,
    target: ReleasePolicyEntry | None,
    baseline_build: str | None,
    wua_secondary: object = None,
) -> InstalledBuildOrigin | None:
    if not installed_build:
        return None

    policy_row = _matching_policy_history_row(
        policy,
        installed_release=installed_release,
        installed_build=installed_build,
        target=target,
    )
    if policy_row is not None:
        classification = _policy_row_classification(policy_row)
        return InstalledBuildOrigin(
            build=installed_build,
            release=installed_release,
            matched_policy_row=policy_row.to_dict(),
            classification=classification,
            kb_article=policy_row.kb_article,
            availability_date=policy_row.availability_date,
            evidence_source=BuildEvidenceSource.POLICY_RELEASE_HISTORY,
            diagnostic_flags=(_diagnostic_flag(classification),),
        )

    wua_origin = _origin_from_wua_history(
        wua_secondary,
        installed_build=installed_build,
        installed_release=installed_release,
    )
    if wua_origin is not None:
        return wua_origin

    installed_key = _build_key(installed_build)
    baseline_key = _build_key(baseline_build)
    if baseline_key == (-1, -1):
        classification = InstalledBuildClassification.UNKNOWN_NEWER_THAN_BASELINE
    elif installed_key >= baseline_key:
        classification = InstalledBuildClassification.UNKNOWN_NEWER_THAN_BASELINE
    else:
        classification = InstalledBuildClassification.UNKNOWN_OLDER_THAN_BASELINE

    if baseline_build and installed_build == baseline_build:
        classification = InstalledBuildClassification.B_RELEASE

    return InstalledBuildOrigin(
        build=installed_build,
        release=installed_release,
        matched_policy_row=None,
        classification=classification,
        evidence_source=BuildEvidenceSource.UNKNOWN,
        diagnostic_flags=(_diagnostic_flag(classification),),
    )


def _local_full_build(local_state: LocalWindowsState) -> str | None:
    if local_state.full_build:
        return local_state.full_build
    if local_state.current_build is None:
        return None
    if local_state.ubr is None:
        return str(local_state.current_build)
    return f"{local_state.current_build}.{local_state.ubr}"


def _result_flags(status: EvaluationStatus) -> tuple[bool, bool]:
    if status is EvaluationStatus.COMPLIANT:
        return False, False
    if status is EvaluationStatus.OUT_OF_SCOPE:
        return False, False
    if status in {EvaluationStatus.UNKNOWN_LOCAL_RELEASE, EvaluationStatus.CHECK_INCOMPLETE}:
        return False, True
    return True, False


def _summary(
    status: EvaluationStatus,
    installed_release: str | None,
    target: ReleasePolicyEntry | None,
    installed_build: str | None,
    baseline_build: str | None,
) -> str:
    target_release = target.version if target else None
    if status is EvaluationStatus.COMPLIANT:
        return f"Compliant: {installed_release} build {installed_build} meets target {target_release}."
    if status is EvaluationStatus.FEATURE_UPDATE_REQUIRED:
        return f"Feature update required: {installed_release} is below broad target {target_release}."
    if status is EvaluationStatus.QUALITY_UPDATE_REQUIRED:
        return f"Quality update required: build {installed_build} is below baseline {baseline_build}."
    if status is EvaluationStatus.PREVIEW_BUILD_INSTALLED:
        return f"Preview build installed: {installed_release} build {installed_build} is classified as preview."
    if status is EvaluationStatus.ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE:
        return f"Special or above-target release: {installed_release} is above broad target {target_release}."
    if status is EvaluationStatus.OUT_OF_SCOPE:
        return "Out of scope: local OS is not in the Windows 11 client release policy scope."
    if status is EvaluationStatus.CHECK_INCOMPLETE:
        return "Check incomplete: release policy is unavailable."
    return "Unknown local release: local state or policy could not be evaluated safely."


def _wua_target_not_offered(wua_secondary: object) -> bool:
    if not isinstance(wua_secondary, dict):
        return False
    if "target_feature_update_offered" in wua_secondary:
        return wua_secondary.get("target_feature_update_offered") is False
    if "target_release_offered" in wua_secondary:
        return wua_secondary.get("target_release_offered") is False
    return False


def _wua_probe_warnings(wua_secondary: object) -> list[str]:
    if not isinstance(wua_secondary, Mapping):
        return []
    warnings: list[str] = []
    if wua_secondary.get("timed_out"):
        warnings.append("WUA secondary probe timed out; primary policy verdict is unchanged.")
    if wua_secondary.get("available") is False and (
        wua_secondary.get("warnings") or wua_secondary.get("errors")
    ):
        warnings.append("WUA secondary probe unavailable; primary policy verdict is unchanged.")
    warnings.extend(f"WUA secondary probe warning: {item}" for item in wua_secondary.get("warnings", []))
    warnings.extend(f"WUA secondary probe error: {item}" for item in wua_secondary.get("errors", []))
    return list(dict.fromkeys(warnings))


def _make_result(
    *,
    status: EvaluationStatus,
    local_state: LocalWindowsState,
    target: ReleasePolicyEntry | None,
    baseline: ReleaseHistoryEntry | dict | None,
    installed_release: str | None,
    installed_build: str | None,
    baseline_build: str | None,
    action: str,
    installed_build_origin: InstalledBuildOrigin | None = None,
    local_consensus: LocalConsensus | None = None,
    notes: list[str] | None = None,
    warnings: list[str] | None = None,
    wua_secondary: object = None,
    metadata: dict[str, object] | None = None,
    target_selection_reason: str | None = None,
) -> EvaluationResult:
    is_warning, is_error = _result_flags(status)
    detail_payload = {
        "installed_release": installed_release,
        "installed_build": installed_build,
        "installed_build_origin": installed_build_origin.to_dict() if installed_build_origin else None,
        "local_consensus": local_consensus.to_dict() if local_consensus else None,
        "display_os_name": local_consensus.display_os_name if local_consensus else None,
        "raw_product_name": local_consensus.raw_product_name if local_consensus else None,
        "target_release": target.version if target else None,
        "target_latest_build": target.latest_build if target else None,
        "target_latest_observed_build": target.latest_observed_build if target else None,
        "baseline_build": baseline_build,
        "target_required_baseline_build": target.required_baseline_build if target else None,
    }
    result_metadata = metadata or {}
    result = EvaluationResult(
        status=status,
        action=action,
        local=local_state,
        target=target,
        baseline=baseline,
        installed_release=installed_release,
        installed_build=installed_build,
        installed_build_origin=installed_build_origin,
        local_consensus=local_consensus,
        baseline_build=baseline_build,
        notes=tuple(notes or []),
        is_warning=is_warning,
        is_error=is_error,
        summary=_summary(status, installed_release, target, installed_build, baseline_build),
        details=detail_payload,
        wua_secondary=wua_secondary if isinstance(wua_secondary, dict) else None,
        metadata=result_metadata,
        target_selection_reason=target_selection_reason,
        warnings=tuple(warnings or []),
    )
    return apply_silent_feature_update_diagnostics(result)


def evaluate_windows_update_state(
    local_state: LocalWindowsState,
    policy: ReleasePolicy,
    *,
    quality_policy: QualityPolicy | str = QualityPolicy.B_RELEASE_ONLY,
    prefer_h2_releases: bool = True,
    excluded_releases: set[str] | None = None,
    explicit_target_release: str | None = None,
    wua_secondary: object = None,
    allow_major_upgrade_recommendation: bool = False,
    allow_server_evaluation: bool = False,
    warn_on_preview_installed: bool = True,
    disallow_preview_installed: bool = False,
) -> EvaluationResult:
    """Evaluate Windows release compliance from local state and release policy."""

    inference = infer_installed_release(
        local_state,
        policy,
        allow_major_upgrade_recommendation=allow_major_upgrade_recommendation,
        allow_server_evaluation=allow_server_evaluation,
    )
    local_consensus = derive_local_consensus(local_state, inference)
    inference_metadata = {
        "installed_release_inference": inference.to_dict(),
        "local_consensus": local_consensus.to_dict(),
    }

    if inference.is_out_of_scope:
        return _make_result(
            status=EvaluationStatus.OUT_OF_SCOPE,
            local_state=local_state,
            target=None,
            baseline=None,
            installed_release=inference.release,
            installed_build=_local_full_build(local_state),
            baseline_build=None,
            action=inference.reasons[0] if inference.reasons else "Local OS is out of scope.",
            local_consensus=local_consensus,
            notes=[*local_consensus.warnings, *inference.reasons],
            warnings=list(local_consensus.warnings),
            wua_secondary=wua_secondary,
            metadata={
                **inference_metadata,
                "allow_major_upgrade_recommendation": allow_major_upgrade_recommendation,
                "allow_server_evaluation": allow_server_evaluation,
            },
        )

    local_edition_scope = _edition_scope(local_state.edition_scope)
    local_servicing_channel = _servicing_channel(local_state.servicing_channel)
    try:
        target, target_selection_reason = _select_broad_fleet_target_for_scope(
            policy,
            prefer_h2_releases=prefer_h2_releases,
            excluded_releases=excluded_releases,
            explicit_target_release=explicit_target_release,
            edition_scope=local_edition_scope,
            servicing_channel=local_servicing_channel,
        )
    except PolicyError as exc:
        return _make_result(
            status=EvaluationStatus.UNKNOWN_LOCAL_RELEASE,
            local_state=local_state,
            target=None,
            baseline=None,
            installed_release=None,
            installed_build=_local_full_build(local_state),
            baseline_build=None,
            action=str(exc),
            local_consensus=local_consensus,
            notes=list(local_consensus.warnings),
            warnings=list(local_consensus.warnings),
            metadata=inference_metadata,
        )

    baseline = select_quality_baseline(policy, target.version, quality_policy, target_entry=target)
    installed_release = inference.release
    installed_build = _local_full_build(local_state)
    baseline_build = (
        baseline.build
        if isinstance(baseline, ReleaseHistoryEntry)
        else target.effective_baseline_build
    )
    installed_build_origin = determine_installed_build_origin(
        local_state=local_state,
        policy=policy,
        installed_release=installed_release,
        installed_build=installed_build,
        target=target,
        baseline_build=baseline_build,
        wua_secondary=wua_secondary,
    )

    if installed_release is None:
        return _make_result(
            status=EvaluationStatus.UNKNOWN_LOCAL_RELEASE,
            local_state=local_state,
            target=target,
            baseline=baseline if isinstance(baseline, ReleaseHistoryEntry) else baseline or None,
            installed_release=None,
            installed_build=installed_build,
            installed_build_origin=installed_build_origin,
            baseline_build=baseline_build,
            action="Manual inspection required. Local release is unknown or unrecognized by policy.",
            local_consensus=local_consensus,
            notes=[*local_consensus.warnings, *inference.reasons],
            warnings=list(local_consensus.warnings),
            wua_secondary=wua_secondary,
            metadata=inference_metadata,
            target_selection_reason=target_selection_reason,
        )

    installed_key = _release_key(installed_release)
    target_key = _release_key(target.version)
    notes: list[str] = []

    if installed_key < target_key:
        status = EvaluationStatus.FEATURE_UPDATE_REQUIRED
        action = f"Feature update required: update from {installed_release} to {target.version}."
        if _wua_target_not_offered(wua_secondary):
            notes.append(
                "Discrepancy: WUA did not offer the target feature update even though policy requires it."
            )
            notes.append(
                "Windows Update bietet Zielrelease aktuell nicht an; Primary Policy bleibt maßgeblich."
            )
    elif installed_key > target_key:
        status = EvaluationStatus.ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE
        action = (
            "Do not use this device as broad-fleet reference; review special device/release."
        )
    elif baseline_build and installed_build is None:
        return _make_result(
            status=EvaluationStatus.UNKNOWN_LOCAL_RELEASE,
            local_state=local_state,
            target=target,
            baseline=baseline if isinstance(baseline, ReleaseHistoryEntry) else baseline or None,
            installed_release=installed_release,
            installed_build=installed_build,
            installed_build_origin=installed_build_origin,
            baseline_build=baseline_build,
            action="Manual inspection required. Local full build could not be inferred.",
            local_consensus=local_consensus,
            notes=list(local_consensus.warnings),
            warnings=list(local_consensus.warnings),
            wua_secondary=wua_secondary,
            target_selection_reason=target_selection_reason,
        )
    elif baseline_build and installed_build and _build_key(installed_build) < _build_key(baseline_build):
        status = EvaluationStatus.QUALITY_UPDATE_REQUIRED
        action = f"Install current cumulative update to reach baseline {baseline_build}."
    else:
        status = EvaluationStatus.COMPLIANT
        action = "No action required."

    edition_warnings: list[str] = []
    if local_edition_scope is EditionScope.UNKNOWN:
        edition_warnings.append(
            "Unknown Windows edition scope; General Availability policy target was selected conservatively."
        )
    origin_warnings: list[str] = []
    if (
        installed_build_origin is not None
        and installed_build_origin.classification is InstalledBuildClassification.PREVIEW
    ):
        if disallow_preview_installed:
            status = EvaluationStatus.PREVIEW_BUILD_INSTALLED
            action = "Preview build installed; move device back to approved non-preview baseline."
        elif warn_on_preview_installed:
            origin_warnings.append(
                "Installed build is classified as a preview update; policy verdict remains based on the B baseline."
            )
    wua_warnings = _wua_probe_warnings(wua_secondary)

    return _make_result(
        status=status,
        local_state=local_state,
        target=target,
        baseline=baseline if isinstance(baseline, ReleaseHistoryEntry) else baseline or None,
        installed_release=installed_release,
        installed_build=installed_build,
        installed_build_origin=installed_build_origin,
        local_consensus=local_consensus,
        baseline_build=baseline_build,
        action=action,
        notes=[*local_consensus.warnings, *edition_warnings, *origin_warnings, *wua_warnings, *notes],
        warnings=[*local_consensus.warnings, *edition_warnings, *origin_warnings, *wua_warnings, *notes],
        wua_secondary=wua_secondary,
        target_selection_reason=target_selection_reason,
        metadata={
            "quality_policy": _quality_policy(quality_policy).value,
            "explicit_target_release": explicit_target_release,
            "prefer_h2_releases": prefer_h2_releases,
            "excluded_releases": sorted(excluded_releases or []),
            "allow_major_upgrade_recommendation": allow_major_upgrade_recommendation,
            "allow_server_evaluation": allow_server_evaluation,
            "warn_on_preview_installed": warn_on_preview_installed,
            "disallow_preview_installed": disallow_preview_installed,
            "edition_scope": local_edition_scope.value,
            "servicing_channel": local_servicing_channel.value,
            **inference_metadata,
        },
    )


def evaluate(
    local: LocalWindowsState,
    policy: ReleasePolicy,
    prefer_h2_releases: bool = True,
    excluded_releases: set[str] | None = None,
    explicit_target_release: str | None = None,
    quality_policy: QualityPolicy | str = QualityPolicy.B_RELEASE_ONLY,
    allow_major_upgrade_recommendation: bool = False,
    allow_server_evaluation: bool = False,
    warn_on_preview_installed: bool = True,
    disallow_preview_installed: bool = False,
) -> EvaluationResult:
    return evaluate_windows_update_state(
        local,
        policy,
        quality_policy=quality_policy,
        prefer_h2_releases=prefer_h2_releases,
        excluded_releases=excluded_releases,
        explicit_target_release=explicit_target_release,
        allow_major_upgrade_recommendation=allow_major_upgrade_recommendation,
        allow_server_evaluation=allow_server_evaluation,
        warn_on_preview_installed=warn_on_preview_installed,
        disallow_preview_installed=disallow_preview_installed,
    )


__all__ = [
    "_build_key",
    "_release_key",
    "evaluate",
    "evaluate_windows_update_state",
    "infer_installed_release",
    "determine_installed_build_origin",
    "derive_display_os_name",
    "derive_local_consensus",
    "select_broad_fleet_target",
    "select_quality_baseline",
]
