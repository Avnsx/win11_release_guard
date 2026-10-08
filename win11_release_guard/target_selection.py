"""Selecting the broad-fleet target and quality baseline for a device."""

from __future__ import annotations

from .exceptions import PolicyError
from .models import EditionScope, QualityPolicy, ReleaseHistoryEntry, ReleasePolicy, ReleasePolicyEntry, ServicingChannel
from .evaluator_common import (
    _build_key,
    _edition_scope,
    _quality_policy,
    _release_key,
    _servicing_channel,
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
        if selected_policy is QualityPolicy.B_RELEASE_ONLY:
            # A preview, OOB, or unclassified row is never a B-release-only baseline.
            return {}
        filtered = rows

    return max(
        filtered,
        key=lambda row: (
            row.availability_date or "",
            _build_key(row.build),
        ),
    )
