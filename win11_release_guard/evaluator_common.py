"""Shared release, build, and scope helpers for evaluation."""

from __future__ import annotations

import re
from .models import EditionScope, LocalWindowsState, QualityPolicy, ReleasePolicy, ReleasePolicyEntry, ServicingChannel
from .local_state import extract_release


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
