from __future__ import annotations

from typing import Mapping
from .exceptions import PolicyError
from .models import EditionScope, EvaluationResult, EvaluationStatus, InstalledBuildClassification, InstalledBuildOrigin, LocalConsensus, LocalWindowsState, QualityPolicy, ReleaseHistoryEntry, ReleasePolicy, ReleasePolicyEntry
from .policy_diagnostics import apply_silent_feature_update_diagnostics
from .build_origin import determine_installed_build_origin
from .evaluator_common import (
    _build_key,
    _edition_scope,
    _quality_policy,
    _release_key,
    _servicing_channel,
)
from .release_inference import derive_display_os_name, derive_local_consensus, infer_installed_release
from .target_selection import _select_broad_fleet_target_for_scope, select_broad_fleet_target, select_quality_baseline
# Public names this module defined before the v0.6.0 split stay importable from it.
# pylint: disable=unused-import
from .release_inference import local_signal_set
# pylint: enable=unused-import


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
    awaiting_b_release = (
        not isinstance(baseline, ReleaseHistoryEntry)
        and _quality_policy(quality_policy) is QualityPolicy.B_RELEASE_ONLY
        and any(row.release.upper() == target.version.upper() for row in policy.release_history)
    )
    if isinstance(baseline, ReleaseHistoryEntry):
        baseline_build = baseline.build
    elif awaiting_b_release:
        # required_baseline_build falls back to latest_build, which is a preview here.
        baseline_build = target.baseline_build
    else:
        baseline_build = target.effective_baseline_build
    baseline_warnings = (
        [
            f"Release history lists no monthly security (B) release for {target.version} yet; "
            "no quality baseline is enforced until its first B release."
        ]
        if awaiting_b_release and baseline_build is None
        else []
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
        notes=[
            *local_consensus.warnings,
            *edition_warnings,
            *baseline_warnings,
            *origin_warnings,
            *wua_warnings,
            *notes,
        ],
        warnings=[
            *local_consensus.warnings,
            *edition_warnings,
            *baseline_warnings,
            *origin_warnings,
            *wua_warnings,
            *notes,
        ],
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
