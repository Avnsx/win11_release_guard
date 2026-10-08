"""Classifying where the installed build came from."""

from __future__ import annotations

import re
from typing import Mapping
from .models import BuildEvidenceSource, InstalledBuildClassification, InstalledBuildOrigin, LocalWindowsState, ReleaseHistoryEntry, ReleasePolicy, ReleasePolicyEntry, ServicingChannel
from .evaluator_common import _build_key
from .target_selection import _entry_channel


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
