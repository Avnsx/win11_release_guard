from __future__ import annotations

import pytest

from win11_release_guard.evaluator import (
    derive_display_os_name,
    evaluate_windows_update_state,
    infer_installed_release,
    select_broad_fleet_target,
)
from win11_release_guard.models import (
    EditionScope,
    EvaluationStatus,
    InstalledBuildClassification,
    LocalWindowsState,
    ReleaseHistoryEntry,
    ReleasePolicy,
    ReleasePolicyEntry,
    ServicingChannel,
)


def _future_policy() -> ReleasePolicy:
    return ReleasePolicy(
        current_versions=(
            ReleasePolicyEntry(
                version="27H1",
                build_family=29000,
                latest_build="29000.1000",
                baseline_build="29000.1000",
                servicing_option="General Availability Channel",
                metadata={"special_release": True, "new_devices_only": True, "not_broad_target": True},
            ),
            ReleasePolicyEntry(
                version="26H2",
                build_family=28200,
                latest_build="28200.1000",
                baseline_build="28200.1000",
                servicing_option="General Availability Channel",
            ),
            ReleasePolicyEntry(
                version="26H1",
                build_family=28000,
                latest_build="28000.2113",
                baseline_build="28000.2113",
                servicing_option="General Availability Channel",
                metadata={"special_release": True, "new_devices_only": True, "not_broad_target": True},
            ),
            ReleasePolicyEntry(
                version="25H2",
                build_family=26200,
                latest_build="26200.8457",
                baseline_build="26200.8457",
                servicing_option="General Availability Channel",
            ),
        ),
        special_releases=(
            ReleasePolicyEntry(
                version="27H1",
                build_family=29000,
                servicing_option="General Availability Channel",
                metadata={"special_release": True, "new_devices_only": True, "not_broad_target": True},
            ),
            ReleasePolicyEntry(
                version="26H1",
                build_family=28000,
                servicing_option="General Availability Channel",
                metadata={"special_release": True, "new_devices_only": True, "not_broad_target": True},
            ),
        ),
        excluded_for_existing_devices=(
            ReleasePolicyEntry(
                version="27H1",
                build_family=29000,
                servicing_option="General Availability Channel",
                metadata={"special_release": True, "new_devices_only": True, "not_broad_target": True},
            ),
            ReleasePolicyEntry(
                version="26H1",
                build_family=28000,
                servicing_option="General Availability Channel",
                metadata={"special_release": True, "new_devices_only": True, "not_broad_target": True},
            ),
        ),
        supported_build_families={26200: "25H2", 28000: "26H1", 28200: "26H2", 29000: "27H1"},
    )


def _ga_ltsc_policy() -> ReleasePolicy:
    return ReleasePolicy(
        broad_target_existing_devices=ReleasePolicyEntry(
            version="25H2",
            build_family=26200,
            latest_build="26200.8457",
            baseline_build="26200.8457",
            servicing_option="General Availability Channel",
            edition_scopes=(EditionScope.HOME_PRO, EditionScope.ENTERPRISE_EDUCATION),
            servicing_channel=ServicingChannel.GENERAL_AVAILABILITY,
        ),
        current_versions=(
            ReleasePolicyEntry(
                version="25H2",
                build_family=26200,
                latest_build="26200.8457",
                baseline_build="26200.8457",
                servicing_option="General Availability Channel",
                edition_scopes=(EditionScope.HOME_PRO, EditionScope.ENTERPRISE_EDUCATION),
                servicing_channel=ServicingChannel.GENERAL_AVAILABILITY,
            ),
            ReleasePolicyEntry(
                version="24H2",
                build_family=26100,
                latest_build="26100.8457",
                baseline_build="26100.8457",
                servicing_option="General Availability Channel",
                edition_scopes=(EditionScope.HOME_PRO, EditionScope.ENTERPRISE_EDUCATION),
                servicing_channel=ServicingChannel.GENERAL_AVAILABILITY,
            ),
            ReleasePolicyEntry(
                version="24H2",
                build_family=26100,
                latest_build="26100.8457",
                baseline_build="26100.8457",
                servicing_option="Long-Term Servicing Channel",
                edition_scopes=(EditionScope.ENTERPRISE_LTSC, EditionScope.IOT_ENTERPRISE_LTSC),
                servicing_channel=ServicingChannel.LTSC,
            ),
            ReleasePolicyEntry(
                version="26H1",
                build_family=28000,
                latest_build="28000.2113",
                baseline_build="28000.2113",
                servicing_option="General Availability Channel",
                metadata={"special_release": True, "new_devices_only": True, "not_broad_target": True},
            ),
        ),
        release_history=(
            ReleaseHistoryEntry(
                release="25H2",
                build_family=26200,
                build="26200.8457",
                update_type="2026-05 B",
                update_type_letter="B",
                availability_date="2026-05-12",
                servicing_option="General Availability Channel",
                kb_article="KB5089549",
            ),
            ReleaseHistoryEntry(
                release="25H2",
                build_family=26200,
                build="26200.8524",
                update_type="2026-05 D Preview",
                update_type_letter="D",
                availability_date="2026-05-27",
                servicing_option="General Availability Channel",
                preview=True,
                kb_article="KB5089573",
            ),
            ReleaseHistoryEntry(
                release="24H2",
                build_family=26100,
                build="26100.8457",
                update_type="2026-05 B",
                update_type_letter="B",
                availability_date="2026-05-12",
                servicing_option="General Availability Channel",
                kb_article="KB5089549",
            ),
            ReleaseHistoryEntry(
                release="24H2",
                build_family=26100,
                build="26100.8457",
                update_type="2026-05 B",
                update_type_letter="B",
                availability_date="2026-05-12",
                servicing_option="Long-Term Servicing Channel",
                kb_article="KB5089549",
            ),
        ),
        special_releases=(
            ReleasePolicyEntry(
                version="26H1",
                build_family=28000,
                servicing_option="General Availability Channel",
                metadata={"special_release": True, "new_devices_only": True, "not_broad_target": True},
            ),
        ),
        excluded_for_existing_devices=(
            ReleasePolicyEntry(
                version="26H1",
                build_family=28000,
                servicing_option="General Availability Channel",
                metadata={"special_release": True, "new_devices_only": True, "not_broad_target": True},
            ),
        ),
        supported_build_families={26100: "24H2", 26200: "25H2", 28000: "26H1"},
    )


def _raw_snapshot(
    *,
    current_build: int,
    ubr: int,
    display_version: str,
    edition_id: str | None,
    product_name: str,
    caption: str,
    dism_current_edition: str | None,
    dism_image_version: str,
    installation_type: str = "Client",
    edition_scope: EditionScope = EditionScope.HOME_PRO,
    servicing_channel: ServicingChannel = ServicingChannel.GENERAL_AVAILABILITY,
) -> dict[str, object]:
    full_build = f"{current_build}.{ubr}"
    version = f"10.0.{current_build}"
    return {
        "current_build": current_build,
        "ubr": ubr,
        "full_build": full_build,
        "display_version": display_version,
        "edition_id": edition_id,
        "product_name": product_name,
        "caption": caption,
        "installation_type": installation_type,
        "os_version": version,
        "rtl_version": version,
        "wmi_version": version,
        "kernel_file_version": f"{version}.{ubr}",
        "dism_current_edition": dism_current_edition,
        "dism_image_version": dism_image_version,
        "dism_tool_version": "10.0.26100.1",
        "edition_scope": edition_scope.value,
        "servicing_channel": servicing_channel.value,
        "product_family": "server" if edition_scope is EditionScope.SERVER else "client",
        "is_server": edition_scope is EditionScope.SERVER,
        "is_windows_client": edition_scope is not EditionScope.SERVER,
        "is_windows_11_or_newer": current_build >= 22000 and edition_scope is not EditionScope.SERVER,
        "raw": {
            "registry": {
                "CurrentBuildNumber": str(current_build),
                "CurrentBuild": str(current_build),
                "UBR": ubr,
                "DisplayVersion": display_version,
                "EditionID": edition_id,
                "InstallationType": installation_type,
                "ProductName": product_name,
            },
            "rtl": {"major": 10, "minor": 0, "build": current_build, "version": version},
            "wmi": {
                "Caption": caption,
                "Version": version,
                "BuildNumber": str(current_build),
                "OSArchitecture": "64-bit",
            },
            "dism": {
                "current_edition": dism_current_edition,
                "image_version": dism_image_version,
                "dism_tool_version": "10.0.26100.1",
            },
            "build_signals": {
                "registry": current_build,
                "rtl": current_build,
                "wmi": current_build,
                "kernel": current_build,
                "dism_image": current_build,
            },
        },
    }


WINDOWS_LOCAL_RAW_SNAPSHOTS = (
    {
        "id": "win11_pro_24h2_26100_feature_update_required",
        "local": _raw_snapshot(
            current_build=26100,
            ubr=8457,
            display_version="24H2",
            edition_id="Professional",
            product_name="Windows 11 Pro",
            caption="Microsoft Windows 11 Pro",
            dism_current_edition="Professional",
            dism_image_version="10.0.26100.8457",
        ),
        "status": EvaluationStatus.FEATURE_UPDATE_REQUIRED,
        "target": "25H2",
        "display_os_name": "Windows 11 Pro",
    },
    {
        "id": "win11_pro_25h2_26200_8457_b_baseline_compliant",
        "local": _raw_snapshot(
            current_build=26200,
            ubr=8457,
            display_version="25H2",
            edition_id="Professional",
            product_name="Windows 11 Pro",
            caption="Microsoft Windows 11 Pro",
            dism_current_edition="Professional",
            dism_image_version="10.0.26200.8457",
        ),
        "status": EvaluationStatus.COMPLIANT,
        "target": "25H2",
        "origin": InstalledBuildClassification.B_RELEASE,
        "display_os_name": "Windows 11 Pro",
    },
    {
        "id": "win11_pro_25h2_26200_8524_preview_compliant",
        "local": _raw_snapshot(
            current_build=26200,
            ubr=8524,
            display_version="25H2",
            edition_id="Professional",
            product_name="Windows 11 Pro",
            caption="Microsoft Windows 11 Pro",
            dism_current_edition="Professional",
            dism_image_version="10.0.26200.8524",
        ),
        "status": EvaluationStatus.COMPLIANT,
        "target": "25H2",
        "origin": InstalledBuildClassification.PREVIEW,
        "origin_flag": "LOCAL_BUILD_IS_PREVIEW",
        "display_os_name": "Windows 11 Pro",
    },
    {
        "id": "win11_26h1_28000_special_release",
        "local": _raw_snapshot(
            current_build=28000,
            ubr=2113,
            display_version="26H1",
            edition_id="Professional",
            product_name="Windows 11 Pro",
            caption="Microsoft Windows 11 Pro",
            dism_current_edition="Professional",
            dism_image_version="10.0.28000.2113",
        ),
        "status": EvaluationStatus.ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE,
        "target": "25H2",
        "display_os_name": "Windows 11 Pro",
    },
    {
        "id": "windows_10_pro_19045_out_of_scope",
        "local": _raw_snapshot(
            current_build=19045,
            ubr=4046,
            display_version="22H2",
            edition_id="Professional",
            product_name="Windows 10 Pro",
            caption="Microsoft Windows 10 Pro",
            dism_current_edition="Professional",
            dism_image_version="10.0.19045.4046",
        ),
        "status": EvaluationStatus.OUT_OF_SCOPE,
        "display_os_name": "Windows 10 Pro",
    },
    {
        "id": "windows_server_out_of_scope",
        "local": _raw_snapshot(
            current_build=26100,
            ubr=8457,
            display_version="24H2",
            edition_id="ServerDatacenter",
            product_name="Windows Server 2025 Datacenter",
            caption="Microsoft Windows Server 2025 Datacenter",
            dism_current_edition="ServerDatacenter",
            dism_image_version="10.0.26100.8457",
            installation_type="Server",
            edition_scope=EditionScope.SERVER,
            servicing_channel=ServicingChannel.UNKNOWN,
        ),
        "status": EvaluationStatus.OUT_OF_SCOPE,
        "display_os_name": "Windows Server",
    },
    {
        "id": "enterprise_ltsc_24h2_uses_ltsc_target",
        "local": _raw_snapshot(
            current_build=26100,
            ubr=8457,
            display_version="24H2",
            edition_id="EnterpriseS",
            product_name="Windows 11 Enterprise LTSC",
            caption="Microsoft Windows 11 Enterprise LTSC",
            dism_current_edition="EnterpriseS",
            dism_image_version="10.0.26100.8457",
            edition_scope=EditionScope.ENTERPRISE_LTSC,
            servicing_channel=ServicingChannel.LTSC,
        ),
        "status": EvaluationStatus.COMPLIANT,
        "target": "24H2",
        "target_channel": ServicingChannel.LTSC,
        "display_os_name": "Windows 11 Enterprise LTSC",
    },
    {
        "id": "stale_windows_10_product_name_on_26200",
        "local": _raw_snapshot(
            current_build=26200,
            ubr=8457,
            display_version="25H2",
            edition_id="Professional",
            product_name="Windows 10 Pro",
            caption="Microsoft Windows 11 Pro",
            dism_current_edition="Professional",
            dism_image_version="10.0.26200.8457",
        ),
        "status": EvaluationStatus.COMPLIANT,
        "target": "25H2",
        "display_os_name": "Windows 11 Pro",
        "conflict": "LOCAL_PRODUCT_NAME_STALE",
    },
)


@pytest.mark.parametrize("snapshot", WINDOWS_LOCAL_RAW_SNAPSHOTS, ids=lambda item: str(item["id"]))
def test_windows_local_raw_snapshot_matrix(snapshot: dict[str, object]) -> None:
    local = LocalWindowsState.from_dict(snapshot["local"])
    result = evaluate_windows_update_state(local, _ga_ltsc_policy())

    assert result.status is snapshot["status"]
    assert result.local_consensus is not None
    assert result.local_consensus.display_os_name == snapshot["display_os_name"]
    if snapshot.get("target"):
        assert result.target is not None
        assert result.target.version == snapshot["target"]
    if snapshot.get("target_channel"):
        assert result.target is not None
        assert result.target.servicing_channel is snapshot["target_channel"]
    if snapshot.get("origin"):
        assert result.installed_build_origin is not None
        assert result.installed_build_origin.classification is snapshot["origin"]
    if snapshot.get("origin_flag"):
        assert result.installed_build_origin is not None
        assert snapshot["origin_flag"] in result.installed_build_origin.diagnostic_flags
    if snapshot.get("conflict"):
        assert snapshot["conflict"] in result.local_consensus.conflicts


def test_windows_local_raw_snapshots_do_not_include_private_device_data() -> None:
    text = repr(WINDOWS_LOCAL_RAW_SNAPSHOTS).lower()

    assert "c:\\users" not in text
    assert "\\users\\" not in text
    assert "serial" not in text
    assert "deviceid" not in text


def test_26h1_excluded_26h2_ga_target_and_27h1_special_ignored():
    target = select_broad_fleet_target(_future_policy())

    assert target.version == "26H2"
    assert target.build_family == 28200


def test_pro_24h2_requires_feature_update_to_25h2():
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26100, full_build="26100.8457", edition_id="Professional"),
        _ga_ltsc_policy(),
    )

    assert result.status is EvaluationStatus.FEATURE_UPDATE_REQUIRED
    assert result.target is not None
    assert result.target.version == "25H2"


def test_25h2_pro_old_ubr_requires_quality_update():
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26200, full_build="26200.7000", edition_id="Professional"),
        _ga_ltsc_policy(),
    )

    assert result.status is EvaluationStatus.QUALITY_UPDATE_REQUIRED
    assert result.baseline_build == "26200.8457"


def test_25h2_pro_current_b_release_is_compliant():
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26200, full_build="26200.8457", edition_id="Professional"),
        _ga_ltsc_policy(),
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.installed_build_origin is not None
    assert result.installed_build_origin.classification is InstalledBuildClassification.B_RELEASE


def test_25h2_pro_preview_above_baseline_is_compliant_with_preview_flag():
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26200, full_build="26200.8524", edition_id="Professional"),
        _ga_ltsc_policy(),
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.installed_build_origin is not None
    assert result.installed_build_origin.classification is InstalledBuildClassification.PREVIEW
    assert "LOCAL_BUILD_IS_PREVIEW" in result.installed_build_origin.diagnostic_flags


def test_windows_10_is_out_of_scope_unless_major_upgrade_mode_enabled():
    local = LocalWindowsState(
        current_build=19045,
        full_build="19045.4046",
        display_version="22H2",
        product_name="Windows 10 Pro",
    )

    normal = evaluate_windows_update_state(local, _ga_ltsc_policy())
    opted_in = evaluate_windows_update_state(
        local,
        _ga_ltsc_policy(),
        allow_major_upgrade_recommendation=True,
    )

    assert normal.status is EvaluationStatus.OUT_OF_SCOPE
    assert opted_in.status is EvaluationStatus.FEATURE_UPDATE_REQUIRED


def test_windows_11_ltsc_uses_ltsc_path_not_normal_25h2_target():
    result = evaluate_windows_update_state(
        LocalWindowsState(
            current_build=26100,
            full_build="26100.8457",
            edition_id="EnterpriseS",
            edition_scope=EditionScope.ENTERPRISE_LTSC,
            servicing_channel=ServicingChannel.LTSC,
        ),
        _ga_ltsc_policy(),
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.target is not None
    assert result.target.version == "24H2"
    assert result.target.servicing_channel is ServicingChannel.LTSC


def test_server_out_of_scope_unless_explicitly_supported():
    local = LocalWindowsState(
        current_build=26100,
        full_build="26100.8457",
        product_name="Windows Server 2025 Datacenter",
        installation_type="Server",
        edition_scope=EditionScope.SERVER,
    )
    server_policy = ReleasePolicy(
        current_versions=(
            ReleasePolicyEntry(
                version="25H2",
                build_family=26100,
                latest_build="26100.8457",
                baseline_build="26100.8457",
                servicing_option="Server",
                edition_scopes=(EditionScope.SERVER,),
                servicing_channel=ServicingChannel.UNKNOWN,
            ),
        ),
        release_history=(
            ReleaseHistoryEntry(
                release="25H2",
                build_family=26100,
                build="26100.8457",
                update_type_letter="B",
                availability_date="2026-05-12",
                servicing_option="Server",
            ),
        ),
        supported_build_families={26100: "25H2"},
    )

    out_of_scope = evaluate_windows_update_state(local, server_policy)
    explicitly_supported = evaluate_windows_update_state(
        local,
        server_policy,
        allow_server_evaluation=True,
    )

    assert out_of_scope.status is EvaluationStatus.OUT_OF_SCOPE
    assert explicitly_supported.status is EvaluationStatus.COMPLIANT


def test_stale_product_name_on_build_26200_is_display_conflict_not_truth():
    local = LocalWindowsState(
        product_name="Windows 10 Pro",
        edition_id="Professional",
        display_version="25H2",
        current_build=26200,
        ubr=8457,
        full_build="26200.8457",
    )
    policy = _ga_ltsc_policy()
    inference = infer_installed_release(local, policy)
    result = evaluate_windows_update_state(local, policy)

    assert derive_display_os_name(local, inference) == "Windows 11 Pro"
    assert result.local_consensus is not None
    assert result.local_consensus.raw_product_name == "Windows 10 Pro"
    assert "LOCAL_PRODUCT_NAME_STALE" in result.local_consensus.conflicts
