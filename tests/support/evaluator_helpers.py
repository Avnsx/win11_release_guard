"""Helpers shared by the test_evaluator test modules."""

from __future__ import annotations

from win11_release_guard.models import EditionScope, LocalWindowsState, ReleaseHistoryEntry, ReleasePolicy, ReleasePolicyEntry, ServicingChannel


def _policy_with_26h1_25h2_24h2() -> ReleasePolicy:
    return ReleasePolicy(
        current_versions=(
            ReleasePolicyEntry(
                version="26H1",
                build_family=28000,
                latest_build="28000.2113",
                servicing_option="General Availability Channel",
                metadata={
                    "special_release": True,
                    "new_devices_only": True,
                    "not_broad_target": True,
                },
            ),
            ReleasePolicyEntry(
                version="25H2",
                build_family=26200,
                latest_build="26200.8457",
                servicing_option="General Availability Channel",
                metadata={"home_pro_end": "2027-10-12"},
            ),
            ReleasePolicyEntry(
                version="24H2",
                build_family=26100,
                latest_build="26100.8457",
                servicing_option="General Availability Channel",
                metadata={"home_pro_end": "2026-10-13"},
            ),
        ),
        release_history=(
            ReleaseHistoryEntry(
                release="25H2",
                build_family=26200,
                build="26200.8457",
                servicing_option="General Availability Channel",
                update_type="2026-05 B",
                update_type_letter="B",
                availability_date="2026-05-12",
            ),
            ReleaseHistoryEntry(
                release="25H2",
                build_family=26200,
                build="26200.8510",
                servicing_option="General Availability Channel",
                update_type="2026-05 D Preview",
                update_type_letter="D",
                preview=True,
                availability_date="2026-05-28",
            ),
            ReleaseHistoryEntry(
                release="25H2",
                build_family=26200,
                build="26200.8460",
                servicing_option="General Availability Channel",
                update_type="2026-05 OOB",
                update_type_letter="OOB",
                out_of_band=True,
                availability_date="2026-05-16",
            ),
            ReleaseHistoryEntry(
                release="24H2",
                build_family=26100,
                build="26100.8457",
                servicing_option="General Availability Channel",
                update_type="2026-05 B",
                update_type_letter="B",
                availability_date="2026-05-12",
            ),
        ),
        special_releases=(
            ReleasePolicyEntry(
                version="26H1",
                build_family=28000,
                servicing_option="General Availability Channel",
                metadata={"not_broad_target": True},
            ),
        ),
        excluded_for_existing_devices=(
            ReleasePolicyEntry(
                version="26H1",
                build_family=28000,
                servicing_option="General Availability Channel",
                metadata={"not_broad_target": True},
            ),
        ),
    )


def _live_26200_8524_policy(*, include_preview_row: bool = True) -> ReleasePolicy:
    history = [
        ReleaseHistoryEntry(
            release="25H2",
            build_family=26200,
            build="26200.8457",
            servicing_option="General Availability Channel",
            update_type="2026-05 B",
            update_type_letter="B",
            availability_date="2026-05-12",
            kb_article="KB5089549",
        ),
    ]
    if include_preview_row:
        history.append(
            ReleaseHistoryEntry(
                release="25H2",
                build_family=26200,
                build="26200.8524",
                servicing_option="General Availability Channel",
                update_type="2026-05 D Preview",
                update_type_letter="D",
                preview=True,
                availability_date="2026-05-27",
                kb_article="KB5089573",
            )
        )
    return ReleasePolicy(
        broad_target_existing_devices=ReleasePolicyEntry(
            version="25H2",
            build_family=26200,
            latest_build="26200.8457",
            baseline_build="26200.8457",
            servicing_option="General Availability Channel",
        ),
        current_versions=(
            ReleasePolicyEntry(
                version="25H2",
                build_family=26200,
                latest_build="26200.8457",
                baseline_build="26200.8457",
                servicing_option="General Availability Channel",
            ),
        ),
        release_history=tuple(history),
        supported_build_families={26200: "25H2"},
    )


def _live_26200_8524_local(full_build: str = "26200.8524") -> LocalWindowsState:
    current_build, ubr = full_build.split(".", 1)
    return LocalWindowsState(
        product_name="Windows 10 Pro",
        edition_id="Professional",
        display_version="25H2",
        release_id="2009",
        current_build=int(current_build),
        ubr=int(ubr),
        full_build=full_build,
        installation_type="Client",
        inferred_release="25H2",
        edition_scope=EditionScope.HOME_PRO,
        servicing_channel=ServicingChannel.GENERAL_AVAILABILITY,
    )


PENDING_26H2_FIXTURE = "tests/fixtures/windows11-release-health-26h2-pending-b.html"


def _pending_26h2_policy() -> ReleasePolicy:
    from win11_release_guard.remote_policy import parse_windows11_release_health_html

    with open(PENDING_26H2_FIXTURE, encoding="utf-8") as handle:
        return parse_windows11_release_health_html(handle.read())


def _client_device(build_family: int, ubr: int, display_version: str | None) -> LocalWindowsState:
    return LocalWindowsState(
        current_build=build_family,
        ubr=ubr,
        full_build=f"{build_family}.{ubr}",
        build_family=build_family,
        display_version=display_version,
        is_windows_client=True,
        is_windows_11_or_newer=True,
        is_server=False,
    )
