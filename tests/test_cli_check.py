from __future__ import annotations

import json
from dataclasses import replace
from win11_release_guard import __main__ as cli
from win11_release_guard.config import DEFAULT_POLICY_URL
from win11_release_guard.evaluator import evaluate_windows_update_state
from win11_release_guard.models import EvaluationResult, EvaluationStatus, LocalWindowsState, ReleaseHistoryEntry, ReleasePolicy, ReleasePolicyEntry, SourceStatus


def _policy() -> ReleasePolicy:
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
                version="26H1",
                build_family=28000,
                latest_build="28000.2113",
                servicing_option="General Availability Channel",
                metadata={"special_release": True, "not_broad_target": True},
            ),
            ReleasePolicyEntry(
                version="25H2",
                build_family=26200,
                latest_build="26200.8457",
                servicing_option="General Availability Channel",
            ),
            ReleasePolicyEntry(
                version="24H2",
                build_family=26100,
                latest_build="26100.8457",
                servicing_option="General Availability Channel",
            ),
        ),
        release_history=(
            ReleaseHistoryEntry(
                release="25H2",
                build_family=26200,
                build="26200.8457",
                update_type_letter="B",
                servicing_option="General Availability Channel",
                availability_date="2026-05-12",
            ),
        ),
        special_releases=(
            ReleasePolicyEntry(
                version="26H1",
                build_family=28000,
                servicing_option="General Availability Channel",
                metadata={"special_release": True, "not_broad_target": True},
            ),
        ),
        excluded_for_existing_devices=(
            ReleasePolicyEntry(
                version="26H1",
                build_family=28000,
                servicing_option="General Availability Channel",
                metadata={"special_release": True, "not_broad_target": True},
            ),
        ),
        supported_build_families={26100: "24H2", 26200: "25H2", 28000: "26H1"},
        metadata={"signature_status": "valid"},
    )


def _patch_common(monkeypatch, local_state):
    def fake_check(config):
        wua_secondary = {"target_feature_update_offered": False} if config.enable_wua_probe else None
        return evaluate_windows_update_state(
            local_state,
            _policy(),
            quality_policy=config.quality_policy,
            explicit_target_release=config.explicit_target_release,
            wua_secondary=wua_secondary,
        )

    monkeypatch.setattr(cli, "check_current_system", fake_check)


def _live_preview_local() -> LocalWindowsState:
    return LocalWindowsState(
        product_name="Windows 10 Pro",
        edition_id="Professional",
        display_version="25H2",
        release_id="2009",
        current_build=26200,
        ubr=8524,
        full_build="26200.8524",
        installation_type="Client",
        inferred_release="25H2",
    )


def _live_preview_policy(*, include_preview_row: bool) -> ReleasePolicy:
    history = [
        ReleaseHistoryEntry(
            release="25H2",
            build_family=26200,
            build="26200.8457",
            update_type="2026-05 B",
            update_type_letter="B",
            servicing_option="General Availability Channel",
            availability_date="2026-05-12",
            kb_article="KB5089549",
        )
    ]
    if include_preview_row:
        history.append(
            ReleaseHistoryEntry(
                release="25H2",
                build_family=26200,
                build="26200.8524",
                update_type="2026-05 D Preview",
                update_type_letter="D",
                preview=True,
                servicing_option="General Availability Channel",
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


def _run_pretty_with_result(monkeypatch, result: EvaluationResult, capsys, *args: str) -> str:
    monkeypatch.setattr(cli, "check_current_system", lambda config: result)
    code = cli.main(["--pretty", *args])
    captured = capsys.readouterr()
    assert code == 0
    return captured.out


def test_cli_json_feature_update_required_exit_code(monkeypatch, capsys):
    _patch_common(
        monkeypatch,
        LocalWindowsState(current_build=26100, full_build="26100.8457"),
    )

    code = cli.main(["--json", "--no-wua"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == 1
    assert payload["status"] == EvaluationStatus.FEATURE_UPDATE_REQUIRED.value
    assert payload["local"]["current_build"] == 26100
    assert payload["target"]["version"] == "25H2"


def test_cli_pretty_compliant_exit_code(monkeypatch, capsys):
    _patch_common(
        monkeypatch,
        LocalWindowsState(current_build=26200, full_build="26200.8457"),
    )

    code = cli.main(["--pretty", "--no-wua"])

    captured = capsys.readouterr()
    assert code == 0
    assert "Status: COMPLIANT" in captured.out
    assert "Local: 25H2 / 26200.8457" in captured.out
    assert "Target: 25H2 / 26200.8457" in captured.out


def test_cli_pretty_shows_required_baseline_and_latest_observed(monkeypatch, capsys):
    base_policy = _policy()
    assert base_policy.broad_target_existing_devices is not None
    target = replace(base_policy.broad_target_existing_devices, latest_observed_build="26200.8524")
    current_versions = tuple(
        replace(entry, latest_observed_build="26200.8524")
        if entry.version == "25H2" and entry.build_family == 26200
        else entry
        for entry in base_policy.current_versions
    )
    policy = replace(
        base_policy,
        broad_target_existing_devices=target,
        current_versions=current_versions,
    )
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26200, full_build="26200.8457"),
        policy,
    )

    output = _run_pretty_with_result(monkeypatch, result, capsys, "--no-wua")

    assert "Target: 25H2 / 26200.8457" in output
    assert "Required baseline: 26200.8457" in output
    assert "Latest observed: 26200.8524" in output


def test_cli_pretty_unknown_newer_bundled_origin_is_explicit(monkeypatch, capsys):
    result = evaluate_windows_update_state(
        _live_preview_local(),
        _live_preview_policy(include_preview_row=False),
    )
    result = replace(
        result,
        source_status=SourceStatus.USING_BUNDLED_POLICY,
        is_source_check_complete=False,
        policy_source_kind="bundled",
    )

    output = _run_pretty_with_result(monkeypatch, result, capsys, "--no-wua")

    assert (
        "Build origin: newer than bundled baseline; exact KB/origin unknown "
        "because live policy/WUA evidence was not used."
    ) in output
    assert "unknown_newer_than_baseline / unknown" not in output


def test_cli_pretty_wua_preview_origin_uses_compact_preview_wording(monkeypatch, capsys):
    result = evaluate_windows_update_state(
        _live_preview_local(),
        _live_preview_policy(include_preview_row=False),
        wua_secondary={"history": [{"title": "2026-05 Vorschauupdate (KB5089573) (26200.8524)"}]},
    )

    def fake_check(config):
        assert config.enable_wua_probe is True
        return result

    monkeypatch.setattr(cli, "check_current_system", fake_check)
    code = cli.main(["--pretty", "--wua"])

    output = capsys.readouterr().out
    assert code == 0
    assert "Build origin: preview / wua_history / KB5089573" in output


def test_cli_pretty_policy_preview_origin_uses_compact_preview_wording(monkeypatch, capsys):
    result = evaluate_windows_update_state(
        _live_preview_local(),
        _live_preview_policy(include_preview_row=True),
    )

    output = _run_pretty_with_result(monkeypatch, result, capsys, "--no-wua")

    assert "Build origin: preview / policy_release_history / KB5089573" in output
    assert "Preview warning: COMPLIANT means the installed build is at or above the required B-release baseline" in output
    assert "but a preview build is installed" in output


def test_cli_pretty_warns_on_stale_cache_source(monkeypatch, capsys):
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26200, full_build="26200.8457"),
        _policy(),
    )
    result = replace(
        result,
        source_status=SourceStatus.USING_STALE_CACHE,
        is_source_check_complete=False,
        policy_source_kind="cache",
    )

    output = _run_pretty_with_result(monkeypatch, result, capsys, "--no-wua")

    assert "Source: USING_STALE_CACHE / cache" in output
    assert "using stale cache; treat this as degraded evidence, not production green" in output


def test_cli_pretty_shows_policy_age_when_available(monkeypatch, capsys):
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26200, full_build="26200.8457"),
        _policy(),
    )
    result = replace(
        result,
        source_status=SourceStatus.REMOTE_POLICY_OK,
        is_source_check_complete=True,
        policy_source_kind="remote_json",
        policy_age_hours=360.0,
        feed_age_days=15.0,
    )

    output = _run_pretty_with_result(monkeypatch, result, capsys, "--no-wua")

    assert "Policy age: 15 days (360 hours)" in output


def test_cli_pretty_prints_source_drift_warnings(monkeypatch, capsys):
    result = evaluate_windows_update_state(
        LocalWindowsState(current_build=26200, full_build="26200.8457"),
        _policy(),
    )
    result = replace(
        result,
        warnings=(
            "Source freshness warning: Servicing index has newer build/KB entries not present in Release Health.",
        ),
    )

    output = _run_pretty_with_result(monkeypatch, result, capsys, "--no-wua")

    assert "Source drift warnings:" in output
    assert "Servicing index has newer build/KB entries" in output


def test_cli_policy_url_and_explicit_target_are_used(monkeypatch):
    calls = []

    def fake_check(config):
        calls.append((config.policy_url, config.explicit_target_release))
        return evaluate_windows_update_state(
            LocalWindowsState(current_build=26100, full_build="26100.8457"),
            _policy(),
            explicit_target_release=config.explicit_target_release,
        )

    monkeypatch.setattr(cli, "check_current_system", fake_check)

    code = cli.main([
        "--json",
        "--no-wua",
        "--policy-url",
        ("https://example" + ".invalid/windows-release-policy.json"),
        "--explicit-target-release",
        "24H2",
    ])

    assert code == 0
    assert calls == [(("https://example" + ".invalid/windows-release-policy.json"), "24H2")]


def test_cli_default_policy_url_is_production_endpoint(monkeypatch):
    monkeypatch.delenv("WIN11_RELEASE_GUARD_POLICY_URL", raising=False)
    calls = []

    def fake_check(config):
        calls.append(config.policy_url)
        return evaluate_windows_update_state(
            LocalWindowsState(current_build=26200, full_build="26200.8457"),
            _policy(),
        )

    monkeypatch.setattr(cli, "check_current_system", fake_check)

    code = cli.main(["--json", "--no-wua"])

    assert code == 0
    assert calls == [DEFAULT_POLICY_URL]


def test_cli_env_policy_url_is_honored(monkeypatch):
    monkeypatch.setenv("WIN11_RELEASE_GUARD_POLICY_URL", ("https://env.example" + ".invalid/windows-release-policy.json"))
    calls = []

    def fake_check(config):
        calls.append(config.policy_url)
        return evaluate_windows_update_state(
            LocalWindowsState(current_build=26200, full_build="26200.8457"),
            _policy(),
        )

    monkeypatch.setattr(cli, "check_current_system", fake_check)

    code = cli.main(["--json", "--no-wua"])

    assert code == 0
    assert calls == [("https://env.example" + ".invalid/windows-release-policy.json")]


def test_cli_policy_url_overrides_env(monkeypatch):
    monkeypatch.setenv("WIN11_RELEASE_GUARD_POLICY_URL", ("https://env.example" + ".invalid/windows-release-policy.json"))
    calls = []

    def fake_check(config):
        calls.append(config.policy_url)
        return evaluate_windows_update_state(
            LocalWindowsState(current_build=26200, full_build="26200.8457"),
            _policy(),
        )

    monkeypatch.setattr(cli, "check_current_system", fake_check)

    code = cli.main([
        "--json",
        "--no-wua",
        "--policy-url",
        ("https://cli.example" + ".invalid/windows-release-policy.json"),
    ])

    assert code == 0
    assert calls == [("https://cli.example" + ".invalid/windows-release-policy.json")]


def test_cli_above_broad_target_exit_code(monkeypatch):
    _patch_common(
        monkeypatch,
        LocalWindowsState(current_build=28000, full_build="28000.1000", inferred_release="26H1"),
    )

    code = cli.main(["--json", "--no-wua"])

    assert code == 3


def test_cli_unknown_local_release_exit_code(monkeypatch):
    _patch_common(monkeypatch, LocalWindowsState())

    code = cli.main(["--json", "--no-wua"])

    assert code == 2


def test_cli_wua_disabled_by_default(monkeypatch):
    targets = []

    def fake_check(config):
        targets.append(config.enable_wua_probe)
        return evaluate_windows_update_state(
            LocalWindowsState(current_build=26100, full_build="26100.8457"),
            _policy(),
            wua_secondary={"target_feature_update_offered": False} if config.enable_wua_probe else None,
        )

    monkeypatch.setattr(cli, "check_current_system", fake_check)

    code = cli.main(["--json"])

    assert code == 1
    assert targets == [False]


def test_cli_wua_explicitly_enabled(monkeypatch):
    targets = []

    def fake_check(config):
        targets.append(
            (
                config.enable_wua_probe,
                config.wua_timeout_seconds,
                config.wua_max_history,
                config.wua_max_relevant_updates,
                config.event_log_max_events,
            )
        )
        return evaluate_windows_update_state(
            LocalWindowsState(current_build=26100, full_build="26100.8457"),
            _policy(),
            wua_secondary={"target_feature_update_offered": False} if config.enable_wua_probe else None,
        )

    monkeypatch.setattr(cli, "check_current_system", fake_check)

    code = cli.main([
        "--json",
        "--wua",
        "--wua-timeout-seconds",
        "3",
        "--wua-max-history",
        "7",
        "--wua-max-relevant-updates",
        "2",
        "--event-log-max-events",
        "11",
    ])

    assert code == 1
    assert targets == [(True, 3.0, 7, 2, 11)]
