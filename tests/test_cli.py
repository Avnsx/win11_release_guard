import json
from dataclasses import replace

import win11_release_guard.api as api
import win11_release_guard.signing as signing
from win11_release_guard import __main__ as cli
from win11_release_guard.config import DEFAULT_POLICY_URL
from win11_release_guard.evaluator import evaluate_windows_update_state
from win11_release_guard.models import (
    BuildEvidenceSource,
    EvaluationResult,
    EvaluationStatus,
    InstalledBuildClassification,
    InstalledBuildOrigin,
    LocalWindowsState,
    ReleaseHistoryEntry,
    ReleasePolicy,
    ReleasePolicyEntry,
    SourceStatus,
)
from win11_release_guard.signing import sign_policy_bytes


TEST_PRIVATE_KEY = "krtF2muLgucP7JDVNKk2g+YQfz92c7xM49dzszxHxjs="
TEST_PUBLIC_KEY = "45dOpVuYqoPkldNrzORHM5ZZUxs6ILVcvpKxRFxsu3s="


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


def _policy_json() -> dict:
    return {
        "schema_version": 1,
        "generated_at_utc": "2026-05-28T00:00:00Z",
        "source_urls": [
            "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information"
        ],
        "current_versions": [
            {
                "version": "24H2",
                "build_family": 26100,
                "latest_build": "26100.8457",
                "servicing_option": "General Availability Channel",
            },
            {
                "version": "25H2",
                "build_family": 26200,
                "latest_build": "26200.8457",
                "baseline_build": "26200.8457",
                "servicing_option": "General Availability Channel",
            },
        ],
        "supported_build_families": {
            "26100": "24H2",
            "26200": "25H2",
        },
        "broad_target_existing_devices": {
            "version": "25H2",
            "build_family": 26200,
            "latest_build": "26200.8457",
            "baseline_build": "26200.8457",
            "servicing_option": "General Availability Channel",
        },
        "release_history": [
            {
                "release": "25H2",
                "build_family": 26200,
                "build": "26200.8457",
                "update_type_letter": "B",
                "servicing_option": "General Availability Channel",
                "availability_date": "2026-05-12",
            },
        ],
        "metadata": {"signature_status": "valid"},
    }


def _write_signed_json(path, data: dict) -> None:
    policy_bytes = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    signature = sign_policy_bytes(policy_bytes, TEST_PRIVATE_KEY)
    path.write_bytes(policy_bytes)
    path.with_name(path.name + ".sig").write_bytes(
        (json.dumps(signature, indent=2, sort_keys=True) + "\n").encode("utf-8")
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


def test_cli_pretty_build_origin_formatter_maps_all_known_classifications():
    result = EvaluationResult(status=EvaluationStatus.COMPLIANT, policy_source_kind="remote_json")

    assert cli._format_build_origin(
        InstalledBuildOrigin(
            classification=InstalledBuildClassification.B_RELEASE,
            evidence_source=BuildEvidenceSource.POLICY_RELEASE_HISTORY,
            kb_article="KB5089549",
        ),
        result,
    ) == "B release / policy_release_history / KB5089549"
    assert cli._format_build_origin(
        InstalledBuildOrigin(
            classification=InstalledBuildClassification.OUT_OF_BAND,
            evidence_source=BuildEvidenceSource.POLICY_RELEASE_HISTORY,
            kb_article="KB5089500",
        ),
        result,
    ) == "out-of-band / policy_release_history / KB5089500"
    assert cli._format_build_origin(
        InstalledBuildOrigin(
            classification=InstalledBuildClassification.UNKNOWN_OLDER_THAN_BASELINE,
            evidence_source=BuildEvidenceSource.UNKNOWN,
        ),
        result,
    ) == "older than policy baseline; exact KB/origin unknown."


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
        "https://example.invalid/windows-release-policy.json",
        "--explicit-target-release",
        "24H2",
    ])

    assert code == 0
    assert calls == [("https://example.invalid/windows-release-policy.json", "24H2")]


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
    monkeypatch.setenv("WIN11_RELEASE_GUARD_POLICY_URL", "https://env.example.invalid/windows-release-policy.json")
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
    assert calls == ["https://env.example.invalid/windows-release-policy.json"]


def test_cli_policy_url_overrides_env(monkeypatch):
    monkeypatch.setenv("WIN11_RELEASE_GUARD_POLICY_URL", "https://env.example.invalid/windows-release-policy.json")
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
        "https://cli.example.invalid/windows-release-policy.json",
    ])

    assert code == 0
    assert calls == ["https://cli.example.invalid/windows-release-policy.json"]


def test_cli_diagnose_config_reports_policy_url_source(monkeypatch, capsys):
    monkeypatch.delenv("WIN11_RELEASE_GUARD_POLICY_URL", raising=False)

    code = cli.main(["--diagnose-config"])
    default_payload = json.loads(capsys.readouterr().out)

    monkeypatch.setenv("WIN11_RELEASE_GUARD_POLICY_URL", "https://env.example.invalid/windows-release-policy.json")
    code_env = cli.main(["--diagnose-config"])
    env_payload = json.loads(capsys.readouterr().out)

    code_cli = cli.main([
        "--diagnose-config",
        "--policy-url",
        "https://cli.example.invalid/windows-release-policy.json",
    ])
    cli_payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert {
        "package_version",
        "effective_policy_url",
        "policy_url_source",
        "cache_file",
        "bundled_policy_present",
        "bundled_policy_generated_at_utc",
        "bundled_policy_signature_status",
        "trusted_public_key_fingerprint",
        "wua_default_enabled",
        "runtime_html_fallback_enabled",
        "source_check_required_for_green",
        "platform_summary",
    }.issubset(default_payload)
    assert default_payload["effective_policy_url"] == DEFAULT_POLICY_URL
    assert default_payload["policy_url"] == DEFAULT_POLICY_URL
    assert default_payload["policy_url_source"] == "default"
    assert default_payload["remote_fetch_enabled"] is True
    assert default_payload["live_remote_fetch_performed"] is False
    assert default_payload["bundled_policy_present"] is True
    assert default_payload["bundled_policy_signature_status"] == "valid"
    assert default_payload["trusted_public_key_fingerprint"].startswith("sha256:")
    assert default_payload["wua_default_enabled"] is False
    assert code_env == 0
    assert env_payload["policy_url"] == "https://env.example.invalid/windows-release-policy.json"
    assert env_payload["policy_url_source"] == "env"
    assert code_cli == 0
    assert cli_payload["policy_url"] == "https://cli.example.invalid/windows-release-policy.json"
    assert cli_payload["policy_url_source"] == "cli"


def test_cli_diagnose_config_does_not_check_source_by_default(monkeypatch, capsys):
    def fail_source_check(config):
        raise AssertionError("source check should not run")

    monkeypatch.setattr(cli, "_load_runtime_policy", fail_source_check)

    code = cli.main(["--diagnose-config"])

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["live_remote_fetch_performed"] is False
    assert "source_check" not in payload


def test_cli_self_test_validates_bundled_policy(capsys):
    code = cli.main(["--self-test"])

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["ok"] is True
    assert payload["checks"]["package_import"] == "ok"
    assert payload["checks"]["bundled_policy_loaded"] == "ok"
    assert payload["checks"]["bundled_policy_signature"] == "valid"
    assert payload["checks"]["policy_schema"] == "ok"
    assert payload["remote_fetch_performed"] is False
    assert payload["wua_probe_performed"] is False


def test_cli_self_test_fails_when_bundled_signature_validation_fails(monkeypatch, capsys):
    monkeypatch.setattr(signing, "verify_policy_signature", lambda *args, **kwargs: False)

    code = cli.main(["--self-test"])

    payload = json.loads(capsys.readouterr().out)
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert payload["ok"] is False
    assert payload["checks"]["bundled_policy_signature"] == "failed"
    assert payload["errors"]


def test_cli_policy_url_can_be_local_json_file(monkeypatch, tmp_path, capsys):
    policy_file = tmp_path / "windows-release-policy.json"
    _write_signed_json(policy_file, _policy_json())

    monkeypatch.setattr(
        api,
        "get_local_windows_state",
        lambda: LocalWindowsState(current_build=26200, full_build="26200.8457"),
    )
    monkeypatch.setattr(api, "query_wua_secondary", lambda target_release: None)

    code = cli.main([
        "--json",
        "--no-wua",
        "--policy-url",
        str(policy_file),
        "--cache-file",
        str(tmp_path / "cache.json"),
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["target"]["version"] == "25H2"
    assert payload["status"] == EvaluationStatus.COMPLIANT.value


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


def test_cli_argument_error_returns_10():
    code = cli.main(["--quality-policy", "invalid"])

    assert code == 10


def test_cli_help_returns_0(capsys):
    code = cli.main(["--help"])

    captured = capsys.readouterr()
    assert code == 0
    assert "usage: win-release-guard" in captured.out
    assert "Evaluate Windows 11 release compliance" in captured.out


def _german_result_with_wua_history() -> EvaluationResult:
    history = [
        {
            "title": f"2026-05 Vorschauupdate für Windows 11 Version 25H2 (KB50895{i:02d}) bösartiger",
            "classification": "quality_preview" if i < 4 else "defender_definition",
            "kb_ids": [f"KB50895{i:02d}"],
            "result_code": 2,
        }
        for i in range(50)
    ]
    return EvaluationResult(
        status=EvaluationStatus.COMPLIANT,
        summary="für Vorschauupdate bösartiger",
        action="No action required.",
        wua_secondary={
            "available": True,
            "service_enabled": True,
            "target_feature_update_offered": False,
            "target_release_in_history": False,
            "available_updates": [
                {
                    "title": "Security Intelligence-Update für bösartiger Software",
                    "classification": "defender_definition",
                }
            ],
            "relevant_os_updates": [
                {
                    "title": "Feature Update to Windows 11, version 25H2",
                    "classification": "feature_update",
                }
            ],
            "history": history,
            "noise_counts": {"defender_definition": 46},
            "warnings": ["Vorschauupdate für Test"],
            "errors": [],
        },
        target_feature_update_offer_expected=True,
        target_feature_update_offered=False,
    )


def test_cli_stdout_json_parses_and_escapes_unicode_by_default(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check_current_system", lambda config: _german_result_with_wua_history())

    code = cli.main(["--json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == 0
    assert payload["summary"] == "für Vorschauupdate bösartiger"
    assert "\\u00fc" in captured.out
    assert "für" not in captured.out


def test_cli_unicode_stdout_is_readable_utf8(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check_current_system", lambda config: _german_result_with_wua_history())

    code = cli.main(["--json", "--unicode"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == 0
    assert payload["summary"] == "für Vorschauupdate bösartiger"
    assert "für" in captured.out
    assert "Vorschauupdate" in captured.out
    assert "bösartiger" in captured.out


def test_cli_output_file_writes_utf8(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "check_current_system", lambda config: _german_result_with_wua_history())
    output = tmp_path / "release-check.json"

    code = cli.main(["--json", "--unicode", "--output", str(output)])

    raw = output.read_bytes()
    text = raw.decode("utf-8")
    payload = json.loads(text)
    assert code == 0
    assert payload["summary"] == "für Vorschauupdate bösartiger"
    assert "für" in text
    assert text.endswith("\n")


def test_cli_json_pretty(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check_current_system", lambda config: _german_result_with_wua_history())

    code = cli.main(["--json-pretty"])

    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["status"] == EvaluationStatus.COMPLIANT.value
    assert "\n  " in captured.out


def test_default_json_compacts_wua_history(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check_current_system", lambda config: _german_result_with_wua_history())

    code = cli.main(["--json"])

    payload = json.loads(capsys.readouterr().out)
    wua = payload["wua_secondary"]
    assert code == 0
    assert "history" not in wua
    assert len(wua["latest_relevant_history"]) == 3
    assert wua["counts_by_category"]["history_total"] == 50
    assert wua["raw_output_truncated"] is True


def test_include_raw_wua_history_includes_full_bounded_history(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check_current_system", lambda config: _german_result_with_wua_history())

    code = cli.main(["--json", "--include-raw-wua-history"])

    payload = json.loads(capsys.readouterr().out)
    wua = payload["wua_secondary"]
    assert code == 0
    assert len(wua["history"]) == 50
    assert wua["raw_output_truncated"] is False
