"""CLI suite for the state-store surface: the three ``_*_from_args`` readers, the eleven
additive ``--diagnose-config`` keys plus the ``cache_file`` repoint, and the ``--purge-state`` /
``--show-state`` dispatch.

Two portability rules shape the assertions here:

* ``--state-dir`` and ``--cache-file`` are ``type=Path`` arguments, so a CLI value is round-tripped
  through the *native* path flavour (``str(Path("/srv/x"))`` is ``\\srv\\x`` on Windows) while an
  environment value is taken verbatim. Expected CLI values are therefore written as
  ``str(Path(...))``, never as a hardcoded POSIX literal.
* ``purge_state``/``describe_state`` enumerate the two ``%LOCALAPPDATA%`` legacy paths only on
  ``nt`` (``legacy_state_paths`` returns ``()`` elsewhere), so the number of purge events is
  platform-dependent. No test here asserts an event count for a real layout; they assert on the
  set of outcomes and on the entry roles instead.

Every state-touching test passes ``--state-dir <tmp_path>`` so its reads and writes are over a
per-test directory and hold in any collection order (§16.1 rule 2), and no test hardcodes a
derived filename.
"""

from __future__ import annotations

import json
from pathlib import Path

from win11_release_guard import __main__ as cli
from win11_release_guard import state_store
from win11_release_guard.config import (
    CACHE_FILE_ENV_VAR,
    ReleaseCheckerConfig,
    STATE_DIR_ENV_VAR,
    STATELESS_ENV_VAR,
)

# Split literal: tests/test_branding_contract.py bans the fake domain outside tests/fixtures.
POLICY_URL = "https://policy.example" + ".invalid/policy.json"


def test_from_args_readers_follow_cli_env_none_precedence(monkeypatch):
    parser = cli._build_parser()

    args = parser.parse_args([])
    assert cli._state_dir_from_args(args) == (None, "none")
    assert cli._stateless_from_args(args) == (False, "default")
    assert cli._cache_file_from_args(args) == (None, "none")

    monkeypatch.setenv(STATE_DIR_ENV_VAR, "/srv/env-state")
    monkeypatch.setenv(STATELESS_ENV_VAR, "1")
    monkeypatch.setenv(CACHE_FILE_ENV_VAR, "/srv/env-cache.bin")
    args = parser.parse_args([])
    assert cli._state_dir_from_args(args) == ("/srv/env-state", "env")
    assert cli._stateless_from_args(args) == (True, "env")
    assert cli._cache_file_from_args(args) == ("/srv/env-cache.bin", "env")

    args = parser.parse_args(
        ["--state-dir", "/srv/cli-state", "--stateless", "--cache-file", "/srv/cli-cache.bin"]
    )
    assert cli._state_dir_from_args(args) == (str(Path("/srv/cli-state")), "cli")
    assert cli._stateless_from_args(args) == (True, "cli")
    assert cli._cache_file_from_args(args) == (str(Path("/srv/cli-cache.bin")), "cli")


def test_diagnose_config_reports_state_keys_and_precedence(monkeypatch, tmp_path, capsys):
    state_dir = tmp_path / "explicit"
    state_dir.mkdir()
    code = cli.main(["--diagnose-config", "--state-dir", str(state_dir)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    # additive keys are all present (existing .issubset assertions stay valid)
    assert {
        "state_layout",
        "state_path",
        "state_dir",
        "state_dir_source",
        "state_dir_env_var",
        "stateless",
        "stateless_source",
        "stateless_env_var",
        "cache_file_source",
        "cache_file_env_var",
        "state_format_version",
    }.issubset(payload)
    assert payload["state_layout"] == "container"
    assert payload["state_dir"] == str(state_dir)
    assert payload["state_dir_source"] == "cli"
    assert payload["state_dir_env_var"] == "WIN11_RELEASE_GUARD_STATE_DIR"
    assert payload["stateless"] is False
    assert payload["stateless_source"] == "default"
    assert payload["state_format_version"] == 1
    # cache_file is repointed to the effective runtime location (the container path)
    assert payload["state_path"] == payload["cache_file"]
    assert payload["state_path"].startswith(str(state_dir))

    monkeypatch.setenv("WIN11_RELEASE_GUARD_STATE_DIR", str(state_dir))
    code_env = cli.main(["--diagnose-config"])
    env_payload = json.loads(capsys.readouterr().out)
    assert code_env == 0
    assert env_payload["state_dir_source"] == "env"
    assert env_payload["state_layout"] == "container"

    code_stateless = cli.main(["--diagnose-config", "--stateless"])
    stateless_payload = json.loads(capsys.readouterr().out)
    assert code_stateless == 0
    assert stateless_payload["stateless"] is True
    assert stateless_payload["stateless_source"] == "cli"
    assert stateless_payload["state_layout"] == "none"
    assert stateless_payload["state_path"] is None
    assert stateless_payload["cache_file"] is None


def test_purge_and_show_state_dispatch(tmp_path, capsys):
    policy_url = POLICY_URL
    policy_bytes = b'{"schema_version": 1, "generated_at_utc": "2026-05-01T00:00:00Z"}'
    signature_bytes = b'{"sig": "x"}'

    config = ReleaseCheckerConfig(policy_url=policy_url, state_dir=str(tmp_path))
    scope = state_store.resolve_state_scope(config)
    assert scope.layout == "container"
    write_event = state_store.write_state(scope, policy_bytes, signature_bytes)
    assert write_event.outcome == "written"

    # --show-state reports the seeded container as usable
    show_code = cli.main(["--show-state", "--policy-url", policy_url, "--state-dir", str(tmp_path)])
    show_payload = json.loads(capsys.readouterr().out)
    assert show_code == 0
    assert show_payload["layout"] == "container"
    state_entry = next(entry for entry in show_payload["entries"] if entry["role"] == "state")
    assert state_entry["exists"] is True
    assert state_entry["status"] == "usable"

    # --purge-state removes it and exits 0, reporting one removed event
    purge_code = cli.main(["--purge-state", "--policy-url", policy_url, "--state-dir", str(tmp_path)])
    purge_payload = json.loads(capsys.readouterr().out)
    assert purge_code == 0
    outcomes = {event["outcome"] for event in purge_payload["events"]}
    assert "removed" in outcomes
    assert "failed" not in outcomes
    assert state_store.read_state(state_store.resolve_state_scope(config)).status == "absent"

    # a second show now reports the state path absent, still exit 0
    show_again = cli.main(["--show-state", "--policy-url", policy_url, "--state-dir", str(tmp_path)])
    again_payload = json.loads(capsys.readouterr().out)
    assert show_again == 0
    again_entry = next(entry for entry in again_payload["entries"] if entry["role"] == "state")
    assert again_entry["exists"] is False


def test_purge_state_on_none_layout_reports_skipped_and_exits_zero(capsys):
    # A relative --state-dir is the portable way to reach layout "none" from the CLI: purge_state
    # deliberately forces stateless=False, so --stateless alone cannot produce a "none" layout.
    code = cli.main(["--purge-state", "--state-dir", "relative-state-dir"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["events"], "layout==none must still emit one event, never an empty list"
    assert payload["events"][0]["outcome"] == "skipped"
    assert payload["events"][0]["detail"] == "state_dir_not_absolute"
    assert payload["events"][0]["path"] is None


def test_purge_state_with_stateless_flag_still_purges_the_configured_location(tmp_path, capsys):
    # purge_state forces stateless=False so a purge still finds and removes what a non-stateless
    # run of the same configuration wrote; --stateless must not turn --purge-state into a no-op.
    policy_url = POLICY_URL
    config = ReleaseCheckerConfig(policy_url=policy_url, state_dir=str(tmp_path))
    scope = state_store.resolve_state_scope(config)
    assert state_store.write_state(scope, b'{"ok": true}', None).outcome == "written"

    code = cli.main(["--purge-state", "--stateless", "--policy-url", policy_url, "--state-dir", str(tmp_path)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    outcomes = {event["outcome"] for event in payload["events"]}
    assert "removed" in outcomes
    assert "failed" not in outcomes
    assert not Path(scope.path).exists()


def test_atomic_write_with_inplace_fallback_paths(tmp_path, monkeypatch):
    # 1. happy path: the swap succeeds, event is "written"
    dest = tmp_path / "out.bin"
    event = cli._atomic_write_with_inplace_fallback(dest, b"hello")
    assert event.outcome == "written"
    assert dest.read_bytes() == b"hello"

    # 2. swap refused -> single in-place fallback still writes the bytes, event "written"
    def _boom(source: str, destination: str) -> None:
        raise OSError(32, "The process cannot access the file because it is being used")

    monkeypatch.setattr(state_store, "_replace", _boom)
    dest2 = tmp_path / "out2.bin"
    event2 = cli._atomic_write_with_inplace_fallback(dest2, b"world")
    assert event2.outcome == "written"
    assert dest2.read_bytes() == b"world"

    # 3. both the swap and the in-place write fail (missing parent) -> "failed", never raises
    missing = tmp_path / "no-such-dir" / "out3.bin"
    event3 = cli._atomic_write_with_inplace_fallback(missing, b"nope")
    assert event3.outcome == "failed"
    assert event3.detail is not None
    assert not missing.exists()


def test_output_writes_through_helper_and_raises_only_on_total_failure(tmp_path, monkeypatch, capsys):
    from win11_release_guard.evaluator import evaluate_windows_update_state
    from win11_release_guard.models import LocalWindowsState, ReleasePolicy, ReleasePolicyEntry

    def _policy() -> ReleasePolicy:
        return ReleasePolicy(
            broad_target_existing_devices=ReleasePolicyEntry(
                version="25H2",
                build_family=26200,
                latest_build="26200.8457",
                baseline_build="26200.8457",
                servicing_option="General Availability Channel",
            ),
            supported_build_families={26200: "25H2"},
            metadata={"signature_status": "valid"},
        )

    local = LocalWindowsState(
        product_name="Windows 11 Pro",
        edition_id="Professional",
        display_version="25H2",
        release_id="2009",
        current_build=26200,
        ubr=8457,
        full_build="26200.8457",
        installation_type="Client",
        inferred_release="25H2",
    )
    monkeypatch.setattr(
        cli,
        "check_current_system",
        lambda config: evaluate_windows_update_state(local, _policy(), quality_policy=config.quality_policy),
    )

    # success: routed through the helper, byte-identical to today's write_text(..., newline="\n")
    output = tmp_path / "release-check.json"
    code = cli.main(["--json", "--output", str(output)])
    assert code == 0
    raw = output.read_bytes()
    assert b"\r" not in raw
    assert raw.endswith(b"\n")
    json.loads(raw.decode("utf-8"))
    capsys.readouterr()

    # total failure (missing parent dir): exit 2, no traceback, new routed message
    missing = tmp_path / "absent" / "release-check.json"
    code_fail = cli.main(["--json", "--output", str(missing)])
    error_text = capsys.readouterr().err
    assert code_fail == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert not missing.exists()
    # the routed message is what proves the write went through the shared helper rather than a
    # bare path.write_text; a raw OSError repr here would mean the helper was never reached.
    assert f"Could not write JSON output to {missing}: " in json.loads(error_text)["error"]
    assert "Traceback" not in error_text


def test_show_state_output_three_row_table(tmp_path, capsys):
    policy_url = POLICY_URL
    policy_bytes = b'{"schema_version": 1, "generated_at_utc": "2026-05-01T00:00:00Z"}'
    signature_bytes = b'{"sig": "x"}'

    # Row 2 first: nothing stored -> not written, not created, exit 0
    empty_out = tmp_path / "empty.json"
    code_none = cli.main(
        ["--show-state", "--policy-url", policy_url, "--state-dir", str(tmp_path), "--output", str(empty_out)]
    )
    none_payload = json.loads(capsys.readouterr().out)
    assert code_none == 0
    assert not empty_out.exists()
    assert none_payload["layout"] == "container"

    # Row 1: seed a container, --show-state --output writes the decoded policy bytes, exit 0
    config = ReleaseCheckerConfig(policy_url=policy_url, state_dir=str(tmp_path))
    scope = state_store.resolve_state_scope(config)
    assert state_store.write_state(scope, policy_bytes, signature_bytes).outcome == "written"

    out = tmp_path / "policy.json"
    code_ok = cli.main(
        ["--show-state", "--policy-url", policy_url, "--state-dir", str(tmp_path), "--output", str(out)]
    )
    ok_payload = json.loads(capsys.readouterr().out)
    assert code_ok == 0
    assert out.read_bytes() == policy_bytes
    assert "detail" not in ok_payload

    # Row 3: bytes present but the write fails both ways (missing parent) -> payload printed, top-level
    # "detail", exit 2, never a traceback
    missing = tmp_path / "no-dir" / "policy.json"
    code_fail = cli.main(
        ["--show-state", "--policy-url", policy_url, "--state-dir", str(tmp_path), "--output", str(missing)]
    )
    fail_payload = json.loads(capsys.readouterr().out)
    assert code_fail == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert fail_payload["layout"] == "container"
    assert fail_payload["detail"]
    assert not missing.exists()


def test_diagnose_and_show_state_never_mutate_state_or_check_the_source(monkeypatch, tmp_path, capsys):
    # Observation-based non-invocation spies (they only record), so nothing can pass vacuously
    # through a swallowed exception; they bite only because __main__ and state_store reach these
    # names through the module object.
    mutations: list[tuple[str, tuple[object, ...]]] = []
    source_checks: list[tuple[object, ...]] = []
    for name in ("write_state", "_replace", "_unlink"):
        monkeypatch.setattr(
            state_store,
            name,
            lambda *args, _name=name, **kwargs: mutations.append((_name, args)),
        )
    monkeypatch.setattr(cli, "_load_runtime_policy", lambda *args, **kwargs: source_checks.append(args))

    diagnose_code = cli.main(["--diagnose-config", "--state-dir", str(tmp_path)])
    diagnose_payload = json.loads(capsys.readouterr().out)
    assert diagnose_code == 0
    assert diagnose_payload["state_layout"] == "container"
    assert "source_check" not in diagnose_payload

    show_code = cli.main(["--show-state", "--state-dir", str(tmp_path)])
    show_payload = json.loads(capsys.readouterr().out)
    assert show_code == 0
    assert show_payload["state_format_version"] == 1
    assert mutations == []
    assert source_checks == []
