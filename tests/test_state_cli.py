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
