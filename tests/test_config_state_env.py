from __future__ import annotations

import win11_release_guard.config as config


def test_state_env_var_constant_names():
    assert config.STATE_DIR_ENV_VAR == "WIN11_RELEASE_GUARD_STATE_DIR"
    assert config.STATELESS_ENV_VAR == "WIN11_RELEASE_GUARD_STATELESS"
    assert config.CACHE_FILE_ENV_VAR == "WIN11_RELEASE_GUARD_CACHE_FILE"


def test_state_dir_from_env_reads_and_normalizes(monkeypatch):
    monkeypatch.setenv(config.STATE_DIR_ENV_VAR, "  /var/lib/w11rg  ")
    assert config.state_dir_from_env() == "/var/lib/w11rg"


def test_state_dir_from_env_blank_is_none(monkeypatch):
    monkeypatch.setenv(config.STATE_DIR_ENV_VAR, "   ")
    assert config.state_dir_from_env() is None


def test_state_dir_from_env_absent_is_none():
    assert config.state_dir_from_env() is None


def test_cache_file_from_env_reads_and_normalizes(monkeypatch):
    monkeypatch.setenv(config.CACHE_FILE_ENV_VAR, "  /tmp/policy.json ")
    assert config.cache_file_from_env() == "/tmp/policy.json"


def test_cache_file_from_env_absent_is_none():
    assert config.cache_file_from_env() is None


def test_stateless_from_env_truthy_values(monkeypatch):
    for value in ("1", "true", "TRUE", "Yes", "on"):
        monkeypatch.setenv(config.STATELESS_ENV_VAR, value)
        assert config.stateless_from_env() is True


def test_stateless_from_env_falsey_values(monkeypatch):
    for value in ("0", "false", "no", "off", "", "   "):
        monkeypatch.setenv(config.STATELESS_ENV_VAR, value)
        assert config.stateless_from_env() is False


def test_stateless_from_env_absent_is_false():
    assert config.stateless_from_env() is False


def test_new_names_are_exported():
    for name in (
        "STATE_DIR_ENV_VAR",
        "STATELESS_ENV_VAR",
        "CACHE_FILE_ENV_VAR",
        "normalize_state_dir",
        "state_dir_from_env",
        "stateless_from_env",
        "cache_file_from_env",
    ):
        assert name in config.__all__
