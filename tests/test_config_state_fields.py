from __future__ import annotations

import dataclasses

import pytest

from win11_release_guard.config import ReleaseCheckerConfig, normalize_state_dir


def test_default_config_state_dir_is_none_not_the_string_none():
    config = ReleaseCheckerConfig()
    # The `if value is not None` guard is load-bearing (§10.3): without it the default None
    # normalises to the STRING "None", every default run takes the state_dir branch against a
    # relative directory literally called "None", and a default run can write into the CWD.
    assert config.state_dir is None
    assert config.stateless is False


def test_state_dir_is_trimmed_and_blank_becomes_none():
    assert ReleaseCheckerConfig(state_dir="  /var/lib/w11rg  ").state_dir == "/var/lib/w11rg"
    assert ReleaseCheckerConfig(state_dir="   ").state_dir is None
    assert ReleaseCheckerConfig(state_dir="").state_dir is None


def test_stateless_is_coerced_to_bool():
    assert ReleaseCheckerConfig(stateless=True).stateless is True
    assert ReleaseCheckerConfig(stateless=1).stateless is True
    assert ReleaseCheckerConfig(stateless=0).stateless is False
    assert ReleaseCheckerConfig(stateless="").stateless is False


def test_normalize_state_dir_copies_the_policy_url_idiom():
    assert normalize_state_dir(None) is None
    assert normalize_state_dir("  keep  ") == "keep"
    assert normalize_state_dir("   ") is None
    assert normalize_state_dir("") is None


def test_config_stays_frozen_with_the_new_fields():
    config = ReleaseCheckerConfig(state_dir="/x")
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.state_dir = "/y"
