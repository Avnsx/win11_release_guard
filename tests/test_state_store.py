import dataclasses
from pathlib import PurePosixPath, PureWindowsPath

import pytest

from win11_release_guard import state_store
from win11_release_guard.state_store import (
    STATE_FORMAT_VERSION,
    STATE_NAMESPACE,
    StateScope,
    derive_state_name,
    staging_name,
    state_path_for,
    state_user_token,
    temp_dir_candidates,
)
from win11_release_guard.config import DEFAULT_TRUSTED_POLICY_PUBLIC_KEY


def test_state_namespace_and_version_constants():
    assert STATE_NAMESPACE == b"w11rg-state"
    assert STATE_FORMAT_VERSION == 1


def test_temp_dir_candidates_posix_orders_env_then_system_and_dedupes():
    env = {"TMPDIR": "/tmp", "TEMP": "/var/tmp", "TMP": "/tmp"}
    assert temp_dir_candidates("posix", env) == ("/tmp", "/var/tmp")


def test_temp_dir_candidates_drops_empty_and_relative():
    env = {"TMPDIR": "  ", "TEMP": "relative/dir", "TMP": "/real/tmp"}
    assert temp_dir_candidates("posix", env) == ("/real/tmp", "/tmp", "/var/tmp")


def test_temp_dir_candidates_nt_appends_systemroot_temp():
    env = {"TEMP": r"C:\Users\me\AppData\Local\Temp", "SystemRoot": r"C:\Windows"}
    result = temp_dir_candidates("nt", env)
    assert result[0] == r"C:\Users\me\AppData\Local\Temp"
    assert result[-1] == r"C:\Windows\Temp"


def test_temp_dir_candidates_nt_drops_rootless_posix_path():
    env = {"TMPDIR": "/tmp", "TEMP": r"D:\Temp"}
    assert temp_dir_candidates("nt", env) == (r"D:\Temp",)


def test_state_user_token_nt_joins_domain_and_user():
    assert state_user_token("nt", {"USERDOMAIN": "CORP", "USERNAME": "alice"}, None) == "CORP\\alice"


def test_state_user_token_nt_missing_vars_yield_empty_sides():
    assert state_user_token("nt", {}, None) == "\\"


def test_state_user_token_posix_uses_uid_string():
    assert state_user_token("posix", {}, 1000) == "1000"
    assert state_user_token("posix", {}, None) == "None"


def _name_kwargs(**overrides):
    base = dict(
        policy_url="https://example.test/policy.json",
        os_name="posix",
        env={"USERDOMAIN": "", "USERNAME": ""},
        uid=1000,
        trusted_public_key="KEYA",
        allow_unsigned_policy=False,
    )
    base.update(overrides)
    return base


def test_derive_state_name_is_deterministic_and_well_formed():
    kwargs = _name_kwargs()
    name = derive_state_name(**kwargs)
    assert name == derive_state_name(**kwargs)
    assert name.startswith("tmp")
    assert name.endswith(".tmp")
    assert len(name) == len("tmp") + 16 + len(".tmp")


def test_derive_state_name_changes_with_each_digest_component():
    base = derive_state_name(**_name_kwargs())
    assert derive_state_name(**_name_kwargs(policy_url="https://other.test/p.json")) != base
    assert derive_state_name(**_name_kwargs(uid=1001)) != base
    assert derive_state_name(**_name_kwargs(trusted_public_key="KEYB")) != base
    assert derive_state_name(**_name_kwargs(allow_unsigned_policy=True)) != base
    assert derive_state_name(**_name_kwargs(format_version=2)) != base


def test_derive_state_name_key_layering_none_matches_empty_but_differs_from_default():
    none_name = derive_state_name(**_name_kwargs(trusted_public_key=None))
    empty_name = derive_state_name(**_name_kwargs(trusted_public_key=""))
    default_name = derive_state_name(**_name_kwargs(trusted_public_key=DEFAULT_TRUSTED_POLICY_PUBLIC_KEY))
    assert none_name == empty_name
    assert none_name != default_name


def test_staging_name_appends_suffix_and_is_injective():
    assert staging_name("report") == "report.staging.tmp"
    assert staging_name("report.tmp") == "report.tmp.staging.tmp"
    assert staging_name("report") != staging_name("report.tmp")
    container = "tmp0123456789abcdef.tmp"
    assert staging_name(container) == "tmp0123456789abcdef.tmp.staging.tmp"
    assert staging_name(container).endswith(".tmp")


def test_state_path_for_returns_flavoured_purepath():
    nt = state_path_for("nt", r"C:\Windows\Temp", "tmpdeadbeefdeadbeef.tmp")
    posix = state_path_for("posix", "/tmp", "tmpdeadbeefdeadbeef.tmp")
    assert isinstance(nt, PureWindowsPath)
    assert isinstance(posix, PurePosixPath)
    assert nt == PureWindowsPath(r"C:\Windows\Temp\tmpdeadbeefdeadbeef.tmp")
    assert posix == PurePosixPath("/tmp/tmpdeadbeefdeadbeef.tmp")
    assert nt.name == "tmpdeadbeefdeadbeef.tmp"


def test_state_scope_is_frozen_and_hashable():
    scope = StateScope(
        layout="container",
        path=PurePosixPath("/tmp/tmpdeadbeefdeadbeef.tmp"),
        signature_path=None,
        staging_path=PurePosixPath("/tmp/tmpdeadbeefdeadbeef.tmp.staging.tmp"),
        source="default_temp",
    )
    assert scope.layout == "container"
    assert scope.source == "default_temp"
    assert scope.signature_path is None
    assert hash(scope) == hash(scope)
    with pytest.raises(dataclasses.FrozenInstanceError):
        scope.layout = "none"
