import dataclasses
import hashlib
import struct
import zlib
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from win11_release_guard import state_store
from win11_release_guard.state_store import (
    MAX_STATE_BODY_BYTES,
    STATE_FORMAT_VERSION,
    STATE_HEADER_LEN,
    STATE_MAGIC,
    STATE_NAMESPACE,
    StateRead,
    StateScope,
    decode_state,
    derive_state_name,
    encode_state,
    staging_name,
    state_path_for,
    state_user_token,
    temp_dir_candidates,
)
from win11_release_guard.config import DEFAULT_TRUSTED_POLICY_PUBLIC_KEY
from win11_release_guard.json_utils import DEFAULT_MAX_SIGNATURE_BYTES


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


_HEADER = struct.Struct("<8sHII32s")

VECTOR_POLICY = b'{"schema":"w11rg-policy/1","generated_at_utc":"2026-05-28T00:00:00+00:00","current_versions":[]}'
VECTOR_SIGNATURE = bytes(range(64))


def _framed(*, policy_len, signature_len, digest, body, magic=STATE_MAGIC, version=1):
    return _HEADER.pack(magic, version, policy_len, signature_len, digest) + body


def test_state_magic_and_header_layout_constants():
    assert STATE_MAGIC == b"\xdb\xa7\x0d\x0aSTR1"
    assert STATE_HEADER_LEN == 50
    assert _HEADER.size == 50


def test_encode_decode_round_trip_with_and_without_signature():
    policy = b'{"schema":"w11rg","v":1}'
    signature = bytes(range(64))
    signed = decode_state(encode_state(policy, signature))
    assert signed.status == "usable"
    assert signed.policy_bytes == policy
    assert signed.signature_bytes == signature
    unsigned = decode_state(encode_state(policy, None))
    assert unsigned.status == "usable"
    assert unsigned.policy_bytes == policy
    assert unsigned.signature_bytes is None


def test_body_digest_is_over_the_uncompressed_body():
    policy = b'{"k":1}' * 200
    signature = bytes(range(64))
    raw = encode_state(policy, signature)
    stored_digest = _HEADER.unpack(raw[:STATE_HEADER_LEN])[4]
    assert stored_digest == hashlib.sha256(policy + signature).digest()
    assert stored_digest != hashlib.sha256(raw[STATE_HEADER_LEN:]).digest()


def test_decode_check1_foreign_when_magic_absent():
    read = decode_state(b"not-a-state-record" + b"\x00" * 40)
    assert read.status == "foreign"
    assert read.detail is None


def test_decode_check2_unusable_short_header():
    read = decode_state(STATE_MAGIC + b"\x00" * 9)  # 17 bytes: magic present, len < 50
    assert read.status == "unusable"
    assert read.detail == "short header"


def test_decode_check3_unusable_wrong_format_version():
    raw = _framed(version=2, policy_len=1, signature_len=0, digest=b"\x00" * 32, body=b"whatever")
    read = decode_state(raw)
    assert read.status == "unusable"
    assert read.detail == "format version 2"


def test_decode_check4_unusable_declared_length_out_of_range():
    empty = _framed(policy_len=0, signature_len=0, digest=b"\x00" * 32, body=b"")
    huge_policy = _framed(policy_len=MAX_STATE_BODY_BYTES + 1, signature_len=0, digest=b"\x00" * 32, body=b"")
    huge_sig = _framed(policy_len=1, signature_len=DEFAULT_MAX_SIGNATURE_BYTES + 1, digest=b"\x00" * 32, body=b"")
    for raw in (empty, huge_policy, huge_sig):
        read = decode_state(raw)
        assert read.status == "unusable"
        assert read.detail == "declared length out of range"


def test_decode_check5_unusable_inflate_failed():
    raw = _framed(policy_len=4, signature_len=0, digest=b"\x00" * 32, body=b"\xff" * 8)
    read = decode_state(raw)
    assert read.status == "unusable"
    assert read.detail == "inflate failed"


def test_decode_check6_unusable_stream_boundary_mismatch_on_trailing_bytes():
    healthy = encode_state(b"POLICYDATA", b"SIG")
    read = decode_state(healthy + b"EXTRA-TRAILING-BYTES")
    assert read.status == "unusable"
    assert read.detail == "stream boundary mismatch"


def test_decode_check7_unusable_length_mismatch():
    body = zlib.compress(b"AB", 9)  # inflates cleanly to 2 bytes, eof True, no tail
    raw = _framed(policy_len=2, signature_len=1, digest=hashlib.sha256(b"ABX").digest(), body=body)
    read = decode_state(raw)
    assert read.status == "unusable"
    assert read.detail == "length mismatch"


def test_decode_check8_unusable_digest_mismatch():
    policy, signature = b"POLICYDATA", b"SIGDATA"
    body = zlib.compress(policy + signature, 9)
    raw = _framed(policy_len=len(policy), signature_len=len(signature), digest=bytes(32), body=body)
    read = decode_state(raw)
    assert read.status == "unusable"
    assert read.detail == "digest mismatch"


def test_decode_check9_usable_returns_exact_bytes():
    policy, signature = b"POLICYDATA", b"SIGDATA"
    read = decode_state(encode_state(policy, signature))
    assert read.status == "usable"
    assert read.policy_bytes == policy
    assert read.signature_bytes == signature
    assert read.detail is None


def test_decode_pins_checked_in_vector():
    raw = (Path(__file__).parent / "fixtures" / "state_container_v1.bin").read_bytes()
    read = decode_state(raw)
    assert read.status == "usable"
    assert read.policy_bytes == VECTOR_POLICY
    assert read.signature_bytes == VECTOR_SIGNATURE
