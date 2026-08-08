import dataclasses
import hashlib
import struct
import tracemalloc
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
    plan_state_scope,
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


def test_derive_state_name_pins_the_six_component_digest():
    """The name is sha256 over exactly six components joined with a single NUL byte,
    truncated to sixteen hex characters.

    The expected value is rebuilt here from the six components in their documented order
    rather than pasted from a run of the code, because a pasted literal would pin whatever
    the code currently does. Permuting the order or changing the separator keeps every
    other test in this file green — the name stays deterministic and stays sensitive to
    each input — while silently renaming the derived file on every deployment, orphaning
    every record already on disk. A deliberate ``STATE_FORMAT_VERSION`` bump has the same
    effect and must update this vector along with it.
    """
    policy_url = "https://example.test/policy.json"
    material = b"\x00".join((
        b"w11rg-state",                    # 1. STATE_NAMESPACE, digest input only
        b"1",                              # 2. str(format_version), ascii
        policy_url.encode("utf-8"),        # 3. the policy url
        b"1000",                           # 4. state_user_token: str(uid) off nt
        hashlib.sha256(b"KEYA").digest(),  # 5. sha256 OF the trusted key, not the key
        b"False",                          # 6. str(bool(allow_unsigned_policy))
    ))
    expected = "tmp" + hashlib.sha256(material).hexdigest()[:16] + ".tmp"
    assert derive_state_name(
        policy_url=policy_url,
        os_name="posix",
        env={},
        uid=1000,
        trusted_public_key="KEYA",
        allow_unsigned_policy=False,
    ) == expected


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


def test_decode_check1_foreign_when_only_the_leading_four_magic_bytes_match():
    """The magic comparison is eight bytes wide, and nothing else in the record can
    stand in for the other four.

    Everything from byte 8 onwards here is a perfectly healthy record, so a comparison
    narrowed to ``raw[:4] != STATE_MAGIC[:4]`` reports this file ``usable`` — it would
    hand a squatter's policy to the caller, and, because ``foreign`` is the one status the
    deletion rule never acts on, it also promotes an untouchable file into a deletable one.
    """
    healthy = encode_state(b"POLICYDATA", b"SIG")
    raw = STATE_MAGIC[:4] + b"str2" + healthy[8:]
    assert raw[:4] == STATE_MAGIC[:4] and raw[4:8] != STATE_MAGIC[4:8]  # premise
    read = decode_state(raw)
    assert read.status == "foreign"
    assert read.detail is None
    assert read.policy_bytes is None


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


def test_decode_check5_bounded_inflate_refuses_a_zip_bomb_without_inflating_it():
    """``max_length=policy_len + signature_len`` is the only thing standing between a
    65 KB record and 64 MiB of resident memory, on a tool built to run unattended under
    an RMM agent.

    The status alone cannot pin it: delete ``max_length`` and the full 64 MiB still
    inflates, then fails check 7 on length and comes back ``unusable`` all the same. So
    the assertion that carries this test is the ``tracemalloc`` peak — bounded, the decode
    allocates well under a megabyte; unbounded it allocates over a hundred.
    """
    bomb = zlib.compress(b"\x00" * (64 * 1024 * 1024), 9)
    raw = _framed(
        policy_len=64,
        signature_len=0,
        digest=hashlib.sha256(b"\x00" * 64).digest(),
        body=bomb,
    )
    assert len(raw) < 256 * 1024  # premise: the record itself is small

    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        read = decode_state(raw)
        peak_bytes = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert read.status == "unusable"
    assert peak_bytes < 4 * 1024 * 1024, f"decode allocated {peak_bytes} bytes for a {len(raw)}-byte record"


def test_decode_check6_unusable_stream_boundary_mismatch_on_trailing_bytes():
    healthy = encode_state(b"POLICYDATA", b"SIG")
    read = decode_state(healthy + b"EXTRA-TRAILING-BYTES")
    assert read.status == "unusable"
    assert read.detail == "stream boundary mismatch"


def test_decode_check6_unusable_when_the_zlib_stream_never_ends():
    """The ``not decompressor.eof`` arm of check 6, which the trailing-bytes test above
    cannot reach: that one trips on ``unused_data``.

    A truncated write leaves a complete deflate stream with its four-byte adler32 trailer
    missing. Every other check passes — the declared lengths are exact, so no input is
    left unconsumed and no bound is hit, and the digest is the real one — so with this arm
    removed the record decodes ``usable`` and a half-written file is served as policy.
    """
    policy, signature = b"POLICYDATA" * 8, b"SIGDATA"
    body = zlib.compress(policy + signature, 9)
    raw = _framed(
        policy_len=len(policy),
        signature_len=len(signature),
        digest=hashlib.sha256(policy + signature).digest(),
        body=body[:-4],  # the adler32 trailer, and only that, is chopped off
    )
    read = decode_state(raw)
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


def _plan(**overrides):
    base = dict(
        os_name="posix",
        env={"USERDOMAIN": "", "USERNAME": ""},
        temp_dir="/tmp",
        uid=1000,
        policy_url="https://example.test/policy.json",
        trusted_public_key="KEYA",
        allow_unsigned_policy=False,
        cache_file=None,
        state_dir=None,
        stateless=False,
    )
    base.update(overrides)
    return plan_state_scope(**base)


def test_plan_state_scope_stateless_beats_every_other_input():
    scope = _plan(stateless=True, cache_file="/c.json", state_dir="/d", temp_dir="/tmp")
    assert scope == StateScope("none", None, None, None, "stateless")


def test_plan_state_scope_cache_file_beats_state_dir_and_uses_dot_sig_suffix():
    scope = _plan(cache_file="/srv/cache.json", state_dir="/srv/state", temp_dir="/tmp")
    assert scope.layout == "legacy_pair"
    assert scope.source == "cache_file"
    assert scope.path == PurePosixPath("/srv/cache.json")
    # .sig via with_name(name + ".sig") -> cache.json.sig, NOT with_suffix -> cache.sig.
    assert scope.signature_path == PurePosixPath("/srv/cache.json.sig")
    assert scope.staging_path == PurePosixPath("/srv/cache.json.staging.tmp")


def test_plan_state_scope_state_dir_beats_default_temp():
    scope = _plan(state_dir="/srv/state", temp_dir="/tmp")
    assert scope.layout == "container"
    assert scope.source == "state_dir"
    assert scope.path is not None
    assert scope.path.parent == PurePosixPath("/srv/state")
    assert scope.signature_path is None
    assert scope.staging_path == scope.path.with_name(scope.path.name + ".staging.tmp")


def test_plan_state_scope_default_temp_when_only_temp_dir():
    scope = _plan(temp_dir="/tmp")
    assert scope.layout == "container"
    assert scope.source == "default_temp"
    assert scope.path.parent == PurePosixPath("/tmp")


def test_plan_state_scope_no_temp_dir_and_no_state_dir_is_none():
    scope = _plan(temp_dir=None)
    assert scope == StateScope("none", None, None, None, "no_temp_dir")


def test_plan_state_scope_non_absolute_state_dir_refused_on_both_flavours():
    posix = _plan(os_name="posix", state_dir="relative/dir", temp_dir="/tmp")
    assert (posix.layout, posix.source) == ("none", "state_dir_not_absolute")
    assert posix.path is None and posix.staging_path is None
    nt = _plan(os_name="nt", env={}, state_dir="relative\\dir", temp_dir=r"C:\Temp")
    assert (nt.layout, nt.source) == ("none", "state_dir_not_absolute")


def test_plan_state_scope_unnameable_cache_file_is_path_not_nameable_both_flavours():
    for bad in (".", "/"):
        scope = _plan(cache_file=bad, temp_dir="/tmp")
        assert (scope.layout, scope.source) == ("none", "path_not_nameable")
    for bad in (".", "\\", "C:\\"):
        scope = _plan(os_name="nt", env={}, cache_file=bad, temp_dir=r"C:\Temp")
        assert (scope.layout, scope.source) == ("none", "path_not_nameable")


def test_plan_state_scope_nt_container_is_windows_flavoured_from_linux():
    scope = _plan(
        os_name="nt",
        env={"USERDOMAIN": "CORP", "USERNAME": "alice"},
        state_dir=r"C:\ProgramData\w11rg",
        temp_dir=r"C:\Temp",
    )
    assert isinstance(scope.path, PureWindowsPath)
    assert scope.path.parent == PureWindowsPath(r"C:\ProgramData\w11rg")
    assert scope.staging_path == scope.path.with_name(scope.path.name + ".staging.tmp")


def test_plan_state_scope_matrix_layout_and_source():
    # {stateless} x {cache_file} x {state_dir} x {temp_dir is None}, asserting (layout, source).
    cases = {
        (True, None, None, "/tmp"): ("none", "stateless"),
        (True, "/c.json", "/d", None): ("none", "stateless"),
        (False, "/c.json", "/d", "/tmp"): ("legacy_pair", "cache_file"),
        (False, "/c.json", None, None): ("legacy_pair", "cache_file"),
        (False, None, "/d", "/tmp"): ("container", "state_dir"),
        (False, None, "/d", None): ("container", "state_dir"),
        (False, None, None, "/tmp"): ("container", "default_temp"),
        (False, None, None, None): ("none", "no_temp_dir"),
    }
    for (stateless, cache_file, state_dir, temp_dir), expected in cases.items():
        scope = _plan(stateless=stateless, cache_file=cache_file, state_dir=state_dir, temp_dir=temp_dir)
        assert (scope.layout, scope.source) == expected, (stateless, cache_file, state_dir, temp_dir)
