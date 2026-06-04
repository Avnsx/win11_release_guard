from __future__ import annotations


import pytest

from win11_release_guard import __main__ as cli
from win11_release_guard.cache import load_policy_cache
from win11_release_guard.exceptions import PolicyParseError, PolicyTrustError
from win11_release_guard.remote_policy import fetch_policy_bytes, load_policy_bytes, load_policy_text
from win11_release_guard.signing import decode_policy_signature_metadata


def test_remote_policy_json_rejects_duplicate_top_level_keys() -> None:
    payload = '{"schema_version": 1, "schema_version": 2}'
    with pytest.raises(PolicyParseError, match="Duplicate JSON object key"):
        load_policy_text(payload)


def test_remote_policy_json_rejects_non_finite_numbers() -> None:
    payload = '{"schema_version": NaN}'
    with pytest.raises(PolicyParseError, match="Non-finite JSON numeric value"):
        load_policy_text(payload)


def test_remote_policy_json_rejects_non_object_top_level() -> None:
    with pytest.raises(PolicyParseError, match="top-level value must be an object"):
        load_policy_text("[]")


def test_remote_policy_invalid_utf8_error_is_policy_parse_error() -> None:
    with pytest.raises(PolicyParseError, match="not valid UTF-8"):
        load_policy_bytes(b"\xffnot-json", content_type="application/json")


def test_public_manifest_json_rejects_duplicate_keys() -> None:
    with pytest.raises(PolicyParseError, match="Duplicate JSON object key"):
        cli._decode_json_bytes(b'{"policy_sha256":"a", "policy_sha256":"b"}', label="Policy manifest")


def test_public_manifest_json_rejects_non_object_top_level() -> None:
    with pytest.raises(PolicyParseError, match="top-level value must be an object"):
        cli._decode_json_bytes(b'[]', label="Policy manifest")


def test_signature_json_rejects_duplicate_keys() -> None:
    with pytest.raises(PolicyTrustError):
        decode_policy_signature_metadata(
            b'{"algorithm":"ed25519", "signature":"AA==", "signature":"BB=="}'
        )


def test_cache_json_rejects_duplicate_keys(tmp_path) -> None:
    cache_file = tmp_path / "windows-release-policy.json"
    cache_file.write_text('{"schema_version": 1, "schema_version": 2}', encoding="utf-8")
    with pytest.raises(PolicyParseError, match="Duplicate JSON object key"):
        load_policy_cache(cache_file)


def test_cache_json_rejects_oversized_file_before_parse(tmp_path, monkeypatch) -> None:
    import win11_release_guard.cache as cache

    monkeypatch.setattr(cache, "DEFAULT_MAX_JSON_BYTES", 4)
    cache_file = tmp_path / "windows-release-policy.json"
    cache_file.write_text("{}   ", encoding="utf-8")

    with pytest.raises(PolicyParseError, match="too large"):
        load_policy_cache(cache_file)


def test_local_policy_fetch_rejects_oversized_file(tmp_path, monkeypatch) -> None:
    import win11_release_guard.remote_policy as remote_policy

    monkeypatch.setattr(remote_policy, "DEFAULT_MAX_JSON_BYTES", 4)
    policy_file = tmp_path / "windows-release-policy.json"
    policy_file.write_text("{}   ", encoding="utf-8")

    with pytest.raises(Exception, match="too large"):
        fetch_policy_bytes(str(policy_file))


def test_signature_invalid_utf8_error_is_policy_trust_error() -> None:
    with pytest.raises(PolicyTrustError, match="Policy signature is not valid UTF-8"):
        decode_policy_signature_metadata(b"\xffnot-json")
