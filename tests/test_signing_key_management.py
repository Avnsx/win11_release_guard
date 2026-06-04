from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools import generate_signing_key
from win11_release_guard.bundled_policy import load_bundled_policy
from win11_release_guard.config import DEFAULT_TRUSTED_POLICY_KEY_ID
from win11_release_guard.signing import (
    TrustedPolicyKey,
    decode_policy_signature_metadata,
    load_trusted_policy_keys,
    sign_policy_bytes,
    verify_policy_signature,
)


TEST_PRIVATE_KEY = "krtF2muLgucP7JDVNKk2g+YQfz92c7xM49dzszxHxjs="
TEST_PUBLIC_KEY = "45dOpVuYqoPkldNrzORHM5ZZUxs6ILVcvpKxRFxsu3s="
PRIVATE_KEY_FILE_NAME = "private-" + "key.b64"


def _public_key_b64(private_key_b64: str) -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(private_key_b64)
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public_key).decode("ascii")


def test_generated_key_signs_and_verifies(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)

    code = generate_signing_key.main([
        "--out-dir",
        ".tmp/signing-key",
        "--key-id",
        "test-policy-key",
        "--created-at-utc",
        "2026-05-31T00:00:00+00:00",
    ])

    output = capsys.readouterr().out
    out_dir = Path(".tmp/signing-key")
    private_key_b64 = (out_dir / PRIVATE_KEY_FILE_NAME).read_text(encoding="utf-8").strip()
    public_key_b64 = (out_dir / "public-key.b64").read_text(encoding="utf-8").strip()
    trusted_keys = json.loads((out_dir / "trusted_policy_keys.json").read_text(encoding="utf-8"))
    policy_bytes = b'{"schema_version":1}\n'
    signature = sign_policy_bytes(policy_bytes, private_key_b64, key_id="test-policy-key")
    signature_bytes = json.dumps(signature).encode("utf-8")

    assert code == 0
    assert generate_signing_key.PRIVATE_KEY_SECRET_NAME in output
    assert public_key_b64 == _public_key_b64(private_key_b64)
    assert trusted_keys["trusted_policy_keys"][0]["key_id"] == "test-policy-key"
    assert trusted_keys["trusted_policy_keys"][0]["public_key_b64"] == public_key_b64
    assert trusted_keys["trusted_policy_keys"][0]["valid_from_utc"] == "2026-05-31T00:00:00+00:00"
    assert verify_policy_signature(policy_bytes, signature_bytes, public_key_b64)


def test_generate_signing_key_retiring_skeleton_requires_verify_window(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)

    missing_code = generate_signing_key.main([
        "--out-dir",
        ".tmp/signing-key-missing",
        "--status",
        "retiring",
    ])
    valid_code = generate_signing_key.main([
        "--out-dir",
        ".tmp/signing-key-retiring",
        "--status",
        "retiring",
        "--created-at-utc",
        "2026-01-01T00:00:00+00:00",
        "--verify-not-after-utc",
        "2026-06-30T00:00:00+00:00",
    ])

    captured = capsys.readouterr()
    trusted_keys = json.loads((Path(".tmp/signing-key-retiring") / "trusted_policy_keys.json").read_text(encoding="utf-8"))
    record = trusted_keys["trusted_policy_keys"][0]
    assert missing_code == 2
    assert "--verify-not-after-utc is required" in captured.err
    assert valid_code == 0
    assert record["status"] == "retiring"
    assert record["valid_from_utc"] == "2026-01-01T00:00:00+00:00"
    assert record["verify_not_after_utc"] == "2026-06-30T00:00:00+00:00"


def test_generate_signing_key_refuses_private_key_outside_tmp(tmp_path, capsys):
    code = generate_signing_key.main(["--out-dir", str(tmp_path / "signing-key")])

    captured = capsys.readouterr()
    assert code == 2
    assert f"Refusing to write {PRIVATE_KEY_FILE_NAME} outside .tmp/ or RUNNER_TEMP" in captured.err


def test_generate_signing_key_allows_explicit_runner_temp(monkeypatch, tmp_path):
    runner_temp = tmp_path / "runner-temp"
    out_dir = runner_temp / "signing-key"
    monkeypatch.setenv("RUNNER_TEMP", str(runner_temp))

    code = generate_signing_key.main([
        "--out-dir",
        str(out_dir),
        "--allow-outside-tmp",
        "--key-id",
        "test-runner-temp-key",
    ])

    assert code == 0
    assert (out_dir / PRIVATE_KEY_FILE_NAME).is_file()


def test_wrong_key_corrupted_policy_and_corrupted_signature_fail():
    policy_bytes = b'{"schema_version":1}\n'
    signature = sign_policy_bytes(policy_bytes, TEST_PRIVATE_KEY, key_id="test-key")
    signature_bytes = json.dumps(signature).encode("utf-8")
    wrong_private_key = Ed25519PrivateKey.generate()
    wrong_public_key = wrong_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    wrong_public_key_b64 = base64.b64encode(wrong_public_key).decode("ascii")

    assert not verify_policy_signature(policy_bytes, signature_bytes, wrong_public_key_b64)
    assert not verify_policy_signature(b'{"schema_version":2}\n', signature_bytes, TEST_PUBLIC_KEY)

    corrupted = dict(signature)
    corrupted["signature"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
    assert not verify_policy_signature(policy_bytes, json.dumps(corrupted).encode("utf-8"), TEST_PUBLIC_KEY)


def test_unknown_key_id_fails_without_public_key_override():
    policy_bytes = b'{"schema_version":1}\n'
    signature = sign_policy_bytes(policy_bytes, TEST_PRIVATE_KEY, key_id="unknown-policy-key")

    assert decode_policy_signature_metadata(json.dumps(signature).encode("utf-8")).key_id == "unknown-policy-key"
    assert not verify_policy_signature(policy_bytes, json.dumps(signature).encode("utf-8"))


def test_default_generated_signature_uses_current_policy_key_id():
    policy_bytes = b'{"schema_version":1}\n'
    signature = sign_policy_bytes(policy_bytes, TEST_PRIVATE_KEY)

    assert DEFAULT_TRUSTED_POLICY_KEY_ID == "win11_release_guard-policy-2026-05"
    assert signature["key_id"] == DEFAULT_TRUSTED_POLICY_KEY_ID
    assert signature["signed_at_utc"]


def _trusted_key(*, key_id: str, status: str, verify_not_after_utc: str | None = None) -> TrustedPolicyKey:
    return TrustedPolicyKey(
        key_id=key_id,
        algorithm="ed25519",
        public_key_b64=TEST_PUBLIC_KEY,
        created_at_utc="2026-01-01T00:00:00+00:00",
        status=status,
        valid_from_utc="2026-01-01T00:00:00+00:00",
        verify_not_after_utc=verify_not_after_utc,
    )


def test_retiring_key_validates_only_inside_verify_window(monkeypatch):
    policy_bytes = b'{"schema_version":1}\n'
    key_id = "test-retiring-key"
    monkeypatch.setattr(
        "win11_release_guard.signing.load_trusted_policy_keys",
        lambda: (_trusted_key(key_id=key_id, status="retiring", verify_not_after_utc="2026-06-30T00:00:00+00:00"),),
    )

    valid_signature = sign_policy_bytes(
        policy_bytes,
        TEST_PRIVATE_KEY,
        key_id=key_id,
        signed_at_utc="2026-06-01T00:00:00+00:00",
    )
    late_signature = sign_policy_bytes(
        policy_bytes,
        TEST_PRIVATE_KEY,
        key_id=key_id,
        signed_at_utc="2026-07-01T00:00:00+00:00",
    )
    missing_signed_at = dict(valid_signature)
    missing_signed_at.pop("signed_at_utc")

    assert verify_policy_signature(policy_bytes, json.dumps(valid_signature).encode("utf-8"))
    assert not verify_policy_signature(policy_bytes, json.dumps(late_signature).encode("utf-8"))
    assert not verify_policy_signature(policy_bytes, json.dumps(missing_signed_at).encode("utf-8"))


def test_retired_key_requires_old_signature_inside_verify_window(monkeypatch):
    policy_bytes = b'{"schema_version":1}\n'
    key_id = "test-retired-key"
    monkeypatch.setattr(
        "win11_release_guard.signing.load_trusted_policy_keys",
        lambda: (_trusted_key(key_id=key_id, status="retired", verify_not_after_utc="2026-02-01T00:00:00+00:00"),),
    )

    old_signature = sign_policy_bytes(
        policy_bytes,
        TEST_PRIVATE_KEY,
        key_id=key_id,
        signed_at_utc="2026-01-15T00:00:00+00:00",
    )
    fresh_signature = sign_policy_bytes(
        policy_bytes,
        TEST_PRIVATE_KEY,
        key_id=key_id,
        signed_at_utc="2026-03-01T00:00:00+00:00",
    )

    assert verify_policy_signature(policy_bytes, json.dumps(old_signature).encode("utf-8"))
    assert not verify_policy_signature(policy_bytes, json.dumps(fresh_signature).encode("utf-8"))


def test_committed_public_key_file_contains_no_private_key_material():
    key_file = Path("win11_release_guard/data/trusted_policy_keys.json")
    data = json.loads(key_file.read_text(encoding="utf-8"))
    text = key_file.read_text(encoding="utf-8").lower()

    assert "private_key" not in text
    assert "private-key" not in text
    assert "seed" not in text
    assert data["trusted_policy_keys"]
    assert all("public_key_b64" in record for record in data["trusted_policy_keys"])
    assert all("private_key_b64" not in record for record in data["trusted_policy_keys"])
    assert all("valid_from_utc" in record for record in data["trusted_policy_keys"])
    assert all(
        record["status"] == "active" or record.get("verify_not_after_utc")
        for record in data["trusted_policy_keys"]
    )


def test_data_directory_contains_only_public_policy_artifacts():
    data_dir = Path("win11_release_guard/data")
    allowed_names = {
        "__init__.py",
        "trusted_policy_keys.json",
        "windows-release-policy.json",
        "windows-release-policy.json.sig",
    }
    names = {path.name for path in data_dir.iterdir() if path.is_file()}

    assert names == allowed_names
    assert not any("private" in name.lower() for name in names)
    assert not any(name.lower().endswith((".pem", ".key")) for name in names)


def test_runtime_can_verify_policy_with_committed_trusted_key():
    trusted = load_bundled_policy()
    trusted_keys = load_trusted_policy_keys()
    keys_by_id = {key.key_id: key for key in trusted_keys}

    assert trusted.signature_status == "valid"
    assert trusted.policy.broad_target_existing_devices is not None
    assert keys_by_id["win11_release_guard-policy-2026-01"].status == "retiring"
    assert keys_by_id["win11_release_guard-policy-2026-01"].verify_not_after_utc == "2026-06-30T00:00:00Z"
    assert keys_by_id[DEFAULT_TRUSTED_POLICY_KEY_ID].status == "active"
    assert keys_by_id[DEFAULT_TRUSTED_POLICY_KEY_ID].valid_from_utc == "2026-05-31T23:16:50+00:00"
