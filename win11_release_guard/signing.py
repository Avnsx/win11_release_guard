from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .config import DEFAULT_TRUSTED_POLICY_KEY_ID
from .exceptions import PolicyTrustError
from .models import ReleasePolicy
from .json_utils import StrictJSONError, strict_json_loads, strict_json_object
from .remote_policy import load_policy_bytes


SIGNATURE_ALGORITHM = "ed25519"
TRUSTED_POLICY_KEYS_PACKAGE = "win11_release_guard.data"
TRUSTED_POLICY_KEYS_FILE = "trusted_policy_keys.json"
TRUSTED_POLICY_KEY_ALLOWED_STATUSES = frozenset({"active", "retiring", "retired"})


@dataclass(frozen=True)
class TrustedPolicy:
    policy: ReleasePolicy
    policy_bytes: bytes
    signature_bytes: bytes | None
    signature_status: str
    source_url: str | None = None


@dataclass(frozen=True)
class TrustedPolicyKey:
    key_id: str
    algorithm: str
    public_key_b64: str
    created_at_utc: str
    status: str
    valid_from_utc: str | None = None
    verify_not_after_utc: str | None = None


@dataclass(frozen=True)
class PolicySignature:
    algorithm: str
    signature: bytes
    key_id: str | None = None
    signed_at_utc: str | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_utc_timestamp(value: str | None, *, field_name: str) -> datetime | None:
    if value is None or not str(value).strip():
        return None
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyTrustError(f"{field_name} must be an ISO-8601 UTC timestamp.") from exc
    if parsed.tzinfo is None:
        raise PolicyTrustError(f"{field_name} must include a UTC offset.")
    return parsed.astimezone(timezone.utc)


def _bytes_from_text(value: str) -> bytes:
    return value.encode("utf-8")


def _decode_key_material(value: str | bytes) -> bytes:
    raw = value if isinstance(value, bytes) else _bytes_from_text(value.strip())
    if raw.startswith(b"-----BEGIN"):
        return raw
    try:
        return base64.b64decode(raw, validate=True)
    except binascii.Error:
        return raw


def _public_key_from_material(value: str | bytes) -> Ed25519PublicKey:
    key_material = _decode_key_material(value)
    if key_material.startswith(b"-----BEGIN"):
        loaded = serialization.load_pem_public_key(key_material)
        if not isinstance(loaded, Ed25519PublicKey):
            raise PolicyTrustError("Trusted policy public key is not an Ed25519 public key.")
        return loaded
    if len(key_material) != 32:
        raise PolicyTrustError("Trusted policy public key must be 32 raw Ed25519 bytes or PEM.")
    return Ed25519PublicKey.from_public_bytes(key_material)


def _trusted_key_records_from_mapping(data: Any) -> tuple[TrustedPolicyKey, ...]:
    if not isinstance(data, dict):
        raise PolicyTrustError("Trusted policy key file must be a JSON object.")
    records = data.get("trusted_policy_keys")
    if not isinstance(records, list) or not records:
        raise PolicyTrustError("Trusted policy key file is missing non-empty 'trusted_policy_keys'.")

    parsed: list[TrustedPolicyKey] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise PolicyTrustError(f"trusted_policy_keys[{index}] must be an object.")
        key_id = str(record.get("key_id") or "").strip()
        algorithm = str(record.get("algorithm") or "").strip().lower()
        public_key_b64 = str(record.get("public_key_b64") or "").strip()
        created_at_utc = str(record.get("created_at_utc") or "").strip()
        status = str(record.get("status") or "").strip().lower()
        valid_from_utc = str(record.get("valid_from_utc") or "").strip() or None
        verify_not_after_utc = str(record.get("verify_not_after_utc") or "").strip() or None
        if not key_id:
            raise PolicyTrustError(f"trusted_policy_keys[{index}] is missing key_id.")
        if algorithm != SIGNATURE_ALGORITHM:
            raise PolicyTrustError(f"trusted_policy_keys[{index}] uses unsupported algorithm {algorithm!r}.")
        if not public_key_b64:
            raise PolicyTrustError(f"trusted_policy_keys[{index}] is missing public_key_b64.")
        if not created_at_utc:
            raise PolicyTrustError(f"trusted_policy_keys[{index}] is missing created_at_utc.")
        if status not in TRUSTED_POLICY_KEY_ALLOWED_STATUSES:
            raise PolicyTrustError(f"trusted_policy_keys[{index}] status {status!r} is not trusted.")
        _parse_utc_timestamp(created_at_utc, field_name=f"trusted_policy_keys[{index}].created_at_utc")
        _parse_utc_timestamp(valid_from_utc, field_name=f"trusted_policy_keys[{index}].valid_from_utc")
        _parse_utc_timestamp(
            verify_not_after_utc,
            field_name=f"trusted_policy_keys[{index}].verify_not_after_utc",
        )
        if status in {"retiring", "retired"} and not verify_not_after_utc:
            raise PolicyTrustError(
                f"trusted_policy_keys[{index}] status {status!r} requires verify_not_after_utc."
            )
        _public_key_from_material(public_key_b64)
        parsed.append(
            TrustedPolicyKey(
                key_id=key_id,
                algorithm=algorithm,
                public_key_b64=public_key_b64,
                created_at_utc=created_at_utc,
                status=status,
                valid_from_utc=valid_from_utc,
                verify_not_after_utc=verify_not_after_utc,
            )
        )
    return tuple(parsed)


def load_trusted_policy_keys() -> tuple[TrustedPolicyKey, ...]:
    try:
        key_text = resources.files(TRUSTED_POLICY_KEYS_PACKAGE).joinpath(TRUSTED_POLICY_KEYS_FILE).read_text(
            encoding="utf-8"
        )
    except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
        raise PolicyTrustError(f"Trusted policy key file is unavailable: {exc}") from exc
    try:
        data = strict_json_object(key_text, label="Trusted policy key file")
    except StrictJSONError as exc:
        raise PolicyTrustError(str(exc)) from exc
    return _trusted_key_records_from_mapping(data)


def _trusted_public_key_record(key_id: str | None = None) -> TrustedPolicyKey:
    keys = load_trusted_policy_keys()
    if key_id:
        for key in keys:
            if key.key_id == key_id:
                return key
        raise PolicyTrustError(f"Policy signature key_id {key_id!r} is not trusted.")

    for key in keys:
        if key.key_id == DEFAULT_TRUSTED_POLICY_KEY_ID:
            return key
    for key in keys:
        if key.status == "active":
            return key
    raise PolicyTrustError("Trusted policy key file contains no active Ed25519 policy key.")


def load_public_key(public_key: str | bytes | None = None) -> Ed25519PublicKey:
    if public_key is not None:
        return _public_key_from_material(public_key)
    return _public_key_from_material(_trusted_public_key_record().public_key_b64)


def load_private_key(private_key: str | bytes) -> Ed25519PrivateKey:
    key_material = _decode_key_material(private_key)
    if key_material.startswith(b"-----BEGIN"):
        loaded = serialization.load_pem_private_key(key_material, password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise PolicyTrustError("Signing key is not an Ed25519 private key.")
        return loaded
    if len(key_material) != 32:
        raise PolicyTrustError("Signing key must be a 32-byte raw Ed25519 seed or PEM.")
    return Ed25519PrivateKey.from_private_bytes(key_material)


def _decode_signature_value(value: str) -> bytes:
    normalized = value.strip()
    try:
        return base64.b64decode(normalized, validate=True)
    except binascii.Error:
        try:
            return bytes.fromhex(normalized)
        except ValueError as exc:
            raise PolicyTrustError("Policy signature is not valid base64 or hex.") from exc


def decode_policy_signature_metadata(signature_bytes: bytes) -> PolicySignature:
    stripped = signature_bytes.strip()
    if not stripped:
        raise PolicyTrustError("Policy signature is empty.")

    try:
        parsed: Any = strict_json_loads(stripped, label="Policy signature")
    except StrictJSONError as exc:
        if len(stripped) == 64:
            return PolicySignature(algorithm=SIGNATURE_ALGORITHM, signature=bytes(stripped))
        try:
            signature_text = stripped.decode("utf-8")
        except UnicodeDecodeError as decode_exc:
            raise PolicyTrustError(
                "Policy signature is not valid UTF-8 JSON, raw 64-byte signature, base64, or hex."
            ) from decode_exc
        try:
            return PolicySignature(
                algorithm=SIGNATURE_ALGORITHM,
                signature=_decode_signature_value(signature_text),
            )
        except PolicyTrustError as decode_exc:
            raise PolicyTrustError(str(exc)) from decode_exc

    if isinstance(parsed, dict):
        algorithm = str(parsed.get("algorithm") or "").lower()
        if algorithm and algorithm != SIGNATURE_ALGORITHM:
            raise PolicyTrustError(f"Unsupported policy signature algorithm {algorithm!r}.")
        signature = parsed.get("signature")
        if not isinstance(signature, str):
            raise PolicyTrustError("Policy signature JSON is missing string field 'signature'.")
        key_id = parsed.get("key_id")
        if key_id is not None and not isinstance(key_id, str):
            raise PolicyTrustError("Policy signature JSON field 'key_id' must be a string.")
        normalized_key_id = key_id.strip() if isinstance(key_id, str) else None
        signed_at = parsed.get("signed_at_utc")
        if signed_at is not None and not isinstance(signed_at, str):
            raise PolicyTrustError("Policy signature JSON field 'signed_at_utc' must be a string.")
        normalized_signed_at = signed_at.strip() if isinstance(signed_at, str) else None
        _parse_utc_timestamp(normalized_signed_at, field_name="Policy signature signed_at_utc")
        return PolicySignature(
            algorithm=algorithm or SIGNATURE_ALGORITHM,
            signature=_decode_signature_value(signature),
            key_id=normalized_key_id or None,
            signed_at_utc=normalized_signed_at or None,
        )
    if isinstance(parsed, str):
        return PolicySignature(algorithm=SIGNATURE_ALGORITHM, signature=_decode_signature_value(parsed))
    raise PolicyTrustError("Policy signature must be raw bytes, text, or a JSON object.")


def decode_policy_signature(signature_bytes: bytes) -> bytes:
    return decode_policy_signature_metadata(signature_bytes).signature


def sign_policy_bytes(
    policy_bytes: bytes,
    private_key: str | bytes,
    *,
    key_id: str = DEFAULT_TRUSTED_POLICY_KEY_ID,
    signed_at_utc: str | None = None,
) -> dict[str, str]:
    normalized_signed_at_utc = signed_at_utc or _utc_now()
    _parse_utc_timestamp(normalized_signed_at_utc, field_name="signed_at_utc")
    signer = load_private_key(private_key)
    signature = signer.sign(policy_bytes)
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "signature": base64.b64encode(signature).decode("ascii"),
        "signed_at_utc": normalized_signed_at_utc,
    }


def _verify_signature_allowed_for_key(signature: PolicySignature, key: TrustedPolicyKey) -> None:
    signed_at = _parse_utc_timestamp(signature.signed_at_utc, field_name="Policy signature signed_at_utc")
    valid_from = _parse_utc_timestamp(key.valid_from_utc, field_name=f"trusted key {key.key_id} valid_from_utc")
    verify_not_after = _parse_utc_timestamp(
        key.verify_not_after_utc,
        field_name=f"trusted key {key.key_id} verify_not_after_utc",
    )

    if key.status in {"retiring", "retired"}:
        if signed_at is None:
            raise PolicyTrustError(
                f"Policy signature signed by {key.status} key {key.key_id!r} must include signed_at_utc."
            )
        if verify_not_after is None:
            raise PolicyTrustError(
                f"Trusted {key.status} key {key.key_id!r} requires verify_not_after_utc."
            )

    if signed_at is not None and valid_from is not None and signed_at < valid_from:
        raise PolicyTrustError(
            f"Policy signature signed_at_utc is before trusted key {key.key_id!r} valid_from_utc."
        )
    if signed_at is not None and verify_not_after is not None and signed_at > verify_not_after:
        raise PolicyTrustError(
            f"Policy signature signed_at_utc is after trusted key {key.key_id!r} verify_not_after_utc."
        )


def _verifier_for_signature(signature: PolicySignature, public_key: str | bytes | None) -> Ed25519PublicKey:
    if public_key is not None:
        return load_public_key(public_key)
    key = _trusted_public_key_record(signature.key_id)
    _verify_signature_allowed_for_key(signature, key)
    return _public_key_from_material(key.public_key_b64)


def verify_policy_signature(
    policy_bytes: bytes,
    signature_bytes: bytes,
    public_key: str | bytes | None = None,
) -> bool:
    try:
        signature = decode_policy_signature_metadata(signature_bytes)
        verifier = _verifier_for_signature(signature, public_key)
        verifier.verify(signature.signature, policy_bytes)
    except (InvalidSignature, PolicyTrustError):
        return False
    return True


def load_trusted_policy(
    policy_bytes: bytes,
    *,
    signature_bytes: bytes | None = None,
    public_key: str | bytes | None = None,
    require_signature: bool = True,
    allow_unsigned: bool = False,
    content_type: str | None = "application/json",
    source_url: str | None = None,
    allow_html_fallback: bool = False,
) -> TrustedPolicy:
    if signature_bytes is None:
        if require_signature and not allow_unsigned:
            raise PolicyTrustError("Policy signature is required but missing.")
        policy = load_policy_bytes(
            policy_bytes,
            content_type=content_type,
            source_url=source_url,
            allow_html_fallback=allow_html_fallback,
        )
        return TrustedPolicy(
            policy=policy,
            policy_bytes=policy_bytes,
            signature_bytes=None,
            signature_status="unsigned_allowed" if allow_unsigned else "unsigned",
            source_url=source_url,
        )

    if not verify_policy_signature(policy_bytes, signature_bytes, public_key):
        raise PolicyTrustError("Policy signature verification failed.")

    policy = load_policy_bytes(
        policy_bytes,
        content_type=content_type,
        source_url=source_url,
        allow_html_fallback=allow_html_fallback,
    )
    return TrustedPolicy(
        policy=policy,
        policy_bytes=policy_bytes,
        signature_bytes=signature_bytes,
        signature_status="valid",
        source_url=source_url,
    )


__all__ = [
    "SIGNATURE_ALGORITHM",
    "TRUSTED_POLICY_KEYS_FILE",
    "TRUSTED_POLICY_KEYS_PACKAGE",
    "PolicySignature",
    "TrustedPolicy",
    "TrustedPolicyKey",
    "decode_policy_signature",
    "decode_policy_signature_metadata",
    "load_private_key",
    "load_public_key",
    "load_trusted_policy_keys",
    "load_trusted_policy",
    "sign_policy_bytes",
    "verify_policy_signature",
]
