from __future__ import annotations

import json

import pytest

from win11_release_guard.bundled_policy import load_bundled_policy
from win11_release_guard.exceptions import PolicyTrustError
from win11_release_guard.signing import load_trusted_policy, sign_policy_bytes, verify_policy_signature


TEST_PRIVATE_KEY = "krtF2muLgucP7JDVNKk2g+YQfz92c7xM49dzszxHxjs="
TEST_PUBLIC_KEY = "45dOpVuYqoPkldNrzORHM5ZZUxs6ILVcvpKxRFxsu3s="


def _policy_json() -> dict:
    return {
        "schema_version": 1,
        "generated_at_utc": "2026-05-28T00:00:00Z",
        "generator_version": "win-release-guard/0.2",
        "source_urls": ["https://example.invalid/windows-release-policy.json"],
        "source_fetch_status": {"release_health_html": {"status": "ok"}},
        "current_versions": [
            {
                "version": "25H2",
                "build_family": 26200,
                "latest_build": "26200.8457",
                "baseline_build": "26200.8457",
                "servicing_option": "General Availability Channel",
            }
        ],
        "supported_build_families": {"26200": "25H2"},
        "broad_target_existing_devices": {
            "version": "25H2",
            "build_family": 26200,
            "latest_build": "26200.8457",
            "baseline_build": "26200.8457",
            "servicing_option": "General Availability Channel",
        },
        "excluded_for_existing_devices": [],
        "special_releases": [],
        "quality_baselines": {
            "25H2": {
                "b_release_only": {
                    "release": "25H2",
                    "build_family": 26200,
                    "build": "26200.8457",
                    "update_type_letter": "B",
                    "preview": False,
                    "out_of_band": False,
                }
            }
        },
        "preview_builds": [],
        "out_of_band_builds": [],
        "known_notes": [],
        "validation_warnings": [],
        "release_history": [
            {
                "release": "25H2",
                "build_family": 26200,
                "build": "26200.8457",
                "update_type_letter": "B",
                "preview": False,
                "out_of_band": False,
            }
        ],
    }


def _policy_bytes() -> bytes:
    return (json.dumps(_policy_json(), indent=2, sort_keys=True) + "\n").encode("utf-8")


def _signature_bytes(policy_bytes: bytes) -> bytes:
    return (json.dumps(sign_policy_bytes(policy_bytes, TEST_PRIVATE_KEY), indent=2, sort_keys=True) + "\n").encode("utf-8")


def test_valid_signature_accepted():
    policy_bytes = _policy_bytes()
    signature_bytes = _signature_bytes(policy_bytes)

    trusted = load_trusted_policy(
        policy_bytes,
        signature_bytes=signature_bytes,
        public_key=TEST_PUBLIC_KEY,
        source_url="https://example.invalid/windows-release-policy.json",
    )

    assert trusted.signature_status == "valid"
    assert trusted.policy.broad_target_existing_devices is not None
    assert verify_policy_signature(policy_bytes, signature_bytes, TEST_PUBLIC_KEY)


def test_invalid_signature_rejected():
    policy_bytes = _policy_bytes()

    with pytest.raises(PolicyTrustError, match="signature verification failed"):
        load_trusted_policy(
            policy_bytes,
            signature_bytes=b'{"algorithm":"ed25519","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}',
            public_key=TEST_PUBLIC_KEY,
        )


def test_missing_signature_rejected_when_required():
    with pytest.raises(PolicyTrustError, match="signature is required"):
        load_trusted_policy(_policy_bytes(), signature_bytes=None, require_signature=True)


def test_unsigned_policy_accepted_only_when_config_allows_it():
    policy_bytes = _policy_bytes()

    trusted = load_trusted_policy(
        policy_bytes,
        signature_bytes=None,
        require_signature=True,
        allow_unsigned=True,
    )

    assert trusted.signature_status == "unsigned_allowed"

    with pytest.raises(PolicyTrustError):
        load_trusted_policy(
            policy_bytes,
            signature_bytes=None,
            require_signature=True,
            allow_unsigned=False,
        )


def test_bundled_policy_loads_as_verified():
    trusted = load_bundled_policy()

    assert trusted.signature_status == "valid"
    assert trusted.policy.broad_target_existing_devices is not None
