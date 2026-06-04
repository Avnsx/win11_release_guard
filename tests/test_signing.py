from __future__ import annotations

import json
from pathlib import Path

import pytest

from win11_release_guard.bundled_policy import load_bundled_policy
from win11_release_guard.config import DEFAULT_POLICY_URL, DEFAULT_PUBLISHED_POLICY_URLS
from win11_release_guard.exceptions import PolicyTrustError
from win11_release_guard.policy_schema import validate_policy_document
from win11_release_guard.signing import load_trusted_policy, sign_policy_bytes, verify_policy_signature


TEST_PRIVATE_KEY = "krtF2muLgucP7JDVNKk2g+YQfz92c7xM49dzszxHxjs="
TEST_PUBLIC_KEY = "45dOpVuYqoPkldNrzORHM5ZZUxs6ILVcvpKxRFxsu3s="
ROOT = Path(__file__).resolve().parents[1]
BUNDLED_POLICY_PATH = ROOT / "win11_release_guard" / "data" / "windows-release-policy.json"
BUNDLED_SIGNATURE_PATH = BUNDLED_POLICY_PATH.with_name(BUNDLED_POLICY_PATH.name + ".sig")


def _policy_json() -> dict:
    return {
        "schema_version": 1,
        "generated_at_utc": "2026-05-28T00:00:00Z",
        "generator_version": "win11_release_guard/0.2",
        "source_urls": [("https://example" + ".invalid/windows-release-policy.json")],
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
        source_url=("https://example" + ".invalid/windows-release-policy.json"),
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
    assert trusted.policy.published_urls["policy"] == DEFAULT_POLICY_URL
    assert trusted.policy.published_urls["api_policy"] == DEFAULT_PUBLISHED_POLICY_URLS["api_policy"]


def test_bundled_legacy_policy_contract_is_explicit_and_schema_safe():
    raw_policy = json.loads(BUNDLED_POLICY_PATH.read_text(encoding="utf-8"))

    assert verify_policy_signature(BUNDLED_POLICY_PATH.read_bytes(), BUNDLED_SIGNATURE_PATH.read_bytes())
    assert raw_policy["schema_version"] == 1
    assert raw_policy["generator_version"] == "win11_release_guard/0.2"
    assert "api_version" not in raw_policy
    assert "compatibility" not in raw_policy
    assert "source_diagnostics" not in raw_policy
    assert raw_policy["source_fetch_status"]
    assert raw_policy["published_urls"] == DEFAULT_PUBLISHED_POLICY_URLS

    target = raw_policy["broad_target_existing_devices"]
    target_release = target["version"]
    baseline = raw_policy["quality_baselines"][target_release]["b_release_only"]
    assert target["baseline_build"] == baseline["build"]
    assert "latest_observed_build" not in raw_policy["current_versions"][0]
    assert "required_baseline_build" not in raw_policy["current_versions"][0]
    assert all(entry.get("latest_build") for entry in raw_policy["current_versions"])

    trusted = load_bundled_policy()
    normalized = trusted.policy.to_dict()
    warnings = validate_policy_document(normalized)

    assert not any("unknown top-level key" in warning for warning in warnings)
    assert normalized["api_version"] is None
    assert normalized["compatibility"] == {}
    assert normalized["source_diagnostics"] == {}
    assert normalized["broad_target_existing_devices"]["latest_observed_build"] == target["latest_build"]
    assert normalized["broad_target_existing_devices"]["required_baseline_build"] == target["baseline_build"]
    current_target = next(
        entry for entry in normalized["current_versions"]
        if entry["version"] == target_release and entry["build_family"] == target["build_family"]
    )
    assert current_target["latest_observed_build"] == current_target["latest_build"]
    assert current_target["required_baseline_build"] == current_target["latest_build"]
