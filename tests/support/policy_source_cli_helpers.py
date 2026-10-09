"""Helpers shared by the test_policy_source_cli test modules."""

from __future__ import annotations

from win11_release_guard import cli_public_pages as _cli_public_pages_module
import json
import hashlib
from datetime import datetime
from pathlib import Path
from win11_release_guard.config import DEFAULT_POLICY_URL, DEFAULT_PUBLISHED_POLICY_URLS, DEFAULT_RELEASE_HEALTH_URL
from win11_release_guard.exceptions import PolicyFetchError
from win11_release_guard.policy_schema import GENERATOR_VERSION
from win11_release_guard.signing import sign_policy_bytes


TEST_PRIVATE_KEY = "krtF2muLgucP7JDVNKk2g+YQfz92c7xM49dzszxHxjs="


TEST_PUBLIC_KEY = "45dOpVuYqoPkldNrzORHM5ZZUxs6ILVcvpKxRFxsu3s="


def _policy_json() -> dict:
    return {
        "schema_version": 1,
        "generated_at_utc": "2026-05-28T00:00:00Z",
        "generator_version": GENERATOR_VERSION,
        "source_urls": [
            DEFAULT_RELEASE_HEALTH_URL,
        ],
        "published_urls": dict(DEFAULT_PUBLISHED_POLICY_URLS),
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
        "release_history": [
            {
                "release": "25H2",
                "build_family": 26200,
                "build": "26200.8457",
                "availability_date": "2026-05-12",
                "servicing_option": "General Availability Channel",
                "update_type": "2026-05 B",
                "update_type_letter": "B",
                "kb_article": "KB5089549",
            }
        ],
        "excluded_for_existing_devices": [
            {
                "version": "26H1",
                "build_family": 28000,
                "reason": "new devices only",
                "servicing_option": "General Availability Channel",
            }
        ],
        "special_releases": [
            {
                "version": "26H1",
                "build_family": 28000,
                "reason": "new devices only",
                "servicing_option": "General Availability Channel",
            }
        ],
        "quality_baselines": {
            "25H2": {
                "b_release_only": {
                    "release": "25H2",
                    "build_family": 26200,
                    "build": "26200.8457",
                    "availability_date": "2026-05-12",
                    "servicing_option": "General Availability Channel",
                    "update_type": "2026-05 B",
                    "update_type_letter": "B",
                    "preview": False,
                    "out_of_band": False,
                    "kb_article": "KB5089549",
                }
            }
        },
        "preview_builds": [],
        "out_of_band_builds": [],
        "known_notes": [],
        "validation_warnings": [],
    }


def _write_policy_and_signature(path: Path, policy_bytes: bytes, *, valid_signature: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(policy_bytes)
    if valid_signature:
        signature = sign_policy_bytes(policy_bytes, TEST_PRIVATE_KEY)
        path.with_name(path.name + ".sig").write_bytes(
            (json.dumps(signature, indent=2, sort_keys=True) + "\n").encode("utf-8")
        )
    else:
        path.with_name(path.name + ".sig").write_bytes(
            b'{"algorithm":"ed25519","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}'
        )


def _policy_bytes() -> bytes:
    return (json.dumps(_policy_json(), indent=2, sort_keys=True) + "\n").encode("utf-8")


def _signature_bytes(policy_bytes: bytes) -> bytes:
    signature = sign_policy_bytes(policy_bytes, TEST_PRIVATE_KEY)
    return (json.dumps(signature, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _manifest_bytes(policy_bytes: bytes, **extra_fields: object) -> bytes:
    manifest = {
        "schema_version": 1,
        "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
        "published_urls": dict(DEFAULT_PUBLISHED_POLICY_URLS),
    }
    manifest.update(extra_fields)
    return (
        json.dumps(
            manifest,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _epoch(value: datetime) -> int:
    return int(value.timestamp())


def _fake_source_fetch(policy_bytes: bytes, signature_bytes: bytes, manifest_bytes: bytes):
    def fake_fetch(url, *args, **kwargs):
        url = str(url)
        if url == DEFAULT_POLICY_URL:
            return policy_bytes, "application/json"
        if url == f"{DEFAULT_POLICY_URL}.sig":
            return signature_bytes, "application/json"
        if url == DEFAULT_PUBLISHED_POLICY_URLS["manifest"]:
            return manifest_bytes, "application/json"
        raise PolicyFetchError(f"unexpected URL {url}")

    return fake_fetch


class PublicResponse:
    def __init__(self, url: str, status_code: int, content: bytes, headers: dict[str, str] | None = None):
        self.url = url
        self.status_code = status_code
        self.content = content
        self.content_type = headers.get("Content-Type") if headers else None
        self.headers = headers or {}

    @property
    def auth_challenge(self) -> bool:
        return self.status_code == 401 or any(key.lower() == "www-authenticate" for key in self.headers)


def _public_page_bytes(
    policy_bytes: bytes,
    signature_bytes: bytes,
    manifest_bytes: bytes,
    *,
    api_policy_bytes: bytes | None = None,
    api_signature_bytes: bytes | None = None,
    api_manifest_bytes: bytes | None = None,
) -> dict[str, bytes]:
    return {
        DEFAULT_PUBLISHED_POLICY_URLS["landing"]: b"<html><title>win11_release_guard</title></html>",
        DEFAULT_POLICY_URL: policy_bytes,
        f"{DEFAULT_POLICY_URL}.sig": signature_bytes,
        DEFAULT_PUBLISHED_POLICY_URLS["manifest"]: manifest_bytes,
        DEFAULT_PUBLISHED_POLICY_URLS["api_policy"]: api_policy_bytes or policy_bytes,
        DEFAULT_PUBLISHED_POLICY_URLS["api_signature"]: api_signature_bytes or signature_bytes,
        DEFAULT_PUBLISHED_POLICY_URLS["api_manifest"]: api_manifest_bytes or manifest_bytes,
        "https://avnsx.github.io/win11_release_guard/robots.txt": b"User-agent: *\nAllow: /\n",
        "https://avnsx.github.io/win11_release_guard/sitemap.xml": b"<?xml version=\"1.0\"?><urlset></urlset>",
    }


def _install_public_page_fetch(monkeypatch, page_bytes: dict[str, bytes]) -> None:
    def fake_public_url(url, *, timeout):
        return PublicResponse(str(url), 200, page_bytes[str(url)], {"Content-Type": "application/json"})

    monkeypatch.setattr(_cli_public_pages_module, "_fetch_public_url", fake_public_url)
