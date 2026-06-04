from __future__ import annotations

import json
import hashlib
from pathlib import Path

from win11_release_guard import __main__ as cli
from win11_release_guard.config import DEFAULT_POLICY_URL, DEFAULT_PUBLISHED_POLICY_URLS, DEFAULT_RELEASE_HEALTH_URL
from win11_release_guard.exceptions import PolicyFetchError
from win11_release_guard.signing import sign_policy_bytes


TEST_PRIVATE_KEY = "krtF2muLgucP7JDVNKk2g+YQfz92c7xM49dzszxHxjs="
TEST_PUBLIC_KEY = "45dOpVuYqoPkldNrzORHM5ZZUxs6ILVcvpKxRFxsu3s="


def _policy_json() -> dict:
    return {
        "schema_version": 1,
        "generated_at_utc": "2026-05-28T00:00:00Z",
        "generator_version": "win11_release_guard/0.2",
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


def _policy_bytes_with_published_urls(published_urls: dict[str, str]) -> bytes:
    policy = _policy_json()
    policy["published_urls"] = dict(published_urls)
    return (json.dumps(policy, indent=2, sort_keys=True) + "\n").encode("utf-8")


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


def test_check_policy_source_local_signed_file_ok(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "check_current_system", lambda config: (_ for _ in ()).throw(AssertionError("local probe ran")))
    policy_file = tmp_path / "windows-release-policy.json"
    _write_policy_and_signature(
        policy_file,
        _policy_bytes(),
    )

    code = cli.main([
        "--check-policy-source",
        "--policy-url",
        str(policy_file),
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == 0
    assert "Policy source: OK" in output
    assert "Signature: valid" in output
    assert "Manifest: not_checked" in output
    assert "Generated at UTC: 2026-05-28T00:00:00Z" in output
    assert f"- {DEFAULT_RELEASE_HEALTH_URL}" in output
    assert f"- policy: {DEFAULT_POLICY_URL}" in output
    assert f"- api_policy: {DEFAULT_PUBLISHED_POLICY_URLS['api_policy']}" in output
    assert "Broad target: 25H2 / 26200" in output
    assert "Latest observed build: 26200.8457" in output
    assert "Required baseline build: 26200.8457" in output
    assert "Required baseline: 26200.8457" in output
    assert "- 26H1 / 28000 / new devices only" in output


def test_check_policy_source_prints_source_freshness_warnings(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "check_current_system", lambda config: (_ for _ in ()).throw(AssertionError("local probe ran")))
    policy_data = _policy_json()
    policy_data["source_diagnostics"] = {
        "release_health_html": {
            "source_url": DEFAULT_RELEASE_HEALTH_URL,
            "fetched_at_utc": "2026-05-31T00:00:00Z",
            "bytes": 1234,
            "status": "ok",
            "newest_current_version_revision_date": "2026-05-12",
            "newest_release_history_availability_date": "2026-05-12",
        },
        "atom_feed": {
            "source_url": "https://support.microsoft.com/en-us/feed/atom/4ec863cc-2ecd-e187-6cb3-b50c6545db92",
            "fetched_at_utc": "2026-05-31T00:00:01Z",
            "bytes": 5678,
            "status": "ok",
            "newest_atom_updated": "2026-05-16T18:00:00Z",
            "newest_atom_published": "2026-05-16T18:00:00Z",
        },
        "warnings": [
            "Source freshness warning: Atom feed has newer build/KB entries not present in Release Health release_history."
        ],
    }
    policy_file = tmp_path / "windows-release-policy.json"
    _write_policy_and_signature(
        policy_file,
        (json.dumps(policy_data, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )

    code = cli.main([
        "--check-policy-source",
        "--policy-url",
        str(policy_file),
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == 0
    assert "Source freshness:" in output
    assert "newest_atom_updated=2026-05-16T18:00:00Z" in output
    assert "Source freshness warning: Atom feed has newer build/KB entries" in output


def test_check_policy_source_invalid_signature_fails(tmp_path, capsys):
    policy_file = tmp_path / "windows-release-policy.json"
    _write_policy_and_signature(
        policy_file,
        _policy_bytes(),
        valid_signature=False,
    )

    code = cli.main([
        "--check-policy-source",
        "--policy-url",
        str(policy_file),
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "Policy source: SIGNATURE_FAILED" in output
    assert "Policy signature invalid:" in output


def test_check_policy_source_malformed_policy_fails(tmp_path, capsys):
    policy_file = tmp_path / "windows-release-policy.json"
    _write_policy_and_signature(policy_file, b"{not-json")

    code = cli.main([
        "--check-policy-source",
        "--policy-url",
        str(policy_file),
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "Policy source: INVALID" in output
    assert "Malformed JSON policy" in output


def test_check_policy_source_network_unavailable_is_explicit(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "fetch_policy_bytes",
        lambda *args, **kwargs: (_ for _ in ()).throw(PolicyFetchError("network unavailable")),
    )

    code = cli.main([
        "--check-policy-source",
        "--policy-url",
        ("https://example" + ".invalid/windows-release-policy.json"),
    ])

    output = capsys.readouterr().out
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "Policy source: UNAVAILABLE" in output
    assert "Policy source unavailable:" in output
    assert "network unavailable" in output


def test_check_policy_source_default_url_checks_manifest_without_local_probes(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check_current_system", lambda config: (_ for _ in ()).throw(AssertionError("local probe ran")))
    policy_bytes = _policy_bytes()
    signature_bytes = _signature_bytes(policy_bytes)
    manifest_bytes = _manifest_bytes(policy_bytes)
    calls: list[str] = []

    def fake_fetch(url, *args, **kwargs):
        calls.append(str(url))
        return _fake_source_fetch(policy_bytes, signature_bytes, manifest_bytes)(url, *args, **kwargs)

    monkeypatch.setattr(cli, "fetch_policy_bytes", fake_fetch)

    code = cli.main([
        "--check-policy-source",
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == 0
    assert calls == [
        DEFAULT_POLICY_URL,
        f"{DEFAULT_POLICY_URL}.sig",
        DEFAULT_PUBLISHED_POLICY_URLS["manifest"],
    ]
    assert f"Policy URL: {DEFAULT_POLICY_URL}" in output
    assert f"Signature URL: {DEFAULT_POLICY_URL}.sig" in output
    assert f"Manifest URL: {DEFAULT_PUBLISHED_POLICY_URLS['manifest']}" in output
    assert "Manifest: ok" in output
    assert "Broad target: 25H2 / 26200" in output
    assert "Latest observed build: 26200.8457" in output
    assert "Required baseline build: 26200.8457" in output
    assert "Required baseline: 26200.8457" in output
    assert "Published URLs:" in output


def test_check_policy_source_remote_missing_manifest_fails(monkeypatch, capsys):
    policy_bytes = _policy_bytes()
    signature_bytes = _signature_bytes(policy_bytes)

    def fake_fetch(url, *args, **kwargs):
        url = str(url)
        if url == DEFAULT_POLICY_URL:
            return policy_bytes, "application/json"
        if url == f"{DEFAULT_POLICY_URL}.sig":
            return signature_bytes, "application/json"
        if url == DEFAULT_PUBLISHED_POLICY_URLS["manifest"]:
            raise PolicyFetchError("manifest 404")
        raise PolicyFetchError(f"unexpected URL {url}")

    monkeypatch.setattr(cli, "fetch_policy_bytes", fake_fetch)

    code = cli.main([
        "--check-policy-source",
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "Policy source: INVALID" in output
    assert f"Manifest URL: {DEFAULT_PUBLISHED_POLICY_URLS['manifest']}" in output
    assert "Manifest: unavailable" in output
    assert "Manifest unavailable: manifest 404" in output


def test_check_policy_source_allow_missing_manifest_escape_hatch(monkeypatch, capsys):
    policy_bytes = _policy_bytes()
    signature_bytes = _signature_bytes(policy_bytes)

    def fake_fetch(url, *args, **kwargs):
        url = str(url)
        if url == DEFAULT_POLICY_URL:
            return policy_bytes, "application/json"
        if url == f"{DEFAULT_POLICY_URL}.sig":
            return signature_bytes, "application/json"
        if url == DEFAULT_PUBLISHED_POLICY_URLS["manifest"]:
            raise PolicyFetchError("manifest temporarily unavailable")
        raise PolicyFetchError(f"unexpected URL {url}")

    monkeypatch.setattr(cli, "fetch_policy_bytes", fake_fetch)

    code = cli.main([
        "--check-policy-source",
        "--allow-missing-manifest",
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == 0
    assert "Policy source: OK" in output
    assert "Manifest: unavailable" in output
    assert "Manifest unavailable: manifest temporarily unavailable" in output


def test_check_policy_source_manifest_hash_mismatch_fails(monkeypatch, capsys):
    policy_bytes = _policy_bytes()
    signature_bytes = _signature_bytes(policy_bytes)
    bad_manifest = b'{"policy_sha256":"bad"}\n'
    monkeypatch.setattr(cli, "fetch_policy_bytes", _fake_source_fetch(policy_bytes, signature_bytes, bad_manifest))

    code = cli.main([
        "--check-policy-source",
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "Policy source: INVALID" in output
    assert "Manifest: sha256_mismatch" in output
    assert "policy_sha256 does not match" in output


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

    monkeypatch.setattr(cli, "_fetch_public_url", fake_public_url)


def test_public_pages_urls_use_policy_published_urls_with_default_fallbacks():
    class Policy:
        published_urls = {
            "landing": "https://example.com/custom",
            "policy": "https://example.com/custom/windows-release-policy.json",
        }

    urls = cli._public_pages_urls(Policy())

    assert urls["landing"] == "https://example.com/custom"
    assert urls["policy"] == "https://example.com/custom/windows-release-policy.json"
    assert urls["signature"] == DEFAULT_PUBLISHED_POLICY_URLS["signature"]
    assert urls["manifest"] == DEFAULT_PUBLISHED_POLICY_URLS["manifest"]
    assert urls["api_policy"] == DEFAULT_PUBLISHED_POLICY_URLS["api_policy"]
    assert urls["api_signature"] == DEFAULT_PUBLISHED_POLICY_URLS["api_signature"]
    assert urls["api_manifest"] == DEFAULT_PUBLISHED_POLICY_URLS["api_manifest"]
    assert urls["robots"] == "https://example.com/custom/robots.txt"
    assert urls["sitemap"] == "https://example.com/custom/sitemap.xml"


def test_check_public_pages_validates_hashes_signatures_and_api_aliases(monkeypatch, capsys):
    policy_bytes = _policy_bytes()
    signature_bytes = _signature_bytes(policy_bytes)
    manifest_bytes = _manifest_bytes(policy_bytes)
    monkeypatch.setattr(cli, "fetch_policy_bytes", _fake_source_fetch(policy_bytes, signature_bytes, manifest_bytes))

    _install_public_page_fetch(monkeypatch, _public_page_bytes(policy_bytes, signature_bytes, manifest_bytes))

    code = cli.main([
        "--check-public-pages",
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == 0
    assert "Public Pages: OK" in output
    assert "- landing: OK HTTP 200" in output
    assert "- api_policy: OK HTTP 200" in output
    assert "- api_signature: OK HTTP 200" in output
    assert "- canonical_signature: OK" in output
    assert "- api_signature_integrity: OK" in output
    assert "- policy_api_alias: OK" in output
    assert "- signature_api_alias: OK" in output
    assert "- manifest_policy_sha256: OK" in output
    assert "- api_manifest_policy_sha256: OK" in output
    assert "- published_urls: OK" in output
    assert "- robots: OK HTTP 200" in output


def test_check_public_pages_uses_custom_policy_published_urls(monkeypatch, capsys):
    custom_urls = {
        "landing": "https://example.com/custom",
        "policy": "https://example.com/custom/windows-release-policy.json",
        "signature": "https://example.com/custom/windows-release-policy.json.sig",
        "manifest": "https://example.com/custom/policy-manifest.json",
        "api_policy": "https://example.com/custom/api/v1/policy.json",
        "api_signature": "https://example.com/custom/api/v1/policy.sig",
        "api_manifest": "https://example.com/custom/api/v1/manifest.json",
    }
    policy_bytes = _policy_bytes_with_published_urls(custom_urls)
    signature_bytes = _signature_bytes(policy_bytes)
    manifest_bytes = _manifest_bytes(policy_bytes, published_urls=custom_urls)

    def fake_source_fetch(url, *args, **kwargs):
        url = str(url)
        if url == custom_urls["policy"]:
            return policy_bytes, "application/json"
        if url == custom_urls["signature"]:
            return signature_bytes, "application/json"
        if url == custom_urls["manifest"]:
            return manifest_bytes, "application/json"
        raise PolicyFetchError(f"unexpected URL {url}")

    monkeypatch.setattr(cli, "fetch_policy_bytes", fake_source_fetch)
    page_bytes = {
        custom_urls["landing"]: b"<html><title>custom mirror</title></html>",
        custom_urls["policy"]: policy_bytes,
        custom_urls["signature"]: signature_bytes,
        custom_urls["manifest"]: manifest_bytes,
        custom_urls["api_policy"]: policy_bytes,
        custom_urls["api_signature"]: signature_bytes,
        custom_urls["api_manifest"]: manifest_bytes,
        "https://example.com/custom/robots.txt": b"User-agent: *\nAllow: /\n",
        "https://example.com/custom/sitemap.xml": b"<?xml version=\"1.0\"?><urlset></urlset>",
    }
    public_fetches: list[str] = []

    def fake_public_url(url, *, timeout):
        url = str(url)
        public_fetches.append(url)
        return PublicResponse(url, 200, page_bytes[url], {"Content-Type": "application/json"})

    monkeypatch.setattr(cli, "_fetch_public_url", fake_public_url)

    code = cli.main([
        "--check-public-pages",
        "--policy-url",
        custom_urls["policy"],
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == 0
    assert "Public Pages: OK" in output
    assert f"Policy URL: {custom_urls['policy']}" in output
    assert f"Manifest URL: {custom_urls['manifest']}" in output
    assert f"- policy: OK HTTP 200 {custom_urls['policy']}" in output
    assert f"- api_policy: OK HTTP 200 {custom_urls['api_policy']}" in output
    assert "- published_urls: OK" in output
    assert public_fetches == [
        custom_urls["landing"],
        custom_urls["policy"],
        custom_urls["signature"],
        custom_urls["manifest"],
        custom_urls["api_policy"],
        custom_urls["api_signature"],
        custom_urls["api_manifest"],
        "https://example.com/custom/robots.txt",
        "https://example.com/custom/sitemap.xml",
    ]
    assert DEFAULT_POLICY_URL not in public_fetches


def test_check_public_pages_invalid_api_signature_fails(monkeypatch, capsys):
    policy_bytes = _policy_bytes()
    signature_bytes = _signature_bytes(policy_bytes)
    manifest_bytes = _manifest_bytes(policy_bytes)
    invalid_api_signature = (
        b'{"algorithm":"ed25519","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}\n'
    )
    monkeypatch.setattr(cli, "fetch_policy_bytes", _fake_source_fetch(policy_bytes, signature_bytes, manifest_bytes))
    _install_public_page_fetch(
        monkeypatch,
        _public_page_bytes(
            policy_bytes,
            signature_bytes,
            manifest_bytes,
            api_signature_bytes=invalid_api_signature,
        ),
    )

    code = cli.main([
        "--check-public-pages",
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "Policy source: PUBLIC_PAGES_FAILED" in output
    assert "- api_signature_integrity: FAILED" in output
    assert "API policy signature verification failed" in output


def test_check_public_pages_api_manifest_hash_mismatch_fails(monkeypatch, capsys):
    policy_bytes = _policy_bytes()
    signature_bytes = _signature_bytes(policy_bytes)
    manifest_bytes = _manifest_bytes(policy_bytes)
    api_manifest_bytes = _manifest_bytes(b"different policy bytes")
    monkeypatch.setattr(cli, "fetch_policy_bytes", _fake_source_fetch(policy_bytes, signature_bytes, manifest_bytes))
    _install_public_page_fetch(
        monkeypatch,
        _public_page_bytes(
            policy_bytes,
            signature_bytes,
            manifest_bytes,
            api_manifest_bytes=api_manifest_bytes,
        ),
    )

    code = cli.main([
        "--check-public-pages",
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "- api_manifest_policy_sha256: FAILED" in output
    assert "API manifest policy_sha256" in output


def test_check_public_pages_api_policy_bytes_mismatch_fails_without_manifest_marker(monkeypatch, capsys):
    policy_bytes = _policy_bytes()
    signature_bytes = _signature_bytes(policy_bytes)
    manifest_bytes = _manifest_bytes(policy_bytes)
    api_policy = _policy_json()
    api_policy["generated_at_utc"] = "2026-05-29T00:00:00Z"
    api_policy_bytes = (json.dumps(api_policy, indent=2, sort_keys=True) + "\n").encode("utf-8")
    api_signature_bytes = _signature_bytes(api_policy_bytes)
    api_manifest_bytes = _manifest_bytes(api_policy_bytes)
    monkeypatch.setattr(cli, "fetch_policy_bytes", _fake_source_fetch(policy_bytes, signature_bytes, manifest_bytes))
    _install_public_page_fetch(
        monkeypatch,
        _public_page_bytes(
            policy_bytes,
            signature_bytes,
            manifest_bytes,
            api_policy_bytes=api_policy_bytes,
            api_signature_bytes=api_signature_bytes,
            api_manifest_bytes=api_manifest_bytes,
        ),
    )

    code = cli.main([
        "--check-public-pages",
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "- policy_api_alias: FAILED" in output
    assert "canonical policy bytes differ from API policy bytes" in output


def test_check_public_pages_manifest_documented_api_policy_difference_passes(monkeypatch, capsys):
    policy_bytes = _policy_bytes()
    signature_bytes = _signature_bytes(policy_bytes)
    api_policy = _policy_json()
    api_policy["generated_at_utc"] = "2026-05-29T00:00:00Z"
    api_policy_bytes = (json.dumps(api_policy, indent=2, sort_keys=True) + "\n").encode("utf-8")
    api_signature_bytes = _signature_bytes(api_policy_bytes)
    manifest_bytes = _manifest_bytes(
        policy_bytes,
        api_policy_differs_from_canonical=True,
        api_policy_sha256=hashlib.sha256(api_policy_bytes).hexdigest(),
        api_signature_sha256=hashlib.sha256(api_signature_bytes).hexdigest(),
    )
    api_manifest_bytes = _manifest_bytes(
        api_policy_bytes,
        api_policy_differs_from_canonical=True,
        api_policy_sha256=hashlib.sha256(api_policy_bytes).hexdigest(),
        api_signature_sha256=hashlib.sha256(api_signature_bytes).hexdigest(),
    )
    monkeypatch.setattr(cli, "fetch_policy_bytes", _fake_source_fetch(policy_bytes, signature_bytes, manifest_bytes))
    _install_public_page_fetch(
        monkeypatch,
        _public_page_bytes(
            policy_bytes,
            signature_bytes,
            manifest_bytes,
            api_policy_bytes=api_policy_bytes,
            api_signature_bytes=api_signature_bytes,
            api_manifest_bytes=api_manifest_bytes,
        ),
    )

    code = cli.main([
        "--check-public-pages",
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == 0
    assert "Public Pages: OK" in output
    assert "- policy_api_alias: OK" in output
    assert "- signature_api_alias: OK" in output


def test_check_public_pages_policy_published_urls_mismatch_fails(monkeypatch, capsys):
    source_policy_bytes = _policy_bytes()
    source_signature_bytes = _signature_bytes(source_policy_bytes)
    source_manifest_bytes = _manifest_bytes(source_policy_bytes)
    public_policy = _policy_json()
    public_policy["published_urls"] = dict(DEFAULT_PUBLISHED_POLICY_URLS)
    public_policy["published_urls"]["api_policy"] = "https://avnsx.github.io/win11_release_guard/wrong/policy.json"
    public_policy_bytes = (json.dumps(public_policy, indent=2, sort_keys=True) + "\n").encode("utf-8")
    public_signature_bytes = _signature_bytes(public_policy_bytes)
    public_manifest_bytes = _manifest_bytes(public_policy_bytes)
    monkeypatch.setattr(
        cli,
        "fetch_policy_bytes",
        _fake_source_fetch(source_policy_bytes, source_signature_bytes, source_manifest_bytes),
    )
    _install_public_page_fetch(
        monkeypatch,
        _public_page_bytes(public_policy_bytes, public_signature_bytes, public_manifest_bytes),
    )

    code = cli.main([
        "--check-public-pages",
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "- published_urls: FAILED" in output
    assert "published_urls.api_policy expected" in output


def test_check_public_pages_auth_challenge_fails(monkeypatch, capsys):
    policy_bytes = _policy_bytes()
    signature_bytes = _signature_bytes(policy_bytes)
    manifest_bytes = _manifest_bytes(policy_bytes)
    monkeypatch.setattr(cli, "fetch_policy_bytes", _fake_source_fetch(policy_bytes, signature_bytes, manifest_bytes))

    def fake_public_url(url, *, timeout):
        if str(url) == DEFAULT_PUBLISHED_POLICY_URLS["landing"]:
            return PublicResponse(str(url), 401, b"", {"WWW-Authenticate": "Basic"})
        return PublicResponse(str(url), 200, b"{}", {"Content-Type": "application/json"})

    monkeypatch.setattr(cli, "_fetch_public_url", fake_public_url)

    code = cli.main([
        "--check-public-pages",
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "Policy source: PUBLIC_PAGES_FAILED" in output
    assert "Public Pages: FAILED" in output
    assert "auth challenge present" in output
