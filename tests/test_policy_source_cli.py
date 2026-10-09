from __future__ import annotations

from win11_release_guard import cli_policy_source as _cli_policy_source_module
from win11_release_guard import cli_public_pages as _cli_public_pages_module
import json
import hashlib
from datetime import datetime, timezone
from win11_release_guard import __main__ as cli
from win11_release_guard.config import DEFAULT_POLICY_URL, DEFAULT_PUBLISHED_POLICY_URLS, DEFAULT_RELEASE_HEALTH_URL
from win11_release_guard.exceptions import PolicyFetchError
from win11_release_guard.signing import load_private_key
from tests.support.policy_source_cli_helpers import (
    PublicResponse,
    TEST_PRIVATE_KEY,
    TEST_PUBLIC_KEY,
    _epoch,
    _fake_source_fetch,
    _install_public_page_fetch,
    _manifest_bytes,
    _policy_bytes,
    _policy_json,
    _public_page_bytes,
    _signature_bytes,
    _write_policy_and_signature,
)


def _raw_signature_bytes(policy_bytes: bytes) -> bytes:
    return load_private_key(TEST_PRIVATE_KEY).sign(policy_bytes)


def _policy_bytes_with_published_urls(published_urls: dict[str, str]) -> bytes:
    policy = _policy_json()
    policy["published_urls"] = dict(published_urls)
    return (json.dumps(policy, indent=2, sort_keys=True) + "\n").encode("utf-8")


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
        "events": [
            {
                "severity": "warning",
                "kind": "atom_newer_than_release_history",
                "release": "25H2",
                "build_family": 26200,
                "build": "26200.8461",
                "kb_article": "KB5089600",
                "affects_broad_target": True,
                "affects_required_baseline": True,
                "message": "Source freshness warning: Atom feed has newer build/KB entries not present in Release Health release_history.",
            }
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


def test_check_policy_source_does_not_print_notice_events_as_warnings(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "check_current_system", lambda config: (_ for _ in ()).throw(AssertionError("local probe ran")))
    policy_data = _policy_json()
    policy_data["source_diagnostics"] = {
        "release_health_html": {
            "source_url": DEFAULT_RELEASE_HEALTH_URL,
            "fetched_at_utc": "2026-05-31T00:00:00Z",
            "bytes": 1234,
            "status": "ok",
        },
        "atom_feed": {
            "source_url": "https://support.microsoft.com/en-us/feed/atom/4ec863cc-2ecd-e187-6cb3-b50c6545db92",
            "fetched_at_utc": "2026-05-31T00:00:01Z",
            "bytes": 5678,
            "status": "ok",
        },
        "events": [
            {
                "severity": "notice",
                "kind": "atom_newer_than_release_history",
                "release": "25H2",
                "build_family": 26200,
                "build": "26200.8460",
                "kb_article": "KB5089550",
                "affects_broad_target": True,
                "affects_required_baseline": False,
                "message": "Atom feed has newer Preview/OOB or non-baseline update information.",
            }
        ],
        "notices": ["Atom feed has newer Preview/OOB or non-baseline update information."],
        "warnings": [],
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
    assert "Warnings:" not in output
    assert "Preview/OOB or non-baseline" not in output


def test_check_policy_source_default_url_checks_manifest_without_local_probes(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check_current_system", lambda config: (_ for _ in ()).throw(AssertionError("local probe ran")))
    policy_bytes = _policy_bytes()
    signature_bytes = _signature_bytes(policy_bytes)
    manifest_bytes = _manifest_bytes(policy_bytes)
    calls: list[str] = []

    def fake_fetch(url, *args, **kwargs):
        calls.append(str(url))
        return _fake_source_fetch(policy_bytes, signature_bytes, manifest_bytes)(url, *args, **kwargs)

    monkeypatch.setattr(_cli_policy_source_module, "fetch_policy_bytes", fake_fetch)
    monkeypatch.setattr(_cli_public_pages_module, "fetch_policy_bytes", fake_fetch)

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

    monkeypatch.setattr(_cli_policy_source_module, "fetch_policy_bytes", fake_fetch)
    monkeypatch.setattr(_cli_public_pages_module, "fetch_policy_bytes", fake_fetch)

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
    monkeypatch.setattr(_cli_public_pages_module, "_utc_now_epoch_s", lambda: _epoch(datetime(2026, 6, 4, tzinfo=timezone.utc)))
    _patched_fetch_policy_bytes = _fake_source_fetch(policy_bytes, signature_bytes, manifest_bytes)
    monkeypatch.setattr(_cli_policy_source_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)
    monkeypatch.setattr(_cli_public_pages_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)

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
    assert "- public_pages_freshness: OK" in output
    assert "- robots: OK HTTP 200" in output


def test_check_public_pages_accepts_legacy_raw_signature_aliases(monkeypatch, capsys):
    policy_bytes = _policy_bytes()
    signature_bytes = _raw_signature_bytes(policy_bytes)
    manifest_bytes = _manifest_bytes(policy_bytes)
    monkeypatch.setattr(_cli_public_pages_module, "_utc_now_epoch_s", lambda: _epoch(datetime(2026, 6, 4, tzinfo=timezone.utc)))
    _patched_fetch_policy_bytes = _fake_source_fetch(policy_bytes, signature_bytes, manifest_bytes)
    monkeypatch.setattr(_cli_policy_source_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)
    monkeypatch.setattr(_cli_public_pages_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)

    _install_public_page_fetch(monkeypatch, _public_page_bytes(policy_bytes, signature_bytes, manifest_bytes))

    code = cli.main([
        "--check-public-pages",
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == 0
    assert "Public Pages: OK" in output
    assert "- canonical_signature: OK" in output
    assert "- api_signature_integrity: OK" in output


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
    monkeypatch.setattr(_cli_public_pages_module, "_utc_now_epoch_s", lambda: _epoch(datetime(2026, 6, 4, tzinfo=timezone.utc)))

    def fake_source_fetch(url, *args, **kwargs):
        url = str(url)
        if url == custom_urls["policy"]:
            return policy_bytes, "application/json"
        if url == custom_urls["signature"]:
            return signature_bytes, "application/json"
        if url == custom_urls["manifest"]:
            return manifest_bytes, "application/json"
        raise PolicyFetchError(f"unexpected URL {url}")

    monkeypatch.setattr(_cli_policy_source_module, "fetch_policy_bytes", fake_source_fetch)
    monkeypatch.setattr(_cli_public_pages_module, "fetch_policy_bytes", fake_source_fetch)
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

    monkeypatch.setattr(_cli_public_pages_module, "_fetch_public_url", fake_public_url)

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
    monkeypatch.setattr(_cli_public_pages_module, "_utc_now_epoch_s", lambda: _epoch(datetime(2026, 6, 4, tzinfo=timezone.utc)))
    _patched_fetch_policy_bytes = _fake_source_fetch(policy_bytes, signature_bytes, manifest_bytes)
    monkeypatch.setattr(_cli_policy_source_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)
    monkeypatch.setattr(_cli_public_pages_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)
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
