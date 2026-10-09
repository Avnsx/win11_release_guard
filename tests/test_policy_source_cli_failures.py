from __future__ import annotations

from win11_release_guard import cli_policy_source as _cli_policy_source_module
from win11_release_guard import cli_public_pages as _cli_public_pages_module
import json
from datetime import datetime, timedelta, timezone
from win11_release_guard import __main__ as cli
from win11_release_guard.config import DEFAULT_POLICY_URL, DEFAULT_PUBLISHED_POLICY_URLS
from win11_release_guard.exceptions import PolicyFetchError
from tests.support.policy_source_cli_helpers import (
    PublicResponse,
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


def _policy_bytes_generated_at(generated_at_utc: str) -> bytes:
    policy = _policy_json()
    policy["generated_at_utc"] = generated_at_utc
    return (json.dumps(policy, indent=2, sort_keys=True) + "\n").encode("utf-8")


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
    _patched_fetch_policy_bytes = lambda *args, **kwargs: (_ for _ in ()).throw(PolicyFetchError("network unavailable"))
    monkeypatch.setattr(_cli_policy_source_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)
    monkeypatch.setattr(_cli_public_pages_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)

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

    monkeypatch.setattr(_cli_policy_source_module, "fetch_policy_bytes", fake_fetch)
    monkeypatch.setattr(_cli_public_pages_module, "fetch_policy_bytes", fake_fetch)

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


def test_check_policy_source_manifest_hash_mismatch_fails(monkeypatch, capsys):
    policy_bytes = _policy_bytes()
    signature_bytes = _signature_bytes(policy_bytes)
    bad_manifest = b'{"policy_sha256":"bad"}\n'
    _patched_fetch_policy_bytes = _fake_source_fetch(policy_bytes, signature_bytes, bad_manifest)
    monkeypatch.setattr(_cli_policy_source_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)
    monkeypatch.setattr(_cli_public_pages_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)

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


def test_check_public_pages_fails_when_manifest_epoch_is_15_days_old(monkeypatch, capsys):
    now = datetime(2026, 6, 20, tzinfo=timezone.utc)
    generated = now - timedelta(days=15)
    policy_bytes = _policy_bytes_generated_at(generated.isoformat())
    signature_bytes = _signature_bytes(policy_bytes)
    manifest_bytes = _manifest_bytes(policy_bytes, generated_at_epoch_s=_epoch(generated))
    monkeypatch.setattr(_cli_public_pages_module, "_utc_now_epoch_s", lambda: _epoch(now))
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
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "Policy source: PUBLIC_PAGES_FAILED" in output
    assert "- public_pages_freshness: FAILED" in output
    assert "15 days old" in output
    assert "14-day public freshness threshold" in output


def test_check_public_pages_fails_strict_stale_when_manifest_epoch_is_46_days_old(monkeypatch, capsys):
    now = datetime(2026, 6, 20, tzinfo=timezone.utc)
    generated = now - timedelta(days=46)
    policy_bytes = _policy_bytes_generated_at(generated.isoformat())
    signature_bytes = _signature_bytes(policy_bytes)
    manifest_bytes = _manifest_bytes(policy_bytes, generated_at_epoch_s=_epoch(generated))
    monkeypatch.setattr(_cli_public_pages_module, "_utc_now_epoch_s", lambda: _epoch(now))
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
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "- public_pages_freshness: FAILED" in output
    assert "46 days old" in output
    assert "45-day strict stale threshold" in output


def test_check_public_pages_freshness_falls_back_to_policy_generated_at(monkeypatch, capsys):
    now = datetime(2026, 6, 20, tzinfo=timezone.utc)
    generated = now - timedelta(days=15)
    policy_bytes = _policy_bytes_generated_at(generated.isoformat())
    signature_bytes = _signature_bytes(policy_bytes)
    manifest_bytes = _manifest_bytes(policy_bytes)
    monkeypatch.setattr(_cli_public_pages_module, "_utc_now_epoch_s", lambda: _epoch(now))
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
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "- public_pages_freshness: FAILED" in output
    assert "15 days old" in output


def test_check_public_pages_invalid_manifest_epoch_fails_clearly(monkeypatch, capsys):
    now = datetime(2026, 6, 20, tzinfo=timezone.utc)
    policy_bytes = _policy_bytes_generated_at(now.isoformat())
    signature_bytes = _signature_bytes(policy_bytes)
    manifest_bytes = _manifest_bytes(policy_bytes, generated_at_epoch_s="not-an-epoch")
    monkeypatch.setattr(_cli_public_pages_module, "_utc_now_epoch_s", lambda: _epoch(now))
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
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "- public_pages_freshness: FAILED" in output
    assert "manifest.generated_at_epoch_s must be an integer epoch timestamp" in output


def test_check_public_pages_invalid_api_signature_fails(monkeypatch, capsys):
    policy_bytes = _policy_bytes()
    signature_bytes = _signature_bytes(policy_bytes)
    manifest_bytes = _manifest_bytes(policy_bytes)
    invalid_api_signature = (
        b'{"algorithm":"ed25519","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}\n'
    )
    _patched_fetch_policy_bytes = _fake_source_fetch(policy_bytes, signature_bytes, manifest_bytes)
    monkeypatch.setattr(_cli_policy_source_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)
    monkeypatch.setattr(_cli_public_pages_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)
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
    _patched_fetch_policy_bytes = _fake_source_fetch(policy_bytes, signature_bytes, manifest_bytes)
    monkeypatch.setattr(_cli_policy_source_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)
    monkeypatch.setattr(_cli_public_pages_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)
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
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "- policy_api_alias: FAILED" in output
    assert "canonical policy bytes differ from API policy bytes" in output


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
    _patched_fetch_policy_bytes = _fake_source_fetch(source_policy_bytes, source_signature_bytes, source_manifest_bytes)
    monkeypatch.setattr(_cli_policy_source_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)
    monkeypatch.setattr(_cli_public_pages_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)
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
    _patched_fetch_policy_bytes = _fake_source_fetch(policy_bytes, signature_bytes, manifest_bytes)
    monkeypatch.setattr(_cli_policy_source_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)
    monkeypatch.setattr(_cli_public_pages_module, "fetch_policy_bytes", _patched_fetch_policy_bytes)

    def fake_public_url(url, *, timeout):
        if str(url) == DEFAULT_PUBLISHED_POLICY_URLS["landing"]:
            return PublicResponse(str(url), 401, b"", {"WWW-Authenticate": "Basic"})
        return PublicResponse(str(url), 200, b"{}", {"Content-Type": "application/json"})

    monkeypatch.setattr(_cli_public_pages_module, "_fetch_public_url", fake_public_url)

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
