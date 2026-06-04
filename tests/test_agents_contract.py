from __future__ import annotations

from pathlib import Path


def _agents_text() -> str:
    return (Path(__file__).resolve().parents[1] / "AGENTS.md").read_text(encoding="utf-8")


def test_agents_contract_exists() -> None:
    assert (Path(__file__).resolve().parents[1] / "AGENTS.md").is_file()


def test_agents_contract_locks_public_and_import_names() -> None:
    text = _agents_text()

    assert "win11_release_guard" in text
    assert "win11_release_guard" in text
    assert "must not revert naming" in text
    assert "https://github.com/Avnsx/win11_release_guard" in text
    assert "https://avnsx.github.io/win11_release_guard/windows-release-policy.json" in text
    assert "Console script: `win11_release_guard`" in text
    assert "python -m win11_release_guard" in text


def test_agents_contract_locks_secret_and_token_rules() -> None:
    text = _agents_text()
    lower_text = text.lower()

    assert "WIN11_RELEASE_GUARD_POLICY_SIGNING_KEY_B64" in text
    assert "clients must not contain github tokens" in lower_text
    assert "private signing keys must not be committed" in lower_text


def test_agents_contract_requires_descriptive_commit_messages() -> None:
    text = _agents_text()
    lower_text = text.lower()

    assert "commit message rules" in lower_text
    assert "do not include prompt numbers" in lower_text
    assert "mention the actual change" in lower_text
    assert "harden signed policy feed deployment" in lower_text
    assert "checkpoint after prompt 12" in lower_text


def test_agents_contract_requires_live_gate_for_deployment_affecting_changes() -> None:
    text = _agents_text()

    assert "Deployment-Affecting Live Verification Gate" in text
    assert "policy generator changes" in text
    assert "manifest/API alias changes" in text
    assert "source URL or published URL changes" in text
    assert "`--check-policy-source`" in text
    assert "`--check-public-pages`" in text
    assert "python -m compileall -q win11_release_guard tools" in text
    assert "pytest -q" in text
    assert "python tools/generate_signing_key.py --out-dir .tmp/signing-test --key-id test-policy-key" in text
    assert "python tools/generate_policy.py --release-health-html tests/fixtures/windows11-release-health.html" in text
    assert "python tools/scan_for_secret_material.py site win11_release_guard tests tools docs README.md AGENTS.md pyproject.toml .github" in text
    assert "python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip" in text
    assert "python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip" in text
    assert "python -m win11_release_guard --check-policy-source" in text
    assert "python -m win11_release_guard --check-public-pages" in text
    assert "If live network is unavailable" in text
    assert "do not claim live success" in text
    assert "exact failing URL, status, and" in text


def test_agents_contract_mentions_codeql_settings_limit() -> None:
    text = _agents_text()

    assert "CodeQL code scanning is configured by `.github/workflows/codeql.yml`" in text
    assert "Code security and analysis" in text


def test_agents_contract_requires_validated_clean_archive_for_handoff() -> None:
    text = _agents_text()

    assert "only recommended handoff artifact is the validated clean archive" in text
    assert "python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip" in text
    assert "python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip" in text
    assert "Do not share raw worktree ZIPs" in text
    assert ".git/" in text
    assert ".tmp/" in text
    assert "private signing-key scratch" in text
