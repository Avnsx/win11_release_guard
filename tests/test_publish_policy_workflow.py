from __future__ import annotations

from pathlib import Path


WORKFLOW = Path(".github/workflows/publish-policy.yml")
SECRET_NAME = "WIN_RELEASE_GUARD_POLICY_SIGNING_KEY_B64"


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_publish_policy_workflow_exists_and_has_expected_triggers() -> None:
    text = _workflow_text()

    assert WORKFLOW.exists()
    assert "workflow_dispatch:" in text
    assert "schedule:" in text
    assert 'cron: "23 6,18 * * *"' in text
    assert "push:" in text
    assert ".github/workflows/publish-policy.yml" in text
    assert "tools/generate_policy.py" in text
    assert "win11_release_guard/**" in text


def test_publish_policy_workflow_uses_minimum_pages_permissions() -> None:
    text = _workflow_text()

    assert "contents: read" in text
    assert "pages: write" in text
    assert "id-token: write" in text
    assert "contents: write" not in text


def test_publish_policy_workflow_has_no_pat_or_branch_publish_mode() -> None:
    text = _workflow_text()
    lowered = text.lower()

    assert "github_pat_" not in lowered
    assert "ghp_" not in lowered
    assert "personal access token" not in lowered
    assert "gh_token" not in lowered
    assert "github_token" not in lowered
    assert "gh-pages" not in lowered
    assert "git push" not in lowered
    assert "git commit" not in lowered


def test_publish_policy_workflow_requires_signing_secret_and_never_falls_back_to_stale_policy() -> None:
    text = _workflow_text()

    assert SECRET_NAME in text
    assert f'[ -z "${{{SECRET_NAME}:-}}" ]' in text
    assert "exit 1" in text
    assert "--signing-key-env WIN_RELEASE_GUARD_POLICY_SIGNING_KEY_B64" in text
    assert "last-known-good" not in text
    assert "checked-in signed" not in text
    assert "cp win11_release_guard/data/windows-release-policy.json" not in text
    assert "--allow-unsigned" not in text


def test_publish_policy_workflow_runs_required_build_validate_and_scan_steps() -> None:
    text = _workflow_text()

    assert 'python-version: "3.12"' in text
    assert 'python -m pip install -e ".[test]"' in text
    assert "python -m compileall -q win11_release_guard tools" in text
    assert "pytest -q" in text
    assert "python tools/generate_policy.py" in text
    assert "--output-dir site" in text
    assert "--write-index" in text
    assert "--write-robots" in text
    assert "--write-sitemap" in text
    assert "--write-manifest" in text
    assert "validate_policy_document" in text
    assert "verify_policy_signature" in text
    assert "python tools/scan_for_secret_material.py" in text


def test_publish_policy_workflow_uses_pages_artifact_deployment_actions() -> None:
    text = _workflow_text()

    assert "actions/configure-pages@v5" in text
    assert "actions/upload-pages-artifact@v4" in text
    assert "actions/upload-pages-artifact@v3" not in text
    assert "actions/deploy-pages@v4" in text
