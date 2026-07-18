from __future__ import annotations

from pathlib import Path


WORKFLOW = Path(".github/workflows/publish-policy.yml")
SECRET_NAME = "WIN11_RELEASE_GUARD_POLICY_SIGNING_KEY_B64"


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_publish_policy_workflow_exists_and_has_expected_triggers() -> None:
    text = _workflow_text()

    assert WORKFLOW.exists()
    assert "workflow_dispatch:" in text
    assert "schedule:" in text
    assert 'cron: "23 6,18 * * *"' in text
    assert "push:" in text
    assert "branches:" in text
    assert "- main" in text
    assert "tags:" not in text
    assert '"v*.*.*"' not in text
    assert ".github/workflows/publish-policy.yml" in text
    assert "tools/generate_policy.py" in text
    assert "tools/check_project_identity.py" in text
    assert "tools/check_version_consistency.py" in text
    assert "pyproject.toml" in text
    assert "CHANGELOG.md" in text
    assert "win11_release_guard/**" in text
    assert "wiki/**" in text


def test_publish_policy_workflow_uses_minimum_pages_permissions() -> None:
    text = _workflow_text()

    assert "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true" in text
    assert "contents: read" in text
    assert "pages: write" in text
    assert "id-token: write" in text
    assert "sync-source-diagnostics-issues:" in text
    issue_sync_job = text.split("sync-source-diagnostics-issues:", 1)[1].split("\n  build:", 1)[0]
    assert "issues: write" in issue_sync_job
    assert SECRET_NAME not in issue_sync_job
    assert 'python -m pip install -e ".[test]"' in issue_sync_job
    assert "python -m compileall -q win11_release_guard tools" in issue_sync_job
    assert "tests/test_source_diagnostics_issue_sync.py" in issue_sync_job
    assert "tests/test_source_diagnostics_issue_metadata.py" in issue_sync_job
    assert "contents: write" not in issue_sync_job
    assert "pages: write" not in issue_sync_job
    assert "id-token: write" not in issue_sync_job
    build_job = text.split("\n  build:", 1)[1].split("\n  deploy:", 1)[0]
    assert "issues: write" not in build_job
    assert "GITHUB_TOKEN: ${{ github.token }}" not in build_job
    deploy_job = text.split("\n  deploy:", 1)[1].split("\n  verify-live-pages:", 1)[0]
    assert "pages: write" in deploy_job
    assert "id-token: write" in deploy_job
    assert "GITHUB_TOKEN: ${{ github.token }}" not in deploy_job
    assert "contents: write" not in text


def test_publish_policy_workflow_degrades_when_issue_sync_mutation_fails() -> None:
    text = _workflow_text()
    issue_sync_job = text.split("sync-source-diagnostics-issues:", 1)[1].split("\n  build:", 1)[0]
    build_job = text.split("\n  build:", 1)[1].split("\n  deploy:", 1)[0]

    assert "id: issue_sync" in issue_sync_job
    assert "continue-on-error: true" in issue_sync_job
    assert "Write degraded issue status when sync fails" in issue_sync_job
    assert "steps.issue_sync.outcome != 'success'" in issue_sync_job
    assert '"issue_status": {}' in issue_sync_job
    assert '"issue_sync": {' in issue_sync_job
    assert '"status": "unavailable"' in issue_sync_job
    assert '"reason": "github_issues_sync_failed"' in issue_sync_job
    assert "Source diagnostics GitHub Issues sync failed" in issue_sync_job
    assert "actions/upload-artifact@v7" in issue_sync_job
    assert "source-diagnostics-issue-status" in issue_sync_job
    assert "actions/download-artifact@v8" in build_job
    assert "--source-diagnostic-issue-status-file" in build_job
    assert "source diagnostics error events block publish" in build_job


def test_publish_policy_workflow_has_no_pat_or_branch_publish_mode() -> None:
    text = _workflow_text()
    lowered = text.lower()

    assert ("github" + "_pat_") not in lowered
    assert ("gh" + "p_") not in lowered
    assert "personal access token" not in lowered
    assert "gh_token" not in lowered
    lowered = lowered.replace("github_token: ${{ github.token }}", "")
    assert "github_token" not in lowered
    assert "gh-pages" not in lowered
    assert "git push" not in lowered
    assert "git commit" not in lowered


def test_publish_policy_workflow_requires_signing_secret_and_never_falls_back_to_stale_policy() -> None:
    text = _workflow_text()

    assert SECRET_NAME in text
    assert f'[ -z "${{{SECRET_NAME}:-}}" ]' in text
    assert "exit 1" in text
    assert "--signing-key-env WIN11_RELEASE_GUARD_POLICY_SIGNING_KEY_B64" in text
    assert "last-known-good" not in text
    assert "checked-in signed" not in text
    assert "cp win11_release_guard/data/windows-release-policy.json" not in text
    assert "--allow-unsigned" not in text


def test_publish_policy_workflow_does_not_reference_old_signing_secret_names() -> None:
    text = _workflow_text()
    old_secret_names = (
        "WIN_" + "RELEASE_GUARD_POLICY_SIGNING_KEY_B64",
        "WIN_" + "RELEASE_GUARD_SIGNING_KEY",
    )

    for secret_name in old_secret_names:
        assert secret_name not in text


def test_publish_policy_workflow_does_not_echo_signing_secret_or_trace_shell() -> None:
    text = _workflow_text()
    echo_lines = [line for line in text.splitlines() if "echo" in line]

    assert "set -x" not in text
    assert f"${SECRET_NAME}" not in "\n".join(echo_lines)
    assert f"${{{SECRET_NAME}}}" not in "\n".join(echo_lines)
    assert f"${{{SECRET_NAME}:-}}" not in "\n".join(echo_lines)


def test_publish_policy_workflow_runs_required_build_validate_and_scan_steps() -> None:
    text = _workflow_text()

    assert 'python-version: "3.12"' in text
    assert 'python -m pip install -e ".[test]"' in text
    assert "python -m compileall -q win11_release_guard tools" in text
    assert "pytest -q" in text
    assert "python tools/generate_policy.py" in text
    assert "python tools/sync_source_diagnostics_issues.py" in text
    assert "--issue-status-output" in text
    assert "--source-diagnostic-issue-status-file" in text
    assert "--output-dir site" in text
    assert "--write-index" in text
    assert "--write-robots" in text
    assert "--write-sitemap" in text
    assert "--write-manifest" in text
    assert "validate_policy_document" in text
    assert "verify_policy_signature" in text
    assert "python tools/check_project_identity.py" in text
    assert "python tools/check_version_consistency.py" in text
    assert "python tools/scan_for_secret_material.py" in text
    assert "CHANGELOG.md" in text
    assert "wiki" in text


def test_publish_policy_workflow_fails_on_source_diagnostics_error_events() -> None:
    text = _workflow_text()

    assert "source_diagnostics" in text
    assert 'event.get("severity") == "error"' in text
    assert "source diagnostics error events block publish" in text


def test_publish_policy_workflow_uses_pages_artifact_deployment_actions() -> None:
    text = _workflow_text()

    assert "actions/checkout@v7" in text
    assert "actions/setup-python@v6" in text
    assert "actions/configure-pages@v6" in text
    assert "actions/upload-pages-artifact@v5" in text
    assert "actions/upload-pages-artifact@" + "v3" not in text
    assert "actions/deploy-pages@v5" in text
    assert "actions/checkout@" + "v4" not in text
    assert "actions/setup-python@" + "v5" not in text
    assert "actions/configure-pages@" + "v5" not in text
    assert "actions/upload-pages-artifact@" + "v4" not in text
    assert "actions/deploy-pages@" + "v4" not in text


def test_publish_policy_workflow_verifies_live_pages_after_deploy() -> None:
    text = _workflow_text()

    assert "verify-live-pages:" in text
    assert "needs: deploy" in text
    assert "runs-on: ubuntu-latest" in text
    assert "python -m pip install -e ." in text
    assert "attempts=8" in text
    assert "sleep \"$delay_seconds\"" in text
    assert "python -m win11_release_guard --check-policy-source --check-public-pages" in text
    assert "Live Pages/API/signature/manifest verification failed" in text
    verify_job = text.split("verify-live-pages:", 1)[1]
    assert SECRET_NAME not in verify_job
    assert "contents: write" not in verify_job


def test_publish_policy_workflow_does_not_rely_only_on_schedule() -> None:
    text = _workflow_text()

    assert "workflow_dispatch:" in text
    assert "schedule:" in text
    assert "branches:" in text
    assert "- main" in text
    assert "tags:" not in text
    assert "verify-live-pages:" in text
    assert "python -m win11_release_guard --check-policy-source --check-public-pages" in text


def test_publish_policy_workflow_keeps_pages_lane_for_wiki_and_changelog() -> None:
    text = _workflow_text()

    assert "CHANGELOG.md" in text
    assert "wiki/**" in text
    assert "--write-index" in text
    assert "--write-sitemap" in text
    assert "actions/upload-pages-artifact@v5" in text
    assert "actions/deploy-pages@v5" in text
    assert "tools/sync_github_wiki.py" not in text
    assert "contents: write" not in text
