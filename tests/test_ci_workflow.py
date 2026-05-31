from __future__ import annotations

from pathlib import Path


WORKFLOW = Path(".github/workflows/ci.yml")


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_ci_workflow_exists_and_has_required_triggers() -> None:
    text = _workflow_text()

    assert WORKFLOW.exists()
    assert "push:" in text
    assert "pull_request:" in text
    assert "workflow_dispatch:" in text


def test_ci_workflow_runs_ubuntu_windows_and_python_312() -> None:
    text = _workflow_text()

    assert "ubuntu-latest" in text
    assert "windows-latest" in text
    assert '"3.11"' in text
    assert '"3.12"' in text
    assert "matrix.os" in text
    assert "matrix.python-version" in text


def test_ci_workflow_uses_node24_ready_actions() -> None:
    text = _workflow_text()
    insecure_node_opt_out = "ACTIONS_ALLOW_USE_" + "UNSECURE_NODE_VERSION"

    assert "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true" in text
    assert "actions/checkout@v6" in text
    assert "actions/setup-python@v6" in text
    assert "actions/checkout@" + "v4" not in text
    assert "actions/setup-python@" + "v5" not in text
    assert insecure_node_opt_out not in text


def test_ci_workflow_runs_required_commands() -> None:
    text = _workflow_text()

    assert 'python -m pip install -e ".[test]"' in text
    assert "python -m compileall -q win11_release_guard tools" in text
    assert "python tools/check_github_action_versions.py" in text
    assert "pytest -q" in text
    assert "python tools/generate_policy.py" in text
    assert "--release-health-html tests/fixtures/windows11-release-health.html" in text
    assert "--atom-feed tests/fixtures/windows11-atom.xml" in text
    assert "--output-dir site" in text
    assert "--write-index" in text
    assert "--write-robots" in text
    assert "--write-sitemap" in text
    assert "--write-manifest" in text
    assert "python -m win11_release_guard" in text
    assert "--json" in text
    assert "--no-wua" in text
    assert "--policy-url win11_release_guard/data/windows-release-policy.json" in text
    assert "python -m json.tool" in text
    assert "python tools/export_clean_archive.py" in text
    assert "python tools/scan_for_secret_material.py" in text
