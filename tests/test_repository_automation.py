from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
WORKFLOWS = ROOT / ".github" / "workflows"
README = ROOT / "README.md"


BAD_TOKEN_PATTERNS = (
    "gh" + "p_",
    "github" + "_pat_",
    "personal access token",
    "gh_token",
    "github_token",
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_dependabot_config_exists_and_covers_python_and_actions() -> None:
    text = _read(DEPENDABOT)

    assert DEPENDABOT.exists()
    assert "version: 2" in text
    assert 'package-ecosystem: "pip"' in text
    assert 'package-ecosystem: "github-actions"' in text
    assert 'directory: "/"' in text
    assert 'interval: "weekly"' in text
    assert 'timezone: "Europe/Berlin"' in text
    assert "open-pull-requests-limit: 10" in text
    assert "python-runtime-dependencies" in text
    assert "python-dev-dependencies" in text
    assert "github-actions:" in text


def test_codeql_workflow_exists_and_uses_codeql_actions() -> None:
    workflow = WORKFLOWS / "codeql.yml"
    text = _read(workflow)

    assert workflow.exists()
    assert "name: CodeQL" in text
    assert "push:" in text
    assert "pull_request:" in text
    assert "schedule:" in text
    assert "workflow_dispatch:" in text
    assert "security-events: write" in text
    assert "contents: read" in text
    assert "actions: read" in text
    assert "github/codeql-action/init@v4" in text
    assert "github/codeql-action/analyze@v4" in text
    assert "languages: python" in text


def test_pylint_workflow_exists_and_lints_package_and_tools() -> None:
    workflow = WORKFLOWS / "pylint.yml"
    text = _read(workflow)

    assert workflow.exists()
    assert "name: Pylint" in text
    assert "push:" in text
    assert "pull_request:" in text
    assert "workflow_dispatch:" in text
    assert 'python-version: "3.12"' in text
    assert 'python -m pip install -e ".[test]" pylint' in text
    assert "pylint --fail-under=8.0 win11_release_guard tools" in text


def test_dependency_workflows_exist() -> None:
    freshness = _read(WORKFLOWS / "dependency-freshness.yml")
    audit = _read(WORKFLOWS / "dependency-audit.yml")

    assert "name: Dependency freshness" in freshness
    assert "workflow_dispatch:" in freshness
    assert "schedule:" in freshness
    assert "python tools/check_dependency_freshness.py --output dependency-freshness.json" in freshness

    assert "name: Dependency audit" in audit
    assert "workflow_dispatch:" in audit
    assert "schedule:" in audit
    assert "pip-audit --local" in audit


def test_readme_contains_truthful_workflow_badges() -> None:
    text = _read(README)
    badge_workflows = (
        "ci.yml",
        "publish-policy.yml",
        "codeql.yml",
        "pylint.yml",
        "dependency-audit.yml",
        "dependency-freshness.yml",
    )

    for workflow in badge_workflows:
        assert f"https://github.com/Avnsx/win-release-guard/actions/workflows/{workflow}/badge.svg" in text
        assert f"https://github.com/Avnsx/win-release-guard/actions/workflows/{workflow}" in text

    assert "fully up to date" not in text.lower()
    assert "Dependency freshness is checked by a scheduled workflow." in text
    assert "direct dependency specifiers" in text


def test_workflows_do_not_request_unnecessary_permissions_or_pat_tokens() -> None:
    for workflow in WORKFLOWS.glob("*.yml"):
        text = _read(workflow)
        lowered = text.lower()

        assert "contents: write" not in text
        assert "pull-requests: write" not in text
        assert "issues: write" not in text
        for pattern in BAD_TOKEN_PATTERNS:
            assert pattern.lower() not in lowered


def test_security_automation_doc_exists_and_explains_ui_limits() -> None:
    doc = ROOT / "docs" / "security-automation.md"
    text = _read(doc)

    assert doc.exists()
    assert ".github/dependabot.yml" in text
    assert ".github/workflows/codeql.yml" in text
    assert "Settings -> Code security and analysis -> Code scanning" in text
    assert "GitHub UI settings are not fully controlled by repository files." in text
    assert "workflow status badges" in text
