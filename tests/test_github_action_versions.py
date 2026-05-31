from __future__ import annotations

from pathlib import Path

from tools import check_github_action_versions


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
INSECURE_NODE_OPT_OUT = "ACTIONS_ALLOW_USE_" + "UNSECURE_NODE_VERSION"


def _write_workflow(tmp_path: Path, text: str) -> Path:
    workflow = tmp_path / ".github" / "workflows" / "test.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(text, encoding="utf-8")
    return workflow


def _minimal_workflow(uses_line: str, *, include_node24: bool = True) -> str:
    env = (
        "env:\n"
        "  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true\n"
        "\n"
        if include_node24
        else ""
    )
    return (
        "name: Test\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "\n"
        f"{env}"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: {uses_line}\n"
    )


def test_current_workflows_pass_action_version_audit() -> None:
    workflows = sorted(WORKFLOWS.glob("*.yml"))

    findings = check_github_action_versions.audit_workflows(workflows)

    assert findings == []


def test_audit_fails_stale_checkout_fixture(tmp_path: Path) -> None:
    workflow = _write_workflow(tmp_path, _minimal_workflow("actions/checkout@" + "v4"))

    findings = check_github_action_versions.audit_workflows([workflow])

    assert len(findings) == 1
    assert "actions/checkout must use v6" in findings[0].message


def test_audit_fails_insecure_node_opt_out(tmp_path: Path) -> None:
    workflow = _write_workflow(
        tmp_path,
        _minimal_workflow("actions/checkout@v6")
        + "\n"
        + "env:\n"
        + f"  {INSECURE_NODE_OPT_OUT}: true\n",
    )

    findings = check_github_action_versions.audit_workflows([workflow])

    assert any(INSECURE_NODE_OPT_OUT in finding.message for finding in findings)


def test_audit_allows_documented_codeql_v4_exception(tmp_path: Path) -> None:
    workflow = _write_workflow(tmp_path, _minimal_workflow("github/codeql-action/init@v4"))

    findings = check_github_action_versions.audit_workflows([workflow])

    assert findings == []


def test_audit_fails_missing_node24_force_env(tmp_path: Path) -> None:
    workflow = _write_workflow(
        tmp_path,
        _minimal_workflow("actions/checkout@v6", include_node24=False),
    )

    findings = check_github_action_versions.audit_workflows([workflow])

    assert len(findings) == 1
    assert "does not set FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true" in findings[0].message


def test_audit_cli_returns_nonzero_for_stale_fixture(tmp_path: Path, capsys) -> None:
    workflow = _write_workflow(tmp_path, _minimal_workflow("actions/setup-python@" + "v5"))

    code = check_github_action_versions.main([str(workflow)])

    captured = capsys.readouterr()
    assert code == 1
    assert "actions/setup-python must use v6" in captured.err
