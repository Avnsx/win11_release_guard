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


def _write_named_workflow(tmp_path: Path, name: str, text: str) -> Path:
    workflow = tmp_path / ".github" / "workflows" / name
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
    assert "actions/checkout must use v7" in findings[0].message


def test_audit_fails_insecure_node_opt_out(tmp_path: Path) -> None:
    workflow = _write_workflow(
        tmp_path,
        _minimal_workflow("actions/checkout@v7")
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
        _minimal_workflow("actions/checkout@v7", include_node24=False),
    )

    findings = check_github_action_versions.audit_workflows([workflow])

    assert len(findings) == 1
    assert "does not set FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true" in findings[0].message


def test_audit_fails_unknown_first_party_action(tmp_path: Path) -> None:
    workflow = _write_workflow(tmp_path, _minimal_workflow("actions/cache@v4"))

    findings = check_github_action_versions.audit_workflows([workflow])

    assert len(findings) == 1
    assert "not in the audited first-party action version map" in findings[0].message


def test_audit_fails_unallowlisted_third_party_action(tmp_path: Path) -> None:
    sha = "0123456789abcdef0123456789abcdef01234567"
    workflow = _write_workflow(tmp_path, _minimal_workflow(f"third-party/example@{sha}"))

    findings = check_github_action_versions.audit_workflows([workflow])

    assert len(findings) == 1
    assert "must be explicitly allowlisted before use" in findings[0].message


def test_audit_fails_allowlisted_third_party_action_without_full_sha(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        check_github_action_versions,
        "ALLOWED_THIRD_PARTY_ACTIONS",
        {"third-party/example": "test fixture"},
    )
    workflow = _write_workflow(tmp_path, _minimal_workflow("third-party/example@v1"))

    findings = check_github_action_versions.audit_workflows([workflow])

    assert len(findings) == 1
    assert "must be pinned to a full 40-character commit SHA" in findings[0].message


def test_audit_allows_allowlisted_third_party_action_with_full_sha(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        check_github_action_versions,
        "ALLOWED_THIRD_PARTY_ACTIONS",
        {"third-party/example": "test fixture"},
    )
    sha = "0123456789abcdef0123456789abcdef01234567"
    workflow = _write_workflow(tmp_path, _minimal_workflow(f"third-party/example@{sha}"))

    findings = check_github_action_versions.audit_workflows([workflow])

    assert findings == []


def test_audit_allows_pypa_publish_action_only_in_pypi_workflow(tmp_path: Path, monkeypatch) -> None:
    sha = check_github_action_versions.PYPA_PUBLISH_ACTION_SHA
    monkeypatch.setattr(
        check_github_action_versions,
        "ALLOWED_THIRD_PARTY_ACTIONS",
        {
            "pypa/gh-action-pypi-publish": {
                "sha": sha,
                "workflows": (Path(".github/workflows/pypi-publish.yml"),),
            }
        },
    )
    workflow = _write_named_workflow(tmp_path, "pypi-publish.yml", _minimal_workflow(f"pypa/gh-action-pypi-publish@{sha}"))

    findings = check_github_action_versions.audit_workflows([workflow])

    assert findings == []


def test_audit_rejects_pypa_publish_action_outside_pypi_workflow(tmp_path: Path, monkeypatch) -> None:
    sha = check_github_action_versions.PYPA_PUBLISH_ACTION_SHA
    monkeypatch.setattr(
        check_github_action_versions,
        "ALLOWED_THIRD_PARTY_ACTIONS",
        {
            "pypa/gh-action-pypi-publish": {
                "sha": sha,
                "workflows": (Path(".github/workflows/pypi-publish.yml"),),
            }
        },
    )
    workflow = _write_named_workflow(tmp_path, "not-pypi.yml", _minimal_workflow(f"pypa/gh-action-pypi-publish@{sha}"))

    findings = check_github_action_versions.audit_workflows([workflow])

    assert len(findings) == 1
    assert "is allowed only in .github/workflows/pypi-publish.yml" in findings[0].message


def test_audit_rejects_pypa_publish_action_wrong_sha(tmp_path: Path, monkeypatch) -> None:
    sha = check_github_action_versions.PYPA_PUBLISH_ACTION_SHA
    wrong_sha = "0123456789abcdef0123456789abcdef01234567"
    monkeypatch.setattr(
        check_github_action_versions,
        "ALLOWED_THIRD_PARTY_ACTIONS",
        {
            "pypa/gh-action-pypi-publish": {
                "sha": sha,
                "workflows": (Path(".github/workflows/pypi-publish.yml"),),
            }
        },
    )
    workflow = _write_named_workflow(
        tmp_path,
        "pypi-publish.yml",
        _minimal_workflow(f"pypa/gh-action-pypi-publish@{wrong_sha}"),
    )

    findings = check_github_action_versions.audit_workflows([workflow])

    assert len(findings) == 1
    assert f"must be pinned to {sha}" in findings[0].message


def test_audit_cli_returns_nonzero_for_stale_fixture(tmp_path: Path, capsys) -> None:
    workflow = _write_workflow(tmp_path, _minimal_workflow("actions/setup-python@" + "v5"))

    code = check_github_action_versions.main([str(workflow)])

    captured = capsys.readouterr()
    assert code == 1
    assert "actions/setup-python must use v6" in captured.err
