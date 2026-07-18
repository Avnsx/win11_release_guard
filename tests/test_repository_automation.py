from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
WORKFLOWS = ROOT / ".github" / "workflows"
README = ROOT / "README.md"
RELEASE_WORKFLOW = WORKFLOWS / "release.yml"
ISSUE_SYNC_WORKFLOW = WORKFLOWS / "sync-source-diagnostics-issues.yml"
WIKI_SYNC_WORKFLOW = WORKFLOWS / "sync-wiki.yml"


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
    assert "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true" in text
    assert "actions/checkout@v7" in text
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
    assert "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true" in text
    assert "actions/checkout@v7" in text
    assert "actions/setup-python@v6" in text
    assert 'python-version: "3.12"' in text
    assert 'python -m pip install -e ".[test]" pylint' in text
    assert "pylint --fail-under=8.0 win11_release_guard tools" in text


def test_dependency_workflows_exist() -> None:
    freshness = _read(WORKFLOWS / "dependency-freshness.yml")
    audit = _read(WORKFLOWS / "dependency-audit.yml")

    assert "name: Dependency freshness" in freshness
    assert "workflow_dispatch:" in freshness
    assert "schedule:" in freshness
    assert "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true" in freshness
    assert "actions/checkout@v7" in freshness
    assert "actions/setup-python@v6" in freshness
    assert "python tools/check_dependency_freshness.py --output dependency-freshness.json" in freshness

    assert "name: Dependency audit" in audit
    assert "workflow_dispatch:" in audit
    assert "schedule:" in audit
    assert "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true" in audit
    assert "actions/checkout@v7" in audit
    assert "actions/setup-python@v6" in audit
    assert "pip-audit --local" in audit


def test_readme_contains_truthful_workflow_badges() -> None:
    text = _read(README)
    lower_text = text.lower()
    repository_url = "https://github.com/Avnsx/win11_release_guard"
    old_repository_url = "https://github.com/Avnsx/" + ("win" + "-release-guard")
    badge_workflows = (
        "ci.yml",
        "publish-policy.yml",
        "codeql.yml",
        "pylint.yml",
        "dependency-audit.yml",
        "dependency-freshness.yml",
    )

    for workflow in badge_workflows:
        assert f"{repository_url}/actions/workflows/{workflow}/badge.svg" in text
        assert f"{repository_url}/actions/workflows/{workflow}" in text

    assert old_repository_url not in text
    assert "fully up to date" not in lower_text
    assert "Dependency freshness is checked by a scheduled workflow." in text
    assert "Dependency freshness` is a scheduled direct-dependency check" in text
    assert "always-current dependency guarantee" in text
    assert "direct dependency specifiers" in text
    assert "The Pylint badge reports the workflow" in text
    assert "current `--fail-under=8.0` gate" in text
    assert "not a permanent quality" in text
    assert "perfect code quality" not in lower_text


def test_readme_documents_branding_and_runtime_trust_model() -> None:
    text = _read(README)
    normalized = " ".join(text.split())
    agents = _read(ROOT / "AGENTS.md")
    ci_workflow = _read(WORKFLOWS / "ci.yml")
    hero_line = (
        "![Windows 11 Release Guard dashboard preview]"
        "(https://raw.githubusercontent.com/Avnsx/win11_release_guard/main/"
        "assets/images/windows-11-release-guard-hero-dashboard.png)"
    )

    assert text.splitlines()[0] == hero_line
    assert "\n# Windows 11 Release Guard\n" in text
    assert text.index(hero_line) < text.index("\n# Windows 11 Release Guard\n")
    assert "Windows release policy guard for broad-fleet Windows 11 version checks." in text
    assert "installed console command, and Python import package use the same `win11_release_guard` name" in normalized
    assert "Repository | `https://github.com/Avnsx/win11_release_guard`" in text
    assert "Public feed | `https://avnsx.github.io/win11_release_guard/windows-release-policy.json`" in text
    assert "Python entry point | `python -m win11_release_guard`" in text
    assert "Console script | `win11_release_guard`" in text
    assert "Do not reintroduce the removed root prototype script" in agents
    assert "https://avnsx.github.io/win11_release_guard/windows-release-policy.json" in text
    assert "https://avnsx.github.io/win11_release_guard/windows-release-policy.json.sig" in text
    assert "https://avnsx.github.io/win11_release_guard/policy-manifest.json" in text
    assert "Runtime clients do not authenticate to GitHub" in text
    assert "do not need GitHub tokens" in text
    assert "private repository access" in text
    assert "paid signing" in text
    assert "diagnostics never override the policy verdict" in text
    assert "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true" in ci_workflow
    assert "python -m win11_release_guard --check-policy-source" in text
    assert "python -m win11_release_guard --check-public-pages" in text
    assert "python tools/export_clean_archive.py" in text


def test_readme_uses_pages_wiki_as_primary_public_documentation() -> None:
    text = _read(README)

    primary_pages_links = (
        "https://avnsx.github.io/win11_release_guard/wiki/Quick-Start/",
        "https://avnsx.github.io/win11_release_guard/wiki/CLI-and-RMM-Usage/",
        "https://avnsx.github.io/win11_release_guard/wiki/GitHub-Pages-Dashboard/",
        "https://avnsx.github.io/win11_release_guard/wiki/changelog/",
    )

    for url in primary_pages_links:
        assert url in text
    assert "| Pages Wiki home | https://avnsx.github.io/win11_release_guard/wiki/ |" in text
    assert "| GitHub internal Wiki (Markdown mirror) | https://github.com/Avnsx/win11_release_guard/wiki |" in text
    assert "The generated Pages Wiki is the primary public, indexed documentation surface." in text


def test_readme_uses_github_alerts_for_compact_guidance() -> None:
    text = _read(README)

    assert text.count("> [!IMPORTANT]") == 1
    assert text.count("> [!TIP]") == 1
    assert text.count("> [!NOTE]") == 1
    assert text.count("> [!WARNING]") == 1
    assert "Compliance trust comes from the signed public policy JSON plus detached signature" in text
    assert "RMM jobs normally want stable JSON and exit codes first" in text
    assert "`Policy Feed Currency` is the latest compilation timestamp for the parsed policy results" in text
    assert "Source Diagnostics explain parser/source health" in text
    assert "https://avnsx.github.io/win11_release_guard/wiki/Policy-Feed-and-Trust-Model/" in text
    assert "https://avnsx.github.io/win11_release_guard/wiki/Local-Windows-Detection/" in text
    assert "https://avnsx.github.io/win11_release_guard/wiki/CLI-and-RMM-Usage/" in text
    assert "https://avnsx.github.io/win11_release_guard/wiki/Anti-Static-Freshness/" in text
    assert "https://avnsx.github.io/win11_release_guard/wiki/Source-Diagnostics/" in text


def test_workflows_do_not_request_unnecessary_permissions_or_pat_tokens() -> None:
    for workflow in WORKFLOWS.glob("*.yml"):
        text = _read(workflow)
        lowered = text.lower()

        if workflow.name in {"release.yml", "sync-wiki.yml"}:
            assert "contents: write" in text
            lowered = lowered.replace("gh_token: ${{ github.token }}", "")
        else:
            assert "contents: write" not in text
        if workflow.name in {"sync-source-diagnostics-issues.yml", "publish-policy.yml"}:
            assert "issues: write" in text
            lowered = lowered.replace("github_token: ${{ github.token }}", "")
        else:
            assert "issues: write" not in text
        assert "pull-requests: write" not in text
        insecure_node_opt_out = "ACTIONS_ALLOW_USE_" + "UNSECURE_NODE_VERSION"
        assert insecure_node_opt_out not in text
        for pattern in BAD_TOKEN_PATTERNS:
            assert pattern.lower() not in lowered


def test_source_diagnostics_issue_sync_workflow_is_manual_and_minimal() -> None:
    text = _read(ISSUE_SYNC_WORKFLOW)

    assert ISSUE_SYNC_WORKFLOW.exists()
    assert "name: Sync source diagnostics issues" in text
    assert "workflow_dispatch:" in text
    assert "schedule:" not in text
    assert "push:" not in text
    assert "pull_request:" not in text
    assert "contents: read" in text
    assert "issues: write" in text
    assert "contents: write" not in text
    assert "pages: write" not in text
    assert "id-token: write" not in text
    assert "GITHUB_TOKEN: ${{ github.token }}" in text
    assert 'python -m pip install -e ".[test]"' in text
    assert "python -m compileall -q win11_release_guard tools" in text
    assert "tests/test_source_diagnostics_issue_sync.py" in text
    assert "tests/test_source_diagnostics_issue_metadata.py" in text
    assert "tests/test_policy_generator.py" in text
    assert "tools/sync_source_diagnostics_issues.py" in text
    assert "include_notices:" not in text
    assert "--include-notices" not in text
    assert "--create-limit" in text
    assert "--dry-run" in text
    assert "--dry-run-report-output" in text
    assert "--dry-run-report-format markdown" in text
    assert "actions/upload-artifact@v7" in text
    assert "source-diagnostics-issue-sync-dry-run" in text


def test_github_wiki_sync_workflow_is_manual_tagged_and_minimal() -> None:
    text = _read(WIKI_SYNC_WORKFLOW)

    assert WIKI_SYNC_WORKFLOW.exists()
    assert "name: Sync GitHub Wiki" in text
    assert "workflow_dispatch:" in text
    assert "dry_run:" in text
    assert "default: true" in text
    assert "push:" in text
    assert '"v*.*.*"' in text
    assert "pull_request:" not in text
    assert "schedule:" not in text
    assert "contents: read" in text
    assert "contents: write" in text
    assert "issues: write" not in text
    assert "pages: write" not in text
    assert "id-token: write" not in text
    assert "WRG_WIKI_SYNC_TOKEN: ${{ github.token }}" in text
    assert "persist-credentials: false" in text
    assert "tools/sync_github_wiki.py" in text
    assert "tests/test_github_wiki_sync.py" in text
    assert "--dry-run" in text
    assert "--push" in text
    assert "--artifact-dir" in text
    assert "actions/upload-artifact@v7" in text
    assert "if: always()" in text
    assert "if-no-files-found: error" in text
    assert "continue-on-error" not in text
    assert "github-wiki-sync-markdown" in text
    assert ".wiki.git" not in text
    assert "git push" not in text
    assert ("gh" + "p_") not in text.lower()
    assert ("github" + "_pat_") not in text.lower()


def test_release_workflow_exists_with_explicit_tagged_triggers() -> None:
    text = _read(RELEASE_WORKFLOW)

    assert RELEASE_WORKFLOW.exists()
    assert "name: Release" in text
    assert "workflow_dispatch:" in text
    assert "tag:" in text
    assert "create_tag:" in text
    assert "draft:" in text
    assert "push:" in text
    assert '"v*.*.*"' in text
    assert "contents: write" in text
    assert "pages: write" not in text
    assert "id-token: write" not in text


def test_release_workflow_validates_tag_version_parity_before_publication() -> None:
    text = _read(RELEASE_WORKFLOW)

    assert r"^v[0-9]+\.[0-9]+\.[0-9]+$" in text
    assert 'version="${tag#v}"' in text
    assert "tomllib.loads" in text
    assert 'data["project"]["version"]' in text
    assert "does not match pyproject version" in text
    assert "python tools/check_version_consistency.py" in text
    assert "Tag '${tag}' does not exist" in text
    assert "create_tag=true is allowed only from main" in text
    assert "Check release changelog and wiki docs" in text
    assert "CHANGELOG.md must contain a historical section" in text
    assert 'docs/releases/${tag}.md' in text
    assert 'wiki/Release-${tag}.md' in text


def test_release_workflow_runs_required_gates_and_attaches_clean_archive() -> None:
    text = _read(RELEASE_WORKFLOW)

    assert "actions/checkout@v7" in text
    assert "actions/setup-python@v6" in text
    assert 'python-version: "3.12"' in text
    assert 'python -m pip install -e ".[test]"' in text
    assert "python -m compileall -q win11_release_guard tools tests" in text
    assert "python tools/check_project_identity.py" in text
    assert "python tools/check_github_action_versions.py" in text
    assert "python tools/check_version_consistency.py" in text
    assert "python tools/check_dependency_freshness.py --output dependency-freshness.json" in text
    assert "pytest -q --durations=20" in text
    assert "python -m win11_release_guard --self-test" in text
    assert "python -m win11_release_guard --check-policy-source" in text
    assert "python -m win11_release_guard --check-public-pages" in text
    assert "python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip --skip-test-run" in text
    assert "python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip --skip-test-run" in text
    assert "python tools/scan_for_secret_material.py" in text
    assert "gh release create" in text
    assert "dist/win11_release_guard-source.zip#win11_release_guard-source.zip" in text
    assert "--notes-file \".tmp/release-notes.md\"" in text
    assert 'if [ "${{ github.event_name }}" != "workflow_dispatch" ] || [ "${{ inputs.draft }}" = "true" ]; then' in text
    assert "--draft" in text


def test_release_workflow_body_uses_compact_human_format() -> None:
    text = _read(RELEASE_WORKFLOW)

    # Compact, human-facing release notes per AGENTS.md "Release Notes Format".
    assert "## Windows 11 Release Guard" in text
    assert "- Version: ${version}" in text
    assert "- Commit: ${commit_sha}" in text
    assert (
        "Read the related changelog hosted here: "
        "https://avnsx.github.io/win11_release_guard/wiki/changelog/v${version}/"
    ) in text
    assert "### Download from PyPI ⬇️" in text
    assert "https://pypi.org/project/win11-release-guard/" in text
    assert "### Summary 📝" in text
    # The Summary is sourced from the version's CHANGELOG section, not hardcoded.
    assert "CHANGELOG.md" in text
    assert "${summary}" in text
    # The verbose operational link dump and boilerplate are gone.
    assert "Pages dashboard: https://avnsx.github.io/win11_release_guard/" not in text
    assert "Public source feed:" not in text
    assert "Runtime clients use the signed public JSON feed" not in text


def test_release_workflow_uses_only_builtin_release_token_reference() -> None:
    text = _read(RELEASE_WORKFLOW)
    lowered = text.lower()

    assert "GH_TOKEN: ${{ github.token }}" in text
    assert ("github" + "_pat_") not in lowered
    assert ("gh" + "p_") not in lowered
    assert "personal access token" not in lowered
    assert "gh-pages" not in lowered
    assert "actions/upload-artifact@" not in text
    assert "actions/create-release@" not in text


def test_security_automation_documents_action_pinning_policy() -> None:
    doc = ROOT / "docs" / "security-automation.md"
    text = _read(doc)

    assert "GitHub Actions Pinning" in text
    assert "GitHub-owned first-party actions may use audited major tags" in text
    assert "Third-party actions are forbidden unless explicitly allowlisted" in text
    assert "full 40-character commit SHA" in text
    assert "tools/check_github_action_versions.py" in text
    assert "contents: write" in text


def test_security_automation_doc_exists_and_explains_ui_limits() -> None:
    doc = ROOT / "docs" / "security-automation.md"
    text = _read(doc)

    assert doc.exists()
    assert ".github/dependabot.yml" in text
    assert ".github/workflows/codeql.yml" in text
    assert "Settings -> Code security and analysis -> Code scanning" in text
    assert "GitHub UI settings are not fully controlled by repository files." in text
    assert "workflow status badges" in text
