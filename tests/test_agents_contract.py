from __future__ import annotations

from pathlib import Path


def _agents_text() -> str:
    return (Path(__file__).resolve().parents[1] / "AGENTS.md").read_text(encoding="utf-8")


def _repo_text(relative_path: str) -> str:
    return (Path(__file__).resolve().parents[1] / relative_path).read_text(encoding="utf-8")


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


def test_agents_contract_documents_product_display_name_boundary() -> None:
    text = _agents_text()

    assert "## Product Display Name" in text
    assert "`Windows 11 Release Guard`" in text
    assert "Markdown headings and human-facing prose" in text
    assert "remain `win11_release_guard`" in text
    assert "Do not replace technical examples" in text
    assert "README.md` intentionally starts with the dashboard preview image" in text
    assert "Do not add tests or agent rules that require the README to start with the" in text
    assert 'multiline `<img align="right" ... width="96" height="96">` formatting' in text
    assert "require a PyPI\n  version badge" in text


def test_human_facing_markdown_and_pages_headings_use_display_name() -> None:
    readme = _repo_text("README.md")
    release_lane = _repo_text("docs/tagged-release-lane.md")
    generator = _repo_text("win11_release_guard/policy_generator/pages/dashboard.py")
    release_lane_text = " ".join(release_lane.split())
    hero_line = (
        "![Windows 11 Release Guard dashboard preview]"
        "(https://raw.githubusercontent.com/Avnsx/win11_release_guard/main/"
        "assets/images/windows-11-release-guard-hero-dashboard.png)"
    )

    assert readme.splitlines()[0] == hero_line
    assert "\n# Windows 11 Release Guard\n" in readme
    assert readme.index(hero_line) < readme.index("\n# Windows 11 Release Guard\n")
    assert "Windows 11 Release Guard tells administrators" in readme
    assert "distribution checkpoints for Windows 11 Release Guard source archives" in release_lane_text
    assert "<title>Windows 11 Release Guard</title>" in generator
    assert "<h1>Windows 11 Release Guard</h1>" in generator


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


def test_agents_contract_preserves_historical_changelog_sections() -> None:
    text = _agents_text()

    assert "Future agents must not delete historical `CHANGELOG.md` version sections" in text
    assert "Newer changelog entries are added at the top" in text
    assert "Older changelog entries remain available for generated Pages changelog" in text
    assert "release history, SEO, and auditability" in text


def test_agents_contract_forbids_license_badges_in_markdown_surfaces() -> None:
    text = _agents_text()

    assert "Future agents must not add or reintroduce license badges" in text
    assert "`README.md`, `docs/*.md`, `wiki/*.md`" in text
    assert "Markdown badge rows must not display license badges" in text


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
    assert "python tools/scan_for_secret_material.py site win11_release_guard tests tools docs wiki README.md CHANGELOG.md AGENTS.md pyproject.toml .github" in text
    assert "python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip" in text
    assert "python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip" in text
    assert "python -m win11_release_guard --check-policy-source" in text
    assert "python -m win11_release_guard --check-public-pages" in text
    assert "If live network is unavailable" in text
    assert "do not claim live success" in text
    assert "exact failing URL, status, and" in text


def test_agents_contract_documents_api_v1_and_key_overlap_compatibility() -> None:
    agents = _agents_text()
    signing = _repo_text("docs/policy-signing.md")
    readme = _repo_text("README.md")

    for text in (agents, signing, readme):
        assert "/api/v1" in text
        assert "24 months" in text
    assert "verification overlap" in signing
    assert "verify_not_after_utc" in signing


def test_agents_contract_links_tagged_release_lane() -> None:
    agents = _agents_text()
    readme = _repo_text("README.md")
    security = _repo_text("docs/security-automation.md")
    release_lane = _repo_text("docs/tagged-release-lane.md")

    assert "docs/tagged-release-lane.md" in agents
    assert "Tagged release lane" in readme
    assert "docs/tagged-release-lane.md" in readme
    assert "docs/tagged-release-lane.md" in security
    assert "vX.Y.Z" in release_lane
    assert "create_tag=true" in release_lane
    assert "python tools/check_version_consistency.py" in release_lane
    assert "GitHub API token" in release_lane
    assert "must never be exposed" in release_lane


def test_security_automation_docs_do_not_rely_only_on_schedule() -> None:
    text = _repo_text("docs/security-automation.md")

    assert "workflow_dispatch" in text
    assert "README badges" in text
    assert "--check-policy-source" in text
    assert "--check-public-pages" in text
    assert "schedule is not the only control" in text
    assert "source-diagnostics `error` events" in text


def test_agents_contract_mentions_codeql_settings_limit() -> None:
    text = _agents_text()

    assert "CodeQL code scanning is configured by `.github/workflows/codeql.yml`" in text
    assert "Code security and analysis" in text


def test_agents_contract_requires_validated_clean_archive_for_handoff() -> None:
    text = _agents_text()

    assert "only recommended handoff artifact is the validated clean archive" in text
    assert "python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip" in text
    assert "python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip" in text
    assert "Raw worktree ZIPs are not release artifacts" in text
    assert ".git/" in text
    assert ".tmp/" in text
    assert "private signing-key scratch" in text


def test_agents_contract_rejects_patch_only_task_completion() -> None:
    text = _agents_text()

    assert "`.tmp/prompt-chain/*.patch` files are local hints only" in text
    assert "implemented only when the intended behavior exists in tracked files" in text
    assert "tests\n  pass" in text
    assert "required docs are updated" in text
    assert "logical commits exist" in text
