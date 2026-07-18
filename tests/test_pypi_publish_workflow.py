from __future__ import annotations

from pathlib import Path

from tools.check_github_action_versions import PYPA_PUBLISH_ACTION_SHA


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "pypi-publish.yml"
README = ROOT / "README.md"
PYPI_DOC_PATHS = (
    ROOT / "CHANGELOG.md",
    ROOT / "docs" / "releases" / "v0.3.4.md",
    ROOT / "docs" / "tagged-release-lane.md",
    ROOT / "docs" / "security-automation.md",
    ROOT / "wiki" / "Build-Test-and-Release.md",
    ROOT / "wiki" / "Tagged-Release-Lane.md",
    ROOT / "wiki" / "Release-v0.3.4.md",
    ROOT / "wiki" / "FAQ.md",
)


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _repo_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_pypi_publish_workflow_exists_with_manual_and_release_triggers() -> None:
    text = _workflow_text()

    assert WORKFLOW.exists()
    assert "name: Publish Python package" in text
    assert "workflow_dispatch:" in text
    assert "release:" in text
    assert "types: [published]" in text
    assert "\npush:" not in text
    assert "\npull_request:" not in text
    assert "tag:" in text


def test_pypi_publish_workflow_uses_trusted_publishing_oidc_without_credentials() -> None:
    text = _workflow_text()
    lowered = text.lower()

    assert "environment:\n      name: pypi" in text
    assert "url: https://pypi.org/project/${{ needs.build.outputs.package-name }}/" in text
    assert "permissions:\n      id-token: write" in text
    assert "contents: write" not in text
    assert f"pypa/gh-action-pypi-publish@{PYPA_PUBLISH_ACTION_SHA}" in text

    forbidden = (
        "PYPI_TOKEN",
        "TWINE_PASSWORD",
        "TWINE_USERNAME",
        "__token__",
        "password:",
        "username:",
        "repository-url:",
        "https://test.pypi.org/legacy/",
    )
    for pattern in forbidden:
        assert pattern.lower() not in lowered


def test_pypi_publish_workflow_builds_and_uploads_dist_artifact() -> None:
    text = _workflow_text()

    assert "actions/checkout@v7" in text
    assert "actions/setup-python@v6" in text
    assert 'python-version: "3.12"' in text
    assert 'python -m pip install -e ".[test]"' in text
    assert "python -m pip install --upgrade build twine" in text
    assert "python -m build" in text
    assert "python -m twine check dist/*" in text
    assert "actions/upload-artifact@v7" in text
    assert "actions/download-artifact@v8" in text
    assert "name: python-package-distributions" in text
    assert "path: dist/" in text
    assert "if-no-files-found: error" in text


def test_workflow_dispatch_without_tag_is_build_only_and_cannot_publish_directly() -> None:
    text = _workflow_text()

    assert "Leave blank for build/twine/self-test only." in text
    assert 'publish_enabled="false"' in text
    assert "Manual dispatch without tag: build/twine/self-test only; publish job will be skipped." in text
    assert "Build-only PyPI workflow run for package version" in text
    assert "if: needs.build.outputs.publish-enabled == 'true'" in text
    assert 'event_tag="v${requested_version}"' not in text
    assert "${{ inputs.version }}" not in text
    assert "Manual PyPI publish must run from main." not in text


def test_workflow_dispatch_with_tag_verifies_existing_tag_before_publish() -> None:
    text = _workflow_text()

    assert 'elif [ -n "${{ inputs.tag }}" ]; then' in text
    assert 'event_tag="${{ inputs.tag }}"' in text
    assert "git rev-parse -q --verify \"refs/tags/${event_tag}^{commit}\"" in text
    assert "PyPI publish tag ${event_tag} does not exist in this repository." in text
    assert 'git checkout --detach "$event_tag"' in text
    assert 'echo "publish_enabled=${publish_enabled}" >> "$GITHUB_OUTPUT"' in text


def test_release_published_event_uses_release_tag_for_publish() -> None:
    text = _workflow_text()

    assert 'if [ "${{ github.event_name }}" = "release" ]; then' in text
    assert 'event_tag="${{ github.event.release.tag_name }}"' in text
    assert 'publish_enabled="true"' in text
    assert "release:\n    types: [published]" in text


def test_pypi_publish_workflow_runs_project_gates_before_publish() -> None:
    text = _workflow_text()

    assert "python -m compileall -q win11_release_guard tools tests" in text
    assert "python tools/check_project_identity.py" in text
    assert "python tools/check_version_consistency.py" in text
    assert "python tools/check_github_action_versions.py" in text
    assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD" in text
    assert "pytest -q --durations=20" in text
    assert "python -m win11_release_guard --self-test" in text
    assert "python tools/scan_for_secret_material.py" in text
    for target in (
        "README.md",
        "CHANGELOG.md",
        "AGENTS.md",
        "docs",
        "wiki",
        "win11_release_guard",
        "tests",
        "tools",
        "pyproject.toml",
        ".github",
    ):
        assert target in text


def test_pypi_publish_workflow_enforces_tag_version_parity_without_tag_creation() -> None:
    text = _workflow_text()

    assert "tomllib.loads" in text
    assert 'data["project"]["name"]' in text
    assert 'data["project"]["version"]' in text
    assert 'expected_tag="v${package_version}"' in text
    assert "github.event.release.tag_name" in text
    assert "Tag version ${requested_version} does not match pyproject version" in text
    assert "does not match expected" in text
    assert "Unexpected package name" in text
    assert "git tag" not in text
    assert "git push" not in text


def test_readme_pypi_badges_install_and_publish_links_are_visible() -> None:
    text = _repo_text(README)
    normalized_text = text.replace("\r\n", "\n")

    hero_asset_url = (
        "https://raw.githubusercontent.com/Avnsx/win11_release_guard/main/"
        "assets/images/windows-11-release-guard-hero-dashboard.png"
    )
    pypi_asset_url = (
        "https://raw.githubusercontent.com/Avnsx/win11_release_guard/main/"
        "assets/images/download_from_pypi.png"
    )
    pypi_button_html = f"""<a href="https://pypi.org/project/win11-release-guard/" aria-label="Download win11_release_guard from PyPI">
  <img align="right"
       src="{pypi_asset_url}"
       alt="Download from PyPI"
       width="96"
       height="96">
</a>"""
    heading_marker = "\n# Windows 11 Release Guard\n"
    assert f"![Windows 11 Release Guard dashboard preview]({hero_asset_url})" in text
    assert "assets/images/windows-11-release-guard-social-preview.png" not in text
    assert text.index(hero_asset_url) < text.index(pypi_asset_url)
    assert (
        normalized_text.index(hero_asset_url)
        < normalized_text.index(pypi_button_html)
        < normalized_text.index(heading_marker)
    )
    assert '<a href="https://pypi.org/project/win11-release-guard/" aria-label="Download win11_release_guard from PyPI">' in text
    assert pypi_button_html in normalized_text
    assert "[![PyPI](https://img.shields.io/pypi/v/win11-release-guard" not in text
    assert "[![Python](https://img.shields.io/pypi/pyversions/win11-release-guard?logo=python&label=Python)]" in text
    assert "[![License]" not in text
    assert "https://img.shields.io/pypi/l/" not in text
    assert "[![PyPI downloads](https://img.shields.io/pypi/dm/win11-release-guard?label=PyPI%20downloads)]" in text
    assert "[![GitHub Release](https://img.shields.io/github/v/release/Avnsx/win11_release_guard?label=release)]" in text
    assert (
        "[![Stars](https://img.shields.io/github/stars/Avnsx/win11_release_guard?"
        "label=%E2%AD%90%20Stars&color=ffc83d)]"
        "(https://github.com/Avnsx/win11_release_guard/stargazers)"
    ) in text
    assert "## Support The Project" in text
    assert "please star the repository" in text
    assert "Stars make the project easier for other Windows administrators to discover" in text
    assert (
        "[![Stargazers repo roster for @Avnsx/win11_release_guard]"
        "(https://reporoster.com/stars/dark/Avnsx/win11_release_guard)]"
        "(https://github.com/Avnsx/win11_release_guard/stargazers)"
    ) in text
    assert "[![Publish Python package](https://github.com/Avnsx/win11_release_guard/actions/workflows/pypi-publish.yml/badge.svg)]" in text
    assert "https://pypi.org/project/win11-release-guard/" in text
    assert "python -m pip install win11_release_guard" in text
    assert 'python -m pip install -e ".[test]"' not in text
    assert "win11_release_guard --pretty" in text
    assert "python -m win11_release_guard --self-test" not in text


def test_readme_uses_pypi_safe_absolute_media_and_doc_links() -> None:
    text = _repo_text(README)
    relative_link_patterns = (
        "](docs/",
        "](CHANGELOG.md",
        "](LICENSE.txt",
        "](AGENTS.md",
        "](assets/",
        'src="assets/',
    )

    for pattern in relative_link_patterns:
        assert pattern not in text
    assert "https://github.com/Avnsx/win11_release_guard/blob/main/docs/dashboard-and-pages.md" in text
    assert "https://github.com/Avnsx/win11_release_guard/blob/main/CHANGELOG.md" in text


def test_readme_pypi_docs_do_not_document_token_secret_setup() -> None:
    texts = [("README.md", _repo_text(README))]
    texts.extend((path.relative_to(ROOT).as_posix(), _repo_text(path)) for path in PYPI_DOC_PATHS)
    forbidden = (
        "PYPI_API_TOKEN",
        "PYPI_TOKEN",
        "TWINE_PASSWORD",
        "username: __token__",
        "password: ${{ secrets",
        "repository-url: https://upload.pypi.org/legacy/",
    )

    findings = [
        f"{name}: {pattern}"
        for name, text in texts
        for pattern in forbidden
        if pattern in text
    ]

    assert findings == []


def test_pypi_docs_connect_release_lane_package_artifacts_and_oidc() -> None:
    for path in PYPI_DOC_PATHS:
        text = _repo_text(path)
        assert "pypi-publish.yml" in text
        assert "Trusted Publishing" in text
        assert "OIDC" in text

    changelog = _repo_text(ROOT / "CHANGELOG.md")
    detailed_release = _repo_text(ROOT / "docs" / "releases" / "v0.3.4.md")
    wiki_release = _repo_text(ROOT / "wiki" / "Release-v0.3.4.md")
    for text in (changelog, detailed_release, wiki_release):
        assert ".github/workflows/pypi-publish.yml" in text
        assert "wheel" in text
        assert "sdist" in text
        assert "twine check" in text.lower()
        assert "Pending Trusted Publisher" in text
    assert all("TestPyPI" not in _repo_text(path) for path in PYPI_DOC_PATHS)


def test_pypi_docs_keep_package_name_and_release_urls_connected() -> None:
    readme = _repo_text(README)
    tagged_docs = _repo_text(ROOT / "docs" / "tagged-release-lane.md")
    tagged_wiki = _repo_text(ROOT / "wiki" / "Tagged-Release-Lane.md")

    for text in (readme, tagged_docs, tagged_wiki):
        assert "https://pypi.org/project/win11-release-guard/" in text
        assert "win11_release_guard" in text
        assert "https://github.com/Avnsx/win11_release_guard/releases" in readme
    assert "Publishing a GitHub Release can trigger the separate PyPI workflow" in tagged_docs
    assert "published GitHub Release" in tagged_wiki
