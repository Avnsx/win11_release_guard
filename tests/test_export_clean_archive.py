from __future__ import annotations

import zipfile
from pathlib import Path

from tools import export_clean_archive


def test_export_clean_archive_contains_only_clean_source_entries(tmp_path: Path) -> None:
    archive_path = tmp_path / "win-release-guard-source.zip"

    created = export_clean_archive.create_archive(export_clean_archive.REPO_ROOT, archive_path)
    names = export_clean_archive.validate_archive(created)

    assert created == archive_path
    assert "AGENTS.md" in names
    assert "README.md" in names
    assert "pyproject.toml" in names
    assert ".gitignore" in names
    assert ".gitattributes" in names
    assert ".github/dependabot.yml" in names
    assert ".github/workflows/ci.yml" in names
    assert ".github/workflows/publish-policy.yml" in names
    assert ".github/workflows/codeql.yml" in names
    assert ".github/workflows/pylint.yml" in names
    assert ".github/workflows/dependency-freshness.yml" in names
    assert ".github/workflows/dependency-audit.yml" in names
    assert "win11_release_guard/data/windows-release-policy.json" in names
    assert "win11_release_guard/data/windows-release-policy.json.sig" in names
    assert "tools/check_dependency_freshness.py" in names
    assert "tools/check_commit_message.py" in names
    assert "tools/check_github_action_versions.py" in names
    assert "tools/export_clean_archive.py" in names
    assert "docs/security-automation.md" in names
    assert any(name.startswith("tests/") for name in names)
    assert any(name.startswith("docs/") for name in names)

    for name in names:
        parts = set(Path(name).parts)
        assert ".git" not in parts
        assert "__pycache__" not in parts
        assert ".pytest_cache" not in parts
        assert ".cache" not in parts
        assert "build" not in parts
        assert "dist" not in parts
        assert not name.endswith(".pyc")
        assert not name.endswith(".pem")
        assert not name.endswith(".key")
        assert not name.endswith(".zip")
        assert not Path(name).match("*handover*.md")
        assert Path(name).name != "out.json"
        assert not Path(name).match("site/*")
        assert Path(name).name != export_clean_archive.LEGACY_PROTOTYPE_NAME
        assert Path(name).name != ("private-" + "key.b64")
        assert "private" not in Path(name).name.lower() or "key" not in Path(name).name.lower()


def test_export_clean_archive_cli_self_check(tmp_path: Path, capsys) -> None:
    archive_path = tmp_path / "source.zip"

    code = export_clean_archive.main(["--output", str(archive_path)])

    captured = capsys.readouterr()
    assert code == 0
    assert archive_path.exists()
    assert "Created" in captured.out
    with zipfile.ZipFile(archive_path) as archive:
        assert "tools/export_clean_archive.py" in archive.namelist()
