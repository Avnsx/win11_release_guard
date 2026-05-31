from __future__ import annotations

import zipfile
from pathlib import Path

from tools import export_clean_archive


def test_export_clean_archive_contains_only_clean_source_entries(tmp_path: Path) -> None:
    archive_path = tmp_path / "win-release-guard-source.zip"

    created = export_clean_archive.create_archive(export_clean_archive.REPO_ROOT, archive_path)
    names = export_clean_archive.validate_archive(created)

    assert created == archive_path
    assert "README.md" in names
    assert "pyproject.toml" in names
    assert ".github/workflows/ci.yml" in names
    assert "win11_release_guard/data/windows-release-policy.json" in names
    assert "win11_release_guard/data/windows-release-policy.json.sig" in names
    assert "tools/export_clean_archive.py" in names
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
        assert Path(name).name != "out.json"
        assert Path(name).name != "windows_releases_info.py"


def test_export_clean_archive_cli_self_check(tmp_path: Path, capsys) -> None:
    archive_path = tmp_path / "source.zip"

    code = export_clean_archive.main(["--output", str(archive_path)])

    captured = capsys.readouterr()
    assert code == 0
    assert archive_path.exists()
    assert "Created" in captured.out
    with zipfile.ZipFile(archive_path) as archive:
        assert "tools/export_clean_archive.py" in archive.namelist()
