from __future__ import annotations

import pytest
import zipfile
from pathlib import Path

from tools import export_clean_archive


def test_export_clean_archive_contains_only_clean_source_entries(tmp_path: Path) -> None:
    archive_path = tmp_path / "win11_release_guard-source.zip"

    created = export_clean_archive.create_archive(export_clean_archive.REPO_ROOT, archive_path)
    names = export_clean_archive.validate_archive(created, run_tests=False)

    assert created == archive_path
    assert "AGENTS.md" in names
    assert "README.md" in names
    assert "CHANGELOG.md" in names
    assert "LICENSE.txt" in names
    assert "pyproject.toml" in names
    assert ".gitignore" in names
    assert ".gitattributes" in names
    assert ".github/dependabot.yml" in names
    assert ".github/workflows/ci.yml" in names
    assert ".github/workflows/publish-policy.yml" in names
    assert ".github/workflows/sync-source-diagnostics-issues.yml" in names
    assert ".github/workflows/sync-wiki.yml" in names
    assert ".github/workflows/pypi-publish.yml" in names
    assert ".github/workflows/codeql.yml" in names
    assert ".github/workflows/pylint.yml" in names
    assert ".github/workflows/dependency-freshness.yml" in names
    assert ".github/workflows/dependency-audit.yml" in names
    assert "assets/images/download_from_pypi.png" in names
    assert "assets/images/windows-11-release-guard-hero-dashboard.png" in names
    assert "win11_release_guard/data/windows-release-policy.json" in names
    assert "win11_release_guard/data/windows-release-policy.json.sig" in names
    assert "tools/check_dependency_freshness.py" in names
    assert "tools/check_commit_message.py" in names
    assert "tools/check_github_action_versions.py" in names
    assert "tools/check_project_identity.py" in names
    assert "tools/sync_github_wiki.py" in names
    assert "tools/export_clean_archive.py" in names
    assert "docs/security-automation.md" in names
    assert "wiki/Home.md" in names
    assert "docs/releases/v0.3.3.md" in names
    assert "docs/releases/v0.3.2.md" in names
    assert "docs/releases/v0.3.1.md" in names
    assert "wiki/Release-v0.3.3.md" in names
    assert "wiki/Release-v0.3.2.md" in names
    assert "wiki/Release-v0.3.1.md" in names
    assert "tests/test_github_wiki_sync.py" in names
    assert any(name.startswith("tests/") for name in names)
    assert any(name.startswith("assets/images/") for name in names)
    assert any(name.startswith("docs/") for name in names)
    assert any(name.startswith("wiki/") for name in names)

    for name in names:
        parts = set(Path(name).parts)
        assert ".git" not in parts
        assert "__pycache__" not in parts
        assert ".pytest_cache" not in parts
        assert ".cache" not in parts
        assert "build" not in parts
        assert "dist" not in parts
        assert "generated_site" not in parts
        assert "site" not in parts
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

    code = export_clean_archive.main(["--output", str(archive_path), "--skip-test-run"])

    captured = capsys.readouterr()
    assert code == 0
    assert archive_path.exists()
    assert "Created" in captured.out
    with zipfile.ZipFile(archive_path) as archive:
        assert "tools/export_clean_archive.py" in archive.namelist()


def test_export_clean_archive_cli_validate_existing_archive(tmp_path: Path, capsys) -> None:
    archive_path = tmp_path / "source.zip"

    create_code = export_clean_archive.main(["--output", str(archive_path), "--skip-test-run"])
    validate_code = export_clean_archive.main(["--validate", str(archive_path), "--skip-test-run"])

    captured = capsys.readouterr()
    assert create_code == 0
    assert validate_code == 0
    assert "Validated" in captured.out
    assert "Entries:" in captured.out


def _write_minimal_required_archive(archive_path: Path, forbidden_entry: str) -> None:
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in sorted(export_clean_archive.REQUIRED_ARCHIVE_ENTRIES):
            archive.write(export_clean_archive.REPO_ROOT / entry, entry)
        archive.writestr(forbidden_entry, "raw worktree artifact\n")


@pytest.mark.parametrize(
    "forbidden_entry",
    [
        ".git/config",
        ".pytest_cache/v/cache/nodeids",
        ".tmp/signing-test/private-key.b64",
        ".tmp/prompt-chain/final-combined.patch",
        "private-key.b64",
        "site/windows-release-policy.json",
        "generated_site/index.html",
        "dist/win11_release_guard-source.zip",
        "win11_release_guard.egg-info/PKG-INFO",
        "win11_release_guard/__pycache__/__init__.cpython-312.pyc",
    ],
)
def test_validate_archive_rejects_raw_worktree_zip_artifacts(tmp_path: Path, forbidden_entry: str) -> None:
    archive_path = tmp_path / "raw-worktree.zip"
    _write_minimal_required_archive(archive_path, forbidden_entry)

    with pytest.raises(RuntimeError, match="forbidden entries"):
        export_clean_archive.validate_archive(archive_path, run_tests=False)


def test_export_clean_archive_rejects_old_repo_path_and_archive_name(tmp_path: Path) -> None:
    archive_path = tmp_path / "bad.zip"
    old_project_name = "win" + "-release-guard"

    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in sorted(export_clean_archive.REQUIRED_ARCHIVE_ENTRIES):
            content = "placeholder\n"
            if entry == "README.md":
                content = (
                    f"https://github.com/Avnsx/{old_project_name}\n"
                    f"https://avnsx.github.io/{old_project_name}/\n"
                    f"dist/{old_project_name}-source.zip\n"
                )
            archive.writestr(entry, content)

    with pytest.raises(RuntimeError, match="stale repo/path identity"):
        export_clean_archive.validate_archive(archive_path, run_tests=False)


def test_export_clean_archive_allows_pypi_oidc_but_rejects_microsoft_oidc(tmp_path: Path) -> None:
    good_archive = tmp_path / "good-pypi-oidc.zip"
    bad_archive = tmp_path / "bad-microsoft-oidc.zip"

    with zipfile.ZipFile(good_archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in sorted(export_clean_archive.REQUIRED_ARCHIVE_ENTRIES):
            content = "placeholder\n"
            if entry == "README.md":
                content = "PyPI Trusted Publishing uses GitHub Actions OIDC.\n"
            archive.writestr(entry, content)

    with zipfile.ZipFile(bad_archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in sorted(export_clean_archive.REQUIRED_ARCHIVE_ENTRIES):
            content = "placeholder\n"
            if entry == "README.md":
                content = "Production generator uses Microsoft OIDC metadata auth.\n"
            archive.writestr(entry, content)

    export_clean_archive.validate_archive(good_archive, run_tests=False)
    with pytest.raises(RuntimeError, match="active auth reference"):
        export_clean_archive.validate_archive(bad_archive, run_tests=False)


def test_export_clean_archive_rejects_legacy_name_in_signed_bundled_policy_json(tmp_path: Path) -> None:
    archive_path = tmp_path / "bad-bundled-policy.zip"
    old_project_name = "win" + "-release-guard"

    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in sorted(export_clean_archive.REQUIRED_ARCHIVE_ENTRIES):
            content = "placeholder\n"
            if entry == "win11_release_guard/data/windows-release-policy.json":
                content = f'{{"generator_version": "{old_project_name}/0.2"}}\n'
            archive.writestr(entry, content)

    with pytest.raises(RuntimeError, match="stale project identity after rename"):
        export_clean_archive.validate_archive(archive_path, run_tests=False)


class _FakeCompletedProcess:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _is_pytest_command(command: object) -> bool:
    parts = [str(part) for part in command] if isinstance(command, (list, tuple)) else [str(command)]
    return any(part == "pytest" or part.endswith("pytest") for part in parts) or (
        "-m" in parts and "pytest" in parts
    )


def test_archive_validation_subprocess_disables_pytest_plugin_autoload(
    tmp_path: Path, monkeypatch
) -> None:
    archive_path = tmp_path / "source.zip"
    export_clean_archive.create_archive(export_clean_archive.REPO_ROOT, archive_path)

    captured: list[tuple[list[str], dict]] = []

    def fake_run(command, **kwargs):
        captured.append((list(command), dict(kwargs.get("env") or {})))
        return _FakeCompletedProcess(0)

    monkeypatch.setattr(export_clean_archive.subprocess, "run", fake_run)
    monkeypatch.delenv("WIN11_RELEASE_GUARD_ARCHIVE_VALIDATION_DEPTH", raising=False)

    export_clean_archive.validate_archive(archive_path, run_tests=True)

    pytest_envs = [env for command, env in captured if _is_pytest_command(command)]
    assert pytest_envs, "archive validation must run an inner pytest gate"
    for env in pytest_envs:
        assert env.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") == "1"
        # Recursion guard must remain so the inner gate does not re-run itself.
        assert env.get("WIN11_RELEASE_GUARD_ARCHIVE_VALIDATION_DEPTH") == "1"


def test_archive_validation_fails_on_inner_test_failure(tmp_path: Path, monkeypatch) -> None:
    archive_path = tmp_path / "source.zip"
    export_clean_archive.create_archive(export_clean_archive.REPO_ROOT, archive_path)

    def fake_run(command, **kwargs):
        if _is_pytest_command(command):
            return _FakeCompletedProcess(1, stdout="1 failed", stderr="")
        return _FakeCompletedProcess(0)

    monkeypatch.setattr(export_clean_archive.subprocess, "run", fake_run)
    monkeypatch.delenv("WIN11_RELEASE_GUARD_ARCHIVE_VALIDATION_DEPTH", raising=False)

    with pytest.raises(RuntimeError, match="Archive test run failed"):
        export_clean_archive.validate_archive(archive_path, run_tests=True)


def test_skip_test_run_skips_pytest_but_still_validates_contents(tmp_path: Path, monkeypatch) -> None:
    archive_path = tmp_path / "source.zip"
    export_clean_archive.create_archive(export_clean_archive.REPO_ROOT, archive_path)

    invoked: list[list[str]] = []

    def fake_run(command, **kwargs):
        invoked.append(list(command))
        return _FakeCompletedProcess(0)

    monkeypatch.setattr(export_clean_archive.subprocess, "run", fake_run)

    # --skip-test-run still validates structure/contents but runs no subprocess gate.
    export_clean_archive.validate_archive(archive_path, run_tests=False)
    assert invoked == []

    # Required-entry validation remains enforced even when tests are skipped.
    tampered = tmp_path / "missing-entry.zip"
    keep = sorted(export_clean_archive.REQUIRED_ARCHIVE_ENTRIES - {"docs/releases/v0.3.1.md"})
    with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in keep:
            archive.write(export_clean_archive.REPO_ROOT / entry, entry)
    with pytest.raises(RuntimeError, match="missing required entries"):
        export_clean_archive.validate_archive(tampered, run_tests=False)


def test_required_archive_entries_preserve_historical_release_docs() -> None:
    for version in ("v0.3.1", "v0.3.2", "v0.3.3"):
        entry = f"docs/releases/{version}.md"
        assert entry in export_clean_archive.REQUIRED_ARCHIVE_ENTRIES
        assert (export_clean_archive.REPO_ROOT / entry).is_file()


def test_no_project_required_pytest_plugins() -> None:
    # Controlled archive validation runs pytest with plugin autoload disabled.
    # That is safe only because the project declares no required pytest plugins.
    pyproject = (export_clean_archive.REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "required_plugins" not in pyproject


def test_archive_validation_pytest_env_strips_ambient_pytest_injection(tmp_path: Path) -> None:
    base_env = {
        "PYTEST_ADDOPTS": "--cov=win11_release_guard",
        "PYTEST_PLUGINS": "not_a_real_plugin",
        "PATH": "/usr/bin",
        "LANG": "en_US.UTF-8",
        "VIRTUAL_ENV": "/some/venv",
    }
    env = export_clean_archive._archive_validation_pytest_env(tmp_path / "source", base_env=base_env)

    # Ambient pytest injection vectors are removed.
    assert "PYTEST_ADDOPTS" not in env
    assert "PYTEST_PLUGINS" not in env
    # Determinism and recursion guard are set.
    assert env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert env["WIN11_RELEASE_GUARD_ARCHIVE_VALIDATION_DEPTH"] == "1"
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert env["PYTHONPATH"] == str(tmp_path / "source")
    # Unrelated runtime variables are preserved (not aggressively stripped).
    assert env["PATH"] == "/usr/bin"
    assert env["LANG"] == "en_US.UTF-8"
    assert env["VIRTUAL_ENV"] == "/some/venv"


def test_archive_validation_subprocess_uses_isolated_env(tmp_path: Path, monkeypatch) -> None:
    archive_path = tmp_path / "source.zip"
    export_clean_archive.create_archive(export_clean_archive.REPO_ROOT, archive_path)

    captured: list[dict] = []

    def fake_run(command, **kwargs):
        if _is_pytest_command(command):
            captured.append(dict(kwargs.get("env") or {}))
        return _FakeCompletedProcess(0)

    monkeypatch.setattr(export_clean_archive.subprocess, "run", fake_run)
    monkeypatch.delenv("WIN11_RELEASE_GUARD_ARCHIVE_VALIDATION_DEPTH", raising=False)
    monkeypatch.setenv("PYTEST_ADDOPTS", "--cov=win11_release_guard")
    monkeypatch.setenv("PYTEST_PLUGINS", "not_a_real_plugin")

    export_clean_archive.validate_archive(archive_path, run_tests=True)

    assert captured, "expected an inner pytest subprocess"
    for env in captured:
        assert "PYTEST_ADDOPTS" not in env
        assert "PYTEST_PLUGINS" not in env
        assert env.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") == "1"
        assert env.get("WIN11_RELEASE_GUARD_ARCHIVE_VALIDATION_DEPTH") == "1"
