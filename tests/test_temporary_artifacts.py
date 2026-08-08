from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_local_hand_off_notes_are_gitignored() -> None:
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")

    assert "*handover*.md" in gitignore


def test_temporary_generated_and_package_artifacts_are_gitignored() -> None:
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    patterns = {line.strip() for line in gitignore if line.strip() and not line.startswith("#")}

    assert ".tmp/" in patterns
    assert "/site/" in patterns
    assert "/dist/" in patterns
    assert ".pytest_cache/" in patterns
    assert "*.egg-info/" in patterns
    assert "__pycache__/" in patterns
    assert "*handover*.md" in patterns


def test_tmp_staging_artifacts_are_gitignored() -> None:
    # A hard-killed run can leave a `<name>.staging.tmp` beside its destination, including the
    # repository root when `--output` targets it, so the bare `*.tmp` pattern is load-bearing.
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    patterns = {line.strip() for line in gitignore if line.strip() and not line.startswith("#")}

    assert "*.tmp" in patterns


def test_local_hand_off_notes_are_not_tracked_when_git_metadata_exists() -> None:
    if not (ROOT / ".git").exists():
        return

    result = subprocess.run(
        ["git", "-c", "safe.directory=*", "ls-files", "*handover*.md"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == ""
