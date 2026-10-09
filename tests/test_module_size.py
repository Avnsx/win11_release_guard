"""Source files stay small enough to read in one sitting; split by responsibility before 800 lines."""

from __future__ import annotations

from pathlib import Path

import pytest

LIMIT = 800
_FILES = sorted(
    [*Path("win11_release_guard").rglob("*.py"), *Path("tools").rglob("*.py"), *Path("tests").rglob("*.py")]
)


@pytest.mark.parametrize("path", _FILES, ids=lambda path: path.as_posix())
def test_module_stays_under_line_limit(path: Path) -> None:
    lines = path.read_text(encoding="utf-8").count("\n") + 1
    assert lines <= LIMIT, f"{path.as_posix()} has {lines} lines; split it by responsibility"
