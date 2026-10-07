"""A second top-level ``def`` silently replaces the first at import time.

``remote_policy._build_key`` was defined twice: the strict validator variant
shadowed the None-tolerant sort key that ``_select_quality_baseline`` relies on.
"""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

import pytest

_SOURCES = sorted([*Path("win11_release_guard").glob("*.py"), *Path("tools").glob("*.py")])


@pytest.mark.parametrize("path", _SOURCES, ids=lambda path: path.as_posix())
def test_module_does_not_redefine_top_level_functions_or_classes(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names = Counter(
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )

    assert {name: count for name, count in names.items() if count > 1} == {}


def test_build_key_tolerates_missing_and_malformed_builds() -> None:
    from win11_release_guard.remote_policy import _build_key

    assert _build_key(None) == (-1, -1)
    assert _build_key("not-a-build") == (-1, -1)
    assert _build_key("26200.9445") == (26200, 9445)
