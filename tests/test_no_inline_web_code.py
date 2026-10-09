"""Pages HTML, CSS, and JavaScript live in policy_generator/pages/assets, not in Python strings."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

PAGES = Path("win11_release_guard/policy_generator/pages")
HTML_TAG = re.compile(r"</?(?:html|head|body|div|span|section|article|nav|table|tr|td|th|svg|a|p|h[1-6]|ul|li|button|main|header|footer|meta|link|details|summary|code|pre|strong|img|label)(?=[\s>/])", re.I)
DETECTION_LITERALS = {"<html", "<!doctype html"}
_FILES = sorted([*Path("win11_release_guard").rglob("*.py"), *Path("tools").rglob("*.py")])


def _strings(tree: ast.AST):
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            yield node.value


@pytest.mark.parametrize("path", _FILES, ids=lambda path: path.as_posix())
def test_python_module_has_no_inline_web_code(path: Path) -> None:
    strings = list(_strings(ast.parse(path.read_text(encoding="utf-8"))))
    assert not [s for s in strings if re.search(r"<script|<style", s, re.I)], "move script/style bodies to pages/assets"
    if PAGES not in path.parents:
        markup = [s for s in strings if HTML_TAG.search(s) and s not in DETECTION_LITERALS]
        assert not markup, f"HTML markup belongs in {PAGES.as_posix()}: {markup[:3]}"
