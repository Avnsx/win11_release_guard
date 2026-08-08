"""Source guard: no CWD, ``tempfile`` or ``shutil`` write sites in the package.

Two AST clauses (design §16.3):

* **Package-wide** over ``win11_release_guard/`` — zero ``(value_name, attribute)`` pairs from
  ``_BANNED_ATTR_PAIRS`` and zero ``from tempfile``/``from shutil`` imports. Matching by *pair*
  (not by value shape) is why ``os.name``, ``os.environ`` and ``shutil.copyfile`` do not fire.
* **``state_store.py`` only** — zero ``.cwd``/``.resolve`` attributes, matched on the attribute
  name alone whatever the value expression, so the instance spellings ``x.resolve()`` /
  ``y.cwd()`` are caught too. The clause is file-scoped because ``cache.py`` legitimately holds
  ``Path.cwd()``.
"""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "win11_release_guard"

# package-wide: banned (value_name, attribute) pairs (§16.3).
_BANNED_ATTR_PAIRS = frozenset({
    ("os", "getcwd"),
    ("os", "link"),
    ("shutil", "rmtree"),
    ("tempfile", "gettempdir"),
    ("tempfile", "mkstemp"),
})
# package-wide: banned `from <module> import ...` sources (§16.3).
_BANNED_IMPORT_MODULES = frozenset({"tempfile", "shutil"})
# state_store.py only: banned attribute NAMES, any value expression (§16.3).
_BANNED_ATTR_NAMES = frozenset({"cwd", "resolve"})


def _forbidden_pair_hits(source: str, filename: str) -> list[str]:
    """AST scan for the package-wide banned attribute pairs and banned `from` imports."""
    tree = ast.parse(source, filename=filename)
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if (node.value.id, node.attr) in _BANNED_ATTR_PAIRS:
                hits.append(f"{filename}:{node.lineno} {node.value.id}.{node.attr}")
        elif isinstance(node, ast.ImportFrom) and node.module in _BANNED_IMPORT_MODULES:
            hits.append(f"{filename}:{node.lineno} from {node.module} import ...")
    return hits


def _forbidden_attr_name_hits(source: str, filename: str) -> list[str]:
    """AST scan for banned attribute NAMES regardless of the value expression."""
    tree = ast.parse(source, filename=filename)
    return [
        f"{filename}:{node.lineno} .{node.attr}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr in _BANNED_ATTR_NAMES
    ]


def test_matcher_flags_planted_pair_and_import_violations() -> None:
    violating = (
        "import os\n"
        "import shutil\n"
        "import tempfile\n"
        "from tempfile import gettempdir\n"
        "os.getcwd()\n"
        "os.link('a', 'b')\n"
        "shutil.rmtree('x')\n"
        "tempfile.mkstemp()\n"
    )
    hits = _forbidden_pair_hits(violating, "planted.py")
    # Every banned pair plus the ImportFrom is caught (5 sites).
    assert len(hits) == 5, hits


def test_matcher_spares_legitimate_lookalikes() -> None:
    legitimate = (
        "import os\n"
        "import shutil\n"
        "import tempfile\n"
        "from dataclasses import replace\n"
        "os.name\n"
        "os.environ.get('X')\n"
        "shutil.copyfile('a', 'b')\n"
        "replace(cfg, stateless=False)\n"
        "'a.b'.replace('.', '_')\n"
    )
    assert _forbidden_pair_hits(legitimate, "legit.py") == []


def test_attr_name_matcher_flags_cwd_and_resolve() -> None:
    violating = "Path.cwd()\nscope_path.resolve()\nPath(x).resolve()\n"
    assert len(_forbidden_attr_name_hits(violating, "planted.py")) == 3


def test_attr_name_matcher_spares_other_attributes() -> None:
    legitimate = "obj.status\nobj.write_bytes(b'')\nos.name\n"
    assert _forbidden_attr_name_hits(legitimate, "legit.py") == []


def test_package_has_no_cwd_or_tempfile_writes() -> None:
    hits: list[str] = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        hits.extend(_forbidden_pair_hits(source, path.name))
    assert hits == [], f"forbidden CWD/tempfile/shutil sites in package: {hits}"


def test_state_store_has_no_cwd_or_resolve() -> None:
    state_store = PACKAGE_ROOT / "state_store.py"
    hits: list[str] = []
    if state_store.exists():
        hits = _forbidden_attr_name_hits(
            state_store.read_text(encoding="utf-8"), state_store.name
        )
    assert hits == [], f"forbidden .cwd()/.resolve() in state_store.py: {hits}"
