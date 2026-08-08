"""Source guard: no CWD, ``tempfile`` or ``shutil`` write sites in the package.

Three AST clauses (design §16.3, R-1):

* **Package-wide** over ``win11_release_guard/`` — zero ``(value_name, attribute)`` pairs from
  ``_BANNED_ATTR_PAIRS`` and zero ``from tempfile``/``from shutil`` imports. Matching by *pair*
  (not by value shape) is why ``os.name``, ``os.environ`` and ``shutil.copyfile`` do not fire.
* **``state_store.py`` only** — zero ``.cwd``/``.resolve`` attributes, matched on the attribute
  name alone whatever the value expression, so the instance spellings ``x.resolve()`` /
  ``y.cwd()`` are caught too. The clause is file-scoped because ``cache.py`` legitimately holds
  ``Path.cwd()``.
* **Package-wide ``os.rmdir`` confinement (R-1)** — the package's only directory-removal call
  must stay inside ``retire_legacy_state``. The owner of each call site is resolved by AST
  subtree containment, so the ``os.rmdir`` mentions in neighbouring docstrings do not count and
  a module-level call cannot hide behind the nearest ``def`` above it.
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
# package-wide: the single (value_name, attribute) pair R-1 confines, and its one legal owner.
_RMDIR_PAIR = ("os", "rmdir")
_RMDIR_OWNER = "retire_legacy_state"
# Reported instead of a function name when a call site sits outside every `def`, so a
# module-level `os.rmdir(...)` fails the set comparison rather than vanishing from it.
_MODULE_SCOPE = "<module>"


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


def _enclosing_function_name(tree: ast.AST, target: ast.AST) -> str:
    """Name of the innermost ``def``/``async def`` whose subtree contains ``target``.

    Containment is decided by node identity inside ``ast.walk(func)``, never by comparing line
    numbers or by taking the nearest ``def`` above the site. When two candidates both contain the
    target one of them necessarily contains the other, so "is the newcomer inside the incumbent"
    is a sound innermost test. Returns ``_MODULE_SCOPE`` for a site at module level.
    """
    owner: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(node is target for node in ast.walk(func)):
            continue
        if owner is None or any(node is func for node in ast.walk(owner)):
            owner = func
    return _MODULE_SCOPE if owner is None else owner.name


def _os_rmdir_sites(source: str, filename: str) -> list[tuple[str, str]]:
    """``(enclosing function, location)`` for every ``os.rmdir`` attribute in ``source`` (R-1).

    Only the ``os.rmdir`` spelling R-1 names is matched; an aliased ``import os as _o`` would
    read as a different value name and is deliberately out of this clause's scope.
    """
    tree = ast.parse(source, filename=filename)
    return [
        (
            _enclosing_function_name(tree, node),
            f"{filename}:{node.lineno} {node.value.id}.{node.attr}",
        )
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and (node.value.id, node.attr) == _RMDIR_PAIR
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


def test_rmdir_matcher_resolves_the_owner_by_containment_not_proximity() -> None:
    planted = (
        "import os\n"
        "def outer():\n"
        "    '''Mentioning os.rmdir in a docstring must not count as a call site.'''\n"
        "    def inner():\n"
        "        os.rmdir('a')\n"          # owner is inner, not outer
        "    return inner\n"
        "async def coro():\n"
        "    os.rmdir('b')\n"
        "def sibling():\n"
        "    pass\n"
        "os.rmdir('c')\n"                  # module level: the nearest def above is sibling
    )
    assert sorted(owner for owner, _ in _os_rmdir_sites(planted, "planted.py")) == [
        _MODULE_SCOPE,
        "coro",
        "inner",
    ]


def test_rmdir_matcher_spares_lookalikes() -> None:
    legitimate = (
        "import os\n"
        "def retire_legacy_state():\n"
        "    '''Never rmdirs (R-1).'''\n"
        "    shim.rmdir('a')\n"
        "    os.rmdir_guard = 1\n"
        "    return 'os.rmdir'\n"
    )
    assert _os_rmdir_sites(legitimate, "legit.py") == []


def test_package_confines_os_rmdir_to_retire_legacy_state() -> None:
    owners: set[str] = set()
    sites: list[str] = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        for owner, site in _os_rmdir_sites(path.read_text(encoding="utf-8"), path.name):
            owners.add(owner)
            sites.append(f"{site} in {owner}()")
    # Exact equality both ways: a second owner fails, and so does losing the call entirely,
    # because R-1 asserts the package HAS exactly one directory-removal site.
    assert owners == {_RMDIR_OWNER}, f"os.rmdir must live only in {_RMDIR_OWNER}; sites: {sites}"


def test_state_store_has_no_cwd_or_resolve() -> None:
    state_store = PACKAGE_ROOT / "state_store.py"
    hits: list[str] = []
    if state_store.exists():
        hits = _forbidden_attr_name_hits(
            state_store.read_text(encoding="utf-8"), state_store.name
        )
    assert hits == [], f"forbidden .cwd()/.resolve() in state_store.py: {hits}"
