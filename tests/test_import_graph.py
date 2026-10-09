"""The package's module-level import graph must stay acyclic so modules can be read and moved one at a time."""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path("win11_release_guard")


def _module(path: Path) -> str:
    parts = path.with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _graph() -> dict[str, set[str]]:
    modules = {_module(p): p for p in PACKAGE.rglob("*.py")}
    graph: dict[str, set[str]] = {m: set() for m in modules}
    for name, path in modules.items():
        package = name if path.name == "__init__.py" else name.rpartition(".")[0]
        for node in ast.parse(path.read_text(encoding="utf-8")).body:  # module level only; lazy imports are fine
            if isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    anchor = package.split(".")[: len(package.split(".")) - (node.level - 1)]
                    base = ".".join([*anchor, *([base] if base else [])])
                for alias in node.names:
                    for candidate in (f"{base}.{alias.name}", base):
                        if candidate in modules and candidate != name:
                            graph[name].add(candidate)
                            break
            elif isinstance(node, ast.Import):
                graph[name].update(a.name for a in node.names if a.name in modules and a.name != name)
    return graph


def test_package_import_graph_has_no_cycles() -> None:
    graph, state, cycles = _graph(), {}, []

    def visit(node: str, trail: list[str]) -> None:
        state[node] = "active"
        for nxt in sorted(graph[node]):
            if state.get(nxt) == "active":
                cycles.append(" -> ".join([*trail[trail.index(nxt):], node, nxt]) if nxt in trail else f"{node} -> {nxt}")
            elif nxt not in state:
                visit(nxt, [*trail, node])
        state[node] = "done"

    for node in sorted(graph):
        if node not in state:
            visit(node, [])
    assert cycles == []
