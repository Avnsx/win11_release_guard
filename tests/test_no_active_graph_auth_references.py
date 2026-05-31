from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_README_STATEMENT = (
    "The production generator uses public Microsoft Release Health and Atom sources only; "
    "it does not use Microsoft Graph, Azure, OIDC, or token-authenticated Microsoft APIs."
)
FORBIDDEN_PATTERNS = (
    "Microsoft Graph",
    "Azure",
    "OIDC",
    "allow-no-subscriptions",
    "WindowsUpdates.Read.All",
)
SCAN_TARGETS = (
    ROOT / "README.md",
    ROOT / "AGENTS.md",
    ROOT / "docs",
    ROOT / "win11_release_guard",
    ROOT / "tools",
    ROOT / ".github",
)
ALLOWED_HISTORICAL_FILES = {
    ROOT / "deep-research-report.md",
    ROOT / "docs" / "source-learnings.md",
}
TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".css",
    ".html",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


def _iter_scanned_files() -> list[Path]:
    files: list[Path] = []
    for target in SCAN_TARGETS:
        if not target.exists():
            continue
        if target.is_file():
            candidates = [target]
        else:
            candidates = [path for path in target.rglob("*") if path.is_file()]
        for path in candidates:
            if path.resolve() in {allowed.resolve() for allowed in ALLOWED_HISTORICAL_FILES}:
                continue
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            if path.suffix.lower() in TEXT_SUFFIXES:
                files.append(path)
    return sorted(files)


def test_readme_states_public_sources_only() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert REQUIRED_README_STATEMENT in readme


def test_no_active_graph_azure_oidc_references() -> None:
    findings: list[str] = []
    for path in _iter_scanned_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        if path == ROOT / "README.md":
            text = text.replace(REQUIRED_README_STATEMENT, "")
        lowered = text.lower()
        for pattern in FORBIDDEN_PATTERNS:
            index = lowered.find(pattern.lower())
            if index == -1:
                continue
            line = text.count("\n", 0, index) + 1
            findings.append(f"{path.relative_to(ROOT)}:{line}: {pattern}")

    assert findings == []
