from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_SOURCE_STATEMENT = (
    "The production generator may use public Microsoft Release Health HTML, the public Microsoft servicing "
    "table-of-contents JSON, public Microsoft servicing support articles, and unauthenticated public MSRC CVRF "
    "data for source diagnostics and informational enrichment; it does not use Microsoft Graph or "
    "token-authenticated Microsoft APIs."
)
REQUIRED_AGENTS_STATEMENT = (
    "The production generator may use public Microsoft Release Health HTML, the public Microsoft servicing "
    "table-of-contents JSON, public Microsoft servicing support articles, and unauthenticated public MSRC CVRF "
    "data for source diagnostics and informational enrichment."
)
ALLOWED_ACTIVE_AUTH_BOUNDARIES = (
    REQUIRED_SOURCE_STATEMENT,
    REQUIRED_AGENTS_STATEMENT,
    "Authenticated Microsoft Graph, token-authenticated Microsoft APIs, and historical authenticated metadata research "
    "remain out of active production generator architecture; historical research may remain only in "
    "`docs/architecture-insight.md` when explicitly marked out of scope.",
)
FORBIDDEN_PATTERNS = (
    "Microsoft " + "Graph",
    "Az" + "ure",
    "allow-no-" + "subscriptions",
    "WindowsUpdates" + ".Read.All",
)
FORBIDDEN_REGEXES = (
    re.compile(r"\b(?:Microsoft|" + "Az" + r"ure)\b[^\n]{0,80}\bOIDC\b", flags=re.IGNORECASE),
    re.compile(r"\bOIDC\b[^\n]{0,80}\b(?:Microsoft|" + "Az" + r"ure)\b", flags=re.IGNORECASE),
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
    ROOT / "docs" / "architecture-insight.md",
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
            if "handover" in path.name and path.suffix.lower() == ".md":
                continue
            if path.resolve() in {allowed.resolve() for allowed in ALLOWED_HISTORICAL_FILES}:
                continue
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            if path.suffix.lower() in TEXT_SUFFIXES:
                files.append(path)
    return sorted(files)


def test_readme_states_public_enrichment_sources_without_auth() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")

    assert REQUIRED_SOURCE_STATEMENT in readme
    assert REQUIRED_AGENTS_STATEMENT in agents


def test_no_active_authenticated_microsoft_api_references() -> None:
    findings: list[str] = []
    for path in _iter_scanned_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for statement in ALLOWED_ACTIVE_AUTH_BOUNDARIES:
            text = text.replace(statement, "")
        lowered = text.lower()
        for pattern in FORBIDDEN_PATTERNS:
            index = lowered.find(pattern.lower())
            if index == -1:
                continue
            line = text.count("\n", 0, index) + 1
            findings.append(f"{path.relative_to(ROOT)}:{line}: {pattern}")
        for pattern in FORBIDDEN_REGEXES:
            match = pattern.search(text)
            if match is None:
                continue
            line = text.count("\n", 0, match.start()) + 1
            findings.append(f"{path.relative_to(ROOT)}:{line}: {pattern.pattern}")

    assert findings == []
