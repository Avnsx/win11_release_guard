from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARCHIVE_PATH = Path("dist") / "win-release-guard-source.zip"
LEGACY_PROTOTYPE_NAME = "_".join(("windows", "releases", "info")) + ".py"
REQUIRED_README_PUBLIC_SOURCES_STATEMENT = (
    "The production generator uses public Microsoft Release Health and Atom sources only; "
    "it does not use Microsoft "
    "Graph, Az"
    "ure, OI"
    "DC, or token-authenticated Microsoft APIs."
)

INCLUDE_PATHS = (
    Path("win11_release_guard"),
    Path("tests"),
    Path("tools"),
    Path("AGENTS.md"),
    Path("README.md"),
    Path("pyproject.toml"),
    Path(".gitignore"),
    Path(".gitattributes"),
    Path(".github") / "dependabot.yml",
    Path(".github") / "workflows" / "ci.yml",
    Path(".github") / "workflows" / "publish-policy.yml",
    Path(".github") / "workflows" / "codeql.yml",
    Path(".github") / "workflows" / "pylint.yml",
    Path(".github") / "workflows" / "dependency-freshness.yml",
    Path(".github") / "workflows" / "dependency-audit.yml",
    Path("docs"),
)

EXCLUDED_DIR_NAMES = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    ".cache",
    ".tmp",
    "build",
    "dist",
}

EXCLUDED_FILE_PATTERNS = (
    "*.pyc",
    "*.pyo",
    "*.pem",
    "*.key",
    "*private*key*",
    "private-" + "key.b64",
    "out*.json",
    "release-check*.json",
    "test-output*.json",
    "cli-output*.json",
    "local-output*.json",
    "*handover*.md",
    "*.tmp",
    "*.temp",
    "*.log",
    "*.bak",
    "*.zip",
    "*.swp",
    "*~",
    "~$*",
    ".DS_Store",
    "Thumbs.db",
    LEGACY_PROTOTYPE_NAME,
)

REQUIRED_ARCHIVE_ENTRIES = {
    "AGENTS.md",
    "README.md",
    "pyproject.toml",
    ".gitignore",
    ".gitattributes",
    ".github/dependabot.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/publish-policy.yml",
    ".github/workflows/codeql.yml",
    ".github/workflows/pylint.yml",
    ".github/workflows/dependency-freshness.yml",
    ".github/workflows/dependency-audit.yml",
    "win11_release_guard/__init__.py",
    "win11_release_guard/data/windows-release-policy.json",
    "win11_release_guard/data/windows-release-policy.json.sig",
    "win11_release_guard/data/trusted_policy_keys.json",
    "tools/generate_policy.py",
    "tools/generate_signing_key.py",
    "tools/scan_for_secret_material.py",
    "tools/check_commit_message.py",
    "tools/check_dependency_freshness.py",
    "tools/check_github_action_versions.py",
    "tools/export_clean_archive.py",
    "docs/policy-signing.md",
    "docs/security-automation.md",
    "tests/test_no_secret_material.py",
}

FORBIDDEN_PACKAGE_IDENTITY_PATTERNS = (
    "w11_" + "versioning" + "_api_controller",
    "w11" + "-versioning-api-controller",
    "versioning" + "_api_controller",
    "win11" + "-release-guard",
)
FORBIDDEN_ACTIVE_AUTH_PATTERNS = (
    "Microsoft " + "Graph",
    "Az" + "ure",
    "OI" + "DC",
    "allow-no-" + "subscriptions",
    "WindowsUpdates" + ".Read.All",
)
ALLOWED_HISTORICAL_AUTH_FILES = {
    "deep-research-report.md",
    "docs/source-learnings.md",
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


def _normalize_archive_name(path: Path) -> str:
    return path.as_posix()


def _is_excluded(relative_path: Path) -> bool:
    parts = set(relative_path.parts)
    if parts.intersection(EXCLUDED_DIR_NAMES):
        return True
    name = relative_path.name
    suffix = relative_path.suffix.lower()
    if suffix == ".zip":
        return True
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in EXCLUDED_FILE_PATTERNS)


def _included_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for include_path in INCLUDE_PATHS:
        source = root / include_path
        if not source.exists():
            raise FileNotFoundError(f"Required archive source path is missing: {include_path}")
        if source.is_file():
            relative = source.relative_to(root)
            if not _is_excluded(relative):
                files.append(source)
            continue
        for path in source.rglob("*"):
            if path.is_file():
                relative = path.relative_to(root)
                if not _is_excluded(relative):
                    files.append(path)
    return sorted(files, key=lambda path: _normalize_archive_name(path.relative_to(root)))


def create_archive(root: Path = REPO_ROOT, archive_path: Path | None = None) -> Path:
    root = root.resolve()
    archive_path = archive_path or root / DEFAULT_ARCHIVE_PATH
    if not archive_path.is_absolute():
        archive_path = root / archive_path
    archive_path.parent.mkdir(parents=True, exist_ok=True)

    files = _included_files(root)
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, _normalize_archive_name(path.relative_to(root)))
    return archive_path


def _is_text_entry(name: str) -> bool:
    return Path(name).suffix.lower() in TEXT_SUFFIXES


def _zip_text_entries(archive: zipfile.ZipFile) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for info in archive.infolist():
        if info.is_dir() or not _is_text_entry(info.filename):
            continue
        data = archive.read(info)
        if b"\0" in data[:4096]:
            continue
        entries.append((info.filename, data.decode("utf-8", errors="replace")))
    return entries


def _validate_archive_content(archive_path: Path) -> None:
    findings: list[str] = []
    with zipfile.ZipFile(archive_path) as archive:
        for name, text in _zip_text_entries(archive):
            identity_text = text
            for pattern in FORBIDDEN_PACKAGE_IDENTITY_PATTERNS:
                if pattern in identity_text:
                    findings.append(f"{name}: stale package identity {pattern!r}")

            auth_text = text
            if name in ALLOWED_HISTORICAL_AUTH_FILES:
                auth_text = ""
            elif name.startswith("tests/"):
                auth_text = ""
            elif name == "README.md":
                auth_text = auth_text.replace(REQUIRED_README_PUBLIC_SOURCES_STATEMENT, "")
            for pattern in FORBIDDEN_ACTIVE_AUTH_PATTERNS:
                if re.search(re.escape(pattern), auth_text, flags=re.IGNORECASE):
                    findings.append(f"{name}: active auth reference {pattern!r}")

    if findings:
        raise RuntimeError("Archive content validation failed: " + "; ".join(sorted(findings)))


def _validate_archive_extracts_and_tests_run(archive_path: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="win-release-guard-archive-") as temp_dir:
        extract_root = Path(temp_dir) / "source"
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(extract_root)

        scan_command = [
            sys.executable,
            "tools/scan_for_secret_material.py",
            "win11_release_guard",
            "tests",
            "tools",
            "docs",
            "README.md",
            "AGENTS.md",
            "pyproject.toml",
            ".github",
        ]
        scan_result = subprocess.run(
            scan_command,
            cwd=extract_root,
            text=True,
            capture_output=True,
            timeout=60,
        )
        if scan_result.returncode != 0:
            output = "\n".join(part for part in (scan_result.stdout, scan_result.stderr) if part)
            raise RuntimeError(f"Archive contains private key material or token-like secrets:\n{output}")

        required_test_paths = (
            extract_root / "pyproject.toml",
            extract_root / "tests",
            extract_root / "win11_release_guard",
            extract_root / "tools",
        )
        missing = [path.relative_to(extract_root).as_posix() for path in required_test_paths if not path.exists()]
        if missing:
            raise RuntimeError(f"Archive cannot run tests because required paths are missing: {', '.join(missing)}")

        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONPATH"] = str(extract_root)
        env["WIN_RELEASE_GUARD_ARCHIVE_VALIDATION_DEPTH"] = "1"
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=extract_root,
            env=env,
            text=True,
            capture_output=True,
            timeout=120,
        )
        if result.returncode != 0:
            output = "\n".join(part for part in (result.stdout, result.stderr) if part)
            raise RuntimeError(f"Archive test run failed:\n{output}")


def validate_archive(archive_path: Path, *, run_tests: bool = True) -> list[str]:
    with zipfile.ZipFile(archive_path) as archive:
        bad_member = archive.testzip()
        if bad_member:
            raise RuntimeError(f"Archive contains a corrupt member: {bad_member}")
        names = sorted(archive.namelist())

    missing = sorted(REQUIRED_ARCHIVE_ENTRIES - set(names))
    if missing:
        raise RuntimeError(f"Archive is missing required entries: {', '.join(missing)}")

    forbidden: list[str] = []
    for name in names:
        path = Path(name)
        if set(path.parts).intersection({".git", ".pytest_cache", "__pycache__", ".cache", ".tmp", "build", "dist"}):
            forbidden.append(name)
            continue
        if (
            path.name == "out.json"
            or path.name == LEGACY_PROTOTYPE_NAME
            or path.suffix in {".pyc", ".pem", ".key", ".zip"}
            or fnmatch.fnmatchcase(path.name, "out*.json")
            or fnmatch.fnmatchcase(path.name, "*private*key*")
        ):
            forbidden.append(name)

    if forbidden:
        raise RuntimeError(f"Archive contains forbidden entries: {', '.join(sorted(forbidden))}")
    _validate_archive_content(archive_path)
    if run_tests and not os.environ.get("WIN_RELEASE_GUARD_ARCHIVE_VALIDATION_DEPTH"):
        _validate_archive_extracts_and_tests_run(archive_path)
    return names


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a clean win-release-guard source archive.")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_ARCHIVE_PATH,
        help="Archive path, relative to the repository root unless absolute.",
    )
    parser.add_argument(
        "--skip-test-run",
        action="store_true",
        help="Validate archive contents without running pytest inside the extracted archive.",
    )
    args = parser.parse_args(argv)

    try:
        archive_path = create_archive(REPO_ROOT, args.output)
        names = validate_archive(archive_path, run_tests=not args.skip_test_run)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Created {archive_path}")
    print(f"Entries: {len(names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
