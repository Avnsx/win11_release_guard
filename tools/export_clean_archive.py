from __future__ import annotations

import argparse
import fnmatch
import sys
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARCHIVE_PATH = Path("dist") / "win-release-guard-source.zip"

INCLUDE_PATHS = (
    Path("win11_release_guard"),
    Path("tests"),
    Path("tools"),
    Path("README.md"),
    Path("pyproject.toml"),
    Path(".github") / "workflows" / "ci.yml",
    Path("docs"),
)

EXCLUDED_DIR_NAMES = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    ".cache",
    "build",
    "dist",
}

EXCLUDED_FILE_PATTERNS = (
    "*.pyc",
    "*.pyo",
    "out*.json",
    "release-check*.json",
    "test-output*.json",
    "cli-output*.json",
    "local-output*.json",
    "*.tmp",
    "*.temp",
    "*.log",
    "*.bak",
    "*.swp",
    "*~",
    "~$*",
    ".DS_Store",
    "Thumbs.db",
    "windows_releases_info.py",
)

REQUIRED_ARCHIVE_ENTRIES = {
    "README.md",
    "pyproject.toml",
    ".github/workflows/ci.yml",
    "win11_release_guard/__init__.py",
    "win11_release_guard/data/windows-release-policy.json",
    "win11_release_guard/data/windows-release-policy.json.sig",
    "tools/generate_policy.py",
    "tools/export_clean_archive.py",
}


def _normalize_archive_name(path: Path) -> str:
    return path.as_posix()


def _is_excluded(relative_path: Path) -> bool:
    parts = set(relative_path.parts)
    if parts.intersection(EXCLUDED_DIR_NAMES):
        return True
    name = relative_path.name
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


def validate_archive(archive_path: Path) -> list[str]:
    with zipfile.ZipFile(archive_path) as archive:
        names = sorted(archive.namelist())

    missing = sorted(REQUIRED_ARCHIVE_ENTRIES - set(names))
    if missing:
        raise RuntimeError(f"Archive is missing required entries: {', '.join(missing)}")

    forbidden: list[str] = []
    for name in names:
        path = Path(name)
        if set(path.parts).intersection({".git", ".pytest_cache", "__pycache__", ".cache", "build", "dist"}):
            forbidden.append(name)
            continue
        if path.name == "out.json" or path.name == "windows_releases_info.py" or path.suffix == ".pyc":
            forbidden.append(name)

    if forbidden:
        raise RuntimeError(f"Archive contains forbidden entries: {', '.join(sorted(forbidden))}")
    return names


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a clean win-release-guard source archive.")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_ARCHIVE_PATH,
        help="Archive path, relative to the repository root unless absolute.",
    )
    args = parser.parse_args(argv)

    try:
        archive_path = create_archive(REPO_ROOT, args.output)
        names = validate_archive(archive_path)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Created {archive_path}")
    print(f"Entries: {len(names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
