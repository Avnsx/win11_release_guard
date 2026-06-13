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
DEFAULT_ARCHIVE_PATH = Path("dist") / "win11_release_guard-source.zip"
LEGACY_PROTOTYPE_NAME = "_".join(("windows", "releases", "info")) + ".py"
ALLOWED_NORMALIZED_PYPI_URL = "https://pypi.org/project/win11-release-guard/"
ALLOWED_NORMALIZED_PYPI_BADGE_ENDPOINTS = (
    "https://img.shields.io/pypi/v/win11-release-guard",
    "https://img.shields.io/pypi/pyversions/win11-release-guard",
    "https://img.shields.io/pypi/dm/win11-release-guard",
)
REQUIRED_PUBLIC_ENRICHMENT_SOURCE_STATEMENT = (
    "The production generator may use public Microsoft Release Health HTML, public Microsoft Update History Atom data, "
    "Atom-linked public Microsoft Support articles, and unauthenticated public MSRC CVRF data for source diagnostics "
    "and informational enrichment; it does not use Microsoft "
    "Graph or token-authenticated Microsoft APIs."
)
REQUIRED_AGENTS_PUBLIC_ENRICHMENT_STATEMENT = (
    "The production generator may use public Microsoft Release Health HTML, public Microsoft Update History Atom feed data, "
    "Atom-linked public Microsoft Support articles, and unauthenticated public MSRC CVRF data for source diagnostics "
    "and informational enrichment."
)
ALLOWED_ACTIVE_AUTH_BOUNDARIES = (
    REQUIRED_PUBLIC_ENRICHMENT_SOURCE_STATEMENT,
    REQUIRED_AGENTS_PUBLIC_ENRICHMENT_STATEMENT,
    "Authenticated Microsoft "
    "Graph, token-authenticated Microsoft APIs, and historical authenticated metadata research "
    "remain out of active production generator architecture; historical research may remain only in "
    "`docs/architecture-insight.md` when explicitly marked out of scope.",
)

INCLUDE_PATHS = (
    Path("win11_release_guard"),
    Path("tests"),
    Path("tools"),
    Path("AGENTS.md"),
    Path("README.md"),
    Path("CHANGELOG.md"),
    Path("LICENSE.txt"),
    Path("pyproject.toml"),
    Path(".gitignore"),
    Path(".gitattributes"),
    Path(".github") / "dependabot.yml",
    Path(".github") / "workflows" / "ci.yml",
    Path(".github") / "workflows" / "publish-policy.yml",
    Path(".github") / "workflows" / "sync-source-diagnostics-issues.yml",
    Path(".github") / "workflows" / "sync-wiki.yml",
    Path(".github") / "workflows" / "release.yml",
    Path(".github") / "workflows" / "pypi-publish.yml",
    Path(".github") / "workflows" / "codeql.yml",
    Path(".github") / "workflows" / "pylint.yml",
    Path(".github") / "workflows" / "dependency-freshness.yml",
    Path(".github") / "workflows" / "dependency-audit.yml",
    Path("assets"),
    Path("docs"),
    Path("wiki"),
)

EXCLUDED_DIR_NAMES = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    ".cache",
    ".tmp",
    "build",
    "dist",
    "generated_site",
    "site",
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
    "CHANGELOG.md",
    "LICENSE.txt",
    "pyproject.toml",
    ".gitignore",
    ".gitattributes",
    ".github/dependabot.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/publish-policy.yml",
    ".github/workflows/sync-source-diagnostics-issues.yml",
    ".github/workflows/sync-wiki.yml",
    ".github/workflows/release.yml",
    ".github/workflows/pypi-publish.yml",
    ".github/workflows/codeql.yml",
    ".github/workflows/pylint.yml",
    ".github/workflows/dependency-freshness.yml",
    ".github/workflows/dependency-audit.yml",
    "assets/images/download_from_pypi.png",
    "win11_release_guard/__init__.py",
    "win11_release_guard/data/windows-release-policy.json",
    "win11_release_guard/data/windows-release-policy.json.sig",
    "win11_release_guard/data/trusted_policy_keys.json",
    "tools/generate_policy.py",
    "tools/generate_signing_key.py",
    "tools/sync_github_wiki.py",
    "tools/scan_for_secret_material.py",
    "tools/check_commit_message.py",
    "tools/check_dependency_freshness.py",
    "tools/check_github_action_versions.py",
    "tools/check_project_identity.py",
    "tools/check_version_consistency.py",
    "tools/export_clean_archive.py",
    "docs/tagged-release-lane.md",
    "docs/policy-signing.md",
    "docs/security-automation.md",
    "docs/releases/v0.3.3.md",
    "docs/releases/v0.3.2.md",
    "docs/releases/v0.3.1.md",
    "wiki/Home.md",
    "wiki/Release-v0.3.3.md",
    "wiki/Release-v0.3.2.md",
    "wiki/Release-v0.3.1.md",
    "tests/test_github_wiki_sync.py",
    "tests/test_no_secret_material.py",
}

FORBIDDEN_PACKAGE_IDENTITY_PATTERNS = (
    "w11_" + "versioning" + "_api_controller",
    "w11" + "-versioning-api-controller",
    "versioning" + "_api_controller",
    "win11" + "-release-guard",
)
FORBIDDEN_RENAMED_REPO_PATTERNS = (
    "https://github.com/Avnsx/" + ("win" + "-release-guard"),
    "Avnsx/" + ("win" + "-release-guard"),
    "https://avnsx.github.io/" + ("win" + "-release-guard"),
    "avnsx.github.io/" + ("win" + "-release-guard"),
    ("win" + "-release-guard") + "-source.zip",
)
FORBIDDEN_ACTIVE_AUTH_PATTERNS = (
    "Microsoft " + "Graph",
    "Az" + "ure",
    "allow-no-" + "subscriptions",
    "WindowsUpdates" + ".Read.All",
)
FORBIDDEN_ACTIVE_AUTH_REGEXES = (
    re.compile(r"\b(?:Microsoft|" + "Az" + r"ure)\b[^\n]{0,80}\bOIDC\b", flags=re.IGNORECASE),
    re.compile(r"\bOIDC\b[^\n]{0,80}\b(?:Microsoft|" + "Az" + r"ure)\b", flags=re.IGNORECASE),
)
ALLOWED_HISTORICAL_AUTH_FILES = {
    "docs/architecture-insight.md",
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
    if _has_excluded_dir_part(relative_path.parts):
        return True
    name = relative_path.name
    suffix = relative_path.suffix.lower()
    if suffix == ".zip":
        return True
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in EXCLUDED_FILE_PATTERNS)


def _has_excluded_dir_part(parts: tuple[str, ...]) -> bool:
    return any(part in EXCLUDED_DIR_NAMES or part.endswith(".egg-info") for part in parts)


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


def _strip_allowed_normalized_pypi_references(text: str) -> str:
    scan_text = text.replace(ALLOWED_NORMALIZED_PYPI_URL, "")
    for endpoint in ALLOWED_NORMALIZED_PYPI_BADGE_ENDPOINTS:
        scan_text = scan_text.replace(endpoint, "")
    return scan_text


def _validate_archive_content(archive_path: Path) -> None:
    findings: list[str] = []
    with zipfile.ZipFile(archive_path) as archive:
        for name, text in _zip_text_entries(archive):
            identity_text = _strip_allowed_normalized_pypi_references(text)
            for pattern in FORBIDDEN_PACKAGE_IDENTITY_PATTERNS:
                if pattern in identity_text:
                    findings.append(f"{name}: stale package identity {pattern!r}")
            for pattern in FORBIDDEN_RENAMED_REPO_PATTERNS:
                if pattern in identity_text:
                    findings.append(f"{name}: stale repo/path identity {pattern!r}")
            if ("win" + "-release-guard") in identity_text:
                findings.append(f"{name}: stale project identity after rename")

            auth_text = text
            if name in ALLOWED_HISTORICAL_AUTH_FILES:
                auth_text = ""
            elif name.startswith("tests/"):
                auth_text = ""
            else:
                for statement in ALLOWED_ACTIVE_AUTH_BOUNDARIES:
                    auth_text = auth_text.replace(statement, "")
            for pattern in FORBIDDEN_ACTIVE_AUTH_PATTERNS:
                if re.search(re.escape(pattern), auth_text, flags=re.IGNORECASE):
                    findings.append(f"{name}: active auth reference {pattern!r}")
            for pattern in FORBIDDEN_ACTIVE_AUTH_REGEXES:
                if pattern.search(auth_text):
                    findings.append(f"{name}: active auth reference {pattern.pattern!r}")

    if findings:
        raise RuntimeError("Archive content validation failed: " + "; ".join(sorted(findings)))


_AMBIENT_PYTEST_INJECTION_VARS = ("PYTEST_ADDOPTS", "PYTEST_PLUGINS")


def _archive_validation_pytest_env(extract_root: Path, base_env=None) -> dict[str, str]:
    """Build the controlled environment for the inner archive-validation pytest.

    The inner gate must be deterministic and resistant to ambient pytest
    configuration so a developer shell cannot change, fail, or hang archive
    validation. `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` stops entry-point plugin
    autoload, but two pytest variables still inject behavior through an inherited
    environment and must be removed here:

    - `PYTEST_ADDOPTS` is appended to every pytest invocation (for example
      `--cov=...` or `-p somplugin`), so a missing plugin can fail the inner run;
    - `PYTEST_PLUGINS` is imported explicitly even when autoload is disabled, so a
      stale value such as `not_a_real_plugin` crashes the run before tests start.

    Only those pytest injection vectors are stripped; required Python runtime
    variables (path, encoding, no-bytecode) are preserved, and the recursion guard
    is kept so the inner gate does not re-run itself.
    """
    env = dict(os.environ if base_env is None else base_env)
    for name in _AMBIENT_PYTEST_INJECTION_VARS:
        env.pop(name, None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(extract_root)
    env["WIN11_RELEASE_GUARD_ARCHIVE_VALIDATION_DEPTH"] = "1"
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    return env


def _validate_archive_extracts_and_tests_run(archive_path: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="win11_release_guard-archive-") as temp_dir:
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
            "wiki",
            "README.md",
            "CHANGELOG.md",
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

        identity_result = subprocess.run(
            [sys.executable, "tools/check_project_identity.py"],
            cwd=extract_root,
            text=True,
            capture_output=True,
            timeout=60,
        )
        if identity_result.returncode != 0:
            output = "\n".join(part for part in (identity_result.stdout, identity_result.stderr) if part)
            raise RuntimeError(f"Archive contains stale project identity:\n{output}")

        required_test_paths = (
            extract_root / "pyproject.toml",
            extract_root / "tests",
            extract_root / "win11_release_guard",
            extract_root / "tools",
        )
        missing = [path.relative_to(extract_root).as_posix() for path in required_test_paths if not path.exists()]
        if missing:
            raise RuntimeError(f"Archive cannot run tests because required paths are missing: {', '.join(missing)}")

        env = _archive_validation_pytest_env(extract_root)
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
        if _has_excluded_dir_part(path.parts):
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
    if run_tests and not os.environ.get("WIN11_RELEASE_GUARD_ARCHIVE_VALIDATION_DEPTH"):
        _validate_archive_extracts_and_tests_run(archive_path)
    return names


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a clean win11_release_guard source archive.")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_ARCHIVE_PATH,
        help="Archive path, relative to the repository root unless absolute.",
    )
    parser.add_argument(
        "--validate",
        type=Path,
        default=None,
        help="Validate an existing clean archive instead of creating one.",
    )
    parser.add_argument(
        "--skip-test-run",
        action="store_true",
        help="Validate archive contents without running pytest inside the extracted archive.",
    )
    args = parser.parse_args(argv)

    try:
        if args.validate is not None:
            archive_path = args.validate
            if not archive_path.is_absolute():
                archive_path = REPO_ROOT / archive_path
            names = validate_archive(archive_path, run_tests=not args.skip_test_run)
            print(f"Validated {archive_path}")
            print(f"Entries: {len(names)}")
            return 0

        archive_path = create_archive(REPO_ROOT, args.output)
        names = validate_archive(archive_path, run_tests=not args.skip_test_run)
    except Exception as exc:
        message = str(exc) or type(exc).__name__
        print(f"Error: {message}", file=sys.stderr)
        return 1

    print(f"Created {archive_path}")
    print(f"Entries: {len(names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
