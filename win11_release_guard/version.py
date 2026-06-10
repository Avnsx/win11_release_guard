from __future__ import annotations

from importlib import metadata
from pathlib import Path


PACKAGE_NAME = "win11_release_guard"
UNKNOWN_VERSION = "unknown"
PYPROJECT_RELATIVE_PATH = Path("pyproject.toml")


def _source_tree_root(start: Path | None = None) -> Path | None:
    path = (start or Path(__file__)).resolve()
    candidates = [path] if path.is_dir() else list(path.parents)
    for candidate in candidates:
        pyproject = candidate / PYPROJECT_RELATIVE_PATH
        if pyproject.exists() and (candidate / PACKAGE_NAME).is_dir():
            return candidate
    return None


def source_tree_package_version(root: Path | None = None) -> str | None:
    source_root = root.resolve() if root is not None else _source_tree_root()
    if source_root is None:
        return None
    pyproject = source_root / PYPROJECT_RELATIVE_PATH
    if not pyproject.exists():
        return None

    in_project_section = False
    try:
        lines = pyproject.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_project_section = line == "[project]"
            continue
        if not in_project_section:
            continue
        name, separator, value = line.partition("=")
        if separator and name.strip() == "version":
            return value.strip().strip('"').strip("'") or None
    return None


def _metadata_version() -> tuple[str | None, Path | None]:
    try:
        distribution = metadata.distribution(PACKAGE_NAME)
    except metadata.PackageNotFoundError:
        return None, None
    version = distribution.version
    try:
        location = Path(distribution.locate_file("")).resolve()
    except (OSError, RuntimeError, ValueError):
        location = None
    return version, location


def package_version() -> str:
    source_root = _source_tree_root()
    source_version = source_tree_package_version(source_root)
    metadata_version, _metadata_location = _metadata_version()

    if source_version:
        return source_version
    if metadata_version:
        return metadata_version
    return UNKNOWN_VERSION


def versioned_product_id() -> str:
    return f"{PACKAGE_NAME}/{package_version()}"


def runtime_user_agent() -> str:
    return versioned_product_id()


def generator_version() -> str:
    return versioned_product_id()


def client_application_id() -> str:
    return versioned_product_id()


__all__ = [
    "PACKAGE_NAME",
    "PYPROJECT_RELATIVE_PATH",
    "UNKNOWN_VERSION",
    "client_application_id",
    "generator_version",
    "package_version",
    "runtime_user_agent",
    "source_tree_package_version",
    "versioned_product_id",
]
