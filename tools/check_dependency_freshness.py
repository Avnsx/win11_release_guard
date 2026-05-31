from __future__ import annotations

import argparse
import json
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PYPROJECT = REPO_ROOT / "pyproject.toml"
DEFAULT_OUTPUT = Path("dependency-freshness.json")
PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"


@dataclass(frozen=True)
class DirectDependency:
    group: str
    raw: str
    requirement: Requirement


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _normalize_name(name: str) -> str:
    return name.lower().replace("_", "-")


def load_pyproject(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"pyproject file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise RuntimeError(f"pyproject parse failed: {exc}") from exc


def parse_direct_dependencies(pyproject: dict[str, Any]) -> list[DirectDependency]:
    project = pyproject.get("project")
    if not isinstance(project, dict):
        raise RuntimeError("pyproject is missing [project]")

    dependencies: list[DirectDependency] = []

    def add_group(group: str, values: object) -> None:
        if values is None:
            return
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise RuntimeError(f"{group} dependencies must be a list of strings")
        for value in values:
            try:
                requirement = Requirement(value)
            except InvalidRequirement as exc:
                raise RuntimeError(f"invalid dependency requirement in {group}: {value}") from exc
            dependencies.append(DirectDependency(group=group, raw=value, requirement=requirement))

    add_group("project.dependencies", project.get("dependencies", []))

    optional = project.get("optional-dependencies", {})
    if optional is None:
        optional = {}
    if not isinstance(optional, dict):
        raise RuntimeError("[project.optional-dependencies] must be a table")
    for group_name in sorted(optional):
        add_group(f"project.optional-dependencies.{group_name}", optional[group_name])

    return sorted(dependencies, key=lambda dep: (_normalize_name(dep.requirement.name), dep.group, dep.raw))


def fetch_pypi_json(name: str, *, timeout_seconds: float) -> dict[str, Any]:
    request = urllib.request.Request(
        PYPI_JSON_URL.format(name=_normalize_name(name)),
        headers={"Accept": "application/json", "User-Agent": "win-release-guard-dependency-freshness"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            data = response.read()
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError(f"failed to query PyPI for {name}: {exc}") from exc
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"failed to parse PyPI JSON for {name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"unexpected PyPI JSON shape for {name}")
    return payload


def _release_has_installable_file(files: object) -> bool:
    if not isinstance(files, list):
        return False
    if not files:
        return False
    for file_record in files:
        if not isinstance(file_record, dict):
            continue
        if not file_record.get("yanked", False):
            return True
    return False


def latest_stable_version(payload: dict[str, Any], *, package_name: str) -> Version:
    releases = payload.get("releases")
    if not isinstance(releases, dict):
        raise RuntimeError(f"PyPI JSON for {package_name} is missing releases")

    versions: list[Version] = []
    for version_text, files in releases.items():
        if not _release_has_installable_file(files):
            continue
        try:
            version = Version(str(version_text))
        except InvalidVersion:
            continue
        if version.is_prerelease or version.is_devrelease:
            continue
        versions.append(version)

    if not versions:
        raise RuntimeError(f"PyPI JSON for {package_name} has no stable installable releases")
    return max(versions)


def evaluate_dependency(dependency: DirectDependency, *, timeout_seconds: float) -> dict[str, Any]:
    payload = fetch_pypi_json(dependency.requirement.name, timeout_seconds=timeout_seconds)
    latest = latest_stable_version(payload, package_name=dependency.requirement.name)
    specifier = dependency.requirement.specifier
    latest_allowed = not specifier or latest in specifier

    return {
        "name": _normalize_name(dependency.requirement.name),
        "group": dependency.group,
        "requirement": dependency.raw,
        "declared_specifier": str(specifier),
        "latest_stable_version": str(latest),
        "latest_stable_allowed_by_specifier": latest_allowed,
        "update_available": not latest_allowed,
    }


def build_summary(pyproject_path: Path, *, timeout_seconds: float) -> tuple[dict[str, Any], int]:
    try:
        pyproject = load_pyproject(pyproject_path)
        dependencies = parse_direct_dependencies(pyproject)
        results = [evaluate_dependency(dependency, timeout_seconds=timeout_seconds) for dependency in dependencies]
    except RuntimeError as exc:
        return (
            {
                "status": "unavailable",
                "generated_at_utc": _utc_now(),
                "pyproject": str(pyproject_path),
                "errors": [str(exc)],
                "dependencies": [],
            },
            2,
        )

    updates = [result for result in results if result["update_available"]]
    status = "updates_available" if updates else "current"
    return (
        {
            "status": status,
            "generated_at_utc": _utc_now(),
            "pyproject": str(pyproject_path),
            "checked_dependency_count": len(results),
            "update_count": len(updates),
            "semantics": (
                "Checks direct pyproject dependencies and optional dependencies. "
                "Passing means each declared direct dependency specifier allows the latest stable PyPI release; "
                "transitive dependencies are not evaluated."
            ),
            "dependencies": results,
            "errors": [],
        },
        1 if updates else 0,
    )


def _print_summary(summary: dict[str, Any]) -> None:
    print(f"Dependency freshness: {summary['status']}")
    if summary.get("errors"):
        for error in summary["errors"]:
            print(f"- {error}")
        return

    print(f"Checked direct dependencies: {summary['checked_dependency_count']}")
    print(f"Updates available: {summary['update_count']}")
    for dependency in summary["dependencies"]:
        marker = "UPDATE" if dependency["update_available"] else "OK"
        print(
            f"- {marker} {dependency['name']} {dependency['requirement']} "
            f"(latest stable: {dependency['latest_stable_version']})"
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check direct dependency freshness against PyPI.")
    parser.add_argument("--pyproject", type=Path, default=DEFAULT_PYPROJECT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--timeout-seconds", type=float, default=12.0)
    args = parser.parse_args(argv)

    summary, exit_code = build_summary(args.pyproject, timeout_seconds=args.timeout_seconds)
    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    _print_summary(summary)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
