from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
NODE24_FORCE_ENV = "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24"
INSECURE_NODE_OPT_OUT = "ACTIONS_ALLOW_USE_" + "UNSECURE_NODE_VERSION"
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<quote>['\"]?)(?P<ref>[^'\"\s#]+)")
FULL_LENGTH_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")

REQUIRED_ACTIONS = {
    "actions/checkout": "v7",
    "actions/setup-python": "v6",
    "actions/configure-pages": "v6",
    "actions/upload-pages-artifact": "v5",
    "actions/upload-artifact": "v7",
    "actions/deploy-pages": "v5",
    "actions/download-artifact": "v8",
}
ALLOWED_ACTIONS = {
    "github/codeql-action/init": {"v4"},
    "github/codeql-action/analyze": {"v4"},
}
PYPA_PUBLISH_ACTION_SHA = "cef221092ed1bacb1cc03d23a2d87d1d172e277b"
ALLOWED_THIRD_PARTY_ACTIONS: dict[str, str | Mapping[str, object]] = {
    "pypa/gh-action-pypi-publish": {
        "sha": PYPA_PUBLISH_ACTION_SHA,
        "workflows": (Path(".github/workflows/pypi-publish.yml"),),
        "reason": "Official PyPA Trusted Publishing action using GitHub OIDC without stored PyPI credentials.",
    },
}


def _is_github_owned_action(action: str) -> bool:
    return action.startswith("actions/") or action.startswith("github/codeql-action/")


def _workflow_key(path: Path) -> Path:
    parts = path.parts
    for index, part in enumerate(parts):
        if part == ".github" and index + 2 < len(parts) and parts[index + 1] == "workflows":
            return Path(*parts[index : index + 3])
    try:
        return path.resolve().relative_to(REPO_ROOT)
    except ValueError:
        return path


def _allowed_third_party_workflows(policy: str | Mapping[str, object]) -> tuple[Path, ...]:
    if not isinstance(policy, Mapping):
        return ()
    workflows = policy.get("workflows")
    if workflows is None:
        return ()
    return tuple(Path(workflow) for workflow in workflows)


def _allowed_third_party_sha(policy: str | Mapping[str, object]) -> str | None:
    if not isinstance(policy, Mapping):
        return None
    value = policy.get("sha")
    return value if isinstance(value, str) else None


@dataclass(frozen=True)
class ActionUse:
    path: Path
    line_number: int
    action: str
    version: str
    raw_ref: str


@dataclass(frozen=True)
class Finding:
    path: Path
    line_number: int
    message: str

    def format(self, root: Path = REPO_ROOT) -> str:
        try:
            display_path = self.path.relative_to(root)
        except ValueError:
            display_path = self.path
        return f"{display_path}:{self.line_number}: {self.message}"


def _workflow_files(workflow_dir: Path) -> list[Path]:
    return sorted(path for path in workflow_dir.glob("*.yml") if path.is_file())


def _split_action_ref(raw_ref: str) -> tuple[str, str] | None:
    action, separator, version = raw_ref.rpartition("@")
    if not separator or not action or not version:
        return None
    return action, version


def _uses_from_text(path: Path, text: str) -> list[ActionUse]:
    uses: list[ActionUse] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = USES_RE.match(line)
        if not match:
            continue
        raw_ref = match.group("ref").strip()
        split = _split_action_ref(raw_ref)
        if split is None:
            continue
        action, version = split
        uses.append(
            ActionUse(
                path=path,
                line_number=line_number,
                action=action,
                version=version,
                raw_ref=raw_ref,
            )
        )
    return uses


def _has_node24_force_env(text: str) -> bool:
    yaml_env = f"{NODE24_FORCE_ENV}: true"
    shell_env = f"{NODE24_FORCE_ENV}=true"
    return yaml_env in text or shell_env in text


def audit_workflow(path: Path) -> list[Finding]:
    text = path.read_text(encoding="utf-8")
    findings: list[Finding] = []
    uses = _uses_from_text(path, text)

    if INSECURE_NODE_OPT_OUT in text:
        findings.append(
            Finding(
                path=path,
                line_number=1,
                message=f"{INSECURE_NODE_OPT_OUT} must not be configured",
            )
        )

    if uses and not _has_node24_force_env(text):
        findings.append(
            Finding(
                path=path,
                line_number=1,
                message=f"workflow uses JavaScript actions but does not set {NODE24_FORCE_ENV}: true",
            )
        )

    for use in uses:
        required_version = REQUIRED_ACTIONS.get(use.action)
        if required_version is not None and use.version != required_version:
            findings.append(
                Finding(
                    path=path,
                    line_number=use.line_number,
                    message=f"{use.action} must use {required_version}, found {use.version}",
                )
            )
            continue

        allowed_versions = ALLOWED_ACTIONS.get(use.action)
        if allowed_versions is not None and use.version not in allowed_versions:
            allowed = ", ".join(sorted(allowed_versions))
            findings.append(
                Finding(
                    path=path,
                    line_number=use.line_number,
                    message=f"{use.action} must use documented allowed version {allowed}, found {use.version}",
                )
            )
            continue

        if required_version is not None or allowed_versions is not None:
            continue

        if _is_github_owned_action(use.action):
            findings.append(
                Finding(
                    path=path,
                    line_number=use.line_number,
                    message=(
                        f"{use.action} is a GitHub-owned action but is not in the "
                        "audited first-party action version map"
                    ),
                )
            )
            continue

        policy = ALLOWED_THIRD_PARTY_ACTIONS.get(use.action)
        if policy is None:
            findings.append(
                Finding(
                    path=path,
                    line_number=use.line_number,
                    message=(
                        f"{use.action} is a third-party action and must be explicitly "
                        "allowlisted before use"
                    ),
                )
            )
            continue

        if FULL_LENGTH_SHA_RE.fullmatch(use.version) is None:
            findings.append(
                Finding(
                    path=path,
                    line_number=use.line_number,
                    message=(
                        f"{use.action} is a third-party action and must be pinned to "
                        "a full 40-character commit SHA"
                    ),
                )
            )
            continue

        allowed_workflows = _allowed_third_party_workflows(policy)
        if allowed_workflows and _workflow_key(use.path) not in allowed_workflows:
            allowed = ", ".join(workflow.as_posix() for workflow in allowed_workflows)
            findings.append(
                Finding(
                    path=path,
                    line_number=use.line_number,
                    message=f"{use.action} is allowed only in {allowed}",
                )
            )
            continue

        required_sha = _allowed_third_party_sha(policy)
        if required_sha is not None and use.version != required_sha:
            findings.append(
                Finding(
                    path=path,
                    line_number=use.line_number,
                    message=f"{use.action} must be pinned to {required_sha}, found {use.version}",
                )
            )

    return findings


def audit_workflows(paths: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        findings.extend(audit_workflow(path))
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit GitHub Actions versions for Node 24 readiness.")
    parser.add_argument(
        "workflow_paths",
        nargs="*",
        type=Path,
        help="Workflow files or directories to scan. Defaults to .github/workflows/*.yml.",
    )
    args = parser.parse_args(argv)

    paths: list[Path] = []
    if args.workflow_paths:
        for input_path in args.workflow_paths:
            if input_path.is_dir():
                paths.extend(_workflow_files(input_path))
            elif input_path.is_file():
                paths.append(input_path)
            else:
                print(f"GitHub action version audit failed: missing path {input_path}", file=sys.stderr)
                return 1
    else:
        paths = _workflow_files(DEFAULT_WORKFLOW_DIR)

    if not paths:
        print("GitHub action version audit failed: no workflow files found.", file=sys.stderr)
        return 1

    findings = audit_workflows(paths)
    if findings:
        print("GitHub action version audit failed:", file=sys.stderr)
        for finding in findings:
            print(f"- {finding.format()}", file=sys.stderr)
        return 1

    print(f"GitHub action version audit passed for {len(paths)} workflow file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
