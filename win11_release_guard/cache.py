from __future__ import annotations

import json
import os
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePath, PureWindowsPath

from .config import DEFAULT_CACHE_FILE_NAME, DEFAULT_CACHE_MAX_AGE_HOURS
from .exceptions import PolicyParseError
from .json_utils import DEFAULT_MAX_JSON_BYTES, StrictJSONError, strict_json_object
from .models import ReleasePolicy


def _default_cache_path_for(
    os_name: str,
    env: Mapping[str, str],
    cwd: Path | PurePath,
) -> Path | PurePath:
    if os_name == "nt" and env.get("LOCALAPPDATA"):
        return PureWindowsPath(env["LOCALAPPDATA"]) / "win11_release_guard" / DEFAULT_CACHE_FILE_NAME
    return cwd / ".cache" / DEFAULT_CACHE_FILE_NAME


def default_cache_path() -> Path:
    return Path(_default_cache_path_for(os.name, os.environ, Path.cwd()))


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _cache_timestamp(path: Path, policy: ReleasePolicy) -> datetime:
    generated = _parse_timestamp(policy.generated_at_utc)
    if generated is not None:
        return generated
    modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return modified


def is_policy_cache_fresh(
    path: str | Path | None = None,
    *,
    max_age_hours: float = DEFAULT_CACHE_MAX_AGE_HOURS,
    now: datetime | None = None,
) -> bool:
    cache_path = Path(path) if path is not None else default_cache_path()
    if not cache_path.exists():
        return False

    policy = load_policy_cache(cache_path)
    reference = now or datetime.now(timezone.utc)
    return reference - _cache_timestamp(cache_path, policy) <= timedelta(hours=max_age_hours)


def load_policy_cache(path: str | Path) -> ReleasePolicy:
    cache_path = Path(path)
    try:
        if cache_path.stat().st_size > DEFAULT_MAX_JSON_BYTES:
            raise StrictJSONError(
                f"Cached release policy at {cache_path} is too large: "
                f"exceeds {DEFAULT_MAX_JSON_BYTES} bytes."
            )
        data = strict_json_object(cache_path.read_bytes(), label=f"Cached release policy at {cache_path}")
        return ReleasePolicy.from_dict(data)
    except (OSError, StrictJSONError, TypeError, ValueError, KeyError) as exc:
        raise PolicyParseError(f"Cached release policy at {cache_path} is invalid: {exc}") from exc


def save_policy_cache(path: str | Path, policy: ReleasePolicy) -> None:
    cache_path = Path(path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(policy.to_dict(), indent=2, sort_keys=True)
    cache_path.write_text(payload + "\n", encoding="utf-8")


def load_cached_policy(
    path: str | Path | None = None,
    *,
    max_age_hours: float = DEFAULT_CACHE_MAX_AGE_HOURS,
    allow_stale: bool = False,
    now: datetime | None = None,
) -> ReleasePolicy | None:
    cache_path = Path(path) if path is not None else default_cache_path()
    if not cache_path.exists():
        return None

    policy = load_policy_cache(cache_path)
    if allow_stale:
        return policy

    reference = now or datetime.now(timezone.utc)
    if reference - _cache_timestamp(cache_path, policy) <= timedelta(hours=max_age_hours):
        return policy
    return None


def save_cached_policy(policy: ReleasePolicy, path: str | Path | None = None) -> Path:
    cache_path = Path(path) if path is not None else default_cache_path()
    save_policy_cache(cache_path, policy)
    return cache_path


__all__ = [
    "_default_cache_path_for",
    "default_cache_path",
    "is_policy_cache_fresh",
    "load_cached_policy",
    "load_policy_cache",
    "save_cached_policy",
    "save_policy_cache",
]
