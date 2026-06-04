from __future__ import annotations

import os
from dataclasses import dataclass, field


DEFAULT_RELEASE_HEALTH_URL = (
    "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information"
)
DEFAULT_POLICY_URL = "https://avnsx.github.io/win11_release_guard/windows-release-policy.json"
DEFAULT_PAGES_BASE_URL = "https://avnsx.github.io/win11_release_guard"
DEFAULT_PUBLISHED_POLICY_URLS = {
    "landing": f"{DEFAULT_PAGES_BASE_URL}/",
    "policy": DEFAULT_POLICY_URL,
    "signature": f"{DEFAULT_POLICY_URL}.sig",
    "manifest": f"{DEFAULT_PAGES_BASE_URL}/policy-manifest.json",
    "api_policy": f"{DEFAULT_PAGES_BASE_URL}/api/v1/policy.json",
    "api_signature": f"{DEFAULT_PAGES_BASE_URL}/api/v1/policy.sig",
    "api_manifest": f"{DEFAULT_PAGES_BASE_URL}/api/v1/manifest.json",
}
POLICY_URL_ENV_VAR = "WIN11_RELEASE_GUARD_POLICY_URL"
STRICT_PRODUCTION_ENV_VAR = "WIN11_RELEASE_GUARD_STRICT_PRODUCTION"

DEFAULT_USER_AGENT = "win11_release_guard/0.2"
DEFAULT_CACHE_FILE_NAME = "windows-release-policy.json"
DEFAULT_QUALITY_POLICY = "b_release_only"
DEFAULT_CACHE_MAX_AGE_HOURS = 72
DEFAULT_STALE_CACHE_MAX_AGE_HOURS = 720
DEFAULT_TRUSTED_POLICY_KEY_ID = "win11_release_guard-policy-2026-05"
DEFAULT_TRUSTED_POLICY_PUBLIC_KEY = "EyYjpk2UGyF2uutZg3PE5+p6gN2sMmSl6mRscTmmz9s="
DEFAULT_HTTP_TIMEOUT_SECONDS = 12.0
DEFAULT_WUA_TIMEOUT_SECONDS = 8.0
DEFAULT_DISM_TIMEOUT_SECONDS = 10.0
DEFAULT_POWERSHELL_TIMEOUT_SECONDS = 8.0
DEFAULT_PANTHER_TAIL_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_WUA_MAX_HISTORY = 50
DEFAULT_WUA_MAX_RELEVANT_UPDATES = 10
DEFAULT_EVENT_LOG_MAX_EVENTS = 100


@dataclass(frozen=True)
class ReleaseCheckerConfig:
    policy_url: str | None = None
    cache_file: str | None = None
    cache_max_age_hours: float = DEFAULT_CACHE_MAX_AGE_HOURS
    stale_cache_max_age_hours: float = DEFAULT_STALE_CACHE_MAX_AGE_HOURS
    quality_policy: str = DEFAULT_QUALITY_POLICY
    explicit_target_release: str | None = None
    prefer_h2_releases: bool = True
    excluded_releases: frozenset[str] = field(default_factory=lambda: frozenset({"26H1"}))
    enable_wua_probe: bool = False
    timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS
    wua_timeout_seconds: float = DEFAULT_WUA_TIMEOUT_SECONDS
    wua_max_history: int = DEFAULT_WUA_MAX_HISTORY
    wua_max_relevant_updates: int = DEFAULT_WUA_MAX_RELEVANT_UPDATES
    event_log_max_events: int = DEFAULT_EVENT_LOG_MAX_EVENTS
    dism_timeout_seconds: float = DEFAULT_DISM_TIMEOUT_SECONDS
    powershell_timeout_seconds: float = DEFAULT_POWERSHELL_TIMEOUT_SECONDS
    panther_tail_max_bytes: int = DEFAULT_PANTHER_TAIL_MAX_BYTES
    allow_runtime_release_health_html: bool = False
    allow_unsigned_policy: bool = False
    trusted_policy_public_key: str | None = None
    use_bundled_policy_fallback: bool = True
    source_check_required_for_green: bool = False
    strict_production: bool = field(default_factory=lambda: strict_production_from_env())
    allow_major_upgrade_recommendation: bool = False
    allow_server_evaluation: bool = False
    warn_on_preview_installed: bool = True
    disallow_preview_installed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "policy_url", normalize_policy_url(self.policy_url))
        object.__setattr__(self, "strict_production", bool(self.strict_production))
        if self.strict_production:
            object.__setattr__(self, "allow_runtime_release_health_html", False)
            object.__setattr__(self, "allow_unsigned_policy", False)
            object.__setattr__(self, "source_check_required_for_green", True)
        object.__setattr__(
            self,
            "excluded_releases",
            frozenset(str(release).upper() for release in self.excluded_releases),
        )


def normalize_policy_url(value: str | None) -> str | None:
    normalized = str(value).strip() if value is not None else None
    return normalized or None


def policy_url_from_env() -> str | None:
    return normalize_policy_url(os.environ.get(POLICY_URL_ENV_VAR))


def strict_production_from_env() -> bool:
    value = str(os.environ.get(STRICT_PRODUCTION_ENV_VAR) or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def resolve_policy_url(configured_policy_url: str | None) -> str | None:
    return (
        normalize_policy_url(configured_policy_url)
        or policy_url_from_env()
        or normalize_policy_url(DEFAULT_POLICY_URL)
    )


def policy_url_source(configured_policy_url: str | None) -> str:
    if normalize_policy_url(configured_policy_url):
        return "config"
    if policy_url_from_env():
        return "env"
    if normalize_policy_url(DEFAULT_POLICY_URL):
        return "default"
    return "none"


__all__ = [
    "DEFAULT_CACHE_FILE_NAME",
    "DEFAULT_CACHE_MAX_AGE_HOURS",
    "DEFAULT_DISM_TIMEOUT_SECONDS",
    "DEFAULT_EVENT_LOG_MAX_EVENTS",
    "DEFAULT_HTTP_TIMEOUT_SECONDS",
    "DEFAULT_PANTHER_TAIL_MAX_BYTES",
    "DEFAULT_PAGES_BASE_URL",
    "DEFAULT_POWERSHELL_TIMEOUT_SECONDS",
    "DEFAULT_POLICY_URL",
    "DEFAULT_PUBLISHED_POLICY_URLS",
    "DEFAULT_QUALITY_POLICY",
    "DEFAULT_RELEASE_HEALTH_URL",
    "DEFAULT_STALE_CACHE_MAX_AGE_HOURS",
    "DEFAULT_TRUSTED_POLICY_KEY_ID",
    "DEFAULT_TRUSTED_POLICY_PUBLIC_KEY",
    "DEFAULT_USER_AGENT",
    "DEFAULT_WUA_MAX_HISTORY",
    "DEFAULT_WUA_MAX_RELEVANT_UPDATES",
    "DEFAULT_WUA_TIMEOUT_SECONDS",
    "POLICY_URL_ENV_VAR",
    "ReleaseCheckerConfig",
    "STRICT_PRODUCTION_ENV_VAR",
    "normalize_policy_url",
    "policy_url_from_env",
    "policy_url_source",
    "resolve_policy_url",
    "strict_production_from_env",
]
