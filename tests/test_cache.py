from datetime import datetime, timezone
from pathlib import PureWindowsPath

import pytest

from win11_release_guard.cache import (
    _default_cache_path_for,
    default_cache_path,
    is_policy_cache_fresh,
    load_cached_policy,
    save_cached_policy,
)
from win11_release_guard.config import DEFAULT_POLICY_URL, ReleaseCheckerConfig, resolve_policy_url
from win11_release_guard.exceptions import PolicyParseError
from win11_release_guard.models import ReleasePolicy, ReleasePolicyEntry


def _policy(generated_at_utc: str = "2026-05-28T00:00:00+00:00") -> ReleasePolicy:
    return ReleasePolicy(
        generated_at_utc=generated_at_utc,
        current_versions=(
            ReleasePolicyEntry(
                version="25H2",
                build_family=26200,
                servicing_option="General Availability Channel",
            ),
        ),
    )


def test_save_and_load_cached_policy_with_ttl(tmp_path):
    cache_file = tmp_path / "windows-release-policy.json"

    saved_path = save_cached_policy(_policy(), cache_file)
    loaded = load_cached_policy(
        cache_file,
        max_age_hours=24 * 7,
        now=datetime(2026, 5, 29, tzinfo=timezone.utc),
    )

    assert saved_path == cache_file
    assert loaded is not None
    assert loaded.current_versions[0].version == "25H2"
    assert is_policy_cache_fresh(
        cache_file,
        max_age_hours=24 * 7,
        now=datetime(2026, 5, 29, tzinfo=timezone.utc),
    )


def test_load_cached_policy_returns_none_when_stale(tmp_path):
    cache_file = tmp_path / "windows-release-policy.json"
    save_cached_policy(_policy(), cache_file)

    loaded = load_cached_policy(
        cache_file,
        max_age_hours=24,
        now=datetime(2026, 5, 30, 1, tzinfo=timezone.utc),
    )
    stale_allowed = load_cached_policy(
        cache_file,
        max_age_hours=24,
        allow_stale=True,
        now=datetime(2026, 5, 30, 1, tzinfo=timezone.utc),
    )

    assert loaded is None
    assert stale_allowed is not None


def test_default_cache_path_for_windows_uses_localappdata_without_windowspath(tmp_path):
    path = _default_cache_path_for(
        "nt",
        {"LOCALAPPDATA": r"C:\Users\admin\AppData\Local"},
        tmp_path,
    )

    assert isinstance(path, PureWindowsPath)
    assert str(path) == (
        r"C:\Users\admin\AppData\Local\win-release-guard"
        r"\windows-release-policy.json"
    )


def test_default_cache_path_for_windows_missing_localappdata_falls_back_to_cwd(tmp_path):
    path = _default_cache_path_for("nt", {}, tmp_path)

    assert path == tmp_path / ".cache" / "windows-release-policy.json"


def test_default_cache_path_for_non_windows_uses_cwd_cache(tmp_path):
    path = _default_cache_path_for("posix", {}, tmp_path)

    assert path == tmp_path / ".cache" / "windows-release-policy.json"


def test_default_cache_path_returns_host_native_path():
    path = default_cache_path()

    assert path.name == "windows-release-policy.json"


def test_malformed_cache_json_raises_policy_parse_error(tmp_path):
    cache_file = tmp_path / "windows-release-policy.json"
    cache_file.write_text("{not-valid-json", encoding="utf-8")

    with pytest.raises(PolicyParseError, match="Cached release policy"):
        load_cached_policy(cache_file, allow_stale=True)

    with pytest.raises(PolicyParseError, match="Cached release policy"):
        is_policy_cache_fresh(cache_file)


def test_config_defaults_exclude_26h1_or_mark_special_release():
    config = ReleaseCheckerConfig()

    assert config.policy_url is None
    assert resolve_policy_url(config.policy_url) == DEFAULT_POLICY_URL
    assert "26H1" in config.excluded_releases
    assert config.prefer_h2_releases is True
    assert config.cache_max_age_hours == 72
    assert config.stale_cache_max_age_hours == 720
    assert config.allow_runtime_release_health_html is False
    assert config.allow_unsigned_policy is False
    assert config.use_bundled_policy_fallback is True
    assert config.source_check_required_for_green is False
