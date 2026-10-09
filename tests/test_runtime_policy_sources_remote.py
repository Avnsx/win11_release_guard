from __future__ import annotations

import json
import win11_release_guard.api as api
import win11_release_guard.config as config_module
from win11_release_guard.config import DEFAULT_POLICY_URL, DEFAULT_PUBLISHED_POLICY_URLS, ReleaseCheckerConfig
from win11_release_guard.exceptions import PolicyFetchError
from win11_release_guard.models import EvaluationStatus, SourceStatus
from tests.support.runtime_policy_sources_helpers import (
    BAD_POLICY_URL,
    TEST_PUBLIC_KEY,
    _fail_remote,
    _generated_at,
    _json_policy,
    _patch_local,
    _policy,
    _write_signed_json,
    _write_signed_policy,
)


def test_runtime_json_policy_url_works(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_file = tmp_path / "windows-release-policy.json"
    _write_signed_json(policy_file, _json_policy())

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=str(policy_file),
            cache_file=str(tmp_path / "cache.json"),
            enable_wua_probe=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.REMOTE_POLICY_OK
    assert result.is_source_check_complete is True
    assert result.policy_source_kind == "local_json"
    assert result.policy_signature_status == "valid"
    assert not any("Remote policy" in warning for warning in result.warnings)
    assert "Loaded policy URL is not listed in published_urls or source_urls." not in result.warnings


def test_runtime_signed_policy_allows_unknown_additive_top_level_metadata(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_file = tmp_path / "windows-release-policy.json"
    data = _json_policy()
    data["future_metadata"] = {"observed": True}
    _write_signed_json(policy_file, data)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=str(policy_file),
            cache_file=str(tmp_path / "cache.json"),
            enable_wua_probe=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.REMOTE_POLICY_OK
    assert any("unknown top-level key 'future_metadata'" in warning for warning in result.warnings)


def test_remote_json_policy_url_warns_when_loaded_url_not_in_published_or_source_urls(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_url = ("https://policy.example" + ".invalid/windows-release-policy.json")
    policy_file = tmp_path / "windows-release-policy.json"
    policy_bytes = _write_signed_json(policy_file, _json_policy())
    signature_bytes = policy_file.with_name(policy_file.name + ".sig").read_bytes()
    calls = []

    def fake_fetch(url, *args, **kwargs):
        calls.append(str(url))
        if str(url).endswith(".sig"):
            return signature_bytes, "application/json"
        return policy_bytes, "application/json"

    monkeypatch.setattr(api, "fetch_policy_bytes", fake_fetch)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=policy_url,
            cache_file=str(tmp_path / "cache.json"),
            enable_wua_probe=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.REMOTE_POLICY_OK
    assert result.policy_source_kind == "remote_json"
    assert result.policy_source_url == policy_url
    assert calls == [policy_url, f"{policy_url}.sig"]
    assert "Loaded policy URL is not listed in published_urls or source_urls." in result.warnings


def test_default_pages_policy_url_does_not_warn_when_listed_in_published_urls(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_file = tmp_path / "windows-release-policy.json"
    policy_bytes = _write_signed_json(policy_file, _json_policy())
    signature_bytes = policy_file.with_name(policy_file.name + ".sig").read_bytes()

    def fake_fetch(url, *args, **kwargs):
        if str(url).endswith(".sig"):
            return signature_bytes, "application/json"
        return policy_bytes, "application/json"

    monkeypatch.setattr(api, "fetch_policy_bytes", fake_fetch)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=DEFAULT_POLICY_URL,
            cache_file=str(tmp_path / "cache.json"),
            enable_wua_probe=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert "Loaded policy URL is not listed in published_urls or source_urls." not in result.warnings


def test_api_policy_alias_does_not_warn_when_listed_in_published_urls(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_url = DEFAULT_PUBLISHED_POLICY_URLS["api_policy"]
    policy_file = tmp_path / "windows-release-policy.json"
    policy_bytes = _write_signed_json(policy_file, _json_policy())
    signature_bytes = policy_file.with_name(policy_file.name + ".sig").read_bytes()

    def fake_fetch(url, *args, **kwargs):
        if str(url).endswith(".sig"):
            return signature_bytes, "application/json"
        return policy_bytes, "application/json"

    monkeypatch.setattr(api, "fetch_policy_bytes", fake_fetch)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=policy_url,
            cache_file=str(tmp_path / "cache.json"),
            enable_wua_probe=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert "Loaded policy URL is not listed in published_urls or source_urls." not in result.warnings


def test_env_policy_url_is_used(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_file = tmp_path / "windows-release-policy.json"
    _write_signed_json(policy_file, _json_policy())
    monkeypatch.setenv("WIN11_RELEASE_GUARD_POLICY_URL", str(policy_file))

    result = api.check_current_system(
        ReleaseCheckerConfig(
            cache_file=str(tmp_path / "cache.json"),
            enable_wua_probe=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.REMOTE_POLICY_OK
    assert result.policy_source_url == str(policy_file)
    assert result.policy_source_kind == "local_json"
    assert result.is_source_check_complete is True


def test_check_current_system_returns_when_wua_probe_fails(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_file = tmp_path / "windows-release-policy.json"
    _write_signed_json(policy_file, _json_policy())

    def broken_wua(*args, **kwargs):
        raise RuntimeError("COM search did not return")

    monkeypatch.setattr(api, "query_wua_secondary", broken_wua)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=str(policy_file),
            cache_file=str(tmp_path / "cache.json"),
            enable_wua_probe=True,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert any("WUA probe failed" in warning for warning in result.warnings)


def test_runtime_rejects_release_health_html_by_default(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    html_file = tmp_path / "windows11-release-information.html"
    html_file.write_text("<html><body>release health</body></html>", encoding="utf-8")

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=str(html_file),
            cache_file=str(tmp_path / "missing-cache.json"),
            enable_wua_probe=False,
            use_bundled_policy_fallback=False,
        )
    )

    assert result.status is EvaluationStatus.CHECK_INCOMPLETE
    assert result.source_status is SourceStatus.POLICY_UNAVAILABLE
    assert any("HTML policy source is not allowed" in problem for problem in result.source_problems)


def test_unsigned_remote_policy_requires_explicit_config(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_file = tmp_path / "windows-release-policy.json"
    policy_file.write_text(json.dumps(_json_policy()), encoding="utf-8")

    rejected = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=str(policy_file),
            cache_file=str(tmp_path / "cache.json"),
            enable_wua_probe=False,
            use_bundled_policy_fallback=False,
        )
    )
    accepted = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=str(policy_file),
            cache_file=str(tmp_path / "cache.json"),
            enable_wua_probe=False,
            allow_unsigned_policy=True,
            use_bundled_policy_fallback=False,
        )
    )

    assert rejected.status is EvaluationStatus.CHECK_INCOMPLETE
    assert any("signature is required" in problem for problem in rejected.source_problems)
    assert accepted.status is EvaluationStatus.COMPLIANT
    assert accepted.policy_signature_status == "unsigned_allowed"


def test_no_internet_uses_fresh_cache_with_warning(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    _fail_remote(monkeypatch)
    cache_file = tmp_path / "windows-release-policy.json"
    _write_signed_policy(cache_file, _policy(generated_at_utc=_generated_at(hours_ago=2)))

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(cache_file),
            enable_wua_probe=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.USING_FRESH_CACHE
    assert result.is_source_check_complete is False
    assert any("using fresh cached policy" in warning for warning in result.warnings)
    assert any("network unavailable" in problem for problem in result.source_problems)


def test_default_production_url_falls_back_to_bundled_when_unavailable(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    monkeypatch.delenv("WIN11_RELEASE_GUARD_POLICY_URL", raising=False)
    calls = []

    def fail_fetch(url, *args, **kwargs):
        calls.append(str(url))
        raise PolicyFetchError("network unavailable")

    monkeypatch.setattr(api, "fetch_policy_bytes", fail_fetch)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            cache_file=str(tmp_path / "missing-cache.json"),
            enable_wua_probe=False,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.USING_BUNDLED_POLICY
    assert result.is_source_check_complete is False
    assert result.policy_source_kind == "bundled"
    assert calls == [DEFAULT_POLICY_URL]
    assert any(problem.source_url == DEFAULT_POLICY_URL for problem in result.source_problems)
    assert any("Remote policy and cache unavailable; using bundled last-known-good policy." in warning for warning in result.warnings)


def test_no_remote_policy_url_configured_uses_bundled_without_source_problem(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    monkeypatch.delenv("WIN11_RELEASE_GUARD_POLICY_URL", raising=False)
    monkeypatch.setattr(config_module, "DEFAULT_POLICY_URL", None)

    fetch_calls: list[tuple] = []

    def fail_if_called(*args, **kwargs):
        # Record the call before raising so invocation is provable by direct
        # observation, not solely by an exception that might get swallowed.
        fetch_calls.append(args)
        raise AssertionError("remote fetch should not be attempted without a policy URL")

    monkeypatch.setattr(api, "fetch_policy_bytes", fail_if_called)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            cache_file=str(tmp_path / "missing-cache.json"),
            enable_wua_probe=False,
        )
    )

    assert fetch_calls == []
    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.USING_BUNDLED_POLICY
    assert result.is_source_check_complete is False
    assert result.policy_source_kind == "bundled"
    assert result.source_problems == ()
    assert result.warnings.count(
        "No remote policy URL configured; using bundled last-known-good policy."
    ) == 1
    assert not any("Remote policy" in warning for warning in result.warnings)


def test_http_timeout_uses_fresh_cache_with_warning(monkeypatch, tmp_path):
    _patch_local(monkeypatch)

    def timeout_fetch(*args, **kwargs):
        raise TimeoutError("HTTP policy fetch timed out after 12 seconds")

    monkeypatch.setattr(api, "fetch_policy_bytes", timeout_fetch)
    cache_file = tmp_path / "windows-release-policy.json"
    _write_signed_policy(cache_file, _policy(generated_at_utc=_generated_at(hours_ago=1)))

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(cache_file),
            enable_wua_probe=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.USING_FRESH_CACHE
    assert any("using fresh cached policy" in warning for warning in result.warnings)
    assert any("timed out after 12 seconds" in problem for problem in result.source_problems)


def test_source_check_required_for_green_blocks_cached_compliant_result(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    _fail_remote(monkeypatch)
    cache_file = tmp_path / "windows-release-policy.json"
    _write_signed_policy(cache_file, _policy(generated_at_utc=_generated_at(hours_ago=2)))

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(cache_file),
            enable_wua_probe=False,
            source_check_required_for_green=True,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.CHECK_INCOMPLETE
    assert result.source_status is SourceStatus.USING_FRESH_CACHE
    assert result.is_source_check_complete is False
    assert result.action == "Source check incomplete; cannot return green result."


def test_strict_production_allows_green_only_for_live_remote_json(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_file = tmp_path / "remote-policy.json"
    policy_bytes = _write_signed_policy(policy_file, _policy(generated_at_utc=_generated_at(hours_ago=1)))
    signature_bytes = policy_file.with_name(policy_file.name + ".sig").read_bytes()
    policy_url = ("https://policy.example" + ".invalid/windows-release-policy.json")

    def fake_fetch(url, *args, **kwargs):
        if str(url).endswith(".sig"):
            return signature_bytes, "application/json"
        return policy_bytes, "application/json"

    monkeypatch.setattr(api, "fetch_policy_bytes", fake_fetch)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=policy_url,
            cache_file=str(tmp_path / "cache.json"),
            enable_wua_probe=False,
            strict_production=True,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.REMOTE_POLICY_OK
    assert result.policy_source_kind == "remote_json"
    assert result.is_source_check_complete is True
    assert result.strict_production is True
    payload = result.to_dict()
    assert payload["strict_production"] is True
    assert payload["source_status"] == SourceStatus.REMOTE_POLICY_OK.value
    assert payload["policy_source_kind"] == "remote_json"
    assert payload["is_source_check_complete"] is True
    assert isinstance(payload["policy_age_hours"], float)


def test_live_remote_policy_older_than_14_days_warns(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_file = tmp_path / "remote-policy.json"
    policy_bytes = _write_signed_policy(policy_file, _policy(generated_at_utc=_generated_at(hours_ago=15 * 24)))
    signature_bytes = policy_file.with_name(policy_file.name + ".sig").read_bytes()
    policy_url = ("https://policy.example" + ".invalid/windows-release-policy.json")

    def fake_fetch(url, *args, **kwargs):
        if str(url).endswith(".sig"):
            return signature_bytes, "application/json"
        return policy_bytes, "application/json"

    monkeypatch.setattr(api, "fetch_policy_bytes", fake_fetch)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=policy_url,
            cache_file=str(tmp_path / "cache.json"),
            enable_wua_probe=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.REMOTE_POLICY_OK
    assert result.policy_source_kind == "remote_json"
    assert result.policy_age_hours is not None and result.policy_age_hours >= 15 * 24
    assert result.feed_age_days is not None and result.feed_age_days >= 15
    assert any("older than 14 days" in warning for warning in result.warnings)
    payload = result.to_dict()
    assert payload["feed_age_days"] >= 15


def test_normal_mode_live_remote_policy_older_than_45_days_warns_without_blocking(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_file = tmp_path / "remote-policy.json"
    policy_bytes = _write_signed_policy(policy_file, _policy(generated_at_utc=_generated_at(hours_ago=46 * 24)))
    signature_bytes = policy_file.with_name(policy_file.name + ".sig").read_bytes()
    policy_url = ("https://policy.example" + ".invalid/windows-release-policy.json")

    def fake_fetch(url, *args, **kwargs):
        if str(url).endswith(".sig"):
            return signature_bytes, "application/json"
        return policy_bytes, "application/json"

    monkeypatch.setattr(api, "fetch_policy_bytes", fake_fetch)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=policy_url,
            cache_file=str(tmp_path / "cache.json"),
            enable_wua_probe=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.REMOTE_POLICY_OK
    assert result.is_source_check_complete is True
    assert any("older than 14 days" in warning for warning in result.warnings)


def test_strict_production_blocks_live_remote_policy_older_than_45_days(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_file = tmp_path / "remote-policy.json"
    policy_bytes = _write_signed_policy(policy_file, _policy(generated_at_utc=_generated_at(hours_ago=46 * 24)))
    signature_bytes = policy_file.with_name(policy_file.name + ".sig").read_bytes()
    policy_url = ("https://policy.example" + ".invalid/windows-release-policy.json")

    def fake_fetch(url, *args, **kwargs):
        if str(url).endswith(".sig"):
            return signature_bytes, "application/json"
        return policy_bytes, "application/json"

    monkeypatch.setattr(api, "fetch_policy_bytes", fake_fetch)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=policy_url,
            cache_file=str(tmp_path / "cache.json"),
            enable_wua_probe=False,
            strict_production=True,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.CHECK_INCOMPLETE
    assert result.candidate_status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.REMOTE_POLICY_OK
    assert result.policy_source_kind == "remote_json"
    assert result.is_source_check_complete is True
    assert result.strict_production is True
    assert "within 45 days" in (result.action or "")
    assert result.metadata["source_degradation"]["force_check_incomplete"] is True


def test_strict_production_blocks_local_json_green_even_when_signed(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_file = tmp_path / "windows-release-policy.json"
    _write_signed_policy(policy_file, _policy(generated_at_utc=_generated_at(hours_ago=1)))

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=str(policy_file),
            cache_file=str(tmp_path / "cache.json"),
            enable_wua_probe=False,
            strict_production=True,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.CHECK_INCOMPLETE
    assert result.source_status is SourceStatus.REMOTE_POLICY_OK
    assert result.policy_source_kind == "local_json"
    assert result.is_source_check_complete is True
    assert result.strict_production is True
    assert "Strict production requires" in result.action


def test_strict_production_blocks_stale_cache_green(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    _fail_remote(monkeypatch)
    cache_file = tmp_path / "windows-release-policy.json"
    _write_signed_policy(cache_file, _policy(generated_at_utc=_generated_at(hours_ago=100)))

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(cache_file),
            cache_max_age_hours=72,
            stale_cache_max_age_hours=720,
            enable_wua_probe=False,
            strict_production=True,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.CHECK_INCOMPLETE
    assert result.source_status is SourceStatus.USING_STALE_CACHE
    assert result.policy_source_kind == "stale_cache"
    assert result.is_source_check_complete is False
    assert result.strict_production is True
    assert "Strict production requires" in result.action


def test_strict_production_degrades_stale_cache_update_required_to_incomplete(monkeypatch, tmp_path):
    _patch_local(monkeypatch, build=26100, full_build="26100.8457")
    _fail_remote(monkeypatch)
    cache_file = tmp_path / "windows-release-policy.json"
    _write_signed_policy(cache_file, _policy(generated_at_utc=_generated_at(hours_ago=100)))

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(cache_file),
            cache_max_age_hours=72,
            stale_cache_max_age_hours=720,
            enable_wua_probe=False,
            strict_production=True,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.CHECK_INCOMPLETE
    assert result.source_status is SourceStatus.USING_STALE_CACHE
    assert result.policy_source_kind == "stale_cache"
    assert result.metadata["source_degradation"]["must_exit_code_2"] is True
    assert "Strict production requires" in result.action


def test_strict_production_blocks_bundled_green(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    _fail_remote(monkeypatch)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(tmp_path / "missing-cache.json"),
            enable_wua_probe=False,
            strict_production=True,
        )
    )

    assert result.status is EvaluationStatus.CHECK_INCOMPLETE
    assert result.source_status is SourceStatus.USING_BUNDLED_POLICY
    assert result.policy_source_kind == "bundled"
    assert result.is_source_check_complete is False
    assert result.strict_production is True
    assert result.candidate_status is EvaluationStatus.COMPLIANT
    assert result.local_scope_status is None
    payload = result.to_dict()
    assert payload["status"] == EvaluationStatus.CHECK_INCOMPLETE.value
    assert payload["candidate_status"] == EvaluationStatus.COMPLIANT.value
    assert payload["local_scope_status"] is None
    assert "Strict production requires" in result.action
