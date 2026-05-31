from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import win11_release_guard.api as api
import win11_release_guard.config as config_module
from win11_release_guard.config import DEFAULT_POLICY_URL, ReleaseCheckerConfig
from win11_release_guard.exceptions import PolicyFetchError
from win11_release_guard.models import (
    EvaluationStatus,
    LocalWindowsState,
    ReleaseHistoryEntry,
    ReleasePolicy,
    ReleasePolicyEntry,
    SourceStatus,
)
from win11_release_guard.signing import sign_policy_bytes


TEST_PRIVATE_KEY = "krtF2muLgucP7JDVNKk2g+YQfz92c7xM49dzszxHxjs="
TEST_PUBLIC_KEY = "45dOpVuYqoPkldNrzORHM5ZZUxs6ILVcvpKxRFxsu3s="
BAD_POLICY_URL = "https://bad.example.invalid/windows-release-policy.json"


def _generated_at(hours_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).replace(microsecond=0).isoformat()


def _policy(*, generated_at_utc: str | None = None, signature_status: str = "valid") -> ReleasePolicy:
    return ReleasePolicy(
        generated_at_utc=generated_at_utc or _generated_at(),
        source_urls=("https://example.invalid/windows-release-policy.json",),
        broad_target_existing_devices=ReleasePolicyEntry(
            version="25H2",
            build_family=26200,
            latest_build="26200.8457",
            baseline_build="26200.8457",
            servicing_option="General Availability Channel",
        ),
        current_versions=(
            ReleasePolicyEntry(
                version="25H2",
                build_family=26200,
                latest_build="26200.8457",
                baseline_build="26200.8457",
                servicing_option="General Availability Channel",
            ),
            ReleasePolicyEntry(
                version="24H2",
                build_family=26100,
                latest_build="26100.8457",
                baseline_build="26100.8457",
                servicing_option="General Availability Channel",
            ),
        ),
        release_history=(
            ReleaseHistoryEntry(
                release="25H2",
                build_family=26200,
                build="26200.8457",
                update_type_letter="B",
                servicing_option="General Availability Channel",
                availability_date="2026-05-12",
            ),
        ),
        supported_build_families={26100: "24H2", 26200: "25H2"},
        metadata={"signature_status": signature_status},
    )


def _json_policy() -> dict:
    return _policy().to_dict()


def _write_signed_policy(path, policy: ReleasePolicy) -> bytes:
    return _write_signed_json(path, policy.to_dict())


def _write_signed_json(path, data: dict) -> bytes:
    policy_bytes = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    signature = sign_policy_bytes(policy_bytes, TEST_PRIVATE_KEY)
    signature_bytes = (json.dumps(signature, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(policy_bytes)
    path.with_name(path.name + ".sig").write_bytes(signature_bytes)
    return policy_bytes


def _patch_local(monkeypatch, *, build: int = 26200, full_build: str = "26200.8457") -> None:
    monkeypatch.setattr(
        api,
        "get_local_windows_state",
        lambda: LocalWindowsState(current_build=build, full_build=full_build),
    )
    monkeypatch.setattr(api, "query_wua_secondary", lambda target_release: None)


def _fail_remote(monkeypatch, message: str = "network unavailable") -> None:
    def fail_fetch(*args, **kwargs):
        raise PolicyFetchError(message)

    monkeypatch.setattr(api, "fetch_policy_bytes", fail_fetch)


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
    assert "Loaded policy URL is not listed in source_urls." not in result.warnings


def test_remote_json_policy_url_warns_when_loaded_url_not_in_source_urls(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_url = "https://policy.example.invalid/windows-release-policy.json"
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
    assert "Loaded policy URL is not listed in source_urls." in result.warnings


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

    def fail_if_called(*args, **kwargs):
        raise AssertionError("remote fetch should not be attempted without a policy URL")

    monkeypatch.setattr(api, "fetch_policy_bytes", fail_if_called)

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


def test_no_internet_uses_stale_cache_with_stronger_warning(monkeypatch, tmp_path):
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
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.USING_STALE_CACHE
    assert result.is_source_check_complete is False
    assert any("using stale cached policy" in warning for warning in result.warnings)
    assert any("Source check is incomplete" in warning for warning in result.warnings)


def test_no_internet_no_cache_uses_bundled_fallback_with_warning(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    _fail_remote(monkeypatch)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(tmp_path / "missing-cache.json"),
            enable_wua_probe=False,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.USING_BUNDLED_POLICY
    assert result.is_source_check_complete is False
    assert "Remote policy and cache unavailable; using bundled last-known-good policy." in result.warnings
    assert any("network unavailable" in problem for problem in result.source_problems)
    assert result.source_problems
    assert "Loaded policy URL is not listed in source_urls." not in result.warnings


def test_no_internet_no_cache_no_bundled_returns_check_incomplete(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    _fail_remote(monkeypatch)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(tmp_path / "missing-cache.json"),
            enable_wua_probe=False,
            use_bundled_policy_fallback=False,
        )
    )

    assert result.status is EvaluationStatus.CHECK_INCOMPLETE
    assert result.source_status is SourceStatus.POLICY_UNAVAILABLE
    assert result.is_warning is True
    assert result.is_source_check_complete is False
    assert any("No valid release policy is available" in error for error in result.errors)


def test_invalid_remote_signature_falls_back_to_verified_cache(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    cache_file = tmp_path / "windows-release-policy.json"
    _write_signed_policy(cache_file, _policy(generated_at_utc=_generated_at(hours_ago=1)))
    remote_file = tmp_path / "remote-policy.json"
    remote_bytes = _write_signed_policy(remote_file, _policy())
    invalid_signature = b'{"algorithm":"ed25519","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}\n'

    def fake_fetch(url, *args, **kwargs):
        if str(url).endswith(".sig"):
            return invalid_signature, "application/json"
        return remote_bytes, "application/json"

    monkeypatch.setattr(api, "fetch_policy_bytes", fake_fetch)

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
    assert result.policy_signature_status == "valid"
    assert any("Policy signature verification failed" in problem for problem in result.source_problems)


def test_remote_500_falls_back_to_verified_cache(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    cache_file = tmp_path / "windows-release-policy.json"
    _write_signed_policy(cache_file, _policy(generated_at_utc=_generated_at(hours_ago=1)))

    def fake_fetch(*args, **kwargs):
        raise PolicyFetchError("Release policy fetch returned HTTP 500.")

    monkeypatch.setattr(api, "fetch_policy_bytes", fake_fetch)

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
    assert any(problem.kind == "http_500" for problem in result.source_problems)


def test_remote_malformed_json_falls_back_to_verified_cache(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    cache_file = tmp_path / "windows-release-policy.json"
    _write_signed_policy(cache_file, _policy(generated_at_utc=_generated_at(hours_ago=1)))

    def fake_fetch(url, *args, **kwargs):
        if str(url).endswith(".sig"):
            raise PolicyFetchError("signature unavailable")
        return b"{not-json", "application/json"

    monkeypatch.setattr(api, "fetch_policy_bytes", fake_fetch)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(cache_file),
            enable_wua_probe=False,
            allow_unsigned_policy=True,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.USING_FRESH_CACHE
    assert any(problem.kind == SourceStatus.REMOTE_POLICY_PARSE_FAILED.value.lower() for problem in result.source_problems)


def test_corrupt_cache_ignored_and_bundled_fallback_continues(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    _fail_remote(monkeypatch)
    cache_file = tmp_path / "windows-release-policy.json"
    cache_file.write_text("{not-json", encoding="utf-8")
    cache_file.with_name(cache_file.name + ".sig").write_text("not-a-signature", encoding="utf-8")

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(cache_file),
            enable_wua_probe=False,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.USING_BUNDLED_POLICY
    assert any("cache failed" in problem.lower() for problem in result.source_problems)
    assert any(problem.kind == "corrupt_cache" for problem in result.source_problems)


def test_all_source_failures_are_structured_in_result_json(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    _fail_remote(monkeypatch, "network unavailable")
    cache_file = tmp_path / "windows-release-policy.json"
    cache_file.write_text("{not-json", encoding="utf-8")
    cache_file.with_name(cache_file.name + ".sig").write_text("not-a-signature", encoding="utf-8")

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(cache_file),
            enable_wua_probe=False,
            use_bundled_policy_fallback=False,
        )
    )
    payload = result.to_dict()

    assert result.status is EvaluationStatus.CHECK_INCOMPLETE
    assert payload["source_status"] == SourceStatus.POLICY_UNAVAILABLE.value
    assert payload["source_problems"]
    assert all({"kind", "message", "source_url", "exception_type", "retryable", "occurred_at_utc"} <= set(problem) for problem in payload["source_problems"])
    assert any("network unavailable" in problem["message"] for problem in payload["source_problems"])
    assert any("cache failed" in problem["message"].lower() for problem in payload["source_problems"])
