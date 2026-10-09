from __future__ import annotations

import json
import win11_release_guard.api as api
from win11_release_guard.config import ReleaseCheckerConfig
from win11_release_guard.exceptions import PolicyFetchError
from win11_release_guard.models import EvaluationStatus, LocalWindowsState, SourceStatus
from tests.support.runtime_policy_sources_helpers import (
    BAD_POLICY_URL,
    TEST_PUBLIC_KEY,
    _fail_remote,
    _generated_at,
    _json_policy,
    _patch_local,
    _policy,
    _write_signed_policy,
)


def _patch_local_state(monkeypatch, local_state: LocalWindowsState) -> None:
    monkeypatch.setattr(api, "get_local_windows_state", lambda: local_state)
    monkeypatch.setattr(api, "query_wua_secondary", lambda target_release: None)


def test_strict_production_blocks_windows10_out_of_scope_from_bundled(monkeypatch, tmp_path):
    _patch_local_state(
        monkeypatch,
        LocalWindowsState(
            product_name="Windows 10 Pro",
            current_build=19045,
            full_build="19045.4529",
            installation_type="Client",
        ),
    )
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
    assert result.strict_production is True
    assert result.candidate_status is EvaluationStatus.OUT_OF_SCOPE
    assert result.local_scope_status is EvaluationStatus.OUT_OF_SCOPE
    payload = result.to_dict()
    assert payload["status"] == EvaluationStatus.CHECK_INCOMPLETE.value
    assert payload["candidate_status"] == EvaluationStatus.OUT_OF_SCOPE.value
    assert payload["local_scope_status"] == EvaluationStatus.OUT_OF_SCOPE.value
    assert payload["source_status"] == SourceStatus.USING_BUNDLED_POLICY.value
    assert payload["is_source_check_complete"] is False
    assert payload["strict_production"] is True
    assert result.metadata["source_degradation"]["candidate_status"] == EvaluationStatus.OUT_OF_SCOPE.value
    assert result.metadata["source_degradation"]["must_exit_code_2"] is True
    assert "Strict production requires" in result.action


def test_strict_production_blocks_server_out_of_scope_from_bundled(monkeypatch, tmp_path):
    _patch_local_state(
        monkeypatch,
        LocalWindowsState(
            product_name="Windows Server 2025 Datacenter",
            current_build=26100,
            full_build="26100.8457",
            installation_type="Server",
        ),
    )
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
    assert result.strict_production is True
    assert result.candidate_status is EvaluationStatus.OUT_OF_SCOPE
    assert result.local_scope_status is EvaluationStatus.OUT_OF_SCOPE
    assert result.metadata["source_degradation"]["candidate_status"] == EvaluationStatus.OUT_OF_SCOPE.value
    assert result.metadata["source_degradation"]["must_exit_code_2"] is True
    assert "Strict production requires" in result.action


def test_strict_production_rejects_unsigned_policy_even_if_unsigned_allowed(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_file = tmp_path / "unsigned-policy.json"
    policy_file.write_bytes((json.dumps(_json_policy(), indent=2, sort_keys=True) + "\n").encode("utf-8"))

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=str(policy_file),
            cache_file=str(tmp_path / "missing-cache.json"),
            enable_wua_probe=False,
            allow_unsigned_policy=True,
            strict_production=True,
            use_bundled_policy_fallback=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.CHECK_INCOMPLETE
    assert result.strict_production is True
    assert result.policy_signature_status == "unavailable"
    assert any(problem.kind == "missing_signature" for problem in result.source_problems)


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
    assert len(result.warnings) == len(set(result.warnings))
    assert len(result.notes) == len(set(result.notes))
    assert not set(result.errors).intersection(result.warnings)


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
    assert result.candidate_status is None
    assert result.local_scope_status is None
    assert "Remote policy and cache unavailable; using bundled last-known-good policy." in result.warnings
    assert any("network unavailable" in problem for problem in result.source_problems)
    assert result.source_problems
    assert "Loaded policy URL is not listed in published_urls or source_urls." not in result.warnings


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
