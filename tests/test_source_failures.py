from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import win11_release_guard.api as api
from win11_release_guard.config import ReleaseCheckerConfig
from win11_release_guard.exceptions import PolicyFetchError, PolicyParseError, PolicyTrustError
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
PARSE_FAILURE_KIND = SourceStatus.REMOTE_POLICY_PARSE_FAILED.value.lower()
SIGNATURE_FAILURE_KIND = SourceStatus.REMOTE_POLICY_SIGNATURE_FAILED.value.lower()
UNREACHABLE_KIND = SourceStatus.REMOTE_POLICY_UNREACHABLE.value.lower()


def _generated_at(*, hours_ago: int = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).replace(microsecond=0).isoformat()


def _generated_policy() -> ReleasePolicy:
    return ReleasePolicy(
        generated_at_utc=_generated_at(),
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
        ),
        release_history=(
            ReleaseHistoryEntry(
                release="25H2",
                build_family=26200,
                build="26200.8457",
                update_type_letter="B",
                availability_date="2026-05-12",
            ),
        ),
        supported_build_families={26200: "25H2"},
    )


def _write_signed_policy(path, *, generated_at_utc: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    policy = replace(_generated_policy(), generated_at_utc=generated_at_utc or _generated_at())
    policy_bytes = (json.dumps(policy.to_dict(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(policy_bytes)
    path.with_name(path.name + ".sig").write_bytes(
        (json.dumps(sign_policy_bytes(policy_bytes, TEST_PRIVATE_KEY), indent=2, sort_keys=True) + "\n").encode("utf-8")
    )


def _patch_local(monkeypatch) -> None:
    monkeypatch.setattr(
        api,
        "get_local_windows_state",
        lambda: LocalWindowsState(current_build=26200, full_build="26200.8457"),
    )


def _run_with_failing_remote(monkeypatch, tmp_path, message: str):
    _patch_local(monkeypatch)
    cache_file = tmp_path / "windows-release-policy.json"
    _write_signed_policy(cache_file)

    def fail_fetch(*args, **kwargs):
        raise PolicyFetchError(message)

    monkeypatch.setattr(api, "fetch_policy_bytes", fail_fetch)
    return api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(cache_file),
            enable_wua_probe=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )


def _classify(exc: BaseException) -> tuple[str, bool]:
    return api._problem_kind_for_exception(exc, context=UNREACHABLE_KIND)


def test_source_problem_classifier_prioritizes_dns_before_json_keywords():
    cases = (
        "<urlopen error [Errno 11001] getaddrinfo failed>",
        "<urlopen error [Errno -3] Temporary failure in name resolution>",
    )
    for message in cases:
        kind, retryable = _classify(
            PolicyFetchError(f"Failed to fetch release policy from {BAD_POLICY_URL}: {message}")
        )

        assert kind == "dns_failure"
        assert retryable is True
        assert kind != PARSE_FAILURE_KIND


def test_source_problem_classifier_parse_signature_http_and_retryability():
    assert _classify(PolicyParseError("Malformed JSON policy: expected value")) == (
        PARSE_FAILURE_KIND,
        False,
    )
    assert _classify(PolicyParseError("Could not parse Windows 11 current-version table.")) == (
        PARSE_FAILURE_KIND,
        False,
    )
    assert _classify(PolicyTrustError("Policy signature verification failed.")) == (
        SIGNATURE_FAILURE_KIND,
        False,
    )
    assert _classify(PolicyTrustError("Policy signature is required but missing.")) == (
        "missing_signature",
        False,
    )
    assert _classify(PolicyTrustError("HTML policy source is not allowed in runtime mode.")) == (
        "runtime_html_rejected",
        False,
    )
    assert _classify(PolicyFetchError("Release policy fetch returned HTTP 500.")) == (
        "http_500",
        True,
    )
    assert _classify(PolicyFetchError("Release policy fetch returned HTTP 403.")) == (
        "http_403",
        False,
    )
    assert _classify(PolicyFetchError("Release policy fetch returned HTTP 404.")) == (
        "http_404",
        False,
    )


def test_valid_json_policy_url(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    policy_file = tmp_path / "windows-release-policy.json"
    _write_signed_policy(policy_file)

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


def test_missing_internet_uses_stale_cache_with_warning(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    cache_file = tmp_path / "windows-release-policy.json"
    _write_signed_policy(cache_file, generated_at_utc="2026-05-20T00:00:00+00:00")
    monkeypatch.setattr(api, "fetch_policy_bytes", lambda *args, **kwargs: (_ for _ in ()).throw(PolicyFetchError("network unavailable")))

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(cache_file),
            cache_max_age_hours=1,
            stale_cache_max_age_hours=720,
            enable_wua_probe=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.USING_STALE_CACHE
    assert any("stale cached policy" in warning for warning in result.warnings)
    assert any("network unavailable" in problem.message for problem in result.source_problems)


def test_missing_internet_no_cache_uses_bundled_fallback(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    monkeypatch.setattr(api, "fetch_policy_bytes", lambda *args, **kwargs: (_ for _ in ()).throw(PolicyFetchError("network unavailable")))

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(tmp_path / "missing.json"),
            enable_wua_probe=False,
        )
    )

    assert result.status is EvaluationStatus.COMPLIANT
    assert result.source_status is SourceStatus.USING_BUNDLED_POLICY
    assert any("bundled last-known-good" in warning for warning in result.warnings)


def test_no_policy_at_all_returns_check_incomplete(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    monkeypatch.setattr(api, "fetch_policy_bytes", lambda *args, **kwargs: (_ for _ in ()).throw(PolicyFetchError("network unavailable")))

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(tmp_path / "missing.json"),
            enable_wua_probe=False,
            use_bundled_policy_fallback=False,
        )
    )

    assert result.status is EvaluationStatus.CHECK_INCOMPLETE
    assert result.source_status is SourceStatus.POLICY_UNAVAILABLE
    assert result.is_warning is True
    assert result.source_problems


def test_http_403_404_500_are_structured_and_fall_back(monkeypatch, tmp_path):
    for code, kind, retryable in ((403, "http_403", False), (404, "http_404", False), (500, "http_500", True)):
        result = _run_with_failing_remote(monkeypatch, tmp_path / f"http{code}", f"Release policy fetch returned HTTP {code}.")
        assert result.status is EvaluationStatus.COMPLIANT
        assert result.source_status is SourceStatus.USING_FRESH_CACHE
        assert any(
            problem.kind == kind and problem.retryable is retryable
            for problem in result.source_problems
        )


def test_tls_proxy_dns_exceptions_are_structured_and_fall_back(monkeypatch, tmp_path):
    cases = (
        ("TLS certificate verify failed", "tls_failure"),
        ("proxy tunnel failed", "proxy_failure"),
        ("DNS getaddrinfo failed", "dns_failure"),
    )
    for message, kind in cases:
        result = _run_with_failing_remote(monkeypatch, tmp_path / kind, message)
        assert result.status is EvaluationStatus.COMPLIANT
        assert any(problem.kind == kind for problem in result.source_problems)


def test_malformed_json_and_malformed_html_fall_back_to_cache(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    cache_file = tmp_path / "windows-release-policy.json"
    _write_signed_policy(cache_file)
    responses = iter([(b"{not-json", "application/json"), (b"<html><table></table></html>", "text/html")])

    def fake_fetch(url, *args, **kwargs):
        if str(url).endswith(".sig"):
            raise PolicyFetchError("signature unavailable")
        return next(responses)

    monkeypatch.setattr(api, "fetch_policy_bytes", fake_fetch)
    malformed_json = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(cache_file),
            enable_wua_probe=False,
            allow_unsigned_policy=True,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )
    malformed_html = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url="https://example.invalid/windows11-release-information",
            cache_file=str(cache_file),
            enable_wua_probe=False,
            allow_runtime_release_health_html=True,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert malformed_json.source_status is SourceStatus.USING_FRESH_CACHE
    assert any(problem.kind == PARSE_FAILURE_KIND for problem in malformed_json.source_problems)
    assert malformed_html.source_status is SourceStatus.USING_FRESH_CACHE
    assert any(problem.kind == PARSE_FAILURE_KIND for problem in malformed_html.source_problems)


def test_invalid_signature_and_corrupt_cache_are_visible(monkeypatch, tmp_path):
    _patch_local(monkeypatch)
    cache_file = tmp_path / "windows-release-policy.json"
    cache_file.write_text("{not-json", encoding="utf-8")
    cache_file.with_name(cache_file.name + ".sig").write_text("not-a-signature", encoding="utf-8")
    policy_bytes = json.dumps(_generated_policy().to_dict()).encode("utf-8")

    def fake_fetch(url, *args, **kwargs):
        if str(url).endswith(".sig"):
            return b'{"algorithm":"ed25519","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}', "application/json"
        return policy_bytes, "application/json"

    monkeypatch.setattr(api, "fetch_policy_bytes", fake_fetch)

    result = api.check_current_system(
        ReleaseCheckerConfig(
            policy_url=BAD_POLICY_URL,
            cache_file=str(cache_file),
            enable_wua_probe=False,
            use_bundled_policy_fallback=False,
            trusted_policy_public_key=TEST_PUBLIC_KEY,
        )
    )

    assert result.status is EvaluationStatus.CHECK_INCOMPLETE
    assert any(problem.kind == SIGNATURE_FAILURE_KIND for problem in result.source_problems)
    assert any(problem.kind == "corrupt_cache" for problem in result.source_problems)
    assert all(problem.to_dict()["occurred_at_utc"] for problem in result.source_problems)
