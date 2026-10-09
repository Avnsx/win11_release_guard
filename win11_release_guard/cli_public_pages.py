"""Checking the public GitHub Pages feed, manifest, and freshness."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence
from .config import DEFAULT_HTTP_TIMEOUT_SECONDS, DEFAULT_POLICY_STRICT_STALE_AGE_SECONDS, DEFAULT_POLICY_WARNING_AGE_SECONDS, DEFAULT_PUBLISHED_POLICY_URLS
from .exceptions import PolicyFetchError, PolicyParseError, PolicyTrustError
from .freshness import epoch_seconds_from_iso
from . import http_client
from .json_utils import DEFAULT_MAX_MANIFEST_BYTES, DEFAULT_MAX_POLICY_BYTES, DEFAULT_MAX_SIGNATURE_BYTES, StrictJSONError, strict_json_object
from .remote_policy import fetch_policy_bytes
from .signing import decode_policy_signature_metadata, verify_policy_signature


@dataclass(frozen=True)
class PublicFetchResult:
    url: str
    status_code: int
    content: bytes
    content_type: str | None = None
    headers: Mapping[str, str] | None = None

    @property
    def auth_challenge(self) -> bool:
        headers = {str(key).lower(): str(value) for key, value in dict(self.headers or {}).items()}
        return self.status_code == 401 or "www-authenticate" in headers


def _policy_signature_source(policy_url: str) -> str:
    if policy_url.endswith("/api/v1/policy.json"):
        return f"{policy_url.rsplit('/', 1)[0]}/policy.sig"
    return f"{policy_url}.sig"


def _is_http_url(value: str | None) -> bool:
    return bool(value and str(value).lower().startswith(("http://", "https://")))


def _payload_too_large_message(label: str, max_bytes: int) -> str:
    return f"{label} is too large: exceeds safety cap of {max_bytes} bytes"


def _fetch_public_url(
    url: str,
    *,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> PublicFetchResult:
    try:
        result = http_client.request(
            url,
            headers={"Accept": "*/*"},
            timeout=timeout,
            max_bytes=max_bytes,
            label="Public Pages response",
            raise_for_status=False,
        )
    except Exception as exc:
        raise PolicyFetchError(f"Failed to fetch public Pages URL {url}: {exc}") from exc
    return PublicFetchResult(
        url=url,
        status_code=result.status_code,
        content=result.content,
        content_type=http_client.get_header(result.headers, "Content-Type"),
        headers=result.headers,
    )


def _call_fetch_public_url(url: str, *, timeout: float, max_bytes: int) -> PublicFetchResult:
    try:
        return _fetch_public_url(url, timeout=timeout, max_bytes=max_bytes)
    except TypeError as exc:
        if "max_bytes" not in str(exc):
            raise
        return _fetch_public_url(url, timeout=timeout)


def _decode_json_bytes(
    data: bytes,
    *,
    label: str,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> Mapping[str, Any]:
    try:
        return strict_json_object(data, label=label, max_bytes=max_bytes)
    except StrictJSONError as exc:
        raise PolicyParseError(str(exc)) from exc


def _sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest_url_for_policy(policy_url: str, policy) -> str | None:
    if not _is_http_url(policy_url):
        return None
    published_urls = dict(policy.published_urls or {})
    if policy_url == published_urls.get("api_policy"):
        return published_urls.get("api_manifest") or DEFAULT_PUBLISHED_POLICY_URLS["api_manifest"]
    return published_urls.get("manifest") or DEFAULT_PUBLISHED_POLICY_URLS["manifest"]


def _manifest_check_payload(
    *,
    policy_url: str,
    policy,
    policy_bytes: bytes,
    timeout_seconds: float,
    allow_missing_manifest: bool = False,
) -> tuple[dict[str, object], bool]:
    manifest_url = _manifest_url_for_policy(policy_url, policy)
    if manifest_url is None:
        return (
            {
                "manifest_url": None,
                "manifest_status": "not_checked",
                "manifest_warning": None,
                "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
            },
            True,
        )

    try:
        manifest_bytes, _manifest_content_type = fetch_policy_bytes(
            manifest_url,
            timeout=timeout_seconds,
            max_bytes=DEFAULT_MAX_MANIFEST_BYTES,
        )
    except Exception as exc:
        policy_sha256 = hashlib.sha256(policy_bytes).hexdigest()
        return (
            {
                "manifest_url": manifest_url,
                "manifest_status": "unavailable",
                "manifest_warning": f"Manifest unavailable: {exc}",
                "manifest_missing_allowed": bool(allow_missing_manifest),
                "policy_sha256": policy_sha256,
            },
            bool(allow_missing_manifest),
        )

    try:
        manifest = _decode_json_bytes(
            manifest_bytes,
            label="Policy manifest",
            max_bytes=DEFAULT_MAX_MANIFEST_BYTES,
        )
    except PolicyParseError as exc:
        return (
            {
                "manifest_url": manifest_url,
                "manifest_status": "invalid",
                "manifest_warning": str(exc),
                "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
            },
            False,
        )

    actual_policy_sha256 = hashlib.sha256(policy_bytes).hexdigest()
    expected_policy_sha256 = str(manifest.get("policy_sha256") or "")
    if not expected_policy_sha256:
        return (
            {
                "manifest_url": manifest_url,
                "manifest_status": "invalid",
                "manifest_warning": "Policy manifest is missing policy_sha256.",
                "policy_sha256": actual_policy_sha256,
            },
            False,
        )
    if expected_policy_sha256 != actual_policy_sha256:
        return (
            {
                "manifest_url": manifest_url,
                "manifest_status": "sha256_mismatch",
                "manifest_warning": "Policy manifest policy_sha256 does not match fetched policy bytes.",
                "policy_sha256": actual_policy_sha256,
                "manifest_policy_sha256": expected_policy_sha256,
            },
            False,
        )

    return (
        {
            "manifest_url": manifest_url,
            "manifest_status": "ok",
            "manifest_warning": None,
            "policy_sha256": actual_policy_sha256,
            "manifest_policy_sha256": expected_policy_sha256,
        },
        True,
    )


def _public_pages_urls(policy) -> dict[str, str]:
    published_urls = dict(DEFAULT_PUBLISHED_POLICY_URLS)
    policy_published_urls = getattr(policy, "published_urls", None)
    if isinstance(policy_published_urls, Mapping):
        for key in DEFAULT_PUBLISHED_POLICY_URLS:
            value = policy_published_urls.get(key)
            if isinstance(value, str) and value:
                published_urls[key] = value
    landing = published_urls["landing"].rstrip("/")
    return {
        "landing": published_urls["landing"],
        "policy": published_urls["policy"],
        "signature": published_urls["signature"],
        "manifest": published_urls["manifest"],
        "api_policy": published_urls["api_policy"],
        "api_signature": published_urls["api_signature"],
        "api_manifest": published_urls["api_manifest"],
        "robots": f"{landing}/robots.txt",
        "sitemap": f"{landing}/sitemap.xml",
    }


def _public_page_fetch_check(
    *,
    name: str,
    url: str,
    timeout_seconds: float,
    max_bytes: int,
    expect_json: bool = False,
    expect_signature: bool = False,
    expect_robots: bool = False,
) -> tuple[dict[str, object], PublicFetchResult | None, Mapping[str, Any] | None]:
    try:
        response = _call_fetch_public_url(url, timeout=timeout_seconds, max_bytes=max_bytes)
    except Exception as exc:
        return (
            {
                "name": name,
                "url": url,
                "ok": False,
                "status_code": None,
                "error": str(exc),
            },
            None,
            None,
        )

    errors: list[str] = []
    decoded_json: Mapping[str, Any] | None = None
    if response.status_code != 200:
        errors.append(f"HTTP {response.status_code}")
    if len(response.content) > max_bytes:
        errors.append(_payload_too_large_message(f"{name} endpoint response", max_bytes))
    if response.auth_challenge:
        errors.append("auth challenge present")

    if expect_json and not errors:
        try:
            decoded_json = _decode_json_bytes(response.content, label=f"{name} endpoint", max_bytes=max_bytes)
        except PolicyParseError as exc:
            errors.append(str(exc))

    if expect_signature and not errors:
        try:
            decode_policy_signature_metadata(response.content)
        except PolicyTrustError as exc:
            errors.append(str(exc))

    if expect_robots and not errors:
        text = response.content.decode("utf-8", errors="replace")
        if "User-agent: *" not in text or "Allow: /" not in text:
            errors.append("robots.txt does not allow all")

    check = {
        "name": name,
        "url": url,
        "ok": not errors,
        "status_code": response.status_code,
        "errors": errors,
    }
    if response.status_code == 200:
        check["sha256"] = _sha256_hex_bytes(response.content)
    return check, response, decoded_json


def _check_public_page_url(
    *,
    name: str,
    url: str,
    timeout_seconds: float,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
    expect_json: bool = False,
    expect_signature: bool = False,
    expect_robots: bool = False,
) -> dict[str, object]:
    check, _response, _decoded_json = _public_page_fetch_check(
        name=name,
        url=url,
        timeout_seconds=timeout_seconds,
        max_bytes=max_bytes,
        expect_json=expect_json,
        expect_signature=expect_signature,
        expect_robots=expect_robots,
    )
    return check


def _public_consistency_check(
    name: str,
    errors: Sequence[str],
    **metadata: object,
) -> dict[str, object]:
    check: dict[str, object] = {
        "name": name,
        "ok": not errors,
        "errors": list(errors),
    }
    check.update({key: value for key, value in metadata.items() if value is not None})
    return check


def _manifest_policy_sha256_errors(
    manifest: Mapping[str, Any] | None,
    expected_policy_sha256: str | None,
    *,
    label: str,
) -> list[str]:
    if expected_policy_sha256 is None:
        return [f"{label} policy bytes unavailable"]
    if manifest is None:
        return [f"{label} manifest unavailable"]
    manifest_policy_sha256 = str(manifest.get("policy_sha256") or "")
    if not manifest_policy_sha256:
        return [f"{label} manifest missing policy_sha256"]
    if manifest_policy_sha256 != expected_policy_sha256:
        return [
            f"{label} manifest policy_sha256 {manifest_policy_sha256} does not match policy SHA-256 {expected_policy_sha256}"
        ]
    return []


def _manifest_documents_different_api_policy(
    manifest: Mapping[str, Any] | None,
    api_policy_sha256: str | None,
) -> bool:
    if manifest is None or api_policy_sha256 is None:
        return False
    marker = bool(
        manifest.get("api_policy_differs_from_canonical")
        or manifest.get("allow_different_api_policy_bytes")
    )
    return marker and str(manifest.get("api_policy_sha256") or "") == api_policy_sha256


def _manifest_documents_different_api_signature(
    manifest: Mapping[str, Any] | None,
    api_signature_sha256: str | None,
) -> bool:
    if manifest is None or api_signature_sha256 is None:
        return False
    marker = bool(
        manifest.get("api_policy_differs_from_canonical")
        or manifest.get("allow_different_api_policy_bytes")
    )
    return marker and str(manifest.get("api_signature_sha256") or "") == api_signature_sha256


def _published_url_errors(
    policy_document: Mapping[str, Any] | None,
    expected_urls: Mapping[str, str],
    *,
    label: str,
) -> list[str]:
    if policy_document is None:
        return [f"{label} policy JSON unavailable"]
    published_urls = policy_document.get("published_urls")
    if not isinstance(published_urls, Mapping):
        return [f"{label} policy JSON missing published_urls object"]

    errors: list[str] = []
    for key in DEFAULT_PUBLISHED_POLICY_URLS:
        expected_url = expected_urls[key]
        actual_url = published_urls.get(key)
        if actual_url != expected_url:
            errors.append(
                f"{label} published_urls.{key} expected {expected_url!r}, got {actual_url!r}"
            )
    return errors


def _utc_now_epoch_s() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _public_document_generated_epoch(
    manifest: Mapping[str, Any] | None,
    policy_document: Mapping[str, Any] | None,
) -> tuple[int | None, str | None, str | None]:
    if manifest is not None and "generated_at_epoch_s" in manifest:
        value = manifest.get("generated_at_epoch_s")
        if isinstance(value, bool):
            return None, None, "manifest.generated_at_epoch_s must be an integer epoch timestamp"
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return None, None, "manifest.generated_at_epoch_s must be an integer epoch timestamp"
        if parsed <= 0:
            return None, None, "manifest.generated_at_epoch_s must be a positive epoch timestamp"
        return parsed, str(manifest.get("generated_at_utc") or ""), None

    generated_at_utc = None
    if policy_document is not None:
        value = policy_document.get("generated_at_utc")
        if value not in (None, ""):
            generated_at_utc = str(value)
    if generated_at_utc is None and manifest is not None:
        value = manifest.get("generated_at_utc")
        if value not in (None, ""):
            generated_at_utc = str(value)
    if not generated_at_utc:
        return None, None, "public policy freshness timestamp unavailable"
    parsed_epoch = epoch_seconds_from_iso(generated_at_utc)
    if parsed_epoch is None:
        return None, generated_at_utc, f"generated_at_utc is invalid: {generated_at_utc}"
    return parsed_epoch, generated_at_utc, None


def _public_pages_freshness_check(
    manifest: Mapping[str, Any] | None,
    policy_document: Mapping[str, Any] | None,
) -> dict[str, object]:
    generated_epoch, generated_at_utc, parse_error = _public_document_generated_epoch(manifest, policy_document)
    errors: list[str] = []
    age_days = None
    freshness_state = "unknown"
    if parse_error:
        errors.append(parse_error)
    elif generated_epoch is not None:
        now_epoch = _utc_now_epoch_s()
        age_seconds = max(0, now_epoch - generated_epoch)
        age_days = round(age_seconds / 86400, 2)
        if age_seconds >= DEFAULT_POLICY_STRICT_STALE_AGE_SECONDS:
            freshness_state = "strict_stale"
            errors.append(
                f"public policy feed is {age_days:g} days old; age is at or beyond the 45-day strict stale threshold"
            )
        elif age_seconds >= DEFAULT_POLICY_WARNING_AGE_SECONDS:
            freshness_state = "stale"
            errors.append(
                f"public policy feed is {age_days:g} days old; age is at or beyond the 14-day public freshness threshold"
            )
        else:
            freshness_state = "fresh"
    return _public_consistency_check(
        "public_pages_freshness",
        errors,
        generated_at_utc=generated_at_utc,
        age_days=age_days,
        freshness_state=freshness_state,
    )


def _check_public_pages_payload(
    policy,
    *,
    timeout_seconds: float,
    trusted_policy_public_key: str | bytes | None = None,
    max_policy_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> tuple[dict[str, object], bool]:
    urls = _public_pages_urls(policy)
    endpoint_specs = [
        ("landing", urls["landing"], max_policy_bytes, False, False, False),
        ("policy", urls["policy"], max_policy_bytes, True, False, False),
        ("signature", urls["signature"], DEFAULT_MAX_SIGNATURE_BYTES, False, True, False),
        ("manifest", urls["manifest"], DEFAULT_MAX_MANIFEST_BYTES, True, False, False),
        ("api_policy", urls["api_policy"], max_policy_bytes, True, False, False),
        ("api_signature", urls["api_signature"], DEFAULT_MAX_SIGNATURE_BYTES, False, True, False),
        ("api_manifest", urls["api_manifest"], DEFAULT_MAX_MANIFEST_BYTES, True, False, False),
        ("robots", urls["robots"], DEFAULT_MAX_MANIFEST_BYTES, False, False, True),
        ("sitemap", urls["sitemap"], DEFAULT_MAX_MANIFEST_BYTES, False, False, False),
    ]
    checks: list[dict[str, object]] = []
    responses: dict[str, PublicFetchResult] = {}
    decoded_documents: dict[str, Mapping[str, Any]] = {}
    for name, url, max_bytes, expect_json, expect_signature, expect_robots in endpoint_specs:
        check, response, decoded_json = _public_page_fetch_check(
            name=name,
            url=url,
            timeout_seconds=timeout_seconds,
            max_bytes=max_bytes,
            expect_json=expect_json,
            expect_signature=expect_signature,
            expect_robots=expect_robots,
        )
        checks.append(check)
        if response is not None:
            responses[name] = response
        if decoded_json is not None:
            decoded_documents[name] = decoded_json

    policy_bytes = responses.get("policy").content if responses.get("policy") else None
    signature_bytes = responses.get("signature").content if responses.get("signature") else None
    api_policy_bytes = responses.get("api_policy").content if responses.get("api_policy") else None
    api_signature_bytes = responses.get("api_signature").content if responses.get("api_signature") else None

    policy_sha256 = _sha256_hex_bytes(policy_bytes) if policy_bytes is not None else None
    api_policy_sha256 = _sha256_hex_bytes(api_policy_bytes) if api_policy_bytes is not None else None
    signature_sha256 = _sha256_hex_bytes(signature_bytes) if signature_bytes is not None else None
    api_signature_sha256 = _sha256_hex_bytes(api_signature_bytes) if api_signature_bytes is not None else None

    canonical_signature_ok = False
    canonical_signature_errors: list[str] = []
    if policy_bytes is None:
        canonical_signature_errors.append("canonical policy bytes unavailable")
    if signature_bytes is None:
        canonical_signature_errors.append("canonical signature bytes unavailable")
    if policy_bytes is not None and signature_bytes is not None:
        canonical_signature_ok = verify_policy_signature(
            policy_bytes,
            signature_bytes,
            trusted_policy_public_key,
        )
        if not canonical_signature_ok:
            canonical_signature_errors.append("canonical policy signature verification failed")
    checks.append(
        _public_consistency_check(
            "canonical_signature",
            canonical_signature_errors,
            policy_sha256=policy_sha256,
            signature_sha256=signature_sha256,
        )
    )

    api_signature_ok = False
    api_signature_errors: list[str] = []
    if api_policy_bytes is None:
        api_signature_errors.append("API policy bytes unavailable")
    if api_signature_bytes is None:
        api_signature_errors.append("API signature bytes unavailable")
    if api_policy_bytes is not None and api_signature_bytes is not None:
        api_signature_ok = verify_policy_signature(
            api_policy_bytes,
            api_signature_bytes,
            trusted_policy_public_key,
        )
        if not api_signature_ok:
            api_signature_errors.append("API policy signature verification failed")
    checks.append(
        _public_consistency_check(
            "api_signature_integrity",
            api_signature_errors,
            policy_sha256=api_policy_sha256,
            signature_sha256=api_signature_sha256,
        )
    )

    manifest = decoded_documents.get("manifest")
    api_manifest = decoded_documents.get("api_manifest")
    documented_api_difference = _manifest_documents_different_api_policy(manifest, api_policy_sha256)

    policy_alias_errors: list[str] = []
    if policy_bytes is None or api_policy_bytes is None:
        policy_alias_errors.append("canonical or API policy bytes unavailable")
    elif policy_bytes != api_policy_bytes and not documented_api_difference:
        policy_alias_errors.append(
            "canonical policy bytes differ from API policy bytes without manifest api_policy_sha256 "
            "and api_policy_differs_from_canonical=true"
        )
    checks.append(_public_consistency_check("policy_api_alias", policy_alias_errors))

    signature_alias_errors: list[str] = []
    if signature_bytes is None or api_signature_bytes is None:
        signature_alias_errors.append("canonical or API signature bytes unavailable")
    elif signature_bytes != api_signature_bytes:
        same_policy_hash = policy_sha256 == api_policy_sha256
        documented_signature_difference = _manifest_documents_different_api_signature(
            manifest,
            api_signature_sha256,
        )
        if same_policy_hash and canonical_signature_ok and api_signature_ok:
            pass
        elif documented_api_difference and documented_signature_difference and canonical_signature_ok and api_signature_ok:
            pass
        else:
            signature_alias_errors.append(
                "canonical signature bytes differ from API signature bytes and do not verify the same policy hash"
            )
    checks.append(_public_consistency_check("signature_api_alias", signature_alias_errors))

    checks.append(
        _public_consistency_check(
            "manifest_policy_sha256",
            _manifest_policy_sha256_errors(manifest, policy_sha256, label="canonical"),
        )
    )
    checks.append(
        _public_consistency_check(
            "api_manifest_policy_sha256",
            _manifest_policy_sha256_errors(api_manifest, api_policy_sha256, label="API"),
        )
    )

    published_url_errors = [
        *_published_url_errors(decoded_documents.get("policy"), urls, label="canonical"),
        *_published_url_errors(decoded_documents.get("api_policy"), urls, label="API"),
    ]
    checks.append(_public_consistency_check("published_urls", published_url_errors))
    checks.append(_public_pages_freshness_check(manifest, decoded_documents.get("policy")))

    ok = all(bool(check.get("ok")) for check in checks)
    return (
        {
            "status": "OK" if ok else "FAILED",
            "checks": checks,
        },
        ok,
    )
