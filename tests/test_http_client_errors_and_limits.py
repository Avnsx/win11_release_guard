from __future__ import annotations

import io
import ssl
import urllib.error
import urllib.request
import pytest
from win11_release_guard import http_client
from win11_release_guard.exceptions import PolicyFetchError
from tests.support.http_client_helpers import (
    DEFAULT_URL,
    _FakeResponse,
    _ScriptedOpener,
    _clear_dns_cache,
    _headers,
    _http_error,
    _recording_sleep,
)


def test_challenge_probe_reads_only_a_bounded_prefix_of_the_body() -> None:
    class _TrackingBody(io.BytesIO):
        def __init__(self, data: bytes) -> None:
            super().__init__(data)
            self.read_sizes: list[int | None] = []

        def read(self, size: int = -1) -> bytes:
            self.read_sizes.append(size)
            return super().read(size)

    tracking_body = _TrackingBody(b"x" * 5000)
    exc = urllib.error.HTTPError(DEFAULT_URL, 503, "status", _headers(), tracking_body)
    opener = _ScriptedOpener([exc, _FakeResponse(body=b"ok")])
    sleep, _delays = _recording_sleep()

    http_client.request(DEFAULT_URL, timeout=1.0, max_bytes=1024, attempts=2, opener=opener, sleep=sleep)

    assert tracking_body.read_sizes
    assert all(size is not None and size <= 4096 for size in tracking_body.read_sizes)


def test_retry_after_is_not_compounded_with_backoff_for_the_same_attempt() -> None:
    opener = _ScriptedOpener(
        [
            _http_error(503, headers={"Retry-After": "2"}),
            _FakeResponse(body=b"ok"),
        ]
    )
    sleep, delays = _recording_sleep()

    http_client.request(
        DEFAULT_URL,
        timeout=1.0,
        max_bytes=1024,
        attempts=2,
        backoff_base=10.0,
        backoff_cap=40.0,
        opener=opener,
        sleep=sleep,
    )

    # Only the (capped) Retry-After wait fires -- never Retry-After plus the
    # exponential backoff that would otherwise apply to this same attempt.
    assert delays == [2.0]


def test_304_reports_unchanged_without_body() -> None:
    opener = _ScriptedOpener([_http_error(304)])
    sleep, _delays = _recording_sleep()

    result = http_client.request(
        DEFAULT_URL,
        timeout=1.0,
        max_bytes=1024,
        etag='"abc123"',
        opener=opener,
        sleep=sleep,
    )

    assert result.not_modified is True
    assert result.status_code == 304
    assert result.content == b""
    sent = opener.calls[0]
    assert sent.get_header("If-none-match") == '"abc123"'


def test_byte_cap_fails_closed_on_oversized_body() -> None:
    opener = _ScriptedOpener([_FakeResponse(body=b"x" * 200)])
    sleep, _delays = _recording_sleep()

    with pytest.raises(PolicyFetchError, match="exceeds safety cap"):
        http_client.request(DEFAULT_URL, timeout=1.0, max_bytes=100, opener=opener, sleep=sleep)


def test_byte_cap_fails_closed_using_declared_content_length() -> None:
    opener = _ScriptedOpener(
        [_FakeResponse(headers={"Content-Length": "999999"}, body=b"short")]
    )
    sleep, _delays = _recording_sleep()

    with pytest.raises(PolicyFetchError, match="exceeds safety cap"):
        http_client.request(DEFAULT_URL, timeout=1.0, max_bytes=100, opener=opener, sleep=sleep)


def test_final_url_validator_rejects_unsafe_redirect() -> None:
    opener = _ScriptedOpener([_FakeResponse(url="https://evil.invalid/resource", body=b"data")])
    sleep, _delays = _recording_sleep()

    def validator(candidate_url: str) -> str | None:
        return None if "evil" in candidate_url else candidate_url

    with pytest.raises(PolicyFetchError, match="unsafe URL"):
        http_client.request(
            DEFAULT_URL,
            timeout=1.0,
            max_bytes=1024,
            final_url_validator=validator,
            opener=opener,
            sleep=sleep,
        )


def test_final_url_validator_allows_safe_redirect() -> None:
    opener = _ScriptedOpener([_FakeResponse(url="https://safe.invalid/resource", body=b"data")])
    sleep, _delays = _recording_sleep()

    def validator(candidate_url: str) -> str | None:
        return None if "evil" in candidate_url else candidate_url

    result = http_client.request(
        DEFAULT_URL,
        timeout=1.0,
        max_bytes=1024,
        final_url_validator=validator,
        opener=opener,
        sleep=sleep,
    )

    assert result.content == b"data"


def test_raise_for_status_false_returns_error_body_instead_of_raising() -> None:
    opener = _ScriptedOpener([_http_error(404, body=b"not found here")])
    sleep, _delays = _recording_sleep()

    result = http_client.request(
        DEFAULT_URL,
        timeout=1.0,
        max_bytes=1024,
        raise_for_status=False,
        opener=opener,
        sleep=sleep,
    )

    assert result.status_code == 404
    assert result.content == b"not found here"


def test_connection_errors_retry_then_raise_after_exhausting_attempts() -> None:
    opener = _ScriptedOpener([ConnectionResetError("boom"), ConnectionResetError("boom")])
    sleep, delays = _recording_sleep()

    with pytest.raises(PolicyFetchError, match="boom"):
        http_client.request(
            DEFAULT_URL,
            timeout=1.0,
            max_bytes=1024,
            attempts=2,
            opener=opener,
            sleep=sleep,
        )

    assert len(opener.calls) == 2
    assert len(delays) == 1


def _cert_verification_error() -> ssl.SSLCertVerificationError:
    return ssl.SSLCertVerificationError(
        1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate"
    )


def test_certificate_verification_failure_is_not_retried_and_names_the_remedy() -> None:
    opener = _ScriptedOpener([_cert_verification_error()])
    sleep, delays = _recording_sleep()

    with pytest.raises(PolicyFetchError) as excinfo:
        http_client.request(
            DEFAULT_URL,
            timeout=1.0,
            max_bytes=1024,
            attempts=3,
            opener=opener,
            sleep=sleep,
        )

    message = str(excinfo.value)
    assert "system trust store" in message
    assert "SSL_CERT_FILE" in message
    assert "SSL_CERT_DIR" in message
    assert "REQUESTS_CA_BUNDLE" not in message
    assert len(opener.calls) == 1
    assert delays == []


def test_certificate_verification_failure_wrapped_in_urlerror_is_not_retried() -> None:
    # This is what real urlopen actually raises: http.client establishes the
    # TLS connection inside AbstractHTTPHandler.do_open's try/except OSError
    # block, which wraps the ssl.SSLCertVerificationError in a URLError.
    wrapped = urllib.error.URLError(_cert_verification_error())
    opener = _ScriptedOpener([wrapped])
    sleep, delays = _recording_sleep()

    with pytest.raises(PolicyFetchError, match="system trust store"):
        http_client.request(
            DEFAULT_URL,
            timeout=1.0,
            max_bytes=1024,
            attempts=3,
            opener=opener,
            sleep=sleep,
        )

    assert len(opener.calls) == 1
    assert delays == []


def test_charset_from_content_type_extracts_charset_param() -> None:
    assert http_client.charset_from_content_type("text/html; charset=iso-8859-1") == "iso-8859-1"
    assert http_client.charset_from_content_type("application/json") is None
    assert http_client.charset_from_content_type(None) is None
