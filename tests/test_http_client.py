from __future__ import annotations

import email.message
import gzip
import io
import socket
import ssl
import urllib.error
import urllib.request
import zlib

import pytest

from win11_release_guard import http_client
from win11_release_guard.exceptions import PolicyFetchError


DEFAULT_URL = "https://http-client-tests.invalid/resource"
DEFAULT_HOST = "http-client-tests.invalid"


@pytest.fixture(autouse=True)
def _clear_dns_cache():
    http_client._dns_cache.clear()
    yield
    http_client._dns_cache.clear()


def _headers(mapping: dict[str, str] | None = None) -> email.message.Message:
    message = email.message.Message()
    for key, value in (mapping or {}).items():
        message[key] = value
    return message


class _FakeResponse:
    def __init__(self, *, status: int = 200, headers: dict[str, str] | None = None, body: bytes = b"", url: str = DEFAULT_URL) -> None:
        self.status = status
        self.headers = _headers(headers)
        self._body = body
        self._url = url
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        return self._body

    def geturl(self) -> str:
        return self._url

    def close(self) -> None:
        self.closed = True


def _http_error(code: int, *, headers: dict[str, str] | None = None, body: bytes = b"", url: str = DEFAULT_URL) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, code, "status", _headers(headers), io.BytesIO(body))


class _ScriptedOpener:
    """Replays a fixed sequence of responses/exceptions; never touches the network."""

    def __init__(self, steps) -> None:
        self._steps = list(steps)
        self.calls: list = []

    def __call__(self, request, timeout):
        self.calls.append(request)
        step = self._steps.pop(0)
        if isinstance(step, BaseException):
            raise step
        return step


def _recording_sleep():
    delays: list[float] = []

    def sleep(seconds: float) -> None:
        delays.append(seconds)

    return sleep, delays


def _scripted_resolver(outcomes):
    """Replays fixed resolution outcomes; never touches a real resolver."""

    outcomes = list(outcomes)
    calls: list[tuple[str, float]] = []

    def resolver(host: str, timeout: float) -> None:
        calls.append((host, timeout))
        outcome = outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome

    return resolver, calls


def test_default_headers_include_shared_browser_identity() -> None:
    headers = http_client.default_headers()

    assert headers["User-Agent"] == http_client.BROWSER_USER_AGENT
    assert headers["Accept-Language"] == "en-US,en;q=0.9"
    assert headers["Accept-Encoding"] == "gzip, deflate"
    assert headers["Accept"] == "*/*"


def test_default_headers_can_be_overridden_case_insensitively() -> None:
    headers = http_client.default_headers({"accept": "application/json", "X-Extra": "1"})

    assert headers["accept"] == "application/json"
    assert "Accept" not in headers
    assert headers["User-Agent"] == http_client.BROWSER_USER_AGENT
    assert headers["X-Extra"] == "1"


def test_request_sends_shared_headers_on_the_wire() -> None:
    opener = _ScriptedOpener([_FakeResponse(body=b"ok")])
    sleep, _delays = _recording_sleep()

    result = http_client.request(
        DEFAULT_URL,
        timeout=1.0,
        max_bytes=1024,
        opener=opener,
        sleep=sleep,
    )

    assert result.content == b"ok"
    sent = opener.calls[0]
    assert sent.get_header("User-agent") == http_client.BROWSER_USER_AGENT
    assert sent.get_header("Accept-language") == "en-US,en;q=0.9"
    assert sent.get_header("Accept-encoding") == "gzip, deflate"


def test_gzip_body_is_transparently_decompressed() -> None:
    payload = b'{"build": "26200.8875"}'
    opener = _ScriptedOpener(
        [_FakeResponse(headers={"Content-Encoding": "gzip"}, body=gzip.compress(payload))]
    )
    sleep, _delays = _recording_sleep()

    result = http_client.request(DEFAULT_URL, timeout=1.0, max_bytes=4096, opener=opener, sleep=sleep)

    assert result.content == payload


def test_deflate_body_is_transparently_decompressed() -> None:
    payload = b'{"build": "26200.8875"}'
    opener = _ScriptedOpener(
        [_FakeResponse(headers={"Content-Encoding": "deflate"}, body=zlib.compress(payload))]
    )
    sleep, _delays = _recording_sleep()

    result = http_client.request(DEFAULT_URL, timeout=1.0, max_bytes=4096, opener=opener, sleep=sleep)

    assert result.content == payload


def test_gzip_body_decompresses_with_lowercase_header_name() -> None:
    payload = b'{"build": "26200.8875"}'
    opener = _ScriptedOpener(
        [_FakeResponse(headers={"content-encoding": "gzip"}, body=gzip.compress(payload))]
    )
    sleep, _delays = _recording_sleep()

    result = http_client.request(DEFAULT_URL, timeout=1.0, max_bytes=4096, opener=opener, sleep=sleep)

    assert result.content == payload


def test_get_header_is_case_insensitive() -> None:
    opener = _ScriptedOpener([_FakeResponse(headers={"content-type": "application/json; charset=utf-8"})])
    sleep, _delays = _recording_sleep()

    result = http_client.request(DEFAULT_URL, timeout=1.0, max_bytes=4096, opener=opener, sleep=sleep)

    assert http_client.get_header(result.headers, "Content-Type") == "application/json; charset=utf-8"


def test_uncompressed_body_is_returned_unchanged() -> None:
    payload = b'{"build": "26200.8875"}'
    opener = _ScriptedOpener([_FakeResponse(body=payload)])
    sleep, _delays = _recording_sleep()

    result = http_client.request(DEFAULT_URL, timeout=1.0, max_bytes=4096, opener=opener, sleep=sleep)

    assert result.content == payload


def test_server_lying_about_gzip_encoding_falls_back_to_raw_bytes() -> None:
    payload = b"not actually gzip"
    opener = _ScriptedOpener([_FakeResponse(headers={"Content-Encoding": "gzip"}, body=payload)])
    sleep, _delays = _recording_sleep()

    result = http_client.request(DEFAULT_URL, timeout=1.0, max_bytes=4096, opener=opener, sleep=sleep)

    assert result.content == payload


def test_gzip_decompression_bomb_fails_closed_on_decompressed_size() -> None:
    # A small, genuinely valid gzip payload whose decompressed size is far
    # larger than the cap -- the compressed body alone fits comfortably
    # under the wire cap, so only a check on the decompressed output can
    # catch this.
    huge_payload = b"0" * (2 * 1024 * 1024)
    compressed = gzip.compress(huge_payload)
    assert len(compressed) < 4096
    opener = _ScriptedOpener(
        [_FakeResponse(headers={"Content-Encoding": "gzip"}, body=compressed)]
    )
    sleep, _delays = _recording_sleep()

    with pytest.raises(PolicyFetchError, match="exceeds safety cap"):
        http_client.request(DEFAULT_URL, timeout=1.0, max_bytes=4096, opener=opener, sleep=sleep)


def test_deflate_decompression_bomb_fails_closed_on_decompressed_size() -> None:
    huge_payload = b"1" * (2 * 1024 * 1024)
    compressed = zlib.compress(huge_payload)
    assert len(compressed) < 4096
    opener = _ScriptedOpener(
        [_FakeResponse(headers={"Content-Encoding": "deflate"}, body=compressed)]
    )
    sleep, _delays = _recording_sleep()

    with pytest.raises(PolicyFetchError, match="exceeds safety cap"):
        http_client.request(DEFAULT_URL, timeout=1.0, max_bytes=4096, opener=opener, sleep=sleep)


def test_truncated_gzip_degrades_to_raw_bytes_instead_of_raising_eoferror() -> None:
    payload = b"a payload long enough to survive truncation" * 10
    compressed = gzip.compress(payload)
    truncated = compressed[: len(compressed) - 10]
    opener = _ScriptedOpener(
        [_FakeResponse(headers={"Content-Encoding": "gzip"}, body=truncated)]
    )
    sleep, _delays = _recording_sleep()

    result = http_client.request(DEFAULT_URL, timeout=1.0, max_bytes=1 << 20, opener=opener, sleep=sleep)

    assert result.content == truncated


def test_dns_resolution_failure_raises_without_retrying() -> None:
    resolver, calls = _scripted_resolver([socket.gaierror(-2, "Name or service not known")])
    opener = _ScriptedOpener([_FakeResponse(body=b"unused")])
    sleep, delays = _recording_sleep()

    with pytest.raises(PolicyFetchError, match="DNS resolution"):
        http_client.request(
            DEFAULT_URL,
            timeout=1.0,
            max_bytes=1024,
            attempts=3,
            opener=opener,
            resolver=resolver,
            sleep=sleep,
        )

    assert calls == [(DEFAULT_HOST, pytest.approx(1.0))]
    assert opener.calls == []
    assert delays == []


def test_dns_preflight_deadline_never_exceeds_the_overall_timeout() -> None:
    resolver, calls = _scripted_resolver([None])
    opener = _ScriptedOpener([_FakeResponse(body=b"ok")])
    sleep, _delays = _recording_sleep()

    http_client.request(
        DEFAULT_URL,
        timeout=1.0,
        max_bytes=1024,
        opener=opener,
        resolver=resolver,
        sleep=sleep,
    )

    assert len(calls) == 1
    dns_timeout = calls[0][1]
    assert dns_timeout <= 1.0
    assert dns_timeout <= http_client.DEFAULT_DNS_RESOLVE_TIMEOUT_SECONDS


def test_repeated_requests_to_same_host_reuse_cached_dns_resolution() -> None:
    resolver, calls = _scripted_resolver([None])
    opener = _ScriptedOpener([_FakeResponse(body=b"first"), _FakeResponse(body=b"second")])
    sleep, _delays = _recording_sleep()

    first = http_client.request(DEFAULT_URL, timeout=1.0, max_bytes=1024, opener=opener, resolver=resolver, sleep=sleep)
    second = http_client.request(DEFAULT_URL, timeout=1.0, max_bytes=1024, opener=opener, resolver=resolver, sleep=sleep)

    assert first.content == b"first"
    assert second.content == b"second"
    assert len(calls) == 1


def test_dns_preflight_is_skipped_for_proxied_urls(monkeypatch) -> None:
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {"https": "http://proxy.invalid:8080"})
    monkeypatch.setattr(urllib.request, "proxy_bypass", lambda host: False)
    resolver, calls = _scripted_resolver([])
    opener = _ScriptedOpener([_FakeResponse(body=b"ok")])
    sleep, _delays = _recording_sleep()

    result = http_client.request(
        DEFAULT_URL,
        timeout=1.0,
        max_bytes=1024,
        opener=opener,
        resolver=resolver,
        sleep=sleep,
    )

    assert result.content == b"ok"
    assert calls == []


def test_default_resolver_is_not_invoked_when_a_custom_opener_replaces_urlopen(monkeypatch) -> None:
    def _boom(host: str, timeout: float) -> None:
        raise AssertionError("real DNS resolution must not run when a fake opener bypasses urlopen")

    monkeypatch.setattr(http_client, "_default_resolve_host", _boom)
    opener = _ScriptedOpener([_FakeResponse(body=b"ok")])
    sleep, _delays = _recording_sleep()

    result = http_client.request(DEFAULT_URL, timeout=1.0, max_bytes=1024, opener=opener, sleep=sleep)

    assert result.content == b"ok"


def test_429_then_503_then_success_retries_and_returns_body() -> None:
    opener = _ScriptedOpener(
        [
            _http_error(429, headers={"Retry-After": "0"}),
            _http_error(503),
            _FakeResponse(body=b"finally"),
        ]
    )
    sleep, delays = _recording_sleep()

    result = http_client.request(
        DEFAULT_URL,
        timeout=1.0,
        max_bytes=1024,
        attempts=3,
        opener=opener,
        sleep=sleep,
    )

    assert result.content == b"finally"
    assert len(opener.calls) == 3
    assert len(delays) == 2


def test_404_does_not_retry_and_raises() -> None:
    opener = _ScriptedOpener([_http_error(404, body=b"missing")])
    sleep, delays = _recording_sleep()

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        http_client.request(
            DEFAULT_URL,
            timeout=1.0,
            max_bytes=1024,
            attempts=3,
            opener=opener,
            sleep=sleep,
        )

    assert excinfo.value.code == 404
    assert len(opener.calls) == 1
    assert delays == []


def test_retry_after_header_is_honoured() -> None:
    opener = _ScriptedOpener(
        [
            _http_error(503, headers={"Retry-After": "17"}),
            _FakeResponse(body=b"ok"),
        ]
    )
    sleep, delays = _recording_sleep()

    result = http_client.request(
        DEFAULT_URL,
        timeout=1.0,
        max_bytes=1024,
        attempts=2,
        opener=opener,
        sleep=sleep,
    )

    assert result.content == b"ok"
    assert delays == [17.0]


def test_503_with_cf_mitigated_challenge_header_is_not_retried() -> None:
    opener = _ScriptedOpener(
        [_http_error(503, headers={"cf-mitigated": "challenge"}, body=b"<html>please wait</html>")]
    )
    sleep, delays = _recording_sleep()

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        http_client.request(
            DEFAULT_URL,
            timeout=1.0,
            max_bytes=1024,
            attempts=3,
            opener=opener,
            sleep=sleep,
        )

    assert excinfo.value.code == 503
    assert len(opener.calls) == 1
    assert delays == []


def test_503_with_challenge_body_marker_is_not_retried() -> None:
    body = b"<html><head><title>Just a moment...</title></head><body>_cf_chl_opt</body></html>"
    opener = _ScriptedOpener([_http_error(503, body=body)])
    sleep, delays = _recording_sleep()

    with pytest.raises(urllib.error.HTTPError):
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


def test_503_with_known_challenge_server_header_is_not_retried() -> None:
    opener = _ScriptedOpener([_http_error(503, headers={"Server": "ddos-guard"}, body=b"blocked")])
    sleep, delays = _recording_sleep()

    with pytest.raises(urllib.error.HTTPError):
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


def test_plain_503_without_challenge_markers_still_retries() -> None:
    opener = _ScriptedOpener(
        [_http_error(503, body=b"Service Unavailable, please retry later."), _FakeResponse(body=b"ok")]
    )
    sleep, delays = _recording_sleep()

    result = http_client.request(
        DEFAULT_URL,
        timeout=1.0,
        max_bytes=1024,
        attempts=2,
        opener=opener,
        sleep=sleep,
    )

    assert result.content == b"ok"
    assert len(delays) == 1


def test_challenge_detected_with_raise_for_status_false_returns_full_body() -> None:
    body = b"<html>just a moment</html>"
    opener = _ScriptedOpener([_http_error(503, body=body)])
    sleep, delays = _recording_sleep()

    result = http_client.request(
        DEFAULT_URL,
        timeout=1.0,
        max_bytes=1024,
        attempts=3,
        raise_for_status=False,
        opener=opener,
        sleep=sleep,
    )

    assert result.status_code == 503
    assert result.content == body
    assert delays == []


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
