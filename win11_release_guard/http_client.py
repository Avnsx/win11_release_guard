from __future__ import annotations

import email.message
import email.utils
import gzip
import io
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from .exceptions import PolicyFetchError


BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)
DEFAULT_ACCEPT = "*/*"
DEFAULT_ACCEPT_LANGUAGE = "en-US,en;q=0.9"
DEFAULT_ACCEPT_ENCODING = "gzip, deflate"

DEFAULT_RETRY_ATTEMPTS = 3
DEFAULT_BACKOFF_BASE_SECONDS = 0.5
DEFAULT_BACKOFF_CAP_SECONDS = 4.0
DEFAULT_RETRY_AFTER_CAP_SECONDS = 30.0
DEFAULT_LABEL = "HTTP response"

# Bounded DNS preflight (see _dns_preflight): resolution runs with its own
# deadline, well short of the overall request timeout, before any socket is
# opened. Successful resolutions are cached briefly so a run that makes many
# requests to the same host only pays the resolution cost once. Failures are
# cached too, under their own shorter TTL, so a host with a black-holed or
# filtered resolver fails fast on the next attempt instead of spawning a
# fresh resolver thread every time. A resolution already in progress for a
# host is shared with any other caller for that same host instead of
# starting a second one.
DEFAULT_DNS_RESOLVE_TIMEOUT_SECONDS = 3.0
DEFAULT_DNS_CACHE_TTL_SECONDS = 60.0
DEFAULT_DNS_NEGATIVE_CACHE_TTL_SECONDS = 5.0
_DNS_CACHE_MAX_ENTRIES = 256

_CERT_VERIFICATION_MESSAGE = (
    "The server's certificate could not be verified against the system trust store. "
    "The most common cause on a corporate network is a TLS-inspecting proxy that "
    "presents a certificate issued by a private root certificate authority which is "
    "not installed in the system trust store. Install that root certificate into the "
    "system trust store, or point Python at an alternative CA bundle with the "
    "SSL_CERT_FILE or SSL_CERT_DIR environment variable."
)

_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})

# Interactive-challenge detection (see _is_challenge_response): a retryable
# status backed by one of these markers is an interstitial that will not
# change before the retry budget is spent, so it is treated the same as a
# non-retryable status instead. Kept deliberately narrow -- a false positive
# turns a recoverable throttle into an immediate failure.
DEFAULT_CHALLENGE_BODY_PEEK_BYTES = 2048
_CHALLENGE_SERVER_TOKENS = ("ddos-guard",)
_CHALLENGE_BODY_MARKERS = (
    b"_cf_chl_opt",
    b"window._cf_chl",
    b"challenges.cloudflare.com",
    b"just a moment",
)

Sleeper = Callable[[float], None]
Opener = Callable[..., Any]
Resolver = Callable[[str, float], None]


@dataclass
class _DnsCacheEntry:
    """A cached resolution outcome. error_message is None for a success."""

    expiry: float
    error_message: str | None


@dataclass
class _DnsInFlight:
    """A resolution in progress for one host.

    A second caller for the same host waits on `done` (subject to its own
    deadline) instead of starting a second resolver thread; see
    _dns_preflight. `error_message` is populated by the owner before `done`
    is set, so it is safe for a waiter to read once `done.wait()` returns
    True.
    """

    done: threading.Event
    error_message: str | None = None


# host -> cached resolution outcome, success or failure, each with its own
# expiry (DEFAULT_DNS_CACHE_TTL_SECONDS / DEFAULT_DNS_NEGATIVE_CACHE_TTL_SECONDS).
_dns_cache: dict[str, _DnsCacheEntry] = {}

# host -> resolution currently in progress, so a second request for the same
# host waits on it instead of starting a second resolver thread.
_dns_inflight: dict[str, _DnsInFlight] = {}

# Guards _dns_cache and _dns_inflight. Critical sections are plain dict
# reads/writes only -- never held across a resolution or any other blocking
# call.
_dns_lock = threading.Lock()


@dataclass(frozen=True)
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    content: bytes
    not_modified: bool = False


def default_headers(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    headers = {
        "User-Agent": BROWSER_USER_AGENT,
        "Accept": DEFAULT_ACCEPT,
        "Accept-Language": DEFAULT_ACCEPT_LANGUAGE,
        "Accept-Encoding": DEFAULT_ACCEPT_ENCODING,
    }
    if overrides:
        existing_by_lower = {key.lower(): key for key in headers}
        for key, value in overrides.items():
            existing_key = existing_by_lower.get(key.lower())
            if existing_key is not None and existing_key != key:
                del headers[existing_key]
            headers[key] = value
            existing_by_lower[key.lower()] = key
    return headers


def get_header(headers: Mapping[str, str] | None, name: str) -> str | None:
    return _header(headers, name)


def charset_from_content_type(content_type: str | None) -> str | None:
    if not content_type:
        return None
    message = email.message.Message()
    message["Content-Type"] = content_type
    return message.get_content_charset()


def _header(headers: Any, name: str) -> str | None:
    if headers is None:
        return None
    if hasattr(headers, "get"):
        value = headers.get(name)
        if value is None:
            value = headers.get(name.lower())
        if value is None:
            value = headers.get(name.title())
        if value is not None:
            return str(value)
    if hasattr(headers, "items"):
        target = name.lower()
        for key, candidate in headers.items():
            if str(key).lower() == target:
                return str(candidate)
    return None


def _headers_dict(headers: Any) -> dict[str, str]:
    if headers is None:
        return {}
    if hasattr(headers, "items"):
        return {str(key): str(value) for key, value in headers.items()}
    return {}


def _content_length(headers: Any) -> int | None:
    value = _header(headers, "Content-Length")
    if value is None:
        return None
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _too_large_message(label: str, max_bytes: int) -> str:
    return f"{label} is too large: exceeds safety cap of {max_bytes} bytes"


def _read_bounded(response: Any, *, max_bytes: int, label: str, prefix: bytes = b"") -> bytes:
    headers = getattr(response, "headers", None)
    content_length = _content_length(headers)
    if content_length is not None and content_length > max_bytes:
        raise PolicyFetchError(_too_large_message(label, max_bytes))
    remaining = max_bytes + 1 - len(prefix)
    more = response.read(remaining) if remaining > 0 else b""
    if isinstance(more, str):
        more = more.encode("utf-8")
    data = prefix + more
    if len(data) > max_bytes:
        raise PolicyFetchError(_too_large_message(label, max_bytes))
    return data


class _DecompressionCapExceeded(Exception):
    """Internal marker: decompressed output would exceed the byte cap."""


def _bounded_gzip_decompress(data: bytes, *, max_bytes: int, label: str) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as reader:
            output = reader.read(max_bytes + 1)
    except (OSError, EOFError, zlib.error):
        return data
    if len(output) > max_bytes:
        raise PolicyFetchError(_too_large_message(label, max_bytes))
    return output


def _bounded_inflate(data: bytes, *, max_bytes: int, wbits: int) -> bytes:
    decompressor = zlib.decompressobj(wbits)
    output = decompressor.decompress(data, max_bytes + 1)
    if len(output) > max_bytes or decompressor.unconsumed_tail:
        raise _DecompressionCapExceeded()
    output += decompressor.flush()
    if len(output) > max_bytes:
        raise _DecompressionCapExceeded()
    return output


def _bounded_deflate_decompress(data: bytes, *, max_bytes: int, label: str) -> bytes:
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            return _bounded_inflate(data, max_bytes=max_bytes, wbits=wbits)
        except _DecompressionCapExceeded:
            raise PolicyFetchError(_too_large_message(label, max_bytes))
        except (zlib.error, EOFError):
            continue
    return data


def _decompress(data: bytes, content_encoding: str | None, *, max_bytes: int, label: str) -> bytes:
    if not data or not content_encoding:
        return data
    normalized = content_encoding.strip().lower()
    if normalized == "gzip":
        return _bounded_gzip_decompress(data, max_bytes=max_bytes, label=label)
    if normalized == "deflate":
        return _bounded_deflate_decompress(data, max_bytes=max_bytes, label=label)
    return data


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    try:
        seconds = float(value)
    except ValueError:
        seconds = None
    if seconds is not None:
        return max(seconds, 0.0)
    try:
        parsed = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    delta = (parsed - datetime.now(timezone.utc)).total_seconds()
    return max(delta, 0.0)


def _backoff_delay(attempt: int, backoff_base: float, backoff_cap: float) -> float:
    delay = backoff_base * (2 ** (attempt - 1))
    return min(delay, backoff_cap)


def _retry_delay(
    exc: urllib.error.HTTPError,
    attempt: int,
    backoff_base: float,
    backoff_cap: float,
    retry_after_cap: float,
) -> float:
    retry_after = _retry_after_seconds(_header(exc.headers, "Retry-After"))
    if retry_after is not None:
        return min(retry_after, retry_after_cap)
    return _backoff_delay(attempt, backoff_base, backoff_cap)


def _read_challenge_probe(exc: urllib.error.HTTPError, *, cap: int) -> bytes:
    reader = getattr(exc, "read", None)
    if not callable(reader):
        return b""
    try:
        data = reader(cap)
    except Exception:
        return b""
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    return data or b""


def _is_challenge_response(headers: Any, body_prefix: bytes) -> bool:
    cf_mitigated = _header(headers, "cf-mitigated")
    if cf_mitigated is not None and cf_mitigated.strip().lower() == "challenge":
        return True
    server = _header(headers, "Server")
    if server is not None:
        lowered_server = server.strip().lower()
        if any(token in lowered_server for token in _CHALLENGE_SERVER_TOKENS):
            return True
    if body_prefix:
        lowered_body = body_prefix.lower()
        if any(marker in lowered_body for marker in _CHALLENGE_BODY_MARKERS):
            return True
    return False


def _dns_cache_lookup(host: str, *, now: float) -> _DnsCacheEntry | None:
    """Return host's cached entry (success or failure) if still fresh."""
    entry = _dns_cache.get(host)
    if entry is not None and entry.expiry > now:
        return entry
    return None


def _dns_cache_store(host: str, *, now: float, ttl: float, error_message: str | None) -> None:
    if host not in _dns_cache and len(_dns_cache) >= _DNS_CACHE_MAX_ENTRIES:
        _dns_cache.pop(next(iter(_dns_cache)))
    _dns_cache[host] = _DnsCacheEntry(expiry=now + ttl, error_message=error_message)


def _dns_reset_state() -> None:
    """Clear cached resolutions and in-flight registrations.

    One entry point for tests that need a clean slate between cases, rather
    than reaching into _dns_cache and _dns_inflight separately.
    """
    with _dns_lock:
        _dns_cache.clear()
        _dns_inflight.clear()


def _await_inflight(host: str, inflight: _DnsInFlight, timeout: float) -> None:
    """Wait for a resolution already in progress, subject to our own deadline."""
    if not inflight.done.wait(timeout):
        raise PolicyFetchError(
            f"DNS resolution for '{host}' failed: did not complete within {timeout:.1f}s (preflight deadline)"
        )
    if inflight.error_message is not None:
        raise PolicyFetchError(inflight.error_message)


def _uses_proxy(url: str) -> bool:
    """True when urllib would route this URL through a configured proxy.

    A proxied request has its name resolved by the proxy, not by us, so the
    DNS preflight is skipped. Detection mirrors urllib's own logic
    (urllib.request.getproxies / proxy_bypass); any failure here is treated
    as "not proxied" so the preflight still runs.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
        if not host:
            return False
        proxies = urllib.request.getproxies()
        scheme = parsed.scheme or "http"
        proxy_url = proxies.get(scheme) or proxies.get("http")
        if not proxy_url:
            return False
        return not urllib.request.proxy_bypass(host)
    except Exception:
        return False


def _default_resolve_host(host: str, timeout: float) -> None:
    """Resolve host with a hard deadline, raising on failure or timeout.

    Runs socket.getaddrinfo on a daemon thread and waits up to timeout
    seconds for it to finish. A thread that never returns (a black-holed or
    filtered resolver) is simply abandoned -- it cannot block interpreter
    exit because it is a daemon thread, and nothing here ever joins it.

    The worker catches BaseException, not just Exception, so nothing it
    raises can escape into the thread unnoticed (which would otherwise print
    to stderr and be lost). The event is always set in `finally`, so a
    failure of any kind -- including something as unusual as MemoryError --
    still wakes the caller immediately rather than leaving it stuck until
    its own deadline.
    """
    done = threading.Event()
    outcome: dict[str, BaseException] = {}

    def _run() -> None:
        try:
            socket.getaddrinfo(host, None)
        except BaseException as exc:
            outcome["error"] = exc
        finally:
            done.set()

    threading.Thread(target=_run, daemon=True).start()
    if not done.wait(timeout):
        raise TimeoutError(f"did not complete within {timeout:.1f}s (preflight deadline)")
    error = outcome.get("error")
    if error is not None:
        raise error


def _dns_preflight(url: str, *, resolver: Resolver, timeout: float) -> None:
    """Resolve url's host once, sharing the outcome across callers.

    A fresh cache hit (success or failure) returns/raises immediately with
    no thread involved. Otherwise, the first caller for a host becomes its
    "owner" and actually invokes `resolver`; any other caller for the same
    host while that resolution is still running waits on the owner's result
    instead of starting a second one, bounding concurrent resolver threads
    to at most one per distinct host.
    """
    if _uses_proxy(url):
        return
    host = urllib.parse.urlsplit(url).hostname
    if not host:
        return

    now = time.monotonic()
    with _dns_lock:
        cached = _dns_cache_lookup(host, now=now)
        if cached is not None:
            if cached.error_message is None:
                return
            raise PolicyFetchError(cached.error_message)

        dns_timeout = min(DEFAULT_DNS_RESOLVE_TIMEOUT_SECONDS, timeout)
        if dns_timeout <= 0:
            raise PolicyFetchError(f"DNS resolution for '{host}' failed: preflight deadline is not positive")

        inflight = _dns_inflight.get(host)
        owner = inflight is None
        if owner:
            inflight = _DnsInFlight(done=threading.Event())
            _dns_inflight[host] = inflight

    if not owner:
        _await_inflight(host, inflight, dns_timeout)
        return

    try:
        resolver(host, dns_timeout)
    except Exception as exc:
        message = f"DNS resolution for '{host}' failed: {exc}"
        inflight.error_message = message
        with _dns_lock:
            _dns_cache_store(host, now=now, ttl=DEFAULT_DNS_NEGATIVE_CACHE_TTL_SECONDS, error_message=message)
            del _dns_inflight[host]
        inflight.done.set()
        raise PolicyFetchError(message) from exc
    except BaseException:
        # Something other than an ordinary resolution failure (e.g. the
        # calling thread being torn down). Don't cache a guess about the
        # outcome -- just stop owning it and let any waiter re-check.
        with _dns_lock:
            del _dns_inflight[host]
        inflight.done.set()
        raise
    else:
        with _dns_lock:
            _dns_cache_store(host, now=now, ttl=DEFAULT_DNS_CACHE_TTL_SECONDS, error_message=None)
            del _dns_inflight[host]
        inflight.done.set()


def _cert_verification_error(exc: BaseException) -> ssl.SSLCertVerificationError | None:
    """Return the SSLCertVerificationError behind exc, if any.

    urlopen never raises ssl.SSLCertVerificationError directly: http.client
    establishes the TLS connection inside AbstractHTTPHandler.do_open's
    try/except OSError block, which wraps it in a urllib.error.URLError
    (exposed as .reason). Check both forms so the check is correct for the
    real urlopen path as well as an opener that raises it unwrapped.
    """
    if isinstance(exc, ssl.SSLCertVerificationError):
        return exc
    reason = getattr(exc, "reason", None)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return reason
    return None


def _finalize(
    response: Any,
    *,
    url: str,
    max_bytes: int,
    label: str,
    final_url_validator: Callable[[str], str | None] | None,
    body_prefix: bytes = b"",
) -> HttpResponse:
    final_url = response.geturl() if hasattr(response, "geturl") else url
    if final_url_validator is not None:
        if final_url_validator(final_url) is None:
            raise PolicyFetchError(f"{label} redirected to an unsafe URL.")
    status_code = int(getattr(response, "status", None) or getattr(response, "code", 200) or 200)
    raw_headers = getattr(response, "headers", None)
    content_encoding = _header(raw_headers, "Content-Encoding")
    headers = _headers_dict(raw_headers)
    raw = _read_bounded(response, max_bytes=max_bytes, label=label, prefix=body_prefix)
    content = _decompress(raw, content_encoding, max_bytes=max_bytes, label=label)
    return HttpResponse(url=final_url or url, status_code=status_code, headers=headers, content=content)


def request(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float,
    max_bytes: int,
    label: str = DEFAULT_LABEL,
    etag: str | None = None,
    final_url_validator: Callable[[str], str | None] | None = None,
    raise_for_status: bool = True,
    attempts: int = DEFAULT_RETRY_ATTEMPTS,
    backoff_base: float = DEFAULT_BACKOFF_BASE_SECONDS,
    backoff_cap: float = DEFAULT_BACKOFF_CAP_SECONDS,
    retry_after_cap: float = DEFAULT_RETRY_AFTER_CAP_SECONDS,
    sleep: Sleeper = time.sleep,
    opener: Opener | None = None,
    resolver: Resolver | None = None,
) -> HttpResponse:
    merged_headers = default_headers(headers)
    if etag:
        merged_headers.setdefault("If-None-Match", etag)
    open_url = opener or urllib.request.urlopen
    # A custom opener fully replaces urlopen, so no real socket or DNS
    # lookup is ever involved -- skip the preflight unless a resolver was
    # explicitly supplied alongside it (as the tests for this module do).
    resolve_host = resolver if resolver is not None else (None if opener is not None else _default_resolve_host)
    if resolve_host is not None:
        _dns_preflight(url, resolver=resolve_host, timeout=timeout)
    total_attempts = max(1, int(attempts))
    last_exc: Exception | None = None

    for attempt in range(1, total_attempts + 1):
        prepared = urllib.request.Request(url, data=data, method=method, headers=dict(merged_headers))
        try:
            response = open_url(prepared, timeout=timeout)
        except urllib.error.HTTPError as exc:
            try:
                if exc.code == 304:
                    return HttpResponse(
                        url=getattr(exc, "url", None) or url,
                        status_code=304,
                        headers=_headers_dict(exc.headers),
                        content=b"",
                        not_modified=True,
                    )
                body_prefix = b""
                should_retry = exc.code in _RETRYABLE_STATUS_CODES and attempt < total_attempts
                if should_retry:
                    body_prefix = _read_challenge_probe(exc, cap=DEFAULT_CHALLENGE_BODY_PEEK_BYTES)
                    if _is_challenge_response(exc.headers, body_prefix):
                        should_retry = False
                if should_retry:
                    sleep(_retry_delay(exc, attempt, backoff_base, backoff_cap, retry_after_cap))
                    last_exc = exc
                    continue
                if raise_for_status:
                    raise
                return _finalize(
                    exc,
                    url=url,
                    max_bytes=max_bytes,
                    label=label,
                    final_url_validator=None,
                    body_prefix=body_prefix,
                )
            finally:
                closer = getattr(exc, "close", None)
                if callable(closer):
                    closer()
        except OSError as exc:
            if _cert_verification_error(exc) is not None:
                raise PolicyFetchError(f"Failed to fetch {url}: {_CERT_VERIFICATION_MESSAGE}") from exc
            if attempt < total_attempts:
                sleep(_backoff_delay(attempt, backoff_base, backoff_cap))
                last_exc = exc
                continue
            raise PolicyFetchError(f"Failed to fetch {url}: {exc}") from exc
        else:
            try:
                return _finalize(
                    response,
                    url=url,
                    max_bytes=max_bytes,
                    label=label,
                    final_url_validator=final_url_validator,
                )
            finally:
                closer = getattr(response, "close", None)
                if callable(closer):
                    closer()

    if last_exc is not None:
        raise PolicyFetchError(f"Failed to fetch {url}: {last_exc}") from last_exc
    raise PolicyFetchError(f"Failed to fetch {url}: exhausted retry attempts")


__all__ = [
    "BROWSER_USER_AGENT",
    "DEFAULT_ACCEPT",
    "DEFAULT_ACCEPT_ENCODING",
    "DEFAULT_ACCEPT_LANGUAGE",
    "DEFAULT_BACKOFF_BASE_SECONDS",
    "DEFAULT_BACKOFF_CAP_SECONDS",
    "DEFAULT_CHALLENGE_BODY_PEEK_BYTES",
    "DEFAULT_DNS_CACHE_TTL_SECONDS",
    "DEFAULT_DNS_NEGATIVE_CACHE_TTL_SECONDS",
    "DEFAULT_DNS_RESOLVE_TIMEOUT_SECONDS",
    "DEFAULT_LABEL",
    "DEFAULT_RETRY_AFTER_CAP_SECONDS",
    "DEFAULT_RETRY_ATTEMPTS",
    "HttpResponse",
    "charset_from_content_type",
    "default_headers",
    "get_header",
    "request",
]
