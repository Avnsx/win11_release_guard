from __future__ import annotations

import email.message
import email.utils
import gzip
import time
import urllib.error
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

_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})

Sleeper = Callable[[float], None]
Opener = Callable[..., Any]


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


def _read_bounded(response: Any, *, max_bytes: int, label: str) -> bytes:
    headers = getattr(response, "headers", None)
    content_length = _content_length(headers)
    if content_length is not None and content_length > max_bytes:
        raise PolicyFetchError(_too_large_message(label, max_bytes))
    data = response.read(max_bytes + 1)
    if isinstance(data, str):
        data = data.encode("utf-8")
    if len(data) > max_bytes:
        raise PolicyFetchError(_too_large_message(label, max_bytes))
    return data


def _decompress(data: bytes, content_encoding: str | None) -> bytes:
    if not data or not content_encoding:
        return data
    normalized = content_encoding.strip().lower()
    if normalized == "gzip":
        try:
            return gzip.decompress(data)
        except OSError:
            return data
    if normalized == "deflate":
        try:
            return zlib.decompress(data)
        except zlib.error:
            try:
                return zlib.decompress(data, -zlib.MAX_WBITS)
            except zlib.error:
                return data
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


def _finalize(
    response: Any,
    *,
    url: str,
    max_bytes: int,
    label: str,
    final_url_validator: Callable[[str], str | None] | None,
) -> HttpResponse:
    final_url = response.geturl() if hasattr(response, "geturl") else url
    if final_url_validator is not None:
        if final_url_validator(final_url) is None:
            raise PolicyFetchError(f"{label} redirected to an unsafe URL.")
    status_code = int(getattr(response, "status", None) or getattr(response, "code", 200) or 200)
    raw_headers = getattr(response, "headers", None)
    content_encoding = _header(raw_headers, "Content-Encoding")
    headers = _headers_dict(raw_headers)
    raw = _read_bounded(response, max_bytes=max_bytes, label=label)
    content = _decompress(raw, content_encoding)
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
) -> HttpResponse:
    merged_headers = default_headers(headers)
    if etag:
        merged_headers.setdefault("If-None-Match", etag)
    open_url = opener or urllib.request.urlopen
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
                if exc.code in _RETRYABLE_STATUS_CODES and attempt < total_attempts:
                    sleep(_retry_delay(exc, attempt, backoff_base, backoff_cap, retry_after_cap))
                    last_exc = exc
                    continue
                if raise_for_status:
                    raise
                return _finalize(exc, url=url, max_bytes=max_bytes, label=label, final_url_validator=None)
            finally:
                closer = getattr(exc, "close", None)
                if callable(closer):
                    closer()
        except OSError as exc:
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
    "DEFAULT_LABEL",
    "DEFAULT_RETRY_AFTER_CAP_SECONDS",
    "DEFAULT_RETRY_ATTEMPTS",
    "HttpResponse",
    "charset_from_content_type",
    "default_headers",
    "get_header",
    "request",
]
