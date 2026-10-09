"""Size-capped HTTP fetching of policy documents."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable
from .config import DEFAULT_HTTP_TIMEOUT_SECONDS, DEFAULT_POLICY_URL
from .exceptions import PolicyFetchError
from . import http_client
from .json_utils import DEFAULT_MAX_POLICY_BYTES
from .models import ReleasePolicy
from .policy_json import _is_url, load_policy_bytes


HttpGet = Callable[..., Any]


def _payload_too_large_message(label: str, max_bytes: int) -> str:
    return f"{label} is too large: exceeds safety cap of {max_bytes} bytes."


def _content_length_from_headers(headers: Any) -> int | None:
    if headers is None:
        return None
    value = None
    if hasattr(headers, "get"):
        value = headers.get("content-length") or headers.get("Content-Length")
    if value is None and hasattr(headers, "items"):
        for key, candidate in headers.items():
            if str(key).lower() == "content-length":
                value = candidate
                break
    if value is None:
        return None
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _declared_content_length(response: Any) -> int | None:
    return _content_length_from_headers(getattr(response, "headers", None))


def _ensure_payload_size(data: bytes, *, max_bytes: int, label: str) -> None:
    if len(data) > max_bytes:
        raise PolicyFetchError(_payload_too_large_message(label, max_bytes))


def _read_limited_response(response: Any, *, max_bytes: int, label: str) -> bytes:
    declared_length = _declared_content_length(response)
    if declared_length is not None and declared_length > max_bytes:
        raise PolicyFetchError(_payload_too_large_message(label, max_bytes))
    try:
        data = response.read(max_bytes + 1)
    except TypeError as exc:
        raise PolicyFetchError(f"{label} reader does not support bounded reads.") from exc
    if isinstance(data, str):
        encoded = data.encode("utf-8")
        _ensure_payload_size(encoded, max_bytes=max_bytes, label=label)
        return encoded
    if isinstance(data, bytes):
        _ensure_payload_size(data, max_bytes=max_bytes, label=label)
        return data
    raise PolicyFetchError("Release policy fetcher returned an unsupported response type.")


def _default_http_get(url: str, timeout: float, *, max_bytes: int = DEFAULT_MAX_POLICY_BYTES) -> bytes:
    result = http_client.request(
        url,
        headers={"Accept": "application/json,text/html,application/xhtml+xml"},
        timeout=timeout,
        max_bytes=max_bytes,
        label="Release policy response",
    )
    return result.content


def _call_http_get(http_get: HttpGet, url: str, timeout: float) -> Any:
    try:
        return http_get(url, timeout=timeout)
    except TypeError:
        return http_get(url)


def _response_text(response: Any, *, max_bytes: int = DEFAULT_MAX_POLICY_BYTES) -> str:
    data, _content_type = _response_bytes(response, max_bytes=max_bytes)
    return data.decode("utf-8", errors="replace")


def _response_bytes(
    response: Any,
    *,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> tuple[bytes, str | None]:
    if hasattr(response, "raise_for_status"):
        response.raise_for_status()

    status_code = getattr(response, "status_code", None)
    if status_code is not None and int(status_code) >= 400:
        raise PolicyFetchError(f"Release policy fetch returned HTTP {status_code}.")

    label = "Release policy response"
    declared_length = _declared_content_length(response)
    if declared_length is not None and declared_length > max_bytes:
        raise PolicyFetchError(_payload_too_large_message(label, max_bytes))

    content_type = _response_content_type(response)

    if isinstance(response, str):
        data = response.encode("utf-8")
        _ensure_payload_size(data, max_bytes=max_bytes, label=label)
        return data, content_type
    if isinstance(response, bytes):
        _ensure_payload_size(response, max_bytes=max_bytes, label=label)
        return response, content_type

    text = getattr(response, "text", None)
    if isinstance(text, str):
        data = text.encode("utf-8")
        _ensure_payload_size(data, max_bytes=max_bytes, label=label)
        return data, content_type

    content = getattr(response, "content", None)
    if isinstance(content, bytes):
        _ensure_payload_size(content, max_bytes=max_bytes, label=label)
        return content, content_type

    if hasattr(response, "read"):
        return _read_limited_response(response, max_bytes=max_bytes, label=label), content_type

    raise PolicyFetchError("Release policy fetcher returned an unsupported response type.")


def _response_content_type(response: Any) -> str | None:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    if hasattr(headers, "get"):
        value = headers.get("content-type") or headers.get("Content-Type")
        if value:
            return str(value)
    if hasattr(headers, "items"):
        for key, value in headers.items():
            if str(key).lower() == "content-type":
                return str(value)
    return None


def _content_type_from_path(path: str) -> str | None:
    suffix = Path(path).suffix.lower()
    if suffix == ".json":
        return "application/json"
    if suffix in {".html", ".htm"}:
        return "text/html"
    return None


def fetch_release_policy(
    url: str | None = DEFAULT_POLICY_URL,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    http_get: HttpGet | None = None,
    *,
    allow_html_fallback: bool = False,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> ReleasePolicy:
    if not url:
        raise PolicyFetchError("No release policy URL configured.")
    data, content_type = fetch_policy_bytes(
        url,
        timeout=timeout,
        http_get=http_get,
        max_bytes=max_bytes,
    )
    return load_policy_bytes(
        data,
        content_type=content_type,
        source_url=url,
        allow_html_fallback=allow_html_fallback,
        max_bytes=max_bytes,
    )


def fetch_policy_bytes(
    url: str,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    http_get: HttpGet | None = None,
    *,
    max_bytes: int = DEFAULT_MAX_POLICY_BYTES,
) -> tuple[bytes, str | None]:
    try:
        if http_get is None and not _is_url(url):
            policy_path = Path(url)
            if policy_path.stat().st_size > max_bytes:
                raise PolicyFetchError(
                    _payload_too_large_message("Release policy file", max_bytes)
                )
            content_type = _content_type_from_path(url)
            return policy_path.read_bytes(), content_type
        response = (
            _call_http_get(http_get, url, timeout)
            if http_get
            else _default_http_get(url, timeout, max_bytes=max_bytes)
        )
        return _response_bytes(response, max_bytes=max_bytes)
    except PolicyFetchError:
        raise
    except Exception as exc:
        raise PolicyFetchError(f"Failed to fetch release policy from {url}: {exc}") from exc
