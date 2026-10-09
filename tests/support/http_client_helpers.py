"""Helpers shared by the test_http_client test modules."""

from __future__ import annotations

import email.message
import io
import urllib.error
import urllib.request
import pytest
from win11_release_guard import http_client


DEFAULT_URL = "https://http-client-tests.invalid/resource"


@pytest.fixture(autouse=True)
def _clear_dns_cache():
    http_client._dns_reset_state()
    yield
    http_client._dns_reset_state()


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
