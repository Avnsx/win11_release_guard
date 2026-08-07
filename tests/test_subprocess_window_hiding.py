"""Tests for hidden console child windows of internal helper processes.

These pin that the library spawns its short-lived powershell.exe / dism.exe
helpers with Windows console-window-hiding flags so GUI consumers (e.g. a
PySide6 admin app) do not see black console windows flash. They mock at the
``subprocess.run`` boundary; no real process is spawned and no network is used.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from win11_release_guard import _subprocess_util, audit_probes, local_state, wua_probe


# The Win32 CREATE_NO_WINDOW constant. getattr keeps this importable off Windows.
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
STARTF_USESHOWWINDOW = getattr(subprocess, "STARTF_USESHOWWINDOW", 0x00000001)

# Building a real STARTUPINFO only works where the Windows subprocess support is
# present. Tests that exercise the Windows branch are skipped on Linux/macOS CI;
# the off-Windows no-op test runs everywhere.
HAS_STARTUPINFO = hasattr(subprocess, "STARTUPINFO")
requires_startupinfo = pytest.mark.skipif(
    not HAS_STARTUPINFO,
    reason="subprocess.STARTUPINFO is only available on Windows",
)


def _force_windows(monkeypatch):
    monkeypatch.setattr(_subprocess_util.os, "name", "nt")
    monkeypatch.setattr(_subprocess_util.sys, "platform", "win32")


def _force_non_windows(monkeypatch):
    monkeypatch.setattr(_subprocess_util.os, "name", "posix")
    monkeypatch.setattr(_subprocess_util.sys, "platform", "linux")


# --- helper unit behavior -------------------------------------------------


@requires_startupinfo
def test_hidden_console_kwargs_hides_window_on_windows(monkeypatch):
    _force_windows(monkeypatch)

    kwargs = _subprocess_util.hidden_console_kwargs()

    assert kwargs["creationflags"] & CREATE_NO_WINDOW
    startupinfo = kwargs["startupinfo"]
    assert startupinfo is not None
    assert startupinfo.dwFlags & STARTF_USESHOWWINDOW
    assert startupinfo.wShowWindow == 0  # SW_HIDE


def test_hidden_console_kwargs_is_noop_off_windows(monkeypatch):
    _force_non_windows(monkeypatch)

    kwargs = _subprocess_util.hidden_console_kwargs()

    assert kwargs == {"creationflags": 0, "startupinfo": None}


@requires_startupinfo
def test_with_hidden_console_preserves_existing_kwargs(monkeypatch):
    _force_windows(monkeypatch)

    merged = _subprocess_util.with_hidden_console(
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=8.0,
        check=False,
    )

    assert merged["capture_output"] is True
    assert merged["text"] is True
    assert merged["encoding"] == "utf-8"
    assert merged["errors"] == "replace"
    assert merged["timeout"] == 8.0
    assert merged["check"] is False
    assert merged["creationflags"] & CREATE_NO_WINDOW
    assert merged["startupinfo"] is not None


@requires_startupinfo
def test_with_hidden_console_caller_creationflags_win(monkeypatch):
    _force_windows(monkeypatch)
    caller_startupinfo = object()

    merged = _subprocess_util.with_hidden_console(
        creationflags=0x00000010,  # CREATE_NEW_CONSOLE, an unrelated caller flag
        startupinfo=caller_startupinfo,
    )

    # The hide flag is OR-combined, never clobbering the caller's flag.
    assert merged["creationflags"] & 0x00000010
    assert merged["creationflags"] & CREATE_NO_WINDOW
    # A caller-supplied STARTUPINFO is preserved as-is (theirs wins).
    assert merged["startupinfo"] is caller_startupinfo


# --- probe passthrough ----------------------------------------------------


class _Recorder:
    """Captures the kwargs of a single subprocess.run call and returns a stub."""

    def __init__(self, stdout="{}", stderr="", returncode=0):
        self.kwargs = None
        self.args = None
        self._result = SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)

    def __call__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        return self._result


def _assert_hidden_and_original(kwargs):
    # Window hiding present.
    assert "creationflags" in kwargs
    assert kwargs["creationflags"] & CREATE_NO_WINDOW
    assert kwargs.get("startupinfo") is not None
    assert kwargs["startupinfo"].wShowWindow == 0
    # Original byte-for-byte kwargs unchanged.
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True
    assert kwargs["encoding"] == "utf-8"
    assert kwargs["errors"] == "replace"
    assert "timeout" in kwargs
    assert kwargs["check"] is False


@requires_startupinfo
def test_read_wmi_operating_system_hides_window(monkeypatch):
    _force_windows(monkeypatch)
    # The native (registry + ctypes) read is tried first and, on this real
    # Windows test host, would succeed without ever spawning powershell.exe.
    # Force it unusable so this test still exercises (and can inspect) the
    # PowerShell fallback's hidden-window subprocess call.
    monkeypatch.setattr(local_state, "_read_native_operating_system", lambda: None)
    recorder = _Recorder(stdout='{"Caption":"Windows 11","Version":"10.0.26200"}')
    monkeypatch.setattr(local_state.subprocess, "run", recorder)

    local_state._read_wmi_operating_system(timeout_seconds=8.0)

    _assert_hidden_and_original(recorder.kwargs)
    assert recorder.kwargs["timeout"] == 8.0


@requires_startupinfo
def test_read_dism_current_edition_hides_window(monkeypatch):
    _force_windows(monkeypatch)
    recorder = _Recorder(stdout="Current Edition : Professional\n", returncode=0)
    monkeypatch.setattr(local_state.subprocess, "run", recorder)

    local_state._read_dism_current_edition(timeout_seconds=10.0)

    _assert_hidden_and_original(recorder.kwargs)
    assert recorder.kwargs["timeout"] == 10.0


@requires_startupinfo
def test_query_event_logs_hides_window(monkeypatch):
    _force_windows(monkeypatch)
    monkeypatch.setattr(wua_probe.os, "name", "nt")
    recorder = _Recorder(stdout='{"events":[],"warnings":[]}')
    monkeypatch.setattr(wua_probe.subprocess, "run", recorder)

    wua_probe._query_event_logs(set(), timeout_seconds=8.0)

    _assert_hidden_and_original(recorder.kwargs)


@requires_startupinfo
def test_query_wua_secondary_subprocess_hides_window(monkeypatch):
    _force_windows(monkeypatch)
    recorder = _Recorder(stdout="{}")
    monkeypatch.setattr(wua_probe.subprocess, "run", recorder)

    wua_probe._query_wua_secondary_subprocess(
        "25H2",
        max_history=10,
        timeout_seconds=30.0,
        max_relevant_updates=5,
        event_log_max_events=50,
    )

    _assert_hidden_and_original(recorder.kwargs)


@requires_startupinfo
def test_query_dism_packages_hides_window(monkeypatch):
    _force_windows(monkeypatch)
    monkeypatch.setattr(audit_probes.os, "name", "nt")
    recorder = _Recorder(stdout="", returncode=0)
    monkeypatch.setattr(audit_probes.subprocess, "run", recorder)

    audit_probes.query_dism_packages(timeout_seconds=20.0)

    _assert_hidden_and_original(recorder.kwargs)
    assert recorder.kwargs["timeout"] == 20.0
