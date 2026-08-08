"""Purge and inspection suite for ``state_store``: ``_state_entries``, ``purge_state``,
``describe_state`` and ``read_state_bytes``.

``_state_entries`` is the sole ``(role, path)`` producer and the only ``PurePath -> Path``
enumeration site, so every consumer (``purge_state`` here, ``describe_state`` and the CLI
later) sees exactly the same set of paths. It forces ``stateless=False`` because a purge
must still find and remove what a non-stateless run of the same configuration wrote.

``purge_state`` carries one of the design's two staging carve-outs: a ``role == "staging"``
path is unlinked with no magic check, while a ``role == "state"`` path — a derived name in a
shared temp directory, where a foreign squatter must survive — is unlinked only after its
first eight bytes are confirmed to equal ``STATE_MAGIC``. Nothing else is magic-gated: the
``legacy_pair`` paths were named by the operator in the very invocation, and the two
``%LOCALAPPDATA%`` ``legacy`` paths are plain JSON plus a raw detached signature that can
never carry ``STATE_MAGIC``.

Every test passes ``state_dir=str(tmp_path)`` or ``cache_file=`` under ``tmp_path`` so its
reads and writes are over a per-test directory and hold in any collection order (§16.1
rule 2); no test hardcodes a derived filename. The legacy pair exists only on ``nt``
(``legacy_state_paths`` returns ``()`` elsewhere) and forcing ``os_name="nt"`` on Linux is
forbidden — a ``PureWindowsPath`` there collapses to one CWD-relative filename — so that one
case is a ``skipif(nt)`` test against the conftest's redirected ``LOCALAPPDATA`` (§16.3).
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from win11_release_guard import state_store
from win11_release_guard.config import ReleaseCheckerConfig

_POLICY = b'{"generated_at_utc": "2026-08-06T02:00:00+00:00"}'


def _seed_container(path, policy_bytes=_POLICY, signature_bytes=b"detached-sig"):
    Path(path).write_bytes(state_store.encode_state(policy_bytes, signature_bytes))


def test_purge_state_removes_container(tmp_path):
    config = ReleaseCheckerConfig(state_dir=str(tmp_path))
    scope = state_store.resolve_state_scope(config)
    _seed_container(scope.path)
    events = state_store.purge_state(config)
    state_event = next(e for e in events if e.path == str(scope.path))
    staging_event = next(e for e in events if e.path == str(scope.staging_path))
    assert state_event.action == "purge"
    assert state_event.outcome == "removed"
    assert not Path(scope.path).exists()
    assert staging_event.outcome == "absent"


def test_purge_state_keeps_foreign_file(tmp_path):
    config = ReleaseCheckerConfig(state_dir=str(tmp_path))
    scope = state_store.resolve_state_scope(config)
    Path(scope.path).write_bytes(b"not our magic at all, foreign squatter bytes")
    events = state_store.purge_state(config)
    state_event = next(e for e in events if e.path == str(scope.path))
    assert state_event.outcome == "skipped"
    assert state_event.detail == "not our format"
    assert Path(scope.path).exists()


def test_purge_state_removes_staging_without_magic(tmp_path):
    config = ReleaseCheckerConfig(state_dir=str(tmp_path))
    scope = state_store.resolve_state_scope(config)
    Path(scope.staging_path).write_bytes(b"")
    events = state_store.purge_state(config)
    staging_event = next(e for e in events if e.path == str(scope.staging_path))
    assert staging_event.outcome == "removed"
    assert not Path(scope.staging_path).exists()


def test_purge_state_legacy_pair_removes_operator_named_paths(tmp_path):
    cache_file = tmp_path / "policy.json"
    cache_file.write_bytes(b"plain json, no magic")
    signature = tmp_path / "policy.json.sig"
    signature.write_bytes(b"signature")
    config = ReleaseCheckerConfig(cache_file=str(cache_file))
    events = state_store.purge_state(config)
    outcomes = {e.path: e.outcome for e in events}
    assert outcomes[str(cache_file)] == "removed"
    assert outcomes[str(signature)] == "removed"
    assert not cache_file.exists()
    assert not signature.exists()


@pytest.mark.skipif(os.name != "nt", reason="the legacy pair exists only under %LOCALAPPDATA%")
def test_purge_state_removes_the_legacy_pair(tmp_path):
    """The legacy pair is exactly what ``cache.save_policy_cache`` wrote — plain JSON — beside a
    raw detached signature, so neither file can ever carry ``STATE_MAGIC``. Magic-gating role
    ``"legacy"`` would leave both permanently unremovable by the shipped CLI while
    ``retire_legacy_state`` unlinks the same two paths unread (O-1, §8.1), so purge removes them
    and a second purge reports them ``absent`` rather than ``failed`` (§16.3)."""
    legacy_dir = Path(os.environ["LOCALAPPDATA"]) / "win11_release_guard"
    legacy_dir.mkdir(parents=True, exist_ok=True)
    policy = legacy_dir / "windows-release-policy.json"
    signature = legacy_dir / "windows-release-policy.json.sig"
    policy.write_text('{"schema_version": 3}\n', encoding="utf-8")
    signature.write_bytes(b"raw detached signature bytes")
    config = ReleaseCheckerConfig(state_dir=str(tmp_path))
    outcomes = {
        event.path: (event.outcome, event.detail) for event in state_store.purge_state(config)
    }
    assert outcomes[str(policy)] == ("removed", None)
    assert outcomes[str(signature)] == ("removed", None)
    assert not policy.exists()
    assert not signature.exists()
    again = {event.path: event.outcome for event in state_store.purge_state(config)}
    assert again[str(policy)] == "absent"
    assert again[str(signature)] == "absent"


def test_purge_state_layout_none_returns_one_skipped():
    config = ReleaseCheckerConfig(state_dir="relative-dir")
    events = state_store.purge_state(config)
    assert len(events) == 1
    assert events[0].action == "purge"
    assert events[0].outcome == "skipped"
    assert events[0].path is None
    assert events[0].detail == "state_dir_not_absolute"


def test_purge_state_reports_failed_when_unlink_raises(tmp_path, monkeypatch):
    config = ReleaseCheckerConfig(state_dir=str(tmp_path))
    scope = state_store.resolve_state_scope(config)
    _seed_container(scope.path)

    def boom(path):
        raise OSError(13, "permission denied")

    monkeypatch.setattr(state_store, "_unlink", boom)
    events = state_store.purge_state(config)
    state_event = next(e for e in events if e.path == str(scope.path))
    assert state_event.outcome == "failed"
    assert "permission denied" in (state_event.detail or "")


def test_purge_state_survives_a_failing_close(tmp_path, monkeypatch):
    """``read_state`` and ``discard_state`` both wrap the magic-check ``os.close`` in
    ``try/except OSError: pass``. ``purge_state`` is documented NEVER raises and must be
    consistent with its two siblings, or an ``EBADF`` on the descriptor it has just read
    escapes a purge that already decided the record is ours and is about to unlink it.

    The descriptor really is closed before the failure is raised, so nothing leaks, and
    the patch is undone before the assertions so a failing run cannot report through a
    broken ``os.close``.
    """
    config = ReleaseCheckerConfig(state_dir=str(tmp_path))
    scope = state_store.resolve_state_scope(config)
    _seed_container(scope.path)
    real_close = os.close
    closed: list[int] = []

    def failing_close(fd):
        closed.append(fd)
        real_close(fd)
        raise OSError(9, "bad file descriptor")

    monkeypatch.setattr(state_store.os, "close", failing_close)
    try:
        events = state_store.purge_state(config)
    finally:
        monkeypatch.undo()

    assert closed, "the magic-check descriptor was never closed"
    state_event = next(e for e in events if e.path == str(scope.path))
    assert state_event.outcome == "removed"
    assert not Path(scope.path).exists()


def test_state_entries_signature_staging_matches_the_writer_derivation(tmp_path, monkeypatch):
    """``StateScope`` carries no ``signature_staging_path`` field. What justifies the
    absence is that ``_state_entries`` recomputes that one name with the same expression
    ``write_bytes_atomically`` uses, so both sides always agree. Should they ever drift, a
    legacy-pair signature write that dies mid-flight leaves a ``.sig.staging.tmp`` orphan
    that ``--purge-state`` can no longer see, in a directory the operator named.
    """
    cache_file = tmp_path / "policy.json"
    config = ReleaseCheckerConfig(cache_file=str(cache_file))
    scope = state_store.resolve_state_scope(config)
    swaps: list[tuple[str, str]] = []
    monkeypatch.setattr(
        state_store, "_replace", lambda source, destination: swaps.append((source, destination))
    )
    state_store.write_state(scope, b'{"policy": true}', b"detached-sig")

    staging = [str(path) for role, path in state_store._state_entries(config) if role == "staging"]
    expected = str(
        scope.signature_path.with_name(state_store.staging_name(scope.signature_path.name))
    )
    assert expected in staging
    assert str(scope.staging_path) in staging
    assert len(staging) == 2  # the policy staging name and the .sig staging name, no more
    # ...and it is the very name the writer staged the signature under.
    staged_signature = next(src for src, dest in swaps if dest == str(scope.signature_path))
    assert staged_signature == expected


def test_describe_state_survives_an_out_of_range_modification_time(tmp_path, monkeypatch):
    """``describe_state`` is documented NEVER raises, but its per-path guard caught only
    ``(OSError, ValueError)``. CPython raises ``OverflowError`` — an ``ArithmeticError``,
    NOT a ``ValueError`` — when a stat timestamp falls outside the platform ``time_t``
    range, so one such file escaped the guard and took the whole ``--show-state`` payload
    down with it.

    The out-of-range clock is injected rather than written to disk with ``os.utime``: no
    filesystem either CI leg can create stores an mtime that far out (a Windows FILETIME
    stops near year 30828 and yields ``OSError``, which was already caught), so the
    branch is unreachable through real host behaviour. The premise is therefore asserted
    against the real host first, and only the conversion itself is replaced.
    """
    assert not issubclass(OverflowError, ValueError)
    with pytest.raises(OverflowError):
        datetime.fromtimestamp(2**63, tz=timezone.utc)

    config = ReleaseCheckerConfig(state_dir=str(tmp_path))
    scope = state_store.resolve_state_scope(config)
    _seed_container(scope.path)

    class _OutOfRangeClock:
        @staticmethod
        def fromtimestamp(timestamp, tz=None):
            raise OverflowError("timestamp out of range for platform time_t")

    monkeypatch.setattr(state_store, "datetime", _OutOfRangeClock)
    payload = state_store.describe_state(config)
    entry = next(e for e in payload["entries"] if e["role"] == "state")
    # The failed conversion costs exactly one field. Everything established before it,
    # and everything the record itself yields, must still be reported.
    assert entry["exists"] is True
    assert entry["size_bytes"] is not None
    assert entry["modified_utc"] is None
    assert entry["status"] == "usable"
    assert entry["policy_sha256"] == hashlib.sha256(_POLICY).hexdigest()


def test_describe_state_reports_usable_container(tmp_path):
    config = ReleaseCheckerConfig(state_dir=str(tmp_path))
    scope = state_store.resolve_state_scope(config)
    Path(scope.path).write_bytes(state_store.encode_state(_POLICY, b"detached-sig"))
    payload = state_store.describe_state(config)
    assert payload["layout"] == "container"
    assert payload["source"] == "state_dir"
    assert payload["stateless"] is False
    assert payload["state_format_version"] == state_store.STATE_FORMAT_VERSION
    entry = next(e for e in payload["entries"] if e["role"] == "state")
    assert entry["exists"] is True
    assert entry["status"] == "usable"
    assert entry["policy_bytes"] == len(_POLICY)
    assert entry["policy_sha256"] == hashlib.sha256(_POLICY).hexdigest()
    assert entry["signature_present"] is True
    assert entry["policy_generated_at_utc"] == "2026-08-06T02:00:00+00:00"
    assert entry["size_bytes"] is not None
    assert entry["modified_utc"] is not None


def test_describe_state_stateless_flag_but_real_location(tmp_path):
    config = ReleaseCheckerConfig(state_dir=str(tmp_path), stateless=True)
    payload = state_store.describe_state(config)
    assert payload["layout"] == "container"
    assert payload["source"] == "state_dir"
    assert payload["stateless"] is True


def test_describe_state_cold_machine_reports_absent(tmp_path):
    config = ReleaseCheckerConfig(state_dir=str(tmp_path))
    payload = state_store.describe_state(config)
    entry = next(e for e in payload["entries"] if e["role"] == "state")
    assert entry["exists"] is False
    assert entry["status"] == "absent"
    assert entry["policy_bytes"] is None
    assert entry["policy_sha256"] is None
    assert entry["signature_present"] is None


def test_describe_state_status_null_for_non_state_roles(tmp_path):
    cache_file = tmp_path / "policy.json"
    cache_file.write_bytes(b'{"generated_at_utc": "2026-08-06T02:00:00+00:00"}')
    (tmp_path / "policy.json.sig").write_bytes(b"sig")
    config = ReleaseCheckerConfig(cache_file=str(cache_file))
    payload = state_store.describe_state(config)
    assert payload["layout"] == "legacy_pair"
    assert all(entry["role"] != "state" for entry in payload["entries"])
    assert all(entry["status"] is None for entry in payload["entries"])
    cache_entry = next(e for e in payload["entries"] if e["role"] == "cache_file")
    assert cache_entry["exists"] is True


def test_read_state_bytes_returns_stored_policy(tmp_path):
    config = ReleaseCheckerConfig(state_dir=str(tmp_path))
    scope = state_store.resolve_state_scope(config)
    Path(scope.path).write_bytes(state_store.encode_state(_POLICY, b"sig"))
    assert state_store.read_state_bytes(config) == _POLICY


def test_read_state_bytes_none_when_absent(tmp_path):
    config = ReleaseCheckerConfig(state_dir=str(tmp_path))
    assert state_store.read_state_bytes(config) is None


def test_read_state_bytes_ignores_stateless(tmp_path):
    seed_config = ReleaseCheckerConfig(state_dir=str(tmp_path))
    scope = state_store.resolve_state_scope(seed_config)
    Path(scope.path).write_bytes(state_store.encode_state(b'{"ok": true}', None))
    stateless_config = ReleaseCheckerConfig(state_dir=str(tmp_path), stateless=True)
    assert state_store.read_state_bytes(stateless_config) == b'{"ok": true}'


def test_state_store_exports_present():
    import win11_release_guard as pkg

    for name in ("purge_state", "describe_state", "read_state_bytes", "StateEvent", "STATE_FORMAT_VERSION"):
        assert name in pkg.__all__
        assert hasattr(pkg, name)
