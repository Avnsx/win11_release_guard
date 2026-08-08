"""Purge suite for ``state_store``: ``_state_entries`` and ``purge_state``.

``_state_entries`` is the sole ``(role, path)`` producer and the only ``PurePath -> Path``
enumeration site, so every consumer (``purge_state`` here, ``describe_state`` and the CLI
later) sees exactly the same set of paths. It forces ``stateless=False`` because a purge
must still find and remove what a non-stateless run of the same configuration wrote.

``purge_state`` carries one of the design's two staging carve-outs: a ``role == "staging"``
path is unlinked with no magic check, while a ``role == "state"`` (or ``"legacy"``) path is
unlinked only after its first eight bytes are confirmed to equal ``STATE_MAGIC``. The
operator-named ``legacy_pair`` paths carry no magic at all — they are raw JSON and a raw
signature — so they are unlinked unconditionally too.

Every test passes ``state_dir=str(tmp_path)`` or ``cache_file=`` under ``tmp_path`` so its
reads and writes are over a per-test directory and hold in any collection order (§16.1
rule 2); no test hardcodes a derived filename.
"""

from __future__ import annotations

from pathlib import Path

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
