"""I/O suite for ``state_store``: the atomic write primitive and its seams.

Every failure path is driven through the named ``_replace``/``_unlink`` seams so both
CI legs exercise the same code; nothing here depends on host-specific kernel behaviour.
"""

from __future__ import annotations

from pathlib import Path

from win11_release_guard import state_store


def test_write_bytes_atomically_writes_and_swaps(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    dest = state_dir / "rec.tmp"
    event = state_store.write_bytes_atomically(dest, b"payload-bytes")
    assert event.action == "write"
    assert event.outcome == "written"
    assert event.path == str(dest)
    assert event.detail is None
    assert dest.read_bytes() == b"payload-bytes"
    # After a successful swap the staging file has been renamed away, so the state
    # directory contains exactly one name and no subdirectory (§16.3).
    assert sorted(p.name for p in state_dir.iterdir()) == ["rec.tmp"]


def test_state_event_to_dict():
    event = state_store.StateEvent("write", "written", "/tmp/x", None)
    assert event.to_dict() == {
        "action": "write",
        "outcome": "written",
        "path": "/tmp/x",
        "detail": None,
    }


def test_write_bytes_atomically_staging_path_matches_derivation(tmp_path, monkeypatch):
    dest = tmp_path / "rec.tmp"
    captured = {}

    def capture(source, destination):
        captured["source"] = source
        captured["destination"] = destination

    monkeypatch.setattr(state_store, "_replace", capture)
    event = state_store.write_bytes_atomically(dest, b"x")
    expected_staging = dest.with_name(state_store.staging_name(dest.name))
    # The primitive derives its own staging name; it must equal the planner's
    # scope.staging_path expression path.with_name(staging_name(path.name)) (§16.3),
    # or --purge-state silently stops finding the orphan.
    assert captured["source"] == str(expected_staging)
    assert captured["destination"] == str(dest)
    assert event.outcome == "written"


def test_write_bytes_atomically_swap_failure_cleans_staging(tmp_path, monkeypatch):
    dest = tmp_path / "rec.tmp"
    dest.write_bytes(b"old-destination")

    def boom(source, destination):
        raise OSError(5, "swap refused")

    monkeypatch.setattr(state_store, "_replace", boom)
    event = state_store.write_bytes_atomically(dest, b"new-payload")
    assert event.outcome == "failed"
    assert "OSError" in event.detail
    expected_staging = dest.with_name(state_store.staging_name(dest.name))
    # §5.1 rule 4: the failure-path cleanup ran (opened is True).
    assert not expected_staging.exists()
    # The destination is untouched by a failed swap.
    assert dest.read_bytes() == b"old-destination"


def test_write_bytes_atomically_missing_parent_returns_failed(tmp_path):
    dest = tmp_path / "does-not-exist" / "rec.tmp"
    event = state_store.write_bytes_atomically(dest, b"x")
    assert event.outcome == "failed"
    # The primitive never mkdirs a missing parent (owner decision O-4).
    assert not (tmp_path / "does-not-exist").exists()


def test_write_bytes_atomically_empty_name_never_raises():
    # Path(".").with_name(...) raises ValueError; the primitive must catch it and
    # return "failed" rather than break its NEVER-raises contract (reachable from
    # `--output .`). staging is None here, so no unlink is attempted.
    event = state_store.write_bytes_atomically(Path("."), b"x")
    assert event.outcome == "failed"
