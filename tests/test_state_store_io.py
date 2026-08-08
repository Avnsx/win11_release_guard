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


def _container_scope(path):
    return state_store.StateScope(
        layout="container",
        path=path,
        signature_path=None,
        staging_path=path.with_name(state_store.staging_name(path.name)),
        source="state_dir",
    )


def test_write_state_container_round_trips(tmp_path):
    # The record lives in its own subdirectory because the autouse _isolate_state
    # fixture puts a `localappdata` directory in every tmp_path, which would make an
    # exact iterdir() assertion over tmp_path itself unusable.
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    scope = _container_scope(state_dir / "rec.tmp")
    event = state_store.write_state(scope, b"policy-body-bytes", b"sig-bytes")
    assert event.action == "write"
    assert event.outcome == "written"
    assert event.path == str(scope.path)
    # The record decodes back to the exact bytes (container branch went through encode_state).
    read = state_store.decode_state(Path(scope.path).read_bytes())
    assert read.status == "usable"
    assert read.policy_bytes == b"policy-body-bytes"
    assert read.signature_bytes == b"sig-bytes"
    # Nothing left beside the record: no directory, no staging orphan (§16.3).
    assert sorted(p.name for p in state_dir.iterdir()) == ["rec.tmp"]


def test_write_state_container_without_signature(tmp_path):
    scope = _container_scope(tmp_path / "rec.tmp")
    event = state_store.write_state(scope, b"policy-only", None)
    assert event.outcome == "written"
    read = state_store.decode_state(Path(scope.path).read_bytes())
    assert read.status == "usable"
    assert read.policy_bytes == b"policy-only"
    assert read.signature_bytes is None


def test_write_state_container_empty_policy_is_skipped(tmp_path):
    scope = _container_scope(tmp_path / "rec.tmp")
    event = state_store.write_state(scope, b"", b"sig")
    assert event.outcome == "skipped"
    assert event.path == str(scope.path)
    assert event.detail == "record too large"
    assert not Path(scope.path).exists()  # nothing written, nothing to be deleted on the next read


def test_write_state_container_oversize_signature_is_skipped(tmp_path):
    from win11_release_guard.json_utils import DEFAULT_MAX_SIGNATURE_BYTES

    scope = _container_scope(tmp_path / "rec.tmp")
    event = state_store.write_state(scope, b"policy", b"x" * (DEFAULT_MAX_SIGNATURE_BYTES + 1))
    assert event.outcome == "skipped"
    assert event.detail == "record too large"
    assert not Path(scope.path).exists()


def test_write_state_none_layout_skips_with_source_detail():
    for source in ("no_temp_dir", "state_dir_not_absolute", "path_not_nameable"):
        scope = state_store.StateScope("none", None, None, None, source)
        event = state_store.write_state(scope, b"policy", b"sig")
        assert event.action == "write"
        assert event.outcome == "skipped"
        assert event.path is None
        assert event.detail == source  # _persist_policy maps each to one cache_write_failed (§6.4)


def test_write_state_stateless_skips_with_stateless_detail():
    scope = state_store.StateScope("none", None, None, None, "stateless")
    event = state_store.write_state(scope, b"policy", b"sig")
    assert event.outcome == "skipped"
    assert event.detail == "stateless"  # _persist_policy emits NOTHING for this one (§6.4)


def _legacy_pair_scope(policy_path):
    return state_store.StateScope(
        layout="legacy_pair",
        path=policy_path,
        signature_path=policy_path.with_name(policy_path.name + ".sig"),
        staging_path=policy_path.with_name(state_store.staging_name(policy_path.name)),
        source="cache_file",
    )


def test_write_state_legacy_pair_writes_both_files_raw(tmp_path):
    cache_dir = tmp_path / "cache"          # own subdirectory, see the note above
    cache_dir.mkdir()
    scope = _legacy_pair_scope(cache_dir / "policy.json")
    event = state_store.write_state(scope, b'{"policy": true}', b'{"sig": true}')
    assert event.outcome == "written"
    assert event.path == str(scope.path)
    # Raw and byte-identical: NOT routed through the container codec.
    assert Path(scope.path).read_bytes() == b'{"policy": true}'
    assert Path(scope.signature_path).read_bytes() == b'{"sig": true}'
    assert sorted(p.name for p in cache_dir.iterdir()) == ["policy.json", "policy.json.sig"]


def test_write_state_legacy_pair_without_signature_writes_only_policy(tmp_path):
    scope = _legacy_pair_scope(tmp_path / "policy.json")
    event = state_store.write_state(scope, b'{"policy": true}', None)
    assert event.outcome == "written"
    assert Path(scope.path).read_bytes() == b'{"policy": true}'
    assert not Path(scope.signature_path).exists()  # .sig only when signature_bytes is not None


def test_write_state_legacy_pair_missing_parent_returns_failed(tmp_path):
    scope = _legacy_pair_scope(tmp_path / "no-such-dir" / "policy.json")
    event = state_store.write_state(scope, b"{}", b"sig")
    assert event.outcome == "failed"       # missing parent, primitive never mkdirs (O-4)
    assert not (tmp_path / "no-such-dir").exists()
