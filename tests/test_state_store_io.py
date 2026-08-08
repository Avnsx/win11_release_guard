"""I/O suite for ``state_store``: the atomic write primitive and its seams.

Every failure path is driven through the named ``_replace``/``_unlink`` seams so both
CI legs exercise the same code; nothing here depends on host-specific kernel behaviour.
"""

from __future__ import annotations

import hashlib
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


def test_write_state_container_oversize_record_is_skipped(tmp_path, monkeypatch):
    """The third arm of the container guard, which neither sibling above reaches.

    What ``MAX_STATE_FILE_BYTES`` bounds is the ENCODED record, so the body has to be
    incompressible or ``zlib`` would shrink it back under the cap and the branch would
    never be entered: a deterministic run of sha256 digests, no randomness, no sleep.
    """
    monkeypatch.setattr(state_store, "MAX_STATE_FILE_BYTES", 1024)
    body = b"".join(hashlib.sha256(n.to_bytes(4, "big")).digest() for n in range(64))
    assert len(state_store.encode_state(body, b"sig")) > 1024  # premise: the cap really bites
    scope = _container_scope(tmp_path / "rec.tmp")
    event = state_store.write_state(scope, body, b"sig")
    assert event.outcome == "skipped"
    assert event.path == str(scope.path)
    assert event.detail == "record too large"
    # Refused before the primitive ran, so there is no record and no staging orphan.
    assert not Path(scope.path).exists()
    assert not Path(scope.staging_path).exists()


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


def test_read_state_round_trip_usable(tmp_path):
    policy = b"policy-body-bytes"
    signature = b"sig-bytes"
    record = state_store.encode_state(policy, signature)
    dest = tmp_path / "rec.tmp"
    dest.write_bytes(record)
    read = state_store.read_state(_container_scope(dest))
    assert read.status == "usable"
    assert read.policy_bytes == policy
    assert read.signature_bytes == signature
    assert read.modified_epoch is not None


def test_read_state_non_container_layout_absent():
    scope = state_store.StateScope("none", None, None, None, "stateless")
    read = state_store.read_state(scope)
    assert read.status == "absent"
    assert read.policy_bytes is None


def test_read_state_legacy_pair_layout_is_absent_even_when_the_record_decodes(tmp_path):
    """The ``layout != "container"`` early return, pinned over a file that decodes
    perfectly, because only that return can turn a usable record into ``absent``.

    ``test_read_state_non_container_layout_absent`` above cannot carry this: its scope has
    ``path=None``, so with the early return gone ``os.open("None")`` merely raises
    ``FileNotFoundError`` and the very same ``absent`` comes back out of the error arm.
    """
    dest = tmp_path / "policy.json"
    dest.write_bytes(state_store.encode_state(b"policy-bytes", b"sig"))
    read = state_store.read_state(_legacy_pair_scope(dest))
    assert read.status == "absent"
    assert read.policy_bytes is None
    assert read.modified_epoch is None
    assert dest.exists()  # the legacy pair is read by cache.py, never by this function


def test_read_state_missing_file_absent(tmp_path):
    read = state_store.read_state(_container_scope(tmp_path / "nope.tmp"))
    assert read.status == "absent"


def test_read_state_foreign_on_magic_mismatch(tmp_path):
    dest = tmp_path / "rec.tmp"
    dest.write_bytes(b"NOTMAGIC" + b"whatever else")
    read = state_store.read_state(_container_scope(dest))
    assert read.status == "foreign"
    assert dest.exists()  # a foreign file is never removed by a read


def test_read_state_short_header_unusable(tmp_path):
    dest = tmp_path / "rec.tmp"
    dest.write_bytes(state_store.STATE_MAGIC + b"\x01\x00")  # 10 bytes < STATE_HEADER_LEN
    read = state_store.read_state(_container_scope(dest))
    assert read.status == "unusable"
    assert read.detail == "short header"


def test_read_state_digest_corrupted_unusable(tmp_path):
    record = bytearray(state_store.encode_state(b"policy-bytes", b"sig"))
    record[18] ^= 0xFF  # corrupt the stored body_digest field (offset 18..50)
    dest = tmp_path / "rec.tmp"
    dest.write_bytes(bytes(record))
    read = state_store.read_state(_container_scope(dest))
    assert read.status == "unusable"
    assert read.detail == "digest mismatch"


def test_read_state_oversize_non_magic_is_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr(state_store, "MAX_STATE_FILE_BYTES", 1024)
    dest = tmp_path / "rec.tmp"
    dest.write_bytes(b"X" * 2048)  # no magic, over the (patched) cap
    read = state_store.read_state(_container_scope(dest))
    assert read.status == "foreign"  # step 4 (magic) precedes step 5 (size cap)
    assert dest.exists()


def test_read_state_oversize_with_magic_unusable(tmp_path, monkeypatch):
    monkeypatch.setattr(state_store, "MAX_STATE_FILE_BYTES", 1024)
    dest = tmp_path / "rec.tmp"
    dest.write_bytes(state_store.STATE_MAGIC + b"X" * 2040)  # 2048 bytes, magic present
    read = state_store.read_state(_container_scope(dest))
    assert read.status == "unusable"
    assert read.detail == "file too large"
    assert dest.exists()  # a read never deletes


def test_read_state_short_read_absent(tmp_path, monkeypatch):
    record = state_store.encode_state(b"policy-body-bytes", b"sig-bytes")
    dest = tmp_path / "rec.tmp"
    dest.write_bytes(record)
    # Force the body loop to return fewer bytes than st_size; the direct 8-byte magic
    # read is unaffected, so this is a short read and not a magic mismatch.
    monkeypatch.setattr(state_store, "_read_all", lambda fd, size: b"")
    read = state_store.read_state(_container_scope(dest))
    assert read.status == "absent"
    assert read.detail == "short read"
    assert dest.exists()  # a short read must never delete a file that was not corrupt


def test_read_state_rejects_a_non_regular_file(tmp_path, monkeypatch):
    """Step 3 of the read path, pinned over a file that is otherwise a perfectly good
    record: only the mode check can report ``foreign`` here, and it must do so before the
    magic read, which is exactly what makes the record's own validity irrelevant.

    The mode verdict is injected rather than staged on disk because no non-regular file
    both CI legs can open read-only actually discriminates: reading ``/dev/null`` or
    ``NUL`` yields EOF, which the magic check reports as ``foreign`` all by itself, and
    Windows refuses to open a directory at all — which is why
    ``test_read_state_directory_at_path`` below has to accept two statuses.
    """
    dest = tmp_path / "rec.tmp"
    dest.write_bytes(state_store.encode_state(b"policy-bytes", b"sig"))

    class _NeverRegular:
        S_ISREG = staticmethod(lambda mode: False)

    monkeypatch.setattr(state_store, "stat", _NeverRegular)
    read = state_store.read_state(_container_scope(dest))
    assert read.status == "foreign"
    assert read.policy_bytes is None
    assert dest.exists()  # a non-regular path is refused, never removed, by a read


def test_read_state_directory_at_path(tmp_path):
    target = tmp_path / "rec.tmp"
    target.mkdir()
    read = state_store.read_state(_container_scope(target))
    # os.open on a directory raises PermissionError on Windows (-> "absent") and
    # succeeds on Linux, where fstat/S_ISREG rejects it (-> "foreign"). A single
    # value cannot hold on both CI legs (§16.3).
    assert read.status in {"foreign", "absent"}


def test_discard_state_removes_container(tmp_path):
    record = state_store.encode_state(b"policy-bytes", b"sig")
    dest = tmp_path / "rec.tmp"
    dest.write_bytes(record)
    event = state_store.discard_state(_container_scope(dest))
    assert event.action == "discard"
    assert event.outcome == "removed"
    assert event.path == str(dest)
    assert not dest.exists()


def test_discard_state_non_container_skipped():
    scope = state_store.StateScope("none", None, None, None, "stateless")
    event = state_store.discard_state(scope)
    assert event.outcome == "skipped"
    assert event.path is None


def test_discard_state_refuses_foreign(tmp_path):
    dest = tmp_path / "rec.tmp"
    dest.write_bytes(b"NOTMAGIC" + b"foreign content")
    event = state_store.discard_state(_container_scope(dest))
    assert event.outcome == "skipped"
    assert event.detail == "not our format"
    assert dest.exists()  # a file whose magic does not match is NEVER unlinked


def test_discard_state_absent_path(tmp_path):
    event = state_store.discard_state(_container_scope(tmp_path / "nope.tmp"))
    assert event.outcome == "absent"
    assert event.detail is None


def test_discard_state_unlink_failure_failed(tmp_path, monkeypatch):
    record = state_store.encode_state(b"policy-bytes", b"sig")
    dest = tmp_path / "rec.tmp"
    dest.write_bytes(record)

    def boom(path):
        raise OSError(13, "permission denied")

    monkeypatch.setattr(state_store, "_unlink", boom)
    event = state_store.discard_state(_container_scope(dest))
    assert event.outcome == "failed"
    # OSError(13, ...) is auto-mapped by Python to the PermissionError subclass, so
    # _reason's f"{type(exc).__name__}: {exc}" names that concrete type. The subclass
    # is still caught by `except (OSError, ValueError)`, which is what "failed" proves.
    assert "PermissionError" in event.detail
    assert dest.exists()  # the unlink failed, so the file survives


def test_discard_state_docstring_carries_deletion_sentence():
    doc = state_store.discard_state.__doc__
    assert (
        "The tool unlinks a record only at a path it derived itself, only after it has "
        "opened that file and confirmed its first eight bytes equal STATE_MAGIC, and only "
        "because the file did not yield a signature-verified policy."
    ) in " ".join(doc.split())
    assert 'A role == "staging" path is unlinked with no magic check' in " ".join(doc.split())
