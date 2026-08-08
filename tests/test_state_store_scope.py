"""Scope suite for ``state_store``: ``resolve_state_scope`` and its two host seams.

``_first_existing_dir`` (the only ``os.path.isdir`` site) and ``_host_uid`` (the only
``os.getuid`` site, ``None`` on Windows) are the sole host-interaction points reached
here, so the stateless short-circuit is assertable by observation: the seams are replaced
with append-to-a-list spies and the list must stay empty.

The R-2 key equality belongs at THIS layer: ``derive_state_name``'s component 5 hashes
``(trusted_public_key or "")``, so ``None`` and the bundled default derive different names
one level down; ``resolve_state_scope`` is where ``or DEFAULT_TRUSTED_POLICY_PUBLIC_KEY``
collapses them onto one path.

The default-temp join is pinned here too. ``state_dir=`` and ``cache_file=`` both outrank
``temp_dir`` inside ``plan_state_scope``, so a suite that only ever passes those two never
exercises ``_first_existing_dir(temp_dir_candidates(os.name, os.environ))`` — the one wiring
that puts an ordinary deployment's record in the temp directory rather than nowhere.

Legacy retirement lives here as well. ``legacy_state_paths`` and ``_legacy_dir_is_retirable``
are pure and build on ``PureWindowsPath`` unconditionally, so the Windows layout and the
path-equality (never string-equality) parent check are assertable from either CI leg; only
the two ``retire_legacy_state`` tests that actually unlink files and remove the directory —
the design's single ``os.rmdir`` (R-1) — are ``skipif(os.name != "nt")``.
"""

from __future__ import annotations

import os

import pytest

from win11_release_guard import state_store
from win11_release_guard.config import DEFAULT_TRUSTED_POLICY_PUBLIC_KEY, ReleaseCheckerConfig


def test_first_existing_dir_returns_first_isdir(tmp_path):
    missing = str(tmp_path / "nope")
    present = str(tmp_path)
    assert state_store._first_existing_dir((missing, present)) == present
    assert state_store._first_existing_dir((missing,)) is None
    assert state_store._first_existing_dir(()) is None


def test_host_uid_matches_platform():
    result = state_store._host_uid()
    if hasattr(os, "getuid"):
        assert result == os.getuid()
    else:
        assert result is None


def test_resolve_state_scope_stateless_short_circuits_before_seams(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(state_store, "_first_existing_dir", lambda candidates: calls.append("dir"))
    monkeypatch.setattr(state_store, "_host_uid", lambda: calls.append("uid"))
    config = ReleaseCheckerConfig(stateless=True, state_dir=str(tmp_path))
    scope = state_store.resolve_state_scope(config)
    assert scope == state_store.StateScope("none", None, None, None, "stateless")
    assert calls == []


def test_resolve_state_scope_state_dir_yields_container(tmp_path):
    config = ReleaseCheckerConfig(state_dir=str(tmp_path))
    scope = state_store.resolve_state_scope(config)
    assert scope.layout == "container"
    assert scope.source == "state_dir"
    assert scope.path is not None
    assert scope.staging_path == scope.path.with_name(state_store.staging_name(scope.path.name))
    assert scope.signature_path is None


def test_resolve_state_scope_cache_file_yields_legacy_pair(tmp_path):
    config = ReleaseCheckerConfig(cache_file=str(tmp_path / "policy.json"))
    scope = state_store.resolve_state_scope(config)
    assert scope.layout == "legacy_pair"
    assert scope.source == "cache_file"
    assert scope.path is not None
    assert scope.signature_path == scope.path.with_name(scope.path.name + ".sig")


def test_resolve_state_scope_r2_default_key_equals_none(tmp_path):
    none_scope = state_store.resolve_state_scope(
        ReleaseCheckerConfig(state_dir=str(tmp_path), trusted_policy_public_key=None)
    )
    default_scope = state_store.resolve_state_scope(
        ReleaseCheckerConfig(
            state_dir=str(tmp_path),
            trusted_policy_public_key=DEFAULT_TRUSTED_POLICY_PUBLIC_KEY,
        )
    )
    other_scope = state_store.resolve_state_scope(
        ReleaseCheckerConfig(
            state_dir=str(tmp_path),
            trusted_policy_public_key="45dOpVuYqoPkldNrzORHM5ZZUxs6ILVcvpKxRFxsu3s=",
        )
    )
    assert none_scope.path == default_scope.path
    assert other_scope.path != none_scope.path


def test_resolve_state_scope_refuses_non_absolute_state_dir():
    config = ReleaseCheckerConfig(state_dir="relative-dir")
    scope = state_store.resolve_state_scope(config)
    assert scope.layout == "none"
    assert scope.source == "state_dir_not_absolute"
    assert scope.path is None
    assert scope.staging_path is None


def test_resolve_state_scope_default_config_lands_in_the_temp_container():
    """A default deployment — no cache_file, no state_dir, not stateless — must resolve to a
    container inside the directory the real seam finds. Without this the whole feature can be
    unwired (temp_dir never reaching plan_state_scope) and every default run degrades to
    StateScope("none", ..., "no_temp_dir"), i.e. no cache at all."""
    expected_dir = state_store._first_existing_dir(
        state_store.temp_dir_candidates(os.name, os.environ)
    )
    assert expected_dir is not None  # tests/conftest.py redirects TMPDIR/TEMP/TMP to a real dir
    scope = state_store.resolve_state_scope(ReleaseCheckerConfig())
    assert scope.layout == "container"
    assert scope.source == "default_temp"
    assert scope.path is not None
    assert str(scope.path.parent) == expected_dir
    assert scope.staging_path == scope.path.with_name(state_store.staging_name(scope.path.name))
    assert scope.signature_path is None


def test_resolve_state_scope_default_temp_comes_from_the_seam(monkeypatch, tmp_path):
    """The seam is asked for the full candidate list and ITS answer becomes the container's
    directory — the default temp dir is not re-read behind the seam's back."""
    chosen = tmp_path / "chosen-temp"
    chosen.mkdir()
    seen = []

    def _seam(candidates):
        seen.append(candidates)
        return str(chosen)

    monkeypatch.setattr(state_store, "_first_existing_dir", _seam)
    scope = state_store.resolve_state_scope(ReleaseCheckerConfig())
    assert seen == [state_store.temp_dir_candidates(os.name, os.environ)]
    assert scope.layout == "container"
    assert scope.source == "default_temp"
    assert scope.path is not None
    assert str(scope.path.parent) == str(chosen)


def test_legacy_state_paths_windows():
    env = {"LOCALAPPDATA": r"C:\Users\admin\AppData\Local"}
    paths = state_store.legacy_state_paths("nt", env)
    assert len(paths) == 2
    assert paths[0].name == "windows-release-policy.json"
    assert paths[1].name == "windows-release-policy.json.sig"
    assert paths[0].parent.name == "win11_release_guard"
    assert paths[1].parent.name == "win11_release_guard"


def test_legacy_state_paths_empty_off_windows_or_no_localappdata():
    assert state_store.legacy_state_paths("posix", {"LOCALAPPDATA": r"C:\x"}) == ()
    assert state_store.legacy_state_paths("nt", {}) == ()
    assert state_store.legacy_state_paths("nt", {"LOCALAPPDATA": ""}) == ()


def test_legacy_dir_is_retirable_path_equality_not_string():
    base = r"C:\Users\x\AppData\Local"
    directory = base + r"\win11_release_guard"
    assert state_store._legacy_dir_is_retirable(directory, {"LOCALAPPDATA": base}) is True
    assert state_store._legacy_dir_is_retirable(directory, {"LOCALAPPDATA": base + "\\"}) is True
    assert state_store._legacy_dir_is_retirable(
        directory, {"LOCALAPPDATA": "C:/Users/x/AppData/Local"}
    ) is True
    assert state_store._legacy_dir_is_retirable(base + r"\other", {"LOCALAPPDATA": base}) is False
    assert state_store._legacy_dir_is_retirable(
        r"C:\Temp\win11_release_guard", {"LOCALAPPDATA": base}
    ) is False


def test_retire_legacy_state_noop_under_explicit_location():
    assert state_store.retire_legacy_state("C:/x/policy.json", None) == ()
    assert state_store.retire_legacy_state(None, "C:/statedir") == ()
    assert state_store.retire_legacy_state("C:/x/policy.json", "C:/statedir") == ()


def test_retire_legacy_state_noop_off_windows(monkeypatch):
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\x\AppData\Local")
    assert state_store.retire_legacy_state(None, None) == ()


@pytest.mark.skipif(os.name != "nt", reason="legacy retirement touches %LOCALAPPDATA% on Windows")
def test_retire_legacy_state_removes_files_and_empty_dir(tmp_path, monkeypatch):
    localappdata = tmp_path / "localappdata"
    legacy_dir = localappdata / "win11_release_guard"
    legacy_dir.mkdir(parents=True)
    policy = legacy_dir / "windows-release-policy.json"
    signature = legacy_dir / "windows-release-policy.json.sig"
    policy.write_bytes(b"{}")
    signature.write_bytes(b"sig")
    monkeypatch.setenv("LOCALAPPDATA", str(localappdata))
    events = state_store.retire_legacy_state(None, None)
    assert {event.action for event in events} == {"retire"}
    assert "removed" in {event.outcome for event in events}
    assert not policy.exists()
    assert not signature.exists()
    assert not legacy_dir.exists()


@pytest.mark.skipif(os.name != "nt", reason="legacy retirement touches %LOCALAPPDATA% on Windows")
def test_retire_legacy_state_keeps_dir_with_sibling(tmp_path, monkeypatch):
    localappdata = tmp_path / "localappdata"
    legacy_dir = localappdata / "win11_release_guard"
    legacy_dir.mkdir(parents=True)
    policy = legacy_dir / "windows-release-policy.json"
    signature = legacy_dir / "windows-release-policy.json.sig"
    policy.write_bytes(b"{}")
    signature.write_bytes(b"sig")
    (legacy_dir / "tmpdeadbeef00000000.tmp").write_bytes(b"sibling container")
    monkeypatch.setenv("LOCALAPPDATA", str(localappdata))
    state_store.retire_legacy_state(None, None)
    assert not policy.exists()
    assert not signature.exists()
    assert legacy_dir.exists()
