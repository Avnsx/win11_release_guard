"""Scope suite for ``state_store``: ``resolve_state_scope`` and its two host seams.

``_first_existing_dir`` (the only ``os.path.isdir`` site) and ``_host_uid`` (the only
``os.getuid`` site, ``None`` on Windows) are the sole host-interaction points reached
here, so the stateless short-circuit is assertable by observation: the seams are replaced
with append-to-a-list spies and the list must stay empty.

The R-2 key equality belongs at THIS layer: ``derive_state_name``'s component 5 hashes
``(trusted_public_key or "")``, so ``None`` and the bundled default derive different names
one level down; ``resolve_state_scope`` is where ``or DEFAULT_TRUSTED_POLICY_PUBLIC_KEY``
collapses them onto one path.
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
