"""Autouse isolation for the win11_release_guard test suite.

``_isolate_state`` is a *safety net*, not a full isolation mechanism (§16.1 rule 2):
``derive_state_name`` keys on the policy URL, user token and public key and deliberately
EXCLUDES the directory, and the redirect target below is one session-scoped directory, so
every test that uses the default layout reads and writes the SAME absolute path. Therefore:

    * Every state-touching test in the new suites passes ``state_dir=str(tmp_path)``
      (CLI: ``--state-dir <tmp_path>``) so its reads and writes are over a per-test directory
      and hold in any collection order.
    * No test hardcodes a derived filename; names come from ``describe_state(config)["entries"]``
      or from ``plan_state_scope`` with an injected ``env`` (§16.1 rule 5).
    * No uid seam is patched; cross-platform name reproducibility comes from the pure ``uid``
      parameter injected per call (§16.1 rule 4).
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_state(monkeypatch, tmp_path_factory, tmp_path):
    # getbasetemp() MUST run before the setenv loop: tempfile.gettempdir() memoises
    # into tempfile.tempdir for the process lifetime, so reversing these two makes
    # the redirect target depend on a value that does not exist yet.
    root = tmp_path_factory.getbasetemp() / "s"
    root.mkdir(exist_ok=True)
    for name in ("WIN11_RELEASE_GUARD_STATE_DIR", "WIN11_RELEASE_GUARD_STATELESS",
                 "WIN11_RELEASE_GUARD_CACHE_FILE", "WIN11_RELEASE_GUARD_POLICY_URL",
                 "WIN11_RELEASE_GUARD_STRICT_PRODUCTION",
                 "WIN11_RELEASE_GUARD_MAX_POLICY_BYTES"):
        monkeypatch.delenv(name, raising=False)
    for name in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.setenv(name, str(root))
    localappdata = tmp_path / "localappdata"      # PER TEST, not session-scoped
    localappdata.mkdir(exist_ok=True)
    monkeypatch.setenv("LOCALAPPDATA", str(localappdata))
