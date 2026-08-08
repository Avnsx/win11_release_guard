from __future__ import annotations

import os
from pathlib import Path

# These absence assertions are the fixture's env-leak guard (§16.1 rule 5): the six vars are
# exactly the WIN11_RELEASE_GUARD_* names the package reads (config.py:24-26 plus the three new
# ones), and no test in the new suites may see any of them leak in from the host.
_SCRUBBED_VARS = (
    "WIN11_RELEASE_GUARD_STATE_DIR",
    "WIN11_RELEASE_GUARD_STATELESS",
    "WIN11_RELEASE_GUARD_CACHE_FILE",
    "WIN11_RELEASE_GUARD_POLICY_URL",
    "WIN11_RELEASE_GUARD_STRICT_PRODUCTION",
    "WIN11_RELEASE_GUARD_MAX_POLICY_BYTES",
)


def test_win11_release_guard_env_vars_are_scrubbed() -> None:
    for name in _SCRUBBED_VARS:
        assert name not in os.environ, f"{name} leaked into the test environment"


def test_temp_env_vars_redirect_to_one_session_dir() -> None:
    values = {os.environ.get(name) for name in ("TMPDIR", "TEMP", "TMP")}
    # All three point at the same directory.
    assert len(values) == 1
    target = values.pop()
    assert target is not None
    path = Path(target)
    assert path.is_dir()
    # Session-scoped redirect target is exactly <basetemp>/s (§16.1 rule 1).
    assert path.name == "s"


def test_localappdata_redirects_per_test(tmp_path: Path) -> None:
    localappdata = os.environ.get("LOCALAPPDATA")
    assert localappdata is not None
    path = Path(localappdata)
    assert path.is_dir()
    # Per-test, not session-scoped (§16.1 rule 3): it lives under this test's own tmp_path.
    assert path.name == "localappdata"
    assert path.parent == tmp_path
    # And it is NOT the session-scoped temp root the three TMP vars point at.
    assert Path(os.environ["TMP"]).name == "s"
