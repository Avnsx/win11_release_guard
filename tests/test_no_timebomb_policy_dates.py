"""Guard against time-bomb policy fixtures.

A "time-bomb" test pins a cached/evaluated policy to an *absolute*
``generated_at_utc`` timestamp and then drives it through the real wall-clock
freshness path (``win11_release_guard.api.check_current_system`` ->
``_policy_is_fresh`` -> ``_policy_age_hours``, which reads ``datetime.now``).
Such a literal silently expires as real time advances: it was the root cause of
``test_missing_internet_uses_stale_cache_with_warning`` flipping COMPLIANT ->
CHECK_INCOMPLETE once the cached date aged past the 720h stale window.

This guard fails if any test module that exercises that real-clock path binds an
absolute ISO-8601 date to ``generated_at_utc=``. Use a *relative* helper instead
(e.g. ``_stale_but_usable_generated_at`` / ``_generated_at(hours_ago=...)``).
When an absolute date is genuinely safe because the clock is frozen, annotate the
line with a ``# time-frozen: <reason>`` marker to opt out deliberately.

The match is intentionally narrow: it targets the ``generated_at_utc=`` keyword
argument / assignment form that actually flows into the freshness gate, and does
NOT match dict-JSON ``"generated_at_utc": "..."`` fixtures or ``==`` equality
assertions, which live on a different, clock-safe surface.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = REPO_ROOT / "tests"

# Test modules that drive the un-injectable real wall-clock freshness path.
REAL_CLOCK_ENTRYPOINT = "check_current_system"

# An absolute ISO-8601 date/time literal bound to ``generated_at_utc=`` (keyword
# argument or assignment to a string literal).
ABSOLUTE_POLICY_DATE = re.compile(r"""generated_at_utc\s*=\s*["'][^"']*\d{4}-\d{2}-\d{2}T""")

# Escape hatch for a deliberate absolute date whose clock is provably frozen.
TIME_FROZEN_MARKER = "time-frozen"


def _real_clock_test_files() -> list[Path]:
    """Every ``tests/**/test_*.py`` that reaches the real-clock freshness path."""
    here = Path(__file__).resolve()
    files: list[Path] = []
    for path in sorted(TESTS_DIR.rglob("test_*.py")):
        if path.resolve() == here:
            continue  # this guard mentions the entrypoint in prose; never scan itself
        if REAL_CLOCK_ENTRYPOINT in path.read_text(encoding="utf-8", errors="replace"):
            files.append(path)
    return files


def test_no_absolute_policy_dates_on_real_clock_path() -> None:
    findings: list[str] = []
    for path in _real_clock_test_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            if TIME_FROZEN_MARKER in line:
                continue
            if ABSOLUTE_POLICY_DATE.search(line):
                findings.append(f"{path.relative_to(REPO_ROOT).as_posix()}:{lineno}: {line.strip()}")

    assert not findings, (
        "Absolute generated_at_utc date(s) on the real wall-clock freshness path will "
        "expire as time advances (time-bomb). Use a relative helper such as "
        "_stale_but_usable_generated_at() / _generated_at(hours_ago=...), or annotate a "
        "provably clock-frozen line with '# time-frozen: <reason>':\n  " + "\n  ".join(findings)
    )
