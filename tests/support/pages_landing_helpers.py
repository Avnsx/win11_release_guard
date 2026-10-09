"""Helpers shared by the test_pages_landing test modules."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from pathlib import Path
import win11_release_guard.policy_generator as policy_generator_module
from win11_release_guard.policy_generator import generate_policy, write_policy_outputs


FIXTURES = Path("tests/fixtures")


REMOVED_SCHEMA_PANEL_LABELS = (
    "API " + "and schema",
    "Policy " + "schema",
    "Reader " + "range",
)


FRESH_FIXTURE_RENDER_REFERENCE_UTC = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


FRESHNESS_SCRIPT_RE = re.compile(
    r'<script type="application/json" id="policy-freshness-data">(.*?)</script>',
    re.DOTALL,
)


SOURCE_DIAGNOSTIC_ID_RE = re.compile(
    r'data-diagnostic-id="'
    r"(wrg-source-diagnostic-v1:"
    r"(?:[0-9a-f]{16}|uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12};id=[1-9][0-9]*))"
    r'"'
)


def _render_landing(tmp_path: Path) -> str:
    policy = generate_policy(
        release_health_html=(FIXTURES / "windows11-release-health.html").read_text(encoding="utf-8"),
        servicing_toc_json=(FIXTURES / "windows11-servicing-toc.json").read_text(encoding="utf-8"),
        generated_at_utc="2026-05-31T14:11:50+00:00",
        signature_status="valid",
    )
    write_policy_outputs(
        policy,
        output_dir=tmp_path,
        write_index=True,
        generated_age_reference=FRESH_FIXTURE_RENDER_REFERENCE_UTC,
    )
    return (tmp_path / "index.html").read_text(encoding="utf-8")


def _freshness_data(index: str) -> dict:
    match = FRESHNESS_SCRIPT_RE.search(index)
    assert match is not None
    return json.loads(match.group(1))


def _assert_no_external_page_dependencies(index: str) -> None:
    lower = index.lower()
    assert "script src" not in lower
    assert 'rel="stylesheet"' not in lower
    assert "fonts.googleapis" not in lower
    assert "fonts.gstatic" not in lower
    assert "@import" not in lower
    assert "cdnjs" not in lower
    assert "cdn.jsdelivr" not in lower
    assert "unpkg.com" not in lower
    assert "esm.sh" not in lower
    assert "animations/auto" not in lower
    assert "auto-table-of-content" not in lower
    assert "auto-table" not in lower
    assert "npm" not in lower
    assert "fontawesome" not in lower
    assert "lucide" not in lower
    assert "github_token" not in lower
    assert "gh_token" not in lower
    assert "authorization:" not in lower
    assert "bearer " not in lower
    assert "credential" not in lower


def _assert_diag_count_tile(index: str, severity: str, count: int, label: str) -> None:
    assert (
        f'<button type="button" class="diag-tile {severity}" '
        f'data-diagnostic-filter="{severity}" data-diagnostic-severity="{severity}" '
        'aria-pressed="false" aria-controls="source-diagnostics-feed"'
        in index
    )
    assert (
        f'<strong>{count}</strong><span>{label}</span>'
        '<svg class="ui-icon diag-tile-icon"'
        in index
    )


def _diag_row_marker(severity: str) -> str:
    return f'<article class="diag-row {severity}" data-diagnostic-severity="{severity}" data-diagnostic-id="'


def _diagnostic_ids(index: str) -> list[str]:
    return SOURCE_DIAGNOSTIC_ID_RE.findall(index)


# ---------------------------------------------------------------------------
# Pages visual scale: the wiki/changelog theme must render at the dashboard's
# reading size at normal browser zoom (no zoom/transform/viewport hacks).
# ---------------------------------------------------------------------------

WIKI_VISUAL_SCALE = policy_generator_module._PAGES_WIKI_VISUAL_SCALE


WIKI_SCALE_DECLARATION = f"font-size: {WIKI_VISUAL_SCALE}"
