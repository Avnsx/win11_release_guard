"""Every date on the dashboard reads like "Friday, 9 October 2026, 15:52:04 CEST"; explicit UTC stays UTC."""

from __future__ import annotations

import html
import re

from tests.support.remote_policy_helpers import _pending_26h2_html
from win11_release_guard.policy_generator import render_policy_index
from win11_release_guard.policy_generator.pages.diagnostic_rows import _source_diagnostic_display_text
from win11_release_guard.policy_generator.time_format import (
    _dual_zone_time_human,
    _generated_at_human,
    _generated_at_local_date,
    _utc_time_human,
)
from win11_release_guard.remote_policy import parse_windows11_release_health_html

MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"


def test_berlin_times_use_the_long_weekday_first_format():
    assert _generated_at_human("2026-10-09T13:52:04Z") == "Friday, 9 October 2026, 15:52:04 CEST"
    assert _generated_at_human("2026-12-01T10:00:00Z") == "Tuesday, 1 December 2026, 11:00:00 CET"
    assert _generated_at_local_date("2026-10-09T13:52:04Z") == "Friday, 9 October 2026"


def test_timestamps_keep_their_explicit_utc_time():
    assert _dual_zone_time_human("2026-10-09T13:52:04Z") == "Friday, 9 October 2026, 15:52:04 CEST / 13:52:04 UTC"
    assert _utc_time_human("2026-10-09T13:52:04Z") == "Friday, 9 October 2026, 13:52:04 UTC"


def test_date_only_values_never_get_an_invented_time():
    assert _dual_zone_time_human("2026-09-08") == "Tuesday, 8 September 2026"


def test_iso_dates_inside_diagnostic_messages_are_shown_in_the_long_format():
    text = _source_diagnostic_display_text("26H2 has no B release yet (available since 2026-09-29), so 25H2 stays.")

    assert text == "26H2 has no B release yet (available since Tuesday, 29 September 2026), so 25H2 stays."
    assert _source_diagnostic_display_text("Update 2026-09 D for build 26300.9550") == (
        "Update 2026-09 D for build 26300.9550"
    )


def test_rendered_dashboard_text_has_no_iso_or_us_style_dates():
    index = render_policy_index(
        parse_windows11_release_health_html(_pending_26h2_html()), policy_bytes=None, signature=None
    )
    body = re.sub(r"<(script|style)\b.*?</\1>", " ", index.split("<body", 1)[1], flags=re.S)
    text = html.unescape(re.sub(r"<[^>]+>", "\n", body))

    assert re.findall(r"\b\d{4}-\d{2}-\d{2}\b", text) == []
    assert re.findall(rf"\b(?:{MONTHS}) \d{{1,2}}, \d{{4}}\b", text) == []
    assert "Tuesday, 29 September 2026" in text


def test_date_rewrite_leaves_urls_ids_files_and_ranges_alone():
    for text in (
        "https://x/a?2026-09-29",
        "see a#2026-09-29",
        "id:2026-09-29",
        "file 2026-09-29.json",
        "range 2026-09-29/2026-10-01",
    ):
        assert _source_diagnostic_display_text(text) == text
