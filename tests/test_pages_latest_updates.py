"""Dashboard notices that show when each Windows 11 version last received an update."""

from __future__ import annotations

from tests.support.remote_policy_helpers import _pending_26h2_html
from win11_release_guard.model_types import ServicingChannel
from win11_release_guard.models import ReleaseHistoryEntry, ReleasePolicy, ReleasePolicyEntry
from win11_release_guard.policy_generator import render_policy_index
from win11_release_guard.policy_generator.pages.diagnostic_rows import _latest_update_diagnostic_rows
from win11_release_guard.policy_generator.support_articles import _safe_support_article_url
from win11_release_guard.remote_policy import parse_windows11_release_health_html


def _fixture_policy() -> ReleasePolicy:
    return parse_windows11_release_health_html(_pending_26h2_html())


def test_each_release_health_version_gets_a_latest_update_notice_in_table_order():
    rows = _latest_update_diagnostic_rows(_fixture_policy())

    assert [row["title"] for row in rows] == [
        "Windows 11 26H2 latest update",
        "Windows 11 26H1 latest update",
        "Windows 11 25H2 latest update",
        "Windows 11 24H2 latest update",
        "Windows 11 23H2 latest update",
    ]
    assert {row["severity"] for row in rows} == {"notice"}
    assert rows[0]["message"] == (
        "Windows 11 26H2 received its latest update on 2026-09-29: build 26300.9550 (2026-09 D, optional preview)."
    )
    assert rows[-1]["message"] == (
        "Windows 11 23H2 received its latest update on 2026-09-14: build 22631.7584 (2026-09 OOB, out-of-band update)."
    )
    assert rows[0]["tags"] == ("Release 26H2", "Build 26300.9550", "2026-09 D", "KB5124010")
    assert len({row["id"] for row in rows}) == len(rows)


def test_ltsc_rows_are_labelled_and_versions_without_a_date_are_skipped():
    policy = ReleasePolicy(
        current_versions=(
            ReleasePolicyEntry(
                version="24H2",
                build_family=26100,
                latest_build="26100.9445",
                servicing_channel=ServicingChannel.LTSC,
                metadata={"latest_revision_date": "2026-09-08", "raw": {"Latest update": "2026-09 B"}},
            ),
            ReleasePolicyEntry(version="25H2", build_family=26200, latest_build="26200.9550"),
        )
    )

    rows = _latest_update_diagnostic_rows(policy)

    assert [row["title"] for row in rows] == ["Windows 11 24H2 LTSC latest update"]
    assert rows[0]["message"] == (
        "Windows 11 24H2 LTSC received its latest update on 2026-09-08: "
        "build 26100.9445 (2026-09 B, monthly security update)."
    )


def test_dashboard_lists_latest_updates_in_the_expanded_notices():
    index = render_policy_index(_fixture_policy(), policy_bytes=None, signature=None)
    expanded = index.split('<details class="diag-more">', 1)[1].split("</details>", 1)[0]

    assert "Windows 11 26H2 received its latest update on Tuesday, 29 September 2026: build 26300.9550" in expanded
    assert "Windows 11 23H2 received its latest update on Monday, 14 September 2026: build 22631.7584" in expanded


def test_latest_update_rows_link_the_microsoft_article_for_that_build():
    rows = _latest_update_diagnostic_rows(_fixture_policy())
    row = rows[0]

    assert row["tags"] == ("Release 26H2", "Build 26300.9550", "2026-09 D", "KB5124010")
    assert row["update_details_url"] == _safe_support_article_url("https://support.microsoft.com/help/5124010")
    assert row["update_details_url"]


def test_latest_update_rows_without_a_safe_article_url_get_no_link():
    policy = ReleasePolicy(
        current_versions=(
            ReleasePolicyEntry(
                version="25H2",
                build_family=26200,
                latest_build="26200.9550",
                metadata={"latest_revision_date": "2026-09-22", "raw": {"Latest update": "2026-09 D"}},
            ),
        ),
        release_history=(
            ReleaseHistoryEntry(
                release="25H2", build_family=26200, build="26200.9550", kb_article="KB5124010",
                kb_url="https://example.com/kb5124010",
            ),
        ),
    )

    (row,) = _latest_update_diagnostic_rows(policy)

    assert "update_details_url" not in row
    assert row["tags"][-1] == "KB5124010"


def test_dashboard_renders_a_read_more_link_on_latest_update_rows():
    index = render_policy_index(_fixture_policy(), policy_bytes=None, signature=None)
    expanded = index.split('<details class="diag-more">', 1)[1].split("</details>", 1)[0]
    row = expanded.split("Windows 11 26H2 received its latest update", 1)[1].split("</article>", 1)[0]
    url = _safe_support_article_url("https://support.microsoft.com/help/5124010")

    assert f'<a class="diag-read-more-inline" href="{url}" rel="noopener noreferrer">Read more</a>' in row
