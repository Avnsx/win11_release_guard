from __future__ import annotations

import pytest
from win11_release_guard.exceptions import PolicyParseError
from win11_release_guard.models import EditionScope, ReleasePolicy, ReleasePolicyEntry, ServicingChannel
from win11_release_guard.remote_policy import parse_windows11_release_health_html
from tests.support.remote_policy_helpers import _fixture_html, _fixture_html_file, _pending_26h2_html


def _fixture_html_with_ltsc_table() -> str:
    ltsc_table = """
  <h2>Windows 11 Enterprise LTSC current versions</h2>
  <table>
    <thead>
      <tr>
        <th>Version</th>
        <th>Servicing option</th>
        <th>Availability date</th>
        <th>End of servicing: Enterprise LTSC and IoT Enterprise LTSC</th>
        <th>Latest revision date</th>
        <th>Latest build</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>24H2</td>
        <td>Long-Term Servicing Channel</td>
        <td>2024-10-01</td>
        <td>2034-10-10</td>
        <td>2026-05-12</td>
        <td>26100.8457</td>
      </tr>
    </tbody>
  </table>
"""
    return _fixture_html().replace("  <h2>Windows 11 release history</h2>", ltsc_table + "\n  <h2>Windows 11 release history</h2>", 1)


def _fixture_html_with_25h2_current_latest_build(build: str) -> str:
    return _fixture_html().replace("        <td>26200.8457</td>\n      </tr>", f"        <td>{build}</td>\n      </tr>", 1)


def _fixture_html_without_26h1_note() -> str:
    html = _fixture_html()
    start = html.index("  <p>\n    Windows 11, version 26H1")
    end = html.index("  </p>", start) + len("  </p>\n")
    return html[:start] + html[end:]


def _fixture_html_with_poison_current_table() -> str:
    poison = """
  <h2>Random dashboard</h2>
  <table>
    <thead>
      <tr>
        <th>Release</th>
        <th>Service option</th>
        <th>Latest OS build</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>25H2</td>
        <td>General Availability Channel</td>
        <td>26200.9999</td>
      </tr>
    </tbody>
  </table>
"""
    return _fixture_html().replace("  <h2>Windows 11 current versions by servicing option</h2>", poison + "\n  <h2>Windows 11 current versions by servicing option</h2>", 1)


def _fixture_html_with_minimal_current_versions() -> str:
    minimal = """
  <h2>Windows 11 current versions by servicing option</h2>
  <table>
    <thead>
      <tr>
        <th>Version</th>
        <th>Servicing option</th>
        <th>Latest build</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>26H1</td>
        <td>General Availability Channel</td>
        <td>28000.2113</td>
      </tr>
      <tr>
        <td>25H2</td>
        <td>General Availability Channel</td>
        <td>26200.8457</td>
      </tr>
      <tr>
        <td>24H2</td>
        <td>General Availability Channel</td>
        <td>26100.8457</td>
      </tr>
    </tbody>
  </table>
"""
    html = _fixture_html()
    start = html.index("  <h2>Windows 11 current versions by servicing option</h2>")
    end = html.index("  <h2>Windows 11 release history</h2>", start)
    return html[:start] + minimal + "\n" + html[end:]


def _fixture_html_without_release_history_kb_column() -> str:
    html = _fixture_html().replace("        <th>KB article</th>\n", "")
    for kb in ("KB5089549", "KB5083631", "KB5089548"):
        html = html.replace(f"        <td>{kb}</td>\n", "")
    return html


def _fixture_html_without_b_baseline_for_25h2() -> str:
    row_start = _fixture_html().index("      <tr>\n        <td>General Availability Channel</td>\n        <td>2026-05 B</td>")
    row_end = _fixture_html().index("      </tr>", row_start) + len("      </tr>\n")
    html = _fixture_html()
    return html[:row_start] + html[row_end:]


def test_parse_release_health_builds_current_versions_and_history():
    policy = parse_windows11_release_health_html(_fixture_html())

    assert {entry.version for entry in policy.current_versions} == {
        "23H2",
        "24H2",
        "25H2",
        "26H1",
    }
    assert policy.release_for_build_family(26200) == "25H2"
    assert any(row.release == "25H2" and row.build == "26200.8457" for row in policy.release_history)


def test_parse_release_health_current_d_preview_fixture_keeps_latest_and_baseline_distinct():
    policy = parse_windows11_release_health_html(
        _fixture_html_file("windows11-release-health-current-d-26h1.html")
    )

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert policy.broad_target_existing_devices.latest_build == "26200.8524"
    assert policy.broad_target_existing_devices.latest_observed_build == "26200.8524"
    assert policy.broad_target_existing_devices.baseline_build == "26200.8457"
    assert policy.broad_target_existing_devices.required_baseline_build == "26200.8457"
    current_25h2 = next(entry for entry in policy.current_versions if entry.version == "25H2")
    assert current_25h2.latest_build == "26200.8524"
    assert current_25h2.latest_observed_build == "26200.8524"
    assert current_25h2.baseline_build == "26200.8457"
    assert current_25h2.required_baseline_build == "26200.8457"
    preview = next(row for row in policy.release_history if row.build == "26200.8524")
    assert preview.preview is True
    assert preview.update_type_letter == "D"
    assert preview.kb_article == "KB5089573"
    assert {entry.version for entry in policy.special_releases} == {"26H1"}


def test_parse_release_health_header_variants_accept_german_latest_and_update_type_headers():
    policy = parse_windows11_release_health_html(
        _fixture_html_file("windows11-release-health-header-variants.html")
    )

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert policy.broad_target_existing_devices.latest_build == "26200.8457"
    assert any(row.release == "25H2" and row.build == "26200.8524" and row.preview for row in policy.release_history)
    current_25h2 = next(entry for entry in policy.current_versions if entry.version == "25H2")
    assert current_25h2.servicing_option == "Allgemeiner Verfügbarkeitskanal"
    assert current_25h2.metadata["latest_revision_date"] == "2026-05-12"
    assert {entry.version for entry in policy.special_releases} == {"26H1"}


def test_parse_release_health_ignores_poison_current_versions_table_before_real_table():
    policy = parse_windows11_release_health_html(_fixture_html_with_poison_current_table())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert policy.broad_target_existing_devices.latest_build == "26200.8457"
    assert all(entry.latest_build != "26200.9999" for entry in policy.current_versions)
    events = policy.source_diagnostics["parser"]["events"]
    assert any(event["kind"] == "ignored_current_versions_subset_table" for event in events)


def test_parse_release_health_current_versions_missing_optional_lifecycle_revision_fields_still_loads():
    policy = parse_windows11_release_health_html(_fixture_html_with_minimal_current_versions())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert policy.broad_target_existing_devices.latest_build == "26200.8457"
    assert policy.broad_target_existing_devices.required_baseline_build == "26200.8457"


def test_parse_release_history_missing_kb_article_column_still_loads():
    policy = parse_windows11_release_health_html(_fixture_html_without_release_history_kb_column())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.required_baseline_build == "26200.8457"
    row = next(row for row in policy.release_history if row.release == "25H2" and row.build == "26200.8457")
    assert row.kb_article is None
    assert row.kb_url is None


def test_parse_release_health_selects_h2_ga_broad_target_not_26h1():
    policy = parse_windows11_release_health_html(_fixture_html())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert policy.broad_target_existing_devices.build_family == 26200
    assert policy.broad_target_existing_devices.latest_build == "26200.8457"
    assert policy.broad_target_existing_devices.baseline_build == "26200.8457"


def test_parse_release_health_keeps_latest_observed_preview_distinct_from_baseline():
    policy = parse_windows11_release_health_html(_fixture_html_with_25h2_current_latest_build("26200.8524"))

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.latest_build == "26200.8524"
    assert policy.broad_target_existing_devices.latest_observed_build == "26200.8524"
    assert policy.broad_target_existing_devices.baseline_build == "26200.8457"
    assert policy.broad_target_existing_devices.required_baseline_build == "26200.8457"
    current_25h2 = next(entry for entry in policy.current_versions if entry.version == "25H2")
    assert current_25h2.latest_build == "26200.8524"
    assert current_25h2.latest_observed_build == "26200.8524"
    assert current_25h2.baseline_build == "26200.8457"
    assert current_25h2.required_baseline_build == "26200.8457"


def test_parse_release_health_marks_26h1_special_new_devices_only():
    policy = parse_windows11_release_health_html(_fixture_html())

    special = {entry.version: entry for entry in policy.special_releases}

    assert "26H1" in special
    assert special["26H1"].metadata["special_release"] is True
    assert special["26H1"].metadata["new_devices_only"] is True
    assert special["26H1"].metadata["not_broad_target"] is True
    assert policy.excluded_for_existing_devices[0].version == "26H1"


def test_parse_release_health_keeps_ltsc_current_versions_separate_from_ga():
    policy = parse_windows11_release_health_html(_fixture_html_with_ltsc_table())
    entries = [
        entry
        for entry in policy.current_versions
        if entry.version == "24H2" and entry.build_family == 26100
    ]

    assert len(entries) == 2
    ga = next(entry for entry in entries if entry.servicing_channel is ServicingChannel.GENERAL_AVAILABILITY)
    ltsc = next(entry for entry in entries if entry.servicing_channel is ServicingChannel.LTSC)
    assert EditionScope.HOME_PRO in ga.edition_scopes
    assert EditionScope.ENTERPRISE_LTSC in ltsc.edition_scopes
    assert EditionScope.IOT_ENTERPRISE_LTSC in ltsc.edition_scopes


def test_release_health_parser_reports_missing_current_version_latest_header():
    html = _fixture_html().replace("<th>Latest build</th>", "<th>Observed build</th>", 1)

    with pytest.raises(PolicyParseError, match=r"current_versions table.*Latest build.*table\[0\]"):
        parse_windows11_release_health_html(html)


def test_release_health_parser_reports_missing_release_history_update_type_header():
    html = _fixture_html().replace("<th>Update type</th>", "<th>Lifecycle marker</th>")

    with pytest.raises(PolicyParseError, match=r"release_history tables.*Update type.*Lifecycle marker"):
        parse_windows11_release_health_html(html)


def test_release_health_parser_requires_26h1_special_note_when_26h1_is_current():
    with pytest.raises(PolicyParseError, match="26H1 new-devices-only special release note"):
        parse_windows11_release_health_html(_fixture_html_without_26h1_note())


def test_release_health_parser_requires_b_baseline_for_broad_target():
    with pytest.raises(PolicyParseError, match="B-release required baseline"):
        parse_windows11_release_health_html(_fixture_html_without_b_baseline_for_25h2())


def _history_row(update_type: str, availability_date: str, build: str, kb_article: str) -> str:
    return (
        "      <tr>\n"
        "        <td>General Availability Channel</td>\n"
        f"        <td>{update_type}</td>\n"
        f"        <td>{availability_date}</td>\n"
        f"        <td>{build}</td>\n"
        f"        <td>{kb_article}</td>\n"
        "      </tr>\n"
    )


def _with_history_row(html: str, heading: str, row: str) -> str:
    section = html.index(f"<h3>{heading}</h3>")
    body = html.index("<tbody>\n", section) + len("<tbody>\n")
    return html[:body] + row + html[body:]


def _pending_26h2_html_after_october_patch_tuesday() -> str:
    html = _with_history_row(
        _pending_26h2_html(),
        "Version 26H2 (OS build 26300)",
        _history_row("2026-10 B", "2026-10-13", "26300.9700", "KB5130001"),
    )
    return _with_history_row(
        html,
        "Version 25H2 (OS build 26200)",
        _history_row("2026-10 B", "2026-10-13", "26200.9700", "KB5130001"),
    )


def _pending_26h2_html_with_patch_tuesday_missing_for_26h2() -> str:
    return _with_history_row(
        _pending_26h2_html(),
        "Version 25H2 (OS build 26200)",
        _history_row("2026-10 B", "2026-10-13", "26200.9700", "KB5130001"),
    )


def _current_entry(policy: ReleasePolicy, version: str) -> ReleasePolicyEntry:
    return next(entry for entry in policy.current_versions if entry.version == version)


def test_release_health_parser_holds_broad_target_while_new_h2_awaits_first_b_release():
    policy = parse_windows11_release_health_html(_pending_26h2_html())

    target = policy.broad_target_existing_devices
    assert target is not None
    assert (target.version, target.build_family) == ("25H2", 26200)
    assert target.baseline_build == "26200.9445"
    assert target.required_baseline_build == "26200.9445"
    assert target.latest_build == "26200.9550"


def test_release_health_parser_marks_pending_release_not_broad_target_without_special_flags():
    policy = parse_windows11_release_health_html(_pending_26h2_html())

    pending = _current_entry(policy, "26H2")
    assert pending.metadata["not_broad_target"] is True
    assert pending.metadata["not_broad_target_existing_devices"] is True
    assert pending.metadata["pending_first_b_release"] is True
    assert "25H2" in pending.metadata["broad_target_hold_reason"]
    assert "special_release" not in pending.metadata
    assert "new_devices_only" not in pending.metadata
    assert pending.baseline_build is None
    assert [entry.version for entry in policy.special_releases] == ["26H1"]
    assert [entry.version for entry in policy.excluded_for_existing_devices] == ["26H1"]
    assert policy.supported_build_families[26300] == "26H2"


def test_hold_reason_keeps_its_key_facts_in_the_dashboard_summary():
    from win11_release_guard.policy_generator.diagnostic_ids import _short_diagnostic_text

    reason = _current_entry(parse_windows11_release_health_html(_pending_26h2_html()), "26H2").metadata[
        "broad_target_hold_reason"
    ]
    summary = _short_diagnostic_text(reason)

    for fact in ("26H2", "2026-09-29", "25H2", "26200.9445"):
        assert fact in summary, summary


def test_release_health_parser_hold_leaves_older_releases_without_b_rows_unflagged():
    html = _pending_26h2_html().replace(_history_row("2026-09 B", "2026-09-08", "22631.7582", "KB5122880"), "", 1)
    policy = parse_windows11_release_health_html(html)

    assert _current_entry(policy, "23H2").baseline_build is None
    assert _current_entry(policy, "26H2").metadata["pending_first_b_release"] is True
    assert "not_broad_target" not in _current_entry(policy, "23H2").metadata
    assert "pending_first_b_release" not in _current_entry(policy, "23H2").metadata


def test_release_health_parser_reports_pending_first_b_release_as_dashboard_notice():
    policy = parse_windows11_release_health_html(_pending_26h2_html())

    events = [
        event
        for event in policy.source_diagnostics["parser"]["events"]
        if event.get("kind") == "broad_target_pending_b_release"
    ]
    assert len(events) == 1
    event = events[0]
    assert event["severity"] == "notice"
    assert (event["release"], event["build_family"], event["build"]) == ("26H2", 26300, "26300.9550")
    assert event["held_release"] == "25H2"
    assert event["held_required_baseline_build"] == "26200.9445"
    assert event["affects_broad_target"] is True
    assert event["affects_required_baseline"] is False
    assert "26H2" in event["message"] and "25H2" in event["message"]


def test_release_health_parser_promotes_new_h2_after_its_first_b_release():
    policy = parse_windows11_release_health_html(_pending_26h2_html_after_october_patch_tuesday())

    target = policy.broad_target_existing_devices
    assert target is not None
    assert (target.version, target.build_family) == ("26H2", 26300)
    assert target.required_baseline_build == "26300.9700"
    assert "pending_first_b_release" not in _current_entry(policy, "26H2").metadata
    assert "not_broad_target" not in _current_entry(policy, "26H2").metadata
    assert not [
        event
        for event in policy.source_diagnostics["parser"]["events"]
        if event.get("kind") == "broad_target_pending_b_release"
    ]


def test_release_health_parser_fails_closed_when_patch_tuesday_passed_without_b_for_new_h2():
    with pytest.raises(PolicyParseError, match="B-release required baseline.*26H2/26300"):
        parse_windows11_release_health_html(_pending_26h2_html_with_patch_tuesday_missing_for_26h2())


def test_release_health_parser_fails_closed_when_only_a_newer_release_could_hold_the_target():
    html = _pending_26h2_html()
    for version in ("25H2", "24H2", "23H2"):
        row_start = html.index(f"      <tr>\n        <td>{version}</td>")
        row_end = html.index("      </tr>\n", row_start) + len("      </tr>\n")
        html = html[:row_start] + html[row_end:]
    newer_h1_row = (
        "      <tr>\n        <td>27H1</td>\n        <td>General Availability Channel</td>\n"
        "        <td>2026-02-10</td>\n        <td>2029-03-13</td>\n        <td>2030-03-12</td>\n"
        "        <td>2026-09 B</td>\n        <td>2026-09-08</td>\n        <td>28100.1000</td>\n      </tr>\n"
    )
    first_current_row = html.index("      <tr>\n        <td>26H2</td>")
    html = html[:first_current_row] + newer_h1_row + html[first_current_row:]
    newer_h1_history = (
        "  <h3>Version 27H1 (OS build 28100)</h3>\n  <table>\n    <thead>\n      <tr>\n"
        "        <th>Servicing option</th>\n        <th>Update type</th>\n        <th>Availability date</th>\n"
        "        <th>Build</th>\n        <th>KB article</th>\n      </tr>\n    </thead>\n    <tbody>\n"
        + _history_row("2026-09 B", "2026-09-08", "28100.1000", "KB5124099")
        + "    </tbody>\n  </table>\n\n"
    )
    html = html.replace("  <h3>Version 26H1 (OS build 28000)</h3>", newer_h1_history + "  <h3>Version 26H1 (OS build 28000)</h3>", 1)

    with pytest.raises(PolicyParseError, match="B-release required baseline.*26H2/26300"):
        parse_windows11_release_health_html(html)


def test_release_health_parser_uses_release_history_date_when_current_availability_is_blank():
    html = _pending_26h2_html().replace("<td>2026-09-29</td>\n        <td>2028-10-10</td>", "<td></td>\n        <td>2028-10-10</td>", 1)

    policy = parse_windows11_release_health_html(html)

    assert policy.broad_target_existing_devices.version == "25H2"
    assert _current_entry(policy, "26H2").metadata["pending_first_b_release"] is True


def test_release_health_parser_fails_closed_when_pending_release_has_no_dates():
    html = _pending_26h2_html().replace("<td>2026-09-29</td>", "<td></td>")

    with pytest.raises(PolicyParseError, match="B-release required baseline.*26H2/26300"):
        parse_windows11_release_health_html(html)
