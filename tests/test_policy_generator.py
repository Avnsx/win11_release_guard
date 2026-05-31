from __future__ import annotations

import json
from pathlib import Path

from tools import generate_policy as generate_policy_cli
from win11_release_guard.models import QualityPolicy
from win11_release_guard.policy_generator import (
    build_policy_from_sources,
    generate_policy,
    parse_atom_feed,
    write_policy_outputs,
)
from win11_release_guard.policy_schema import validate_policy_document


FIXTURES = Path("tests/fixtures")


def _html() -> str:
    return (FIXTURES / "windows11-release-health.html").read_text(encoding="utf-8")


def _atom() -> str:
    return (FIXTURES / "windows11-atom.xml").read_text(encoding="utf-8")


def _with_26h2_ga(html: str) -> str:
    row = """      <tr>
        <td>26H2</td>
        <td>General Availability Channel</td>
        <td>2026-10-01</td>
        <td>2028-10-10</td>
        <td>2029-10-09</td>
        <td>2026-10-13</td>
        <td>28200.1000</td>
      </tr>
"""
    history = """
  <h3>Version 26H2 (OS build 28200)</h3>
  <table>
    <thead>
      <tr>
        <th>Servicing option</th>
        <th>Update type</th>
        <th>Availability date</th>
        <th>Build</th>
        <th>KB article</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>General Availability Channel</td>
        <td>2026-10 B</td>
        <td>2026-10-13</td>
        <td>28200.1000</td>
        <td>KB5090001</td>
      </tr>
    </tbody>
  </table>
"""
    html = html.replace("      <tr>\n        <td>26H1</td>", row + "      <tr>\n        <td>26H1</td>", 1)
    return html.replace("  <h3>Version 26H1 (OS build 28000)</h3>", history + "\n  <h3>Version 26H1 (OS build 28000)</h3>", 1)


def _with_27h1_special(html: str) -> str:
    note = """
  <p>
    Windows 11, version 27H1 is scoped to support new devices and is not
    designed as a feature update for existing devices. This version is not
    offered as an in-place update from 25H2 or 26H2 on existing devices.
  </p>
"""
    row = """      <tr>
        <td>27H1</td>
        <td>General Availability Channel</td>
        <td>2027-02-10</td>
        <td>2029-03-13</td>
        <td>2030-03-12</td>
        <td>2027-02-10</td>
        <td>29000.1000</td>
      </tr>
"""
    history = """
  <h3>Version 27H1 (OS build 29000)</h3>
  <table>
    <thead>
      <tr>
        <th>Servicing option</th>
        <th>Update type</th>
        <th>Availability date</th>
        <th>Build</th>
        <th>KB article</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>General Availability Channel</td>
        <td>2027-02 B</td>
        <td>2027-02-10</td>
        <td>29000.1000</td>
        <td>KB5097001</td>
      </tr>
    </tbody>
  </table>
"""
    html = html.replace("  <h2>Windows 11 current versions by servicing option</h2>", note + "\n  <h2>Windows 11 current versions by servicing option</h2>", 1)
    html = html.replace("      <tr>\n        <td>26H2</td>", row + "      <tr>\n        <td>26H2</td>", 1)
    return html.replace("  <h3>Version 26H2 (OS build 28200)</h3>", history + "\n  <h3>Version 26H2 (OS build 28200)</h3>", 1)


def _with_oob_row(html: str) -> str:
    row = """      <tr>
        <td>General Availability Channel</td>
        <td>2026-05</td>
        <td>2026-05-16</td>
        <td>26200.8460</td>
        <td>KB5089550</td>
      </tr>
"""
    return html.replace("      <tr>\n        <td>General Availability Channel</td>\n        <td>2026-04 D</td>", row + "      <tr>\n        <td>General Availability Channel</td>\n        <td>2026-04 D</td>", 1)


def test_generate_policy_from_local_html_and_atom_fixtures(tmp_path):
    policy = build_policy_from_sources(
        release_health_html_path=FIXTURES / "windows11-release-health.html",
        atom_feed_path=FIXTURES / "windows11-atom.xml",
        signature_status="valid",
    )
    data = policy.to_dict()
    validate_policy_document(data)
    written = write_policy_outputs(
        policy,
        output_dir=tmp_path,
        write_index=True,
        write_robots=True,
        write_sitemap=True,
        write_manifest=True,
    )

    assert written["policy"].name == "windows-release-policy.json"
    assert written["index"].name == "index.html"
    assert written["robots"].name == "robots.txt"
    assert written["sitemap"].name == "sitemap.xml"
    assert written["manifest"].name == "manifest.json"
    assert json.loads(written["policy"].read_text(encoding="utf-8"))["broad_target_existing_devices"]["version"] == "25H2"
    assert "Sitemap:" in written["robots"].read_text(encoding="utf-8")
    assert "windows-release-policy.json" in written["sitemap"].read_text(encoding="utf-8")
    assert json.loads(written["manifest"].read_text(encoding="utf-8"))["broad_target_existing_devices"]["version"] == "25H2"
    assert data["source_fetch_status"]["release_health_html"]["status"] == "ok"
    assert data["source_fetch_status"]["atom_feed"]["status"] == "ok"
    assert "quality_baselines" in data
    assert "preview_builds" in data


def test_write_signed_policy_output_includes_key_id(tmp_path):
    policy = build_policy_from_sources(
        release_health_html_path=FIXTURES / "windows11-release-health.html",
        atom_feed_path=FIXTURES / "windows11-atom.xml",
        signature_status="valid",
    )

    written = write_policy_outputs(
        policy,
        output_dir=tmp_path,
        signing_key="krtF2muLgucP7JDVNKk2g+YQfz92c7xM49dzszxHxjs=",
        key_id="test-policy-key",
    )
    signature = json.loads(written["signature"].read_text(encoding="utf-8"))

    assert signature["algorithm"] == "ed25519"
    assert signature["key_id"] == "test-policy-key"
    assert signature["signature"]
    assert signature["signed_at_utc"]


def test_fixture_with_26h1_25h2_24h2_chooses_25h2():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    special = {entry.version: entry for entry in policy.special_releases}
    assert special["26H1"].metadata["special_release"] is True
    assert special["26H1"].metadata["new_devices_only"] is True
    assert special["26H1"].metadata["not_broad_target_existing_devices"] is True


def test_future_26h2_ga_chooses_26h2():
    policy = generate_policy(release_health_html=_with_26h2_ga(_html()), atom_feed_xml=_atom())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "26H2"
    assert policy.broad_target_existing_devices.build_family == 28200


def test_future_27h1_special_does_not_choose_27h1():
    policy = generate_policy(release_health_html=_with_27h1_special(_with_26h2_ga(_html())), atom_feed_xml=_atom())

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "26H2"
    special = {entry.version for entry in policy.special_releases}
    assert "27H1" in special


def test_atom_feed_marks_preview_when_table_is_ambiguous():
    html = _html().replace("2026-04 D", "2026-04")
    policy = generate_policy(release_health_html=html, atom_feed_xml=_atom())
    row = next(row for row in policy.release_history if row.kb_article == "KB5083631")

    assert row.preview is True
    assert row.update_type_letter == "D"
    assert row.metadata["atom_enriched"] is True
    assert row.kb_url == "https://support.microsoft.com/help/5083631"
    assert row.catalog_url == "https://www.catalog.update.microsoft.com/Search.aspx?q=KB5083631"


def test_atom_feed_marks_oob_when_table_is_ambiguous():
    policy = generate_policy(release_health_html=_with_oob_row(_html()), atom_feed_xml=_atom())
    row = next(row for row in policy.release_history if row.kb_article == "KB5089550")

    assert row.out_of_band is True
    assert row.update_type_letter == "OOB"
    assert row.metadata["atom_enriched"] is True
    assert any(item["kb_article"] == "KB5089550" for item in policy.out_of_band_builds)


def test_b_release_quality_baseline_does_not_require_preview():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=_atom())
    baseline = policy.quality_baselines["25H2"][QualityPolicy.B_RELEASE_ONLY.value]

    assert baseline["build"] == "26200.8457"
    assert baseline["preview"] is False


def test_missing_atom_feed_still_generates_policy_with_warning():
    policy = generate_policy(release_health_html=_html(), atom_feed_xml=None)

    assert policy.broad_target_existing_devices is not None
    assert policy.broad_target_existing_devices.version == "25H2"
    assert any("Atom feed missing" in warning for warning in policy.validation_warnings)


def test_parse_atom_feed_extracts_kb_build_and_classification():
    entries = parse_atom_feed(_atom())
    preview = next(entry for entry in entries if entry.kb_article == "KB5083631")
    oob = next(entry for entry in entries if entry.kb_article == "KB5089550")

    assert preview.preview is True
    assert preview.builds == ("26200.8328",)
    assert oob.out_of_band is True


def test_generator_source_failure_exits_nonzero_and_explains_failure(tmp_path, capsys):
    code = generate_policy_cli.main([
        "--release-health-html",
        str(tmp_path / "missing.html"),
        "--atom-feed",
        str(FIXTURES / "windows11-atom.xml"),
        "--output-dir",
        str(tmp_path / "site"),
    ])

    captured = capsys.readouterr()
    assert code == 1
    assert "release_health_html source failure" in captured.err


def test_generator_cli_writes_pages_support_files(tmp_path):
    output_dir = tmp_path / "site"

    code = generate_policy_cli.main([
        "--release-health-html",
        str(FIXTURES / "windows11-release-health.html"),
        "--atom-feed",
        str(FIXTURES / "windows11-atom.xml"),
        "--output-dir",
        str(output_dir),
        "--write-index",
        "--write-robots",
        "--write-sitemap",
        "--write-manifest",
    ])

    assert code == 0
    assert (output_dir / "windows-release-policy.json").exists()
    assert (output_dir / "index.html").exists()
    assert (output_dir / "robots.txt").exists()
    assert (output_dir / "sitemap.xml").exists()
    assert (output_dir / "manifest.json").exists()
