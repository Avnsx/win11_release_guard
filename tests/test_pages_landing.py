from __future__ import annotations

import re
from pathlib import Path

from win11_release_guard.policy_generator import generate_policy, write_policy_outputs


FIXTURES = Path("tests/fixtures")
CURATED_26H1_SUMMARY = (
    "26H1 is excluded for existing devices because Microsoft scopes it to new devices and does not offer "
    "it as an in-place update from 24H2/25H2."
)


def _render_landing(tmp_path: Path) -> str:
    policy = generate_policy(
        release_health_html=(FIXTURES / "windows11-release-health.html").read_text(encoding="utf-8"),
        atom_feed_xml=(FIXTURES / "windows11-atom.xml").read_text(encoding="utf-8"),
        generated_at_utc="2026-05-31T14:11:50+00:00",
        signature_status="valid",
    )
    write_policy_outputs(policy, output_dir=tmp_path, write_index=True)
    return (tmp_path / "index.html").read_text(encoding="utf-8")


def test_excluded_release_summary_uses_curated_26h1_copy(tmp_path: Path) -> None:
    index = _render_landing(tmp_path)

    assert "existing devi." not in index
    assert "26H1 excluded for existing devices" in index
    assert CURATED_26H1_SUMMARY in index


def test_excluded_release_reason_summaries_do_not_end_with_half_words(tmp_path: Path) -> None:
    index = _render_landing(tmp_path)
    summaries = re.findall(
        r"<li><strong>[^<]*excluded for existing devices</strong><span>(.*?)</span></li>",
        index,
    )

    assert summaries
    for summary in summaries:
        assert not summary.endswith("devi.")
        last_word = re.search(r"([A-Za-z]+)\.$", summary)
        assert last_word is None or len(last_word.group(1)) >= 5
