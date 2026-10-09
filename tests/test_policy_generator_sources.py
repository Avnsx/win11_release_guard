from __future__ import annotations

import json
import pytest
from win11_release_guard.exceptions import PolicyFetchError
import win11_release_guard.policy_generator as policy_generator_module
from win11_release_guard.policy_generator import sources as generator_sources
from tests.support.policy_generator_helpers import KB5094126_SUPPORT_URL, _kb_atom, _kb_row


def test_kb_url_rejects_unsafe_direct_atom_link() -> None:
    entry = policy_generator_module.AtomFeedEntry(
        title="June 9, 2026-KB5094126 (OS Build 26200.8655)",
        link="https://evil.example/topic/kb5094126",
        kb_article="KB5094126",
        builds=("26200.8655",),
    )

    assert policy_generator_module._kb_url("KB5094126", entry) is None


def test_enrich_history_does_not_copy_unsafe_direct_atom_link() -> None:
    row = policy_generator_module.ReleaseHistoryEntry(
        release="25H2",
        build_family=26200,
        build="26200.8655",
        availability_date="2026-06-09",
        update_type="2026-06 B",
        update_type_letter="B",
        kb_article="KB5094126",
        kb_url="https://support.microsoft.com/help/5094126",
    )
    atom_entry = policy_generator_module.AtomFeedEntry(
        title="June 9, 2026-KB5094126 (OS Build 26200.8655)",
        entry_id="tag:test,unsafe",
        link="https://evil.example/topic/kb5094126",
        kb_article="KB5094126",
        builds=("26200.8655",),
        published="2026-06-09T17:04:01Z",
        updated="2026-06-10T17:20:31Z",
    )

    enriched = policy_generator_module._enrich_history((row,), (atom_entry,))[0]

    assert enriched.kb_url == "https://support.microsoft.com/help/5094126"
    assert "atom_feed_url" not in enriched.metadata
    assert "evil.example" not in json.dumps(enriched.to_dict(), sort_keys=True)


def test_match_atom_prefers_same_kb_and_build_over_wrong_build_first() -> None:
    row = policy_generator_module.ReleaseHistoryEntry(
        release="25H2",
        build_family=26200,
        build="26200.8655",
        availability_date="2026-06-09",
        update_type="2026-06 B",
        update_type_letter="B",
        kb_article="KB5094126",
    )
    wrong_build = policy_generator_module.AtomFeedEntry(
        title="Wrong build",
        entry_id="tag:test,wrong",
        link=KB5094126_SUPPORT_URL,
        kb_article="KB5094126",
        builds=("26100.8655",),
        updated="2026-06-11T00:00:00Z",
    )
    matching_build = policy_generator_module.AtomFeedEntry(
        title="Matching build",
        entry_id="tag:test,matching",
        link=KB5094126_SUPPORT_URL,
        kb_article="KB5094126",
        builds=("26200.8655",),
        updated="2026-06-10T00:00:00Z",
    )

    assert policy_generator_module._match_atom(row, (wrong_build, matching_build)) is matching_build


def test_match_atom_uses_newest_valid_timestamp_then_stable_tie_breaker() -> None:
    row = policy_generator_module.ReleaseHistoryEntry(
        release="25H2",
        build_family=26200,
        build="26200.8655",
        availability_date="2026-06-09",
        update_type="2026-06 B",
        update_type_letter="B",
        kb_article="KB5094126",
    )
    stale = policy_generator_module.AtomFeedEntry(
        title="Stale match",
        entry_id="tag:test,stale",
        link=KB5094126_SUPPORT_URL,
        kb_article="KB5094126",
        builds=("26200.8655",),
        updated="2026-06-09T00:00:00Z",
    )
    newest = policy_generator_module.AtomFeedEntry(
        title="Newest match",
        entry_id="tag:test,newest",
        link=KB5094126_SUPPORT_URL,
        kb_article="KB5094126",
        builds=("26200.8655",),
        updated="2026-06-11T00:00:00Z",
    )
    tie_low = policy_generator_module.AtomFeedEntry(
        title="A tie",
        entry_id="tag:test,a",
        link=KB5094126_SUPPORT_URL,
        kb_article="KB5094126",
        builds=("26200.8655",),
        updated="not-a-date",
    )
    tie_high = policy_generator_module.AtomFeedEntry(
        title="B tie",
        entry_id="tag:test,b",
        link=KB5094126_SUPPORT_URL,
        kb_article="KB5094126",
        builds=("26200.8655",),
        updated="not-a-date",
    )

    assert policy_generator_module._match_atom(row, (stale, newest)) is newest
    assert policy_generator_module._match_atom(row, (tie_low, tie_high)) is tie_high


def test_match_atom_skips_ambiguous_kb_only_source_or_security_fallback() -> None:
    row = policy_generator_module.ReleaseHistoryEntry(
        release="25H2",
        build_family=26200,
        build="26200.8655",
        availability_date="2026-06-09",
        update_type="2026-06 B",
        update_type_letter="B",
        kb_article="KB5094126",
    )
    support_a = "https://support.microsoft.com/en-us/topic/kb5094126-alpha"
    support_b = "https://support.microsoft.com/en-us/topic/kb5094126-beta"
    source_a = policy_generator_module.AtomFeedEntry(
        title="June 9, 2026-KB5094126 (OS Build 26200.9000)",
        entry_id="tag:test,a",
        link=support_a,
        kb_article="KB5094126",
        builds=("26200.9000",),
    )
    source_b = policy_generator_module.AtomFeedEntry(
        title="June 9, 2026-KB5094126 (OS Build 26200.9001)",
        entry_id="tag:test,b",
        link=support_b,
        kb_article="KB5094126",
        builds=("26200.9001",),
    )
    security_bucket = policy_generator_module.AtomFeedEntry(
        title="Security intelligence update for KB5094126",
        entry_id="tag:test,security",
        link=support_a,
        kb_article="KB5094126",
        builds=("26200.9002",),
    )

    assert policy_generator_module._match_atom(row, (source_a, source_b)) is None
    assert policy_generator_module._match_atom(row, (source_a, security_bucket)) is None


def test_load_source_text_propagates_programming_error_from_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    # load_source_text's network-fetch except block shares the same "programming
    # errors must surface, not degrade" contract as the other injection
    # boundaries: this applies regardless of required=True/False.
    def raising_fetch(url: str, *, timeout: float, charset: str | None, max_bytes: int) -> str:
        raise AssertionError("fetch must not be attempted")

    monkeypatch.setattr(generator_sources, "fetch_url", raising_fetch)

    with pytest.raises(AssertionError, match="fetch must not be attempted"):
        policy_generator_module.load_source_text(
            url="https://policy-source.invalid/source.json",
            source_name="example_source",
            required=False,
        )


def test_load_source_text_still_degrades_genuine_fetch_failure_when_not_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failing_fetch(url: str, *, timeout: float, charset: str | None, max_bytes: int) -> str:
        raise PolicyFetchError("network unavailable")

    monkeypatch.setattr(generator_sources, "fetch_url", failing_fetch)

    result = policy_generator_module.load_source_text(
        url="https://policy-source.invalid/source.json",
        source_name="example_source",
        required=False,
    )

    assert result.text == ""
    assert result.status["url"] == "https://policy-source.invalid/source.json"
    assert result.status["status"] == "error"
    assert result.status["error"] == "network unavailable"


def test_load_source_text_required_genuine_fetch_failure_still_raises_policy_fetch_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failing_fetch(url: str, *, timeout: float, charset: str | None, max_bytes: int) -> str:
        raise OSError("connection reset")

    monkeypatch.setattr(generator_sources, "fetch_url", failing_fetch)

    with pytest.raises(PolicyFetchError, match="could not fetch"):
        policy_generator_module.load_source_text(
            url="https://policy-source.invalid/source.json",
            source_name="example_source",
            required=True,
        )


def test_enrich_history_does_not_attach_wrong_build_atom_metadata() -> None:
    row = policy_generator_module.ReleaseHistoryEntry(
        release="24H2",
        build_family=26100,
        build="26100.5000",
        update_type="2026-06 B",
        update_type_letter="B",
        kb_article="KB5090000",
    )
    wrong_build_only = policy_generator_module.AtomFeedEntry(
        title="June 2026 Update for 26200",
        entry_id="tag:test,wrong",
        link="https://support.microsoft.com/help/5090000",
        kb_article="KB5090000",
        builds=("26200.5000",),
    )
    enriched = policy_generator_module._enrich_history((row,), (wrong_build_only,))[0]
    assert enriched.metadata.get("atom_enriched") is not True
    assert "atom_feed_title" not in enriched.metadata
    assert "atom_feed_url" not in enriched.metadata


def test_match_atom_enriches_each_build_of_a_multi_build_kb() -> None:
    atom = policy_generator_module.AtomFeedEntry(
        title="June 9, 2026-KB5094126 (OS Builds 26200.8655 and 26100.8655)",
        entry_id="tag:test,multi",
        link=KB5094126_SUPPORT_URL,
        kb_article="KB5094126",
        builds=("26200.8655", "26100.8655"),
    )
    row_25h2 = policy_generator_module.ReleaseHistoryEntry(
        release="25H2",
        build_family=26200,
        build="26200.8655",
        update_type="2026-06 B",
        update_type_letter="B",
        kb_article="KB5094126",
    )
    row_24h2 = policy_generator_module.ReleaseHistoryEntry(
        release="24H2",
        build_family=26100,
        build="26100.8655",
        update_type="2026-06 B",
        update_type_letter="B",
        kb_article="KB5094126",
    )
    assert policy_generator_module._match_atom(row_25h2, (atom,)) is atom
    assert policy_generator_module._match_atom(row_24h2, (atom,)) is atom


def test_match_atom_rejects_same_family_wrong_build_even_with_agnostic_sibling() -> None:
    row = _kb_row(26100, "26100.5000")
    agnostic = _kb_atom("urn:agnostic")
    same_family_wrong = _kb_atom("urn:wrong", builds=("26100.9999",))
    # A contradictory same-family explicit candidate makes the fallback ambiguous.
    assert policy_generator_module._match_atom(row, (agnostic, same_family_wrong)) is None


def test_match_atom_rejects_multiple_build_agnostic_candidates_with_different_urls() -> None:
    row = _kb_row(26100, "26100.5000")
    a1 = _kb_atom("urn:a1", url="https://support.microsoft.com/help/5091111")
    a2 = _kb_atom("urn:a2", url="https://support.microsoft.com/help/5099999")
    assert policy_generator_module._match_atom(row, (a1, a2)) is None
