from __future__ import annotations

import win11_release_guard.policy_generator as policy_generator_module
from tests.support.policy_generator_helpers import KB5094126_SUPPORT_URL, _kb_atom, _kb_row


def test_match_atom_skips_ambiguous_preview_kb_only_fallback() -> None:
    row = policy_generator_module.ReleaseHistoryEntry(
        release="25H2",
        build_family=26200,
        build="26200.8655",
        availability_date="2026-06-09",
        update_type="2026-06 B",
        update_type_letter="B",
        kb_article="KB5094126",
    )
    preview_only = policy_generator_module.AtomFeedEntry(
        title="Preview-only KB match",
        entry_id="tag:test,preview",
        link=KB5094126_SUPPORT_URL,
        kb_article="KB5094126",
        builds=("26200.9000",),
        preview=True,
    )

    assert policy_generator_module._match_atom(row, (preview_only,)) is None


# ---------------------------------------------------------------------------
# KB-only Atom fallback must never attach build-specific metadata for a build
# the Atom entry does not actually list (a KB can map to multiple builds).
# ---------------------------------------------------------------------------


def test_match_atom_skips_kb_only_when_atom_lists_a_different_build() -> None:
    row = policy_generator_module.ReleaseHistoryEntry(
        release="24H2",
        build_family=26100,
        build="26100.5000",
        update_type="2026-06 B",
        update_type_letter="B",
        kb_article="KB5090000",
    )
    wrong_build_only = policy_generator_module.AtomFeedEntry(
        title="June 2026 Update",
        entry_id="tag:test,wrong",
        link="https://support.microsoft.com/help/5090000",
        kb_article="KB5090000",
        builds=("26200.5000",),
    )
    assert policy_generator_module._match_atom(row, (wrong_build_only,)) is None


def test_match_atom_kb_only_fallback_allows_build_agnostic_entry() -> None:
    row = policy_generator_module.ReleaseHistoryEntry(
        release="24H2",
        build_family=26100,
        build="26100.5000",
        update_type="2026-06 B",
        update_type_letter="B",
        kb_article="KB5091111",
    )
    servicing_stack = policy_generator_module.AtomFeedEntry(
        title="Servicing stack update",
        entry_id="tag:test,ssu",
        link="https://support.microsoft.com/help/5091111",
        kb_article="KB5091111",
        builds=(),
    )
    assert policy_generator_module._match_atom(row, (servicing_stack,)) is servicing_stack


def test_match_atom_other_family_explicit_does_not_block_build_agnostic_fallback() -> None:
    row = _kb_row(26100, "26100.5000")
    agnostic = _kb_atom("urn:agnostic")
    other_family_explicit = _kb_atom("urn:other", builds=("26200.9999",))
    # The unrelated other-family explicit entry must not block the safe build-agnostic one.
    assert policy_generator_module._match_atom(row, (agnostic, other_family_explicit)) is agnostic


def test_match_atom_rejects_build_agnostic_with_unsafe_url() -> None:
    row = _kb_row(26100, "26100.5000")
    unsafe = _kb_atom("urn:unsafe", url="https://evil.example/help/5091111")
    assert policy_generator_module._match_atom(row, (unsafe,)) is None


def test_match_atom_rejects_build_agnostic_preview_or_oob_for_normal_row() -> None:
    row = _kb_row(26100, "26100.5000")
    preview = _kb_atom("urn:preview", preview=True)
    oob = _kb_atom("urn:oob", out_of_band=True)
    assert policy_generator_module._match_atom(row, (preview,)) is None
    assert policy_generator_module._match_atom(row, (oob,)) is None


def test_match_atom_single_safe_build_agnostic_candidate_attaches() -> None:
    row = _kb_row(26100, "26100.5000")
    agnostic = _kb_atom("urn:agnostic")
    assert policy_generator_module._match_atom(row, (agnostic,)) is agnostic
