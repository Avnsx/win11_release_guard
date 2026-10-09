from __future__ import annotations

import pytest
import win11_release_guard.policy_generator as policy_generator_module
from tests.support.policy_generator_helpers import KB5094126_SUPPORT_URL, _broad_target_25h2, _release_history_25h2


@pytest.mark.parametrize(
    ("applies_to", "release", "expected"),
    (
        ("Windows 11, version 25H2", "25H2", "compatible"),
        ("Windows 11, version 25H2; Windows 11, version 24H2", "24H2", "compatible"),
        ("Windows 11, version 24H2", "25H2", "incompatible"),
        ("Windows 10, version 22H2", "25H2", "incompatible"),
        ("", "25H2", "unknown"),
        ("Windows 11", "25H2", "unknown"),
    ),
)
def test_support_article_applies_to_compatibility(applies_to: str, release: str, expected: str) -> None:
    assert (
        policy_generator_module._support_article_applies_to_compatibility(
            applies_to,
            release=release,
            build_family=26200,
        )
        == expected
    )


def test_support_article_missing_applies_to_is_degraded_not_mismatch() -> None:
    validation = policy_generator_module._support_article_validation_for_record(
        {
            "kb_article": "KB5094126",
            "build": "26200.8655",
            "release": "25H2",
            "build_family": 26200,
            "support_url": KB5094126_SUPPORT_URL,
        },
        {
            "url": KB5094126_SUPPORT_URL,
            "status": "ok",
            "kb_article": "KB5094126",
            "builds": ["26200.8655"],
        },
    )

    assert validation["support_article_validation_status"] == "degraded"
    assert validation["support_article_validation_reasons"] == ["applies_to_missing"]


def test_support_article_applies_to_release_miss_is_untrusted_for_windows11_event() -> None:
    validation = policy_generator_module._support_article_validation_for_record(
        {
            "kb_article": "KB5094126",
            "build": "26200.8655",
            "release": "25H2",
            "build_family": 26200,
            "support_url": KB5094126_SUPPORT_URL,
        },
        {
            "url": KB5094126_SUPPORT_URL,
            "status": "ok",
            "kb_article": "KB5094126",
            "builds": ["26200.8655"],
            "applies_to": "Windows 11, version 24H2",
            "applies_to_releases": ["24H2"],
        },
    )

    assert validation["support_article_validation_status"] == "mismatch"
    assert validation["support_article_validation_reasons"] == ["applies_to_mismatch"]


# ---------------------------------------------------------------------------
# Applies-to compatibility produces a closed set of statuses (no dead
# "release_unmatched" branch), and validation never emits its phantom reason.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "applies_to",
    [
        "",
        "Windows 11, version 25H2",
        "Windows 11, version 24H2",
        "Windows 11, version 25H2; Windows 11, version 24H2",
        "Windows 10, version 22H2",
        "Windows 11",
        "Some unrelated product",
        "Windows Server 2025",
        None,
    ],
)
@pytest.mark.parametrize("release", ["25H2", "24H2", "", None])
def test_applies_to_compatibility_only_yields_known_statuses(applies_to, release) -> None:
    result = policy_generator_module._support_article_applies_to_compatibility(
        applies_to, release=release, build_family=26200
    )
    assert result in {"compatible", "incompatible", "unknown"}
    assert result != "release_unmatched"


def test_support_article_validation_never_emits_release_unmatched_reason() -> None:
    record = {
        "kb_article": "KB5094126",
        "build": "26200.8655",
        "release": "25H2",
        "build_family": 26200,
        "support_url": KB5094126_SUPPORT_URL,
    }
    matrix = [
        (None, None),
        ("Windows 11, version 25H2", ["25H2"]),
        ("Windows 11, version 24H2", ["24H2"]),
        ("Windows 10, version 22H2", []),
        ("Windows 11", []),
        ("", []),
    ]
    for applies_to, applies_releases in matrix:
        article = {
            "url": KB5094126_SUPPORT_URL,
            "status": "ok",
            "kb_article": "KB5094126",
            "builds": ["26200.8655"],
        }
        if applies_to is not None:
            article["applies_to"] = applies_to
        if applies_releases is not None:
            article["applies_to_releases"] = applies_releases
        validation = policy_generator_module._support_article_validation_for_record(record, article)
        reasons = validation.get("support_article_validation_reasons", [])
        assert "applies_to_release_unmatched" not in reasons


def test_release_history_record_enters_the_enrichment_work_set_once() -> None:
    record = policy_generator_module._release_history_enrichment_record(
        _broad_target_25h2(), _release_history_25h2()
    )

    records = policy_generator_module._records_for_support_article_enrichment(
        target=_broad_target_25h2(),
        atom_entries=(),
        release_history=_release_history_25h2(),
        observed_record=None,
        release_history_record=record,
    )

    assert len(records) == 1
    assert records[0]["build"] == "26200.8875"
    assert not any(item.get("preview") for item in records)
    assert not any(item.get("out_of_band") for item in records)
