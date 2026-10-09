from __future__ import annotations

import re
import win11_release_guard.policy_generator as policy_generator_module
from win11_release_guard.policy_generator.diagnostic_ids import _source_diagnostic_id


def test_source_diagnostic_id_is_stable_for_equivalent_input():
    first = _source_diagnostic_id(
        severity="Warning",
        source="Atom feed",
        title="Atom Newer Than Release History",
        message="Atom feed reports a newer baseline build.",
        tags=("Release 25H2", "Build 26200.8461", "KB5089600"),
    )
    second = _source_diagnostic_id(
        severity=" warning ",
        source="Atom  feed",
        title="Atom Newer Than Release History",
        message="Atom feed reports a newer baseline   build.",
        tags=("Release 25H2", "Build 26200.8461", "KB5089600"),
    )

    assert first == second
    assert re.fullmatch(r"wrg-source-diagnostic-v1:[0-9a-f]{16}", first)


def test_source_diagnostic_id_ignores_volatile_timestamp_tag_order_and_message_wording():
    first = _source_diagnostic_id(
        severity="warning",
        source="Atom feed",
        title="Atom Newer Than Release History",
        message="Atom feed reports a newer baseline build.",
        tags=(
            "Release 25H2",
            "Build 26200.8461",
            "KB5089600",
            "Family 26200",
            "Required baseline",
            "2026-06-09T18:00:00Z",
        ),
    )
    second = _source_diagnostic_id(
        severity="warning",
        source="Atom feed",
        title="Atom Newer Than Release History",
        message="A newer baseline build is present in the Atom feed.",
        tags=(
            "2026-06-10T09:30:00Z",
            "Required baseline",
            "Family 26200",
            "KB 5089600",
            "Build 26200.8461",
            "Release 25H2",
        ),
    )

    assert second == first


def test_source_diagnostic_event_id_ignores_volatile_message_and_timestamp_fields():
    event = {
        "severity": "warning",
        "kind": "atom_newer_than_release_history",
        "release": "25H2",
        "build_family": 26200,
        "build": "26200.8461",
        "kb_article": "KB5089600",
        "affects_broad_target": True,
        "affects_required_baseline": True,
        "updated": "2026-06-09T18:00:00Z",
        "message": "Atom feed reports a newer baseline build.",
    }
    changed = {
        **event,
        "updated": "2026-06-10T09:30:00Z",
        "message": "A newer baseline build is present in the Atom feed.",
    }

    assert policy_generator_module._source_diagnostic_id_for_event(changed) == (
        policy_generator_module._source_diagnostic_id_for_event(event)
    )


def test_source_diagnostic_id_changes_when_meaning_changes():
    base = {
        "severity": "warning",
        "source": "Atom feed",
        "title": "Atom Newer Than Release History",
        "message": "Atom feed reports a newer baseline build.",
        "tags": ("Release 25H2", "Build 26200.8461", "KB5089600"),
    }
    base_id = _source_diagnostic_id(**base)

    for key, value in (
        ("severity", "error"),
        ("source", "Release Health"),
        ("title", "Current Versions Lag Release History"),
        ("tags", ("Release 25H2", "Build 26200.8462", "KB5089600")),
    ):
        changed = dict(base)
        changed[key] = value
        assert _source_diagnostic_id(**changed) != base_id


def test_source_diagnostic_event_id_changes_when_stable_fields_change():
    base = {
        "severity": "warning",
        "kind": "atom_newer_than_release_history",
        "release": "25H2",
        "build_family": 26200,
        "build": "26200.8461",
        "kb_article": "KB5089600",
        "affects_broad_target": True,
        "affects_required_baseline": True,
        "updated": "2026-06-09T18:00:00Z",
        "message": "Atom feed reports a newer baseline build.",
    }
    base_id = policy_generator_module._source_diagnostic_id_for_event(base)

    for key, value in (
        ("severity", "error"),
        ("kind", "current_versions_lag_release_history"),
        ("release", "24H2"),
        ("build_family", 26100),
        ("build", "26200.8462"),
        ("kb_article", "KB5089601"),
        ("affects_broad_target", False),
        ("affects_required_baseline", False),
    ):
        changed = dict(base)
        changed[key] = value
        assert policy_generator_module._source_diagnostic_id_for_event(changed) != base_id


def test_source_diagnostic_event_id_ignores_invalid_atom_diagnostic_hint() -> None:
    event = {
        "severity": "warning",
        "kind": "atom_newer_than_release_history",
        "release": "25H2",
        "build_family": 26200,
        "build": "26200.8655",
        "kb_article": "KB5094126",
        "affects_broad_target": True,
        "affects_required_baseline": True,
        "diagnostic_id_hint": "wrg-source-diagnostic-v1:uuid:not-a-canonical-id;id=968480",
        "message": "Atom feed reports a newer baseline build.",
    }

    assert re.fullmatch(
        r"wrg-source-diagnostic-v1:[0-9a-f]{16}",
        policy_generator_module._source_diagnostic_id_for_event(event),
    )
