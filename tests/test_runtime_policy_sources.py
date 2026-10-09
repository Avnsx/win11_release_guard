from __future__ import annotations

import win11_release_guard.api as api
from win11_release_guard.config import ReleaseCheckerConfig
from win11_release_guard.models import EvaluationStatus, SourceStatus
from tests.support.runtime_policy_sources_helpers import _policy


def test_source_degradation_decision_classifies_cache_and_exit_code_semantics():
    source = api.PolicySourceResult(
        policy=_policy(),
        source_status=SourceStatus.USING_STALE_CACHE,
        is_source_check_complete=False,
        policy_source_kind="stale_cache",
    )

    lenient = api.decide_source_degradation(
        ReleaseCheckerConfig(),
        source,
        candidate_status=EvaluationStatus.COMPLIANT,
    )
    strict = api.decide_source_degradation(
        ReleaseCheckerConfig(strict_production=True),
        source,
        candidate_status=EvaluationStatus.COMPLIANT,
    )

    assert lenient.source_class == "stale_cache"
    assert lenient.allow_compliant_green is True
    assert lenient.force_check_incomplete is False
    assert lenient.must_exit_code_2 is False
    assert strict.allow_compliant_green is False
    assert strict.force_check_incomplete is True
    assert strict.must_exit_code_2 is True
    assert strict.reason and "Strict production requires" in strict.reason
