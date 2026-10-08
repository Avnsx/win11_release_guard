"""The evaluation result model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping
from .local_models import InstalledBuildOrigin, LocalConsensus, LocalWindowsState
from .model_types import (
    EvaluationStatus,
    SourceProblem,
    SourceStatus,
    _evaluation_status,
    _optional_bool,
    _optional_str,
    _source_problem,
    _source_status,
)
from .policy_models import ReleaseHistoryEntry, ReleasePolicyEntry


@dataclass(frozen=True)
class EvaluationResult:
    """Serializable result returned by the evaluator."""

    status: EvaluationStatus
    candidate_status: EvaluationStatus | None = None
    local_scope_status: EvaluationStatus | None = None
    local: LocalWindowsState | None = None
    target: ReleasePolicyEntry | None = None
    baseline: ReleaseHistoryEntry | Mapping[str, Any] | None = None
    installed_release: str | None = None
    installed_build: str | None = None
    installed_build_origin: InstalledBuildOrigin | None = None
    local_consensus: LocalConsensus | None = None
    baseline_build: str | None = None
    action: str | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)
    is_warning: bool = False
    is_error: bool = False
    summary: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)
    wua_secondary: Mapping[str, Any] | None = None
    silent_feature_update_missing: bool = False
    target_feature_update_offer_expected: bool = False
    target_feature_update_offered: bool | None = None
    possible_causes: tuple[str, ...] = field(default_factory=tuple)
    recommended_actions: tuple[str, ...] = field(default_factory=tuple)
    policy_blocks: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    wua_health: Mapping[str, Any] = field(default_factory=dict)
    setup_failure_evidence: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    source_status: SourceStatus | None = None
    is_source_check_complete: bool = True
    policy_age_hours: float | None = None
    feed_age_days: float | None = None
    policy_source_url: str | None = None
    policy_source_kind: str | None = None
    policy_signature_status: str | None = None
    strict_production: bool = False
    target_selection_reason: str | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)
    source_problems: tuple[SourceProblem, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        status = self.status if isinstance(self.status, EvaluationStatus) else EvaluationStatus(str(self.status))
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "candidate_status", _evaluation_status(self.candidate_status))
        object.__setattr__(self, "local_scope_status", _evaluation_status(self.local_scope_status))
        object.__setattr__(self, "notes", tuple(self.notes))
        object.__setattr__(self, "source_status", _source_status(self.source_status))
        object.__setattr__(self, "warnings", tuple(str(item) for item in self.warnings))
        object.__setattr__(self, "errors", tuple(str(item) for item in self.errors))
        object.__setattr__(self, "strict_production", bool(self.strict_production))
        object.__setattr__(self, "possible_causes", tuple(str(item) for item in self.possible_causes))
        object.__setattr__(self, "recommended_actions", tuple(str(item) for item in self.recommended_actions))
        object.__setattr__(self, "policy_blocks", tuple(dict(item) for item in self.policy_blocks))
        object.__setattr__(self, "wua_health", dict(self.wua_health))
        object.__setattr__(self, "setup_failure_evidence", tuple(dict(item) for item in self.setup_failure_evidence))
        object.__setattr__(
            self,
            "source_problems",
            tuple(_source_problem(item) for item in self.source_problems),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "candidate_status": self.candidate_status.value if self.candidate_status else None,
            "local_scope_status": self.local_scope_status.value if self.local_scope_status else None,
            "local": self.local.to_dict() if self.local else None,
            "target": self.target.to_dict() if self.target else None,
            "baseline": (
                self.baseline.to_dict()
                if isinstance(self.baseline, ReleaseHistoryEntry)
                else dict(self.baseline)
                if self.baseline is not None
                else None
            ),
            "installed_release": self.installed_release,
            "installed_build": self.installed_build,
            "installed_build_origin": (
                self.installed_build_origin.to_dict()
                if self.installed_build_origin
                else None
            ),
            "local_consensus": self.local_consensus.to_dict() if self.local_consensus else None,
            "baseline_build": self.baseline_build,
            "action": self.action,
            "notes": list(self.notes),
            "is_warning": self.is_warning,
            "is_error": self.is_error,
            "summary": self.summary,
            "details": dict(self.details),
            "wua_secondary": dict(self.wua_secondary) if self.wua_secondary is not None else None,
            "silent_feature_update_missing": self.silent_feature_update_missing,
            "target_feature_update_offer_expected": self.target_feature_update_offer_expected,
            "target_feature_update_offered": self.target_feature_update_offered,
            "possible_causes": list(self.possible_causes),
            "recommended_actions": list(self.recommended_actions),
            "policy_blocks": [dict(item) for item in self.policy_blocks],
            "wua_health": dict(self.wua_health),
            "setup_failure_evidence": [dict(item) for item in self.setup_failure_evidence],
            "metadata": dict(self.metadata),
            "source_status": self.source_status.value if self.source_status else None,
            "is_source_check_complete": self.is_source_check_complete,
            "policy_age_hours": self.policy_age_hours,
            "feed_age_days": self.feed_age_days,
            "policy_source_url": self.policy_source_url,
            "policy_source_kind": self.policy_source_kind,
            "policy_signature_status": self.policy_signature_status,
            "strict_production": self.strict_production,
            "target_selection_reason": self.target_selection_reason,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "source_problems": [problem.to_dict() for problem in self.source_problems],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvaluationResult":
        local_data = data.get("local")
        target_data = data.get("target")
        baseline_data = data.get("baseline")
        baseline = None
        if isinstance(baseline_data, Mapping):
            if {"release", "build_family", "build"}.issubset(baseline_data):
                baseline = ReleaseHistoryEntry.from_dict(baseline_data)
            else:
                baseline = dict(baseline_data)
        return cls(
            status=EvaluationStatus(str(data["status"])),
            candidate_status=_evaluation_status(data.get("candidate_status")),
            local_scope_status=_evaluation_status(data.get("local_scope_status")),
            local=LocalWindowsState.from_dict(local_data) if local_data else None,
            target=ReleasePolicyEntry.from_dict(target_data) if target_data else None,
            baseline=baseline,
            installed_release=_optional_str(data.get("installed_release")),
            installed_build=_optional_str(data.get("installed_build")),
            installed_build_origin=(
                InstalledBuildOrigin.from_dict(data["installed_build_origin"])
                if data.get("installed_build_origin")
                else None
            ),
            local_consensus=(
                LocalConsensus.from_dict(data["local_consensus"])
                if data.get("local_consensus")
                else None
            ),
            baseline_build=_optional_str(data.get("baseline_build")),
            action=_optional_str(data.get("action")),
            notes=tuple(str(item) for item in data.get("notes", [])),
            is_warning=bool(data.get("is_warning", False)),
            is_error=bool(data.get("is_error", False)),
            summary=_optional_str(data.get("summary")),
            details=dict(data.get("details") or {}),
            wua_secondary=dict(data["wua_secondary"]) if data.get("wua_secondary") else None,
            silent_feature_update_missing=bool(data.get("silent_feature_update_missing", False)),
            target_feature_update_offer_expected=bool(data.get("target_feature_update_offer_expected", False)),
            target_feature_update_offered=(
                _optional_bool(data.get("target_feature_update_offered"))
                if data.get("target_feature_update_offered") is not None
                else None
            ),
            possible_causes=tuple(str(item) for item in data.get("possible_causes", [])),
            recommended_actions=tuple(str(item) for item in data.get("recommended_actions", [])),
            policy_blocks=tuple(dict(item) for item in data.get("policy_blocks", [])),
            wua_health=dict(data.get("wua_health") or {}),
            setup_failure_evidence=tuple(dict(item) for item in data.get("setup_failure_evidence", [])),
            metadata=dict(data.get("metadata") or {}),
            source_status=_source_status(data.get("source_status")),
            is_source_check_complete=bool(data.get("is_source_check_complete", True)),
            policy_age_hours=(
                float(data["policy_age_hours"])
                if data.get("policy_age_hours") is not None
                else None
            ),
            feed_age_days=(
                float(data["feed_age_days"])
                if data.get("feed_age_days") is not None
                else None
            ),
            policy_source_url=_optional_str(data.get("policy_source_url")),
            policy_source_kind=_optional_str(data.get("policy_source_kind")),
            policy_signature_status=_optional_str(data.get("policy_signature_status")),
            strict_production=bool(data.get("strict_production", False)),
            target_selection_reason=_optional_str(data.get("target_selection_reason")),
            warnings=tuple(str(item) for item in data.get("warnings", [])),
            errors=tuple(str(item) for item in data.get("errors", [])),
            source_problems=tuple(_source_problem(item) for item in data.get("source_problems", [])),
        )
