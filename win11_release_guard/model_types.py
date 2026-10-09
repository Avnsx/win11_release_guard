"""Enumerations and value coercion shared by the data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping


class EvaluationStatus(str, Enum):
    """Final release-compliance state."""

    COMPLIANT = "COMPLIANT"
    FEATURE_UPDATE_REQUIRED = "FEATURE_UPDATE_REQUIRED"
    QUALITY_UPDATE_REQUIRED = "QUALITY_UPDATE_REQUIRED"
    PREVIEW_BUILD_INSTALLED = "PREVIEW_BUILD_INSTALLED"
    ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE = "ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE"
    UNKNOWN_LOCAL_RELEASE = "UNKNOWN_LOCAL_RELEASE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    CHECK_INCOMPLETE = "CHECK_INCOMPLETE"


class QualityPolicy(str, Enum):
    """How strict the quality-update baseline should be."""

    B_RELEASE_ONLY = "b_release_only"
    LATEST_NON_PREVIEW = "latest_non_preview"
    LATEST_ANYTHING = "latest_anything"


class ServicingChannel(str, Enum):
    """Windows servicing channel relevant to release-target selection."""

    GENERAL_AVAILABILITY = "general_availability"
    LTSC = "ltsc"
    HOTPATCH = "hotpatch"
    UNKNOWN = "unknown"


class EditionScope(str, Enum):
    """Edition family used to choose the correct policy path."""

    HOME_PRO = "home_pro"
    ENTERPRISE_EDUCATION = "enterprise_education"
    ENTERPRISE_LTSC = "enterprise_ltsc"
    IOT_ENTERPRISE_LTSC = "iot_enterprise_ltsc"
    SERVER = "server"
    UNKNOWN = "unknown"


class SourceStatus(str, Enum):
    REMOTE_POLICY_OK = "REMOTE_POLICY_OK"
    REMOTE_POLICY_UNREACHABLE = "REMOTE_POLICY_UNREACHABLE"
    REMOTE_POLICY_PARSE_FAILED = "REMOTE_POLICY_PARSE_FAILED"
    REMOTE_POLICY_SIGNATURE_FAILED = "REMOTE_POLICY_SIGNATURE_FAILED"
    USING_FRESH_CACHE = "USING_FRESH_CACHE"
    USING_STALE_CACHE = "USING_STALE_CACHE"
    USING_BUNDLED_POLICY = "USING_BUNDLED_POLICY"
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    RUNTIME_HTML_FALLBACK_USED = "RUNTIME_HTML_FALLBACK_USED"
    CHECK_INCOMPLETE = "CHECK_INCOMPLETE"


@dataclass(frozen=True)
class SourceProblem:
    kind: str
    message: str
    source_url: str | None = None
    exception_type: str | None = None
    retryable: bool = False
    occurred_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", str(self.kind))
        object.__setattr__(self, "message", str(self.message))
        object.__setattr__(self, "source_url", _optional_str(self.source_url))
        object.__setattr__(self, "exception_type", _optional_str(self.exception_type))
        object.__setattr__(self, "retryable", bool(self.retryable))
        object.__setattr__(self, "occurred_at_utc", str(self.occurred_at_utc))

    def __str__(self) -> str:
        return self.message

    def __contains__(self, needle: object) -> bool:
        return str(needle) in self.message

    def lower(self) -> str:
        return self.message.lower()

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "message": self.message,
            "source_url": self.source_url,
            "exception_type": self.exception_type,
            "retryable": self.retryable,
            "occurred_at_utc": self.occurred_at_utc,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SourceProblem":
        return cls(
            kind=str(data.get("kind") or "unknown"),
            message=str(data.get("message") or ""),
            source_url=_optional_str(data.get("source_url")),
            exception_type=_optional_str(data.get("exception_type")),
            retryable=bool(data.get("retryable", False)),
            occurred_at_utc=str(data.get("occurred_at_utc") or datetime.now(timezone.utc).replace(microsecond=0).isoformat()),
        )


class InstalledBuildClassification(str, Enum):
    B_RELEASE = "b_release"
    PREVIEW = "preview"
    OUT_OF_BAND = "out_of_band"
    UNKNOWN_NEWER_THAN_BASELINE = "unknown_newer_than_baseline"
    UNKNOWN_OLDER_THAN_BASELINE = "unknown_older_than_baseline"


class BuildEvidenceSource(str, Enum):
    POLICY_RELEASE_HISTORY = "policy_release_history"
    WUA_HISTORY = "wua_history"
    DISM_PACKAGE = "dism_package"
    UNKNOWN = "unknown"


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y"}:
        return True
    if text in {"0", "false", "no", "n"}:
        return False
    return bool(value)


def _quality_policy(value: QualityPolicy | str | None) -> QualityPolicy:
    if value is None:
        return QualityPolicy.B_RELEASE_ONLY
    if isinstance(value, QualityPolicy):
        return value
    return QualityPolicy(str(value))


def _servicing_channel(value: ServicingChannel | str | None) -> ServicingChannel:
    if value is None or value == "":
        return ServicingChannel.UNKNOWN
    if isinstance(value, ServicingChannel):
        return value
    text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "ga": ServicingChannel.GENERAL_AVAILABILITY,
        "general_availability_channel": ServicingChannel.GENERAL_AVAILABILITY,
        "general_availability": ServicingChannel.GENERAL_AVAILABILITY,
        "long_term_servicing_channel": ServicingChannel.LTSC,
        "long-term_servicing_channel": ServicingChannel.LTSC,
        "long_term_servicing": ServicingChannel.LTSC,
        "ltsc": ServicingChannel.LTSC,
        "ltsb": ServicingChannel.LTSC,
        "hot_patch": ServicingChannel.HOTPATCH,
        "hotpatch": ServicingChannel.HOTPATCH,
        "unknown": ServicingChannel.UNKNOWN,
    }
    try:
        return aliases.get(text, ServicingChannel(text))
    except ValueError:
        return ServicingChannel.UNKNOWN


def _edition_scope(value: EditionScope | str | None) -> EditionScope:
    if value is None or value == "":
        return EditionScope.UNKNOWN
    if isinstance(value, EditionScope):
        return value
    text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "home": EditionScope.HOME_PRO,
        "core": EditionScope.HOME_PRO,
        "pro": EditionScope.HOME_PRO,
        "professional": EditionScope.HOME_PRO,
        "professionaln": EditionScope.HOME_PRO,
        "professional_n": EditionScope.HOME_PRO,
        "professionalworkstation": EditionScope.HOME_PRO,
        "professional_workstation": EditionScope.HOME_PRO,
        "professionalworkstationn": EditionScope.HOME_PRO,
        "professionaleducation": EditionScope.HOME_PRO,
        "professional_education": EditionScope.HOME_PRO,
        "enterprise": EditionScope.ENTERPRISE_EDUCATION,
        "enterprisen": EditionScope.ENTERPRISE_EDUCATION,
        "enterprise_n": EditionScope.ENTERPRISE_EDUCATION,
        "education": EditionScope.ENTERPRISE_EDUCATION,
        "educationn": EditionScope.ENTERPRISE_EDUCATION,
        "education_n": EditionScope.ENTERPRISE_EDUCATION,
        "enterprises": EditionScope.ENTERPRISE_LTSC,
        "enterprise_s": EditionScope.ENTERPRISE_LTSC,
        "enterprisesn": EditionScope.ENTERPRISE_LTSC,
        "enterprise_s_n": EditionScope.ENTERPRISE_LTSC,
        "enterprise_ltsc": EditionScope.ENTERPRISE_LTSC,
        "iotenterprises": EditionScope.IOT_ENTERPRISE_LTSC,
        "iot_enterprise_s": EditionScope.IOT_ENTERPRISE_LTSC,
        "iot_enterprise_ltsc": EditionScope.IOT_ENTERPRISE_LTSC,
        "server": EditionScope.SERVER,
        "unknown": EditionScope.UNKNOWN,
    }
    try:
        return aliases.get(text, EditionScope(text))
    except ValueError:
        return EditionScope.UNKNOWN


def _edition_scopes(values: Any) -> tuple[EditionScope, ...]:
    if values in (None, ""):
        return ()
    if isinstance(values, (EditionScope, str)):
        return (_edition_scope(values),)
    return tuple(_edition_scope(value) for value in values)


def _build_classification(value: InstalledBuildClassification | str | None) -> InstalledBuildClassification | None:
    if value is None or value == "":
        return None
    if isinstance(value, InstalledBuildClassification):
        return value
    return InstalledBuildClassification(str(value))


def _evidence_source(value: BuildEvidenceSource | str | None) -> BuildEvidenceSource:
    if value is None or value == "":
        return BuildEvidenceSource.UNKNOWN
    if isinstance(value, BuildEvidenceSource):
        return value
    return BuildEvidenceSource(str(value))


def _source_status(value: SourceStatus | str | None) -> SourceStatus | None:
    if value in (None, ""):
        return None
    if isinstance(value, SourceStatus):
        return value
    try:
        return SourceStatus(str(value))
    except ValueError:
        return None


def _evaluation_status(value: EvaluationStatus | str | None) -> EvaluationStatus | None:
    if value in (None, ""):
        return None
    if isinstance(value, EvaluationStatus):
        return value
    try:
        return EvaluationStatus(str(value))
    except ValueError:
        return None


def _source_problem(value: SourceProblem | Mapping[str, Any] | str) -> SourceProblem:
    if isinstance(value, SourceProblem):
        return value
    if isinstance(value, Mapping):
        return SourceProblem.from_dict(value)
    return SourceProblem(kind="legacy", message=str(value))
