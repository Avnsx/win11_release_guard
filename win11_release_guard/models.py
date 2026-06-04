from __future__ import annotations

import re
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


def _source_problem(value: SourceProblem | Mapping[str, Any] | str) -> SourceProblem:
    if isinstance(value, SourceProblem):
        return value
    if isinstance(value, Mapping):
        return SourceProblem.from_dict(value)
    return SourceProblem(kind="legacy", message=str(value))


@dataclass(frozen=True)
class LocalWindowsState:
    """Local Windows state as raw, admin-facing signals.

    Product and caption fields are retained for diagnostics, but the build
    fields are the intended release truth anchors.
    """

    current_build: int | None = None
    ubr: int | None = None
    full_build: str | None = None
    inferred_release: str | None = None
    edition_id: str | None = None
    display_version: str | None = None
    release_id: str | None = None
    installation_type: str | None = None
    product_name: str | None = None
    caption: str | None = None
    os_version: str | None = None
    operating_system_sku: int | None = None
    major_version: int | None = None
    product_family: str | None = None
    is_windows_client: bool | None = None
    is_windows_11_or_newer: bool | None = None
    is_server: bool | None = None
    is_ltsc: bool | None = None
    edition_family: str | None = None
    edition_scope: EditionScope = EditionScope.UNKNOWN
    servicing_channel: ServicingChannel = ServicingChannel.UNKNOWN
    build_family: int | None = None
    architecture: str | None = None
    rtl_version: str | None = None
    wmi_version: str | None = None
    kernel_file_version: str | None = None
    dism_current_edition: str | None = None
    dism_image_version: str | None = None
    dism_tool_version: str | None = None
    product_info_code: int | None = None
    source: str | None = None
    available: bool = True
    errors: tuple[str, ...] = field(default_factory=tuple)
    raw: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "errors", tuple(str(error) for error in self.errors))
        if self.build_family is None:
            object.__setattr__(self, "build_family", self._derive_build_family())
        if self.major_version is None:
            object.__setattr__(self, "major_version", self._derive_major_version())
        if self.is_server is None:
            object.__setattr__(self, "is_server", self._derive_is_server())
        if self.product_family is None:
            object.__setattr__(self, "product_family", "server" if self.is_server else "client")
        if self.is_windows_client is None:
            object.__setattr__(self, "is_windows_client", not bool(self.is_server))
        if self.is_windows_11_or_newer is None:
            object.__setattr__(
                self,
                "is_windows_11_or_newer",
                bool(self.is_windows_client and self.build_family is not None and self.build_family >= 22000),
            )
        if self.is_ltsc is None:
            object.__setattr__(self, "is_ltsc", self._derive_is_ltsc())
        if self.edition_family is None:
            object.__setattr__(self, "edition_family", self._derive_edition_family())
        object.__setattr__(self, "edition_scope", _edition_scope(self.edition_scope))
        if self.edition_scope is EditionScope.UNKNOWN:
            object.__setattr__(self, "edition_scope", self._derive_edition_scope())
        object.__setattr__(self, "servicing_channel", _servicing_channel(self.servicing_channel))
        if self.servicing_channel is ServicingChannel.UNKNOWN:
            object.__setattr__(self, "servicing_channel", self._derive_servicing_channel())
        if self.servicing_channel is ServicingChannel.LTSC and not self.is_ltsc:
            object.__setattr__(self, "is_ltsc", True)

    def _derive_build_family(self) -> int | None:
        if self.current_build is not None:
            return self.current_build
        for candidate in (
            self.full_build,
            self.rtl_version,
            self.wmi_version,
            self.kernel_file_version,
            self.dism_image_version,
        ):
            if not candidate:
                continue
            try:
                parts = str(candidate).split(".")
                return int(parts[2] if len(parts) >= 3 else parts[0])
            except (TypeError, ValueError):
                continue
        return None

    def _derive_major_version(self) -> int | None:
        for candidate in (
            self.rtl_version,
            self.os_version,
            self.wmi_version,
            self.kernel_file_version,
            self.dism_image_version,
        ):
            if not candidate:
                continue
            try:
                return int(str(candidate).split(".")[0])
            except (TypeError, ValueError):
                continue
        return 10 if self.build_family is not None and self.build_family >= 10240 else None

    def _derive_is_server(self) -> bool:
        values = (
            self.product_family,
            self.installation_type,
            self.product_name,
            self.caption,
            self.edition_id,
            self.dism_current_edition,
        )
        return any("server" in str(value).lower() for value in values if value)

    def _derive_is_ltsc(self) -> bool:
        values = (self.edition_id, self.dism_current_edition, self.product_name, self.caption)
        return any(token in str(value).lower() for value in values if value for token in ("ltsc", "ltsb"))

    def _derive_edition_family(self) -> str | None:
        edition = (self.edition_id or self.dism_current_edition or "").lower()
        if "enterprise" in edition:
            return "enterprise"
        if "education" in edition:
            return "education"
        if "professional" in edition or edition == "pro":
            return "pro"
        if "home" in edition or "core" in edition:
            return "home"
        return _optional_str(self.edition_id or self.dism_current_edition)

    def _edition_signal_values(self) -> tuple[Any, ...]:
        return (
            self.dism_current_edition,
            self.edition_id,
            self.edition_family,
            self.product_name,
            self.caption,
            self.installation_type,
        )

    def _derive_edition_scope(self) -> EditionScope:
        if self.is_server or any(
            "server" in str(value).lower()
            for value in self._edition_signal_values()
            if value
        ):
            return EditionScope.SERVER

        text = " ".join(str(value).lower() for value in self._edition_signal_values() if value)
        compact = re.sub(r"[^a-z0-9]+", "", text)
        if "iotenterprises" in compact or ("iot" in compact and "enterprise" in compact and "ltsc" in compact):
            return EditionScope.IOT_ENTERPRISE_LTSC
        if (
            "enterprises" in compact
            or "enterpriseltsc" in compact
            or "ltsc" in compact
            or "ltsb" in compact
        ):
            return EditionScope.ENTERPRISE_LTSC
        if "enterprise" in compact or "education" in compact:
            return EditionScope.ENTERPRISE_EDUCATION
        if "professional" in compact or re.search(r"\bpro\b", text) or "workstation" in compact or "core" in compact or "home" in compact:
            return EditionScope.HOME_PRO
        return EditionScope.UNKNOWN

    def _derive_servicing_channel(self) -> ServicingChannel:
        if self.edition_scope in {EditionScope.ENTERPRISE_LTSC, EditionScope.IOT_ENTERPRISE_LTSC} or self.is_ltsc:
            return ServicingChannel.LTSC
        if self.edition_scope in {EditionScope.HOME_PRO, EditionScope.ENTERPRISE_EDUCATION}:
            return ServicingChannel.GENERAL_AVAILABILITY
        return ServicingChannel.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_build": self.current_build,
            "ubr": self.ubr,
            "full_build": self.full_build,
            "inferred_release": self.inferred_release,
            "edition_id": self.edition_id,
            "display_version": self.display_version,
            "release_id": self.release_id,
            "installation_type": self.installation_type,
            "product_name": self.product_name,
            "caption": self.caption,
            "os_version": self.os_version,
            "operating_system_sku": self.operating_system_sku,
            "major_version": self.major_version,
            "product_family": self.product_family,
            "is_windows_client": self.is_windows_client,
            "is_windows_11_or_newer": self.is_windows_11_or_newer,
            "is_server": self.is_server,
            "is_ltsc": self.is_ltsc,
            "edition_family": self.edition_family,
            "edition_scope": self.edition_scope.value,
            "servicing_channel": self.servicing_channel.value,
            "build_family": self.build_family,
            "architecture": self.architecture,
            "rtl_version": self.rtl_version,
            "wmi_version": self.wmi_version,
            "kernel_file_version": self.kernel_file_version,
            "dism_current_edition": self.dism_current_edition,
            "dism_image_version": self.dism_image_version,
            "dism_tool_version": self.dism_tool_version,
            "product_info_code": self.product_info_code,
            "source": self.source,
            "available": self.available,
            "errors": list(self.errors),
            "raw": dict(self.raw),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "LocalWindowsState":
        return cls(
            current_build=_optional_int(data.get("current_build")),
            ubr=_optional_int(data.get("ubr")),
            full_build=_optional_str(data.get("full_build")),
            inferred_release=_optional_str(data.get("inferred_release")),
            edition_id=_optional_str(data.get("edition_id")),
            display_version=_optional_str(data.get("display_version")),
            release_id=_optional_str(data.get("release_id")),
            installation_type=_optional_str(data.get("installation_type")),
            product_name=_optional_str(data.get("product_name")),
            caption=_optional_str(data.get("caption")),
            os_version=_optional_str(data.get("os_version")),
            operating_system_sku=_optional_int(data.get("operating_system_sku")),
            major_version=_optional_int(data.get("major_version")),
            product_family=_optional_str(data.get("product_family")),
            is_windows_client=_optional_bool(data.get("is_windows_client")),
            is_windows_11_or_newer=_optional_bool(data.get("is_windows_11_or_newer")),
            is_server=_optional_bool(data.get("is_server")),
            is_ltsc=_optional_bool(data.get("is_ltsc")),
            edition_family=_optional_str(data.get("edition_family")),
            edition_scope=_edition_scope(data.get("edition_scope")),
            servicing_channel=_servicing_channel(data.get("servicing_channel")),
            build_family=_optional_int(data.get("build_family")),
            architecture=_optional_str(data.get("architecture")),
            rtl_version=_optional_str(data.get("rtl_version")),
            wmi_version=_optional_str(data.get("wmi_version")),
            kernel_file_version=_optional_str(data.get("kernel_file_version")),
            dism_current_edition=_optional_str(data.get("dism_current_edition")),
            dism_image_version=_optional_str(data.get("dism_image_version")),
            dism_tool_version=_optional_str(data.get("dism_tool_version")),
            product_info_code=_optional_int(data.get("product_info_code")),
            source=_optional_str(data.get("source")),
            available=bool(data.get("available", True)),
            errors=tuple(str(error) for error in data.get("errors", [])),
            raw=dict(data.get("raw") or {}),
        )


@dataclass(frozen=True)
class InstalledReleaseInference:
    release: str | None = None
    confidence: str = "unknown"
    source: str = "unknown"
    reasons: tuple[str, ...] = field(default_factory=tuple)
    is_recognized_by_policy: bool = False
    is_out_of_scope: bool = False
    conflicts: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        release = self.release.upper() if self.release else None
        object.__setattr__(self, "release", release)
        object.__setattr__(self, "reasons", tuple(str(reason) for reason in self.reasons))
        object.__setattr__(self, "conflicts", tuple(str(conflict) for conflict in self.conflicts))

    def to_dict(self) -> dict[str, Any]:
        return {
            "release": self.release,
            "confidence": self.confidence,
            "source": self.source,
            "reasons": list(self.reasons),
            "is_recognized_by_policy": self.is_recognized_by_policy,
            "is_out_of_scope": self.is_out_of_scope,
            "conflicts": list(self.conflicts),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "InstalledReleaseInference":
        return cls(
            release=_optional_str(data.get("release")),
            confidence=str(data.get("confidence") or "unknown"),
            source=str(data.get("source") or "unknown"),
            reasons=tuple(str(item) for item in data.get("reasons", [])),
            is_recognized_by_policy=bool(data.get("is_recognized_by_policy", False)),
            is_out_of_scope=bool(data.get("is_out_of_scope", False)),
            conflicts=tuple(str(item) for item in data.get("conflicts", [])),
        )


@dataclass(frozen=True)
class InstalledBuildOrigin:
    build: str | None = None
    release: str | None = None
    matched_policy_row: Mapping[str, Any] | None = None
    classification: InstalledBuildClassification | None = None
    kb_article: str | None = None
    availability_date: str | None = None
    evidence_source: BuildEvidenceSource = BuildEvidenceSource.UNKNOWN
    diagnostic_flags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "release", self.release.upper() if self.release else None)
        object.__setattr__(self, "matched_policy_row", dict(self.matched_policy_row) if self.matched_policy_row else None)
        object.__setattr__(self, "classification", _build_classification(self.classification))
        object.__setattr__(self, "evidence_source", _evidence_source(self.evidence_source))
        object.__setattr__(self, "diagnostic_flags", tuple(str(flag) for flag in self.diagnostic_flags))

    def to_dict(self) -> dict[str, Any]:
        return {
            "build": self.build,
            "release": self.release,
            "matched_policy_row": dict(self.matched_policy_row) if self.matched_policy_row else None,
            "classification": self.classification.value if self.classification else None,
            "kb_article": self.kb_article,
            "availability_date": self.availability_date,
            "evidence_source": self.evidence_source.value,
            "diagnostic_flags": list(self.diagnostic_flags),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "InstalledBuildOrigin":
        return cls(
            build=_optional_str(data.get("build")),
            release=_optional_str(data.get("release")),
            matched_policy_row=dict(data["matched_policy_row"]) if data.get("matched_policy_row") else None,
            classification=_build_classification(data.get("classification")),
            kb_article=_optional_str(data.get("kb_article")),
            availability_date=_optional_str(data.get("availability_date")),
            evidence_source=_evidence_source(data.get("evidence_source")),
            diagnostic_flags=tuple(str(flag) for flag in data.get("diagnostic_flags", [])),
        )


@dataclass(frozen=True)
class LocalSignal:
    source: str
    name: str
    value: Any
    kind: str = "raw"
    normalized_value: str | None = None
    trust: str = "diagnostic"
    diagnostic_flags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", str(self.source))
        object.__setattr__(self, "name", str(self.name))
        object.__setattr__(self, "kind", str(self.kind))
        object.__setattr__(self, "normalized_value", _optional_str(self.normalized_value))
        object.__setattr__(self, "trust", str(self.trust))
        object.__setattr__(self, "diagnostic_flags", tuple(str(flag) for flag in self.diagnostic_flags))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "name": self.name,
            "value": self.value,
            "kind": self.kind,
            "normalized_value": self.normalized_value,
            "trust": self.trust,
            "diagnostic_flags": list(self.diagnostic_flags),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "LocalSignal":
        return cls(
            source=str(data.get("source") or "unknown"),
            name=str(data.get("name") or "unknown"),
            value=data.get("value"),
            kind=str(data.get("kind") or "raw"),
            normalized_value=_optional_str(data.get("normalized_value")),
            trust=str(data.get("trust") or "diagnostic"),
            diagnostic_flags=tuple(str(flag) for flag in data.get("diagnostic_flags", [])),
        )


@dataclass(frozen=True)
class LocalSignalSet:
    signals: tuple[LocalSignal, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "signals",
            tuple(signal if isinstance(signal, LocalSignal) else LocalSignal.from_dict(signal) for signal in self.signals),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"signals": [signal.to_dict() for signal in self.signals]}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "LocalSignalSet":
        return cls(signals=tuple(LocalSignal.from_dict(item) for item in data.get("signals", [])))


@dataclass(frozen=True)
class LocalConsensus:
    display_os_name: str
    raw_product_name: str | None = None
    edition_scope: EditionScope = EditionScope.UNKNOWN
    servicing_channel: ServicingChannel = ServicingChannel.UNKNOWN
    release: str | None = None
    build_family: int | None = None
    conflicts: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    signal_set: LocalSignalSet = field(default_factory=LocalSignalSet)

    def __post_init__(self) -> None:
        object.__setattr__(self, "edition_scope", _edition_scope(self.edition_scope))
        object.__setattr__(self, "servicing_channel", _servicing_channel(self.servicing_channel))
        object.__setattr__(self, "release", self.release.upper() if self.release else None)
        object.__setattr__(self, "build_family", _optional_int(self.build_family))
        object.__setattr__(self, "conflicts", tuple(str(conflict) for conflict in self.conflicts))
        object.__setattr__(self, "warnings", tuple(str(warning) for warning in self.warnings))
        if not isinstance(self.signal_set, LocalSignalSet):
            object.__setattr__(self, "signal_set", LocalSignalSet.from_dict(self.signal_set))

    def to_dict(self) -> dict[str, Any]:
        return {
            "display_os_name": self.display_os_name,
            "raw_product_name": self.raw_product_name,
            "edition_scope": self.edition_scope.value,
            "servicing_channel": self.servicing_channel.value,
            "release": self.release,
            "build_family": self.build_family,
            "conflicts": list(self.conflicts),
            "warnings": list(self.warnings),
            "signal_set": self.signal_set.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "LocalConsensus":
        return cls(
            display_os_name=str(data.get("display_os_name") or "Windows unknown edition"),
            raw_product_name=_optional_str(data.get("raw_product_name")),
            edition_scope=_edition_scope(data.get("edition_scope")),
            servicing_channel=_servicing_channel(data.get("servicing_channel")),
            release=_optional_str(data.get("release")),
            build_family=_optional_int(data.get("build_family")),
            conflicts=tuple(str(conflict) for conflict in data.get("conflicts", [])),
            warnings=tuple(str(warning) for warning in data.get("warnings", [])),
            signal_set=LocalSignalSet.from_dict(data.get("signal_set") or {}),
        )


@dataclass(frozen=True)
class ReleasePolicyEntry:
    """One release row from a generated policy feed."""

    version: str
    build_family: int
    latest_build: str | None = None
    baseline_build: str | None = None
    required_baseline_build: str | None = None
    servicing_option: str | None = None
    availability_date: str | None = None
    reason: str | None = None
    edition_scopes: tuple[EditionScope, ...] = field(default_factory=tuple)
    servicing_channel: ServicingChannel = ServicingChannel.UNKNOWN
    quality_policy: QualityPolicy = QualityPolicy.B_RELEASE_ONLY
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "version", self.version.upper())
        object.__setattr__(self, "build_family", int(self.build_family))
        object.__setattr__(self, "latest_build", _optional_str(self.latest_build))
        object.__setattr__(self, "baseline_build", _optional_str(self.baseline_build))
        required_baseline = _optional_str(self.required_baseline_build)
        if required_baseline is None:
            required_baseline = self.baseline_build or self.latest_build
        object.__setattr__(self, "required_baseline_build", required_baseline)
        object.__setattr__(self, "quality_policy", _quality_policy(self.quality_policy))
        object.__setattr__(self, "edition_scopes", _edition_scopes(self.edition_scopes))
        channel = _servicing_channel(self.servicing_channel)
        if channel is ServicingChannel.UNKNOWN:
            channel = self._derive_servicing_channel()
        object.__setattr__(self, "servicing_channel", channel)
        if not self.edition_scopes:
            object.__setattr__(self, "edition_scopes", self._derive_edition_scopes())

    def _derive_servicing_channel(self) -> ServicingChannel:
        servicing = (self.servicing_option or "").lower()
        metadata_text = " ".join(str(value).lower() for value in self.metadata.values() if not isinstance(value, Mapping))
        text = f"{servicing} {metadata_text}"
        if "hotpatch" in text or "hot patch" in text:
            return ServicingChannel.HOTPATCH
        if "long-term" in text or "long term" in text or "ltsc" in text or "ltsb" in text:
            return ServicingChannel.LTSC
        if "general availability" in text or "allgemeine" in text:
            return ServicingChannel.GENERAL_AVAILABILITY
        return ServicingChannel.UNKNOWN

    def _derive_edition_scopes(self) -> tuple[EditionScope, ...]:
        if self.servicing_channel is ServicingChannel.LTSC:
            return (EditionScope.ENTERPRISE_LTSC, EditionScope.IOT_ENTERPRISE_LTSC)
        if self.servicing_channel is ServicingChannel.GENERAL_AVAILABILITY:
            return (EditionScope.HOME_PRO, EditionScope.ENTERPRISE_EDUCATION)
        if self.servicing_channel is ServicingChannel.HOTPATCH:
            return (EditionScope.ENTERPRISE_EDUCATION,)
        return ()

    @property
    def effective_baseline_build(self) -> str | None:
        return self.required_baseline_build or self.baseline_build or self.latest_build

    @property
    def latest_observed_build(self) -> str | None:
        return self.latest_build

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "build_family": self.build_family,
            "latest_build": self.latest_build,
            "latest_observed_build": self.latest_observed_build,
            "baseline_build": self.baseline_build,
            "required_baseline_build": self.required_baseline_build,
            "servicing_option": self.servicing_option,
            "availability_date": self.availability_date,
            "reason": self.reason,
            "edition_scopes": [scope.value for scope in self.edition_scopes],
            "servicing_channel": self.servicing_channel.value,
            "quality_policy": self.quality_policy.value,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ReleasePolicyEntry":
        return cls(
            version=str(data["version"]),
            build_family=int(data["build_family"]),
            latest_build=_optional_str(data.get("latest_build")),
            baseline_build=_optional_str(data.get("baseline_build")),
            required_baseline_build=_optional_str(data.get("required_baseline_build")),
            servicing_option=_optional_str(data.get("servicing_option")),
            availability_date=_optional_str(data.get("availability_date")),
            reason=_optional_str(data.get("reason")),
            edition_scopes=_edition_scopes(data.get("edition_scopes")),
            servicing_channel=_servicing_channel(data.get("servicing_channel")),
            quality_policy=_quality_policy(data.get("quality_policy")),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass(frozen=True)
class ReleaseHistoryEntry:
    """One row from Windows 11 release history."""

    release: str
    build_family: int
    build: str
    availability_date: str | None = None
    servicing_option: str | None = None
    update_type: str | None = None
    update_type_letter: str | None = None
    preview: bool = False
    out_of_band: bool = False
    kb_article: str | None = None
    kb_url: str | None = None
    catalog_url: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "release", self.release.upper())
        object.__setattr__(self, "build_family", int(self.build_family))
        if self.update_type_letter is not None:
            object.__setattr__(self, "update_type_letter", self.update_type_letter.upper())

    def to_dict(self) -> dict[str, Any]:
        return {
            "release": self.release,
            "build_family": self.build_family,
            "build": self.build,
            "availability_date": self.availability_date,
            "servicing_option": self.servicing_option,
            "update_type": self.update_type,
            "update_type_letter": self.update_type_letter,
            "preview": self.preview,
            "out_of_band": self.out_of_band,
            "kb_article": self.kb_article,
            "kb_url": self.kb_url,
            "catalog_url": self.catalog_url,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ReleaseHistoryEntry":
        return cls(
            release=str(data["release"]),
            build_family=int(data["build_family"]),
            build=str(data["build"]),
            availability_date=_optional_str(data.get("availability_date")),
            servicing_option=_optional_str(data.get("servicing_option")),
            update_type=_optional_str(data.get("update_type")),
            update_type_letter=_optional_str(data.get("update_type_letter")),
            preview=bool(data.get("preview", False)),
            out_of_band=bool(data.get("out_of_band", False)),
            kb_article=_optional_str(data.get("kb_article")),
            kb_url=_optional_str(data.get("kb_url")),
            catalog_url=_optional_str(data.get("catalog_url")),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass(frozen=True)
class ReleasePolicy:
    """Generated remote policy for evaluating existing Windows devices."""

    generated_at_utc: str | None = None
    source: Mapping[str, Any] = field(default_factory=dict)
    source_urls: tuple[str, ...] = field(default_factory=tuple)
    published_urls: Mapping[str, str] = field(default_factory=dict)
    generator_version: str | None = None
    source_fetch_status: Mapping[str, Any] = field(default_factory=dict)
    source_diagnostics: Mapping[str, Any] = field(default_factory=dict)
    quality_policy: QualityPolicy = QualityPolicy.B_RELEASE_ONLY
    broad_target_existing_devices: ReleasePolicyEntry | None = None
    current_versions: tuple[ReleasePolicyEntry, ...] = field(default_factory=tuple)
    release_history: tuple[ReleaseHistoryEntry, ...] = field(default_factory=tuple)
    special_releases: tuple[ReleasePolicyEntry, ...] = field(default_factory=tuple)
    supported_releases: tuple[ReleasePolicyEntry, ...] = field(default_factory=tuple)
    excluded_for_existing_devices: tuple[ReleasePolicyEntry, ...] = field(default_factory=tuple)
    supported_build_families: Mapping[int, str] = field(default_factory=dict)
    quality_baselines: Mapping[str, Any] = field(default_factory=dict)
    preview_builds: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    out_of_band_builds: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    known_notes: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    validation_warnings: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = 1
    min_reader_schema_version: int | None = None
    max_reader_schema_version: int | None = None
    api_version: str | None = None
    compatibility: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "quality_policy", _quality_policy(self.quality_policy))
        object.__setattr__(self, "source_urls", tuple(str(url) for url in self.source_urls))
        object.__setattr__(
            self,
            "published_urls",
            {str(key): str(value) for key, value in dict(self.published_urls or {}).items()},
        )
        object.__setattr__(self, "source_fetch_status", dict(self.source_fetch_status))
        object.__setattr__(self, "source_diagnostics", dict(self.source_diagnostics))
        object.__setattr__(self, "current_versions", tuple(self.current_versions))
        object.__setattr__(self, "release_history", tuple(self.release_history))
        object.__setattr__(self, "special_releases", tuple(self.special_releases))
        object.__setattr__(self, "supported_releases", tuple(self.supported_releases))
        object.__setattr__(self, "excluded_for_existing_devices", tuple(self.excluded_for_existing_devices))
        object.__setattr__(self, "quality_baselines", dict(self.quality_baselines))
        object.__setattr__(self, "schema_version", int(self.schema_version))
        object.__setattr__(
            self,
            "min_reader_schema_version",
            int(self.min_reader_schema_version) if self.min_reader_schema_version is not None else None,
        )
        object.__setattr__(
            self,
            "max_reader_schema_version",
            int(self.max_reader_schema_version) if self.max_reader_schema_version is not None else None,
        )
        object.__setattr__(self, "api_version", _optional_str(self.api_version))
        object.__setattr__(self, "compatibility", dict(self.compatibility))
        object.__setattr__(self, "preview_builds", tuple(dict(item) for item in self.preview_builds))
        object.__setattr__(self, "out_of_band_builds", tuple(dict(item) for item in self.out_of_band_builds))
        object.__setattr__(self, "known_notes", tuple(dict(item) for item in self.known_notes))
        object.__setattr__(
            self,
            "validation_warnings",
            tuple(str(warning) for warning in self.validation_warnings),
        )
        if self.supported_build_families:
            build_map = {
                int(key): str(value).upper()
                for key, value in dict(self.supported_build_families).items()
            }
        else:
            build_map = {
                int(entry.build_family): entry.version.upper()
                for entry in self.current_versions
            }
        object.__setattr__(self, "supported_build_families", build_map)

    def release_for_build_family(self, build_family: int | None) -> str | None:
        if build_family is None:
            return None
        return self.supported_build_families.get(int(build_family))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "min_reader_schema_version": self.min_reader_schema_version,
            "max_reader_schema_version": self.max_reader_schema_version,
            "api_version": self.api_version,
            "compatibility": dict(self.compatibility),
            "generated_at_utc": self.generated_at_utc,
            "source": dict(self.source),
            "source_urls": list(self.source_urls),
            "published_urls": dict(self.published_urls),
            "generator_version": self.generator_version,
            "source_fetch_status": dict(self.source_fetch_status),
            "source_diagnostics": dict(self.source_diagnostics),
            "quality_policy": self.quality_policy.value,
            "broad_target_existing_devices": (
                self.broad_target_existing_devices.to_dict()
                if self.broad_target_existing_devices
                else None
            ),
            "current_versions": [entry.to_dict() for entry in self.current_versions],
            "release_history": [entry.to_dict() for entry in self.release_history],
            "special_releases": [entry.to_dict() for entry in self.special_releases],
            "supported_releases": [entry.to_dict() for entry in self.supported_releases],
            "excluded_for_existing_devices": [
                entry.to_dict() for entry in self.excluded_for_existing_devices
            ],
            "supported_build_families": {
                str(key): value for key, value in self.supported_build_families.items()
            },
            "quality_baselines": dict(self.quality_baselines),
            "preview_builds": [dict(item) for item in self.preview_builds],
            "out_of_band_builds": [dict(item) for item in self.out_of_band_builds],
            "known_notes": [dict(item) for item in self.known_notes],
            "validation_warnings": list(self.validation_warnings),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ReleasePolicy":
        broad_data = data.get("broad_target_existing_devices")
        current_versions = tuple(
            ReleasePolicyEntry.from_dict(item)
            for item in data.get("current_versions", [])
        )
        release_history = tuple(
            ReleaseHistoryEntry.from_dict(item)
            for item in data.get("release_history", [])
        )
        special_releases = tuple(
            ReleasePolicyEntry.from_dict(item)
            for item in data.get("special_releases", [])
        )
        return cls(
            generated_at_utc=_optional_str(data.get("generated_at_utc")),
            source=dict(data.get("source") or {}),
            source_urls=tuple(str(url) for url in data.get("source_urls", [])),
            published_urls={
                str(key): str(value)
                for key, value in dict(data.get("published_urls") or {}).items()
            },
            generator_version=_optional_str(data.get("generator_version")),
            source_fetch_status=dict(data.get("source_fetch_status") or {}),
            source_diagnostics=dict(data.get("source_diagnostics") or {}),
            quality_policy=_quality_policy(data.get("quality_policy")),
            broad_target_existing_devices=(
                ReleasePolicyEntry.from_dict(broad_data) if broad_data else None
            ),
            current_versions=current_versions,
            release_history=release_history,
            special_releases=special_releases,
            supported_releases=tuple(
                ReleasePolicyEntry.from_dict(item)
                for item in data.get("supported_releases", [])
            ),
            excluded_for_existing_devices=tuple(
                ReleasePolicyEntry.from_dict(item)
                for item in data.get("excluded_for_existing_devices", [])
            ),
            supported_build_families={
                int(key): str(value).upper()
                for key, value in dict(data.get("supported_build_families") or {}).items()
            },
            quality_baselines=dict(data.get("quality_baselines") or {}),
            preview_builds=tuple(dict(item) for item in data.get("preview_builds", [])),
            out_of_band_builds=tuple(dict(item) for item in data.get("out_of_band_builds", [])),
            known_notes=tuple(dict(item) for item in data.get("known_notes", [])),
            validation_warnings=tuple(
                str(warning) for warning in data.get("validation_warnings", [])
            ),
            metadata=dict(data.get("metadata") or {}),
            schema_version=int(data.get("schema_version", 1)),
            min_reader_schema_version=(
                int(data["min_reader_schema_version"])
                if data.get("min_reader_schema_version") is not None
                else None
            ),
            max_reader_schema_version=(
                int(data["max_reader_schema_version"])
                if data.get("max_reader_schema_version") is not None
                else None
            ),
            api_version=_optional_str(data.get("api_version")),
            compatibility=dict(data.get("compatibility") or {}),
        )


@dataclass(frozen=True)
class EvaluationResult:
    """Serializable result returned by the evaluator."""

    status: EvaluationStatus
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
            policy_source_url=_optional_str(data.get("policy_source_url")),
            policy_source_kind=_optional_str(data.get("policy_source_kind")),
            policy_signature_status=_optional_str(data.get("policy_signature_status")),
            strict_production=bool(data.get("strict_production", False)),
            target_selection_reason=_optional_str(data.get("target_selection_reason")),
            warnings=tuple(str(item) for item in data.get("warnings", [])),
            errors=tuple(str(item) for item in data.get("errors", [])),
            source_problems=tuple(_source_problem(item) for item in data.get("source_problems", [])),
        )
