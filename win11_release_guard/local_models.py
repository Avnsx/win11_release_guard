"""Data models for local Windows state and local evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping
from .model_types import (
    BuildEvidenceSource,
    EditionScope,
    InstalledBuildClassification,
    ServicingChannel,
    _build_classification,
    _edition_scope,
    _evidence_source,
    _optional_bool,
    _optional_int,
    _optional_str,
    _servicing_channel,
)


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
