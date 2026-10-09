"""Data models for the signed release policy."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping
from .model_types import (
    EditionScope,
    QualityPolicy,
    ServicingChannel,
    _edition_scopes,
    _optional_str,
    _quality_policy,
    _servicing_channel,
)


@dataclass(frozen=True)
class ReleasePolicyEntry:
    """One release row from a generated policy feed."""

    version: str
    build_family: int
    latest_build: str | None = None
    baseline_build: str | None = None
    required_baseline_build: str | None = None
    latest_observed_build: str | None = None
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
        latest_observed = _optional_str(self.latest_observed_build) or self.latest_build
        object.__setattr__(self, "latest_observed_build", latest_observed)
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
            latest_observed_build=_optional_str(data.get("latest_observed_build")),
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
