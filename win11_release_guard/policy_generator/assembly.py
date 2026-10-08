"""Building the signed release policy from Microsoft sources."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping
from ..config import DEFAULT_HTTP_TIMEOUT_SECONDS, DEFAULT_PUBLISHED_POLICY_URLS, DEFAULT_RELEASE_HEALTH_URL
from ..evaluator import select_broad_fleet_target
from ..exceptions import PolicyError, PolicyParseError
from ..freshness import freshness_policy_metadata
from ..models import EditionScope, QualityPolicy, ReleaseHistoryEntry, ReleasePolicy, ReleasePolicyEntry, ServicingChannel
from ..policy_schema import GENERATOR_VERSION, SUPPORTED_POLICY_SCHEMA_VERSION, policy_document_to_json, validate_policy_document
from ..remote_policy import parse_windows11_release_health_html
from ..servicing_toc import parse_servicing_toc
from .baseline_notice import (
    _baseline_notice_is_active,
    _baseline_update_notice_payload,
    _baseline_update_notice_record,
    _required_baseline_history_row,
)
from .constants import DEFAULT_MAX_SERVICING_TOC_BYTES, DEFAULT_SERVICING_TOC_URL
from .diagnostics import _known_notes, _source_diagnostics
from .msrc_cvrf import MsrcCvrfFetcher
from .observed import _entry_with_latest_observed_evidence, _latest_observed_atom_support_record
from .security_events import _msrc_cvrf_events, _msrc_cvrf_payloads, _support_articles_with_security
from .servicing_match import _enrich_history, _entry_with_special_flag, _quality_baselines
from .source_events import _source_input_event, _source_status, _windows_update_probe_events
from .sources import (
    AtomFeedEntry,
    WindowsUpdateProbe,
    _feed_entries_from_servicing_toc,
    load_source_text,
)
from .support_articles import SupportArticleFetcher
from .support_validation import (
    _records_for_support_article_enrichment,
    _release_history_enrichment_record,
    _support_article_enrichment_events,
    _support_article_enrichments,
)
from . import clock
from . import msrc_cvrf
from . import support_articles


def _entry_with_b_release_baseline(
    entry: ReleasePolicyEntry,
    quality_baselines: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> ReleasePolicyEntry:
    baseline = quality_baselines.get(entry.version, {}).get(QualityPolicy.B_RELEASE_ONLY.value)
    if not isinstance(baseline, Mapping):
        return entry
    build = baseline.get("build")
    if not build:
        return entry
    baseline_build = str(build)
    return replace(
        entry,
        baseline_build=baseline_build,
        required_baseline_build=baseline_build,
    )

def _policy_with_enrichment(
    base_policy: ReleasePolicy,
    *,
    release_history: tuple[ReleaseHistoryEntry, ...],
    atom_entries: tuple[AtomFeedEntry, ...],
    generated_at_utc: str,
    release_health_url: str,
    release_health_html: str,
    source_fetch_status: Mapping[str, Any],
    validation_warnings: tuple[str, ...],
    source_input_events: tuple[Mapping[str, Any], ...] = (),
    servicing_toc_url: str | None = None,
    servicing_toc_json: str | None = None,
    servicing_toc_entries: tuple[AtomFeedEntry, ...] = (),
    support_article_fetcher: SupportArticleFetcher | None = None,
    support_article_timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    msrc_cvrf_fetcher: MsrcCvrfFetcher | None = None,
    msrc_cvrf_timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    signature_status: str,
    published_urls: Mapping[str, str] | None = None,
) -> ReleasePolicy:
    quality_baselines = _quality_baselines(release_history)
    special_releases = tuple(
        _entry_with_b_release_baseline(_entry_with_special_flag(entry), quality_baselines)
        for entry in base_policy.special_releases
    )
    excluded = tuple(
        _entry_with_b_release_baseline(_entry_with_special_flag(entry), quality_baselines)
        for entry in base_policy.excluded_for_existing_devices
    )
    current_versions = tuple(
        _entry_with_b_release_baseline(_entry_with_special_flag(entry), quality_baselines)
        for entry in base_policy.current_versions
    )
    preview_builds = tuple(row.to_dict() for row in release_history if row.preview)
    out_of_band_builds = tuple(row.to_dict() for row in release_history if row.out_of_band)
    source_urls = [release_health_url]
    if servicing_toc_url and servicing_toc_json:
        source_urls.append(servicing_toc_url)

    target = base_policy.broad_target_existing_devices
    if target is not None:
        baseline_found = False
        baseline = quality_baselines.get(target.version, {}).get(QualityPolicy.B_RELEASE_ONLY.value)
        if isinstance(baseline, Mapping):
            build = baseline.get("build")
            if build:
                baseline_found = True
                baseline_build = str(build)
                target = replace(
                    target,
                    baseline_build=baseline_build,
                    required_baseline_build=baseline_build,
                )
        if not baseline_found:
            raise PolicyParseError(
                "Could not select B-release required baseline for broad_target_existing_devices "
                f"{target.version}/{target.build_family} from Release Health release_history."
            )
        observed_record, observed_source_events = _latest_observed_atom_support_record(
            target,
            atom_entries,
            release_history,
        )
        if observed_record is not None:
            target = _entry_with_latest_observed_evidence(target, observed_record)
            current_versions = tuple(
                _entry_with_latest_observed_evidence(entry, observed_record)
                if entry.version == target.version and entry.build_family == target.build_family
                else entry
                for entry in current_versions
            )
            source_input_events = (*source_input_events, *observed_source_events)
        else:
            source_input_events = (*source_input_events, *observed_source_events)
    else:
        observed_record = None

    baseline_update_row = _required_baseline_history_row(target, release_history)
    baseline_update_record = _baseline_update_notice_record(target, baseline_update_row)
    baseline_notice_active = _baseline_notice_is_active(
        baseline_update_row, generated_at_utc=generated_at_utc
    )
    baseline_update_enrichment_record = (
        baseline_update_record
        if baseline_update_record is not None and baseline_notice_active
        else None
    )
    release_history_enrichment_record = (
        _release_history_enrichment_record(target, release_history)
        if baseline_notice_active
        else None
    )
    support_article_records = _records_for_support_article_enrichment(
        target=target,
        atom_entries=atom_entries,
        release_history=release_history,
        observed_record=observed_record,
        baseline_update_record=baseline_update_enrichment_record,
        release_history_record=release_history_enrichment_record,
    )
    support_articles = _support_article_enrichments(
        support_article_records,
        fetcher=support_article_fetcher,
        timeout=support_article_timeout,
    )
    msrc_payloads, msrc_cvrf_statuses = _msrc_cvrf_payloads(
        support_article_records,
        fetcher=msrc_cvrf_fetcher,
        timeout=msrc_cvrf_timeout,
    )
    support_articles = _support_articles_with_security(
        support_article_records,
        support_articles,
        msrc_payloads=msrc_payloads,
        msrc_statuses=msrc_cvrf_statuses,
    )
    source_input_events = (
        *source_input_events,
        *_support_article_enrichment_events(support_article_records, support_articles, target),
        *_msrc_cvrf_events(support_article_records, msrc_cvrf_statuses, target),
    )
    baseline_update_notice = _baseline_update_notice_payload(
        target=target,
        row=baseline_update_row,
        baseline_record=baseline_update_record,
        support_articles=support_articles,
        msrc_payloads=msrc_payloads,
        msrc_statuses=msrc_cvrf_statuses,
        generated_at_utc=generated_at_utc,
    )

    metadata = dict(base_policy.metadata)
    metadata["signature_status"] = signature_status
    metadata["generator"] = GENERATOR_VERSION
    metadata["freshness_policy"] = freshness_policy_metadata()
    parser_source = base_policy.source_diagnostics.get("parser")
    parser_diagnostics: tuple[Mapping[str, Any], ...] = ()
    if isinstance(parser_source, Mapping):
        parser_events = parser_source.get("events")
        if isinstance(parser_events, list):
            parser_diagnostics = tuple(item for item in parser_events if isinstance(item, Mapping))
    # No support-article or MSRC CVRF fetcher configured for this run at all (as opposed to a
    # fetcher that simply found nothing to fetch, or a record deliberately excluded from
    # enrichment) — the only condition under which _atom_newer_event's date-only
    # msrc_cvrf_month_id fallback is allowed to fire. This keeps production runs, which always
    # configure real fetchers, emitting exactly the diagnostics payload they emitted before
    # that fallback existed.
    msrc_month_id_fallback_allowed = support_article_fetcher is None and msrc_cvrf_fetcher is None
    source_diagnostics = _source_diagnostics(
        current_versions=current_versions,
        release_history=release_history,
        atom_entries=atom_entries,
        support_articles=support_articles,
        msrc_cvrf_statuses=msrc_cvrf_statuses,
        baseline_update_notice=baseline_update_notice,
        broad_target=target,
        parser_diagnostics=parser_diagnostics,
        source_input_events=source_input_events,
        source_fetch_status=source_fetch_status,
        release_health_url=release_health_url,
        release_health_html=release_health_html,
        generated_at_utc=generated_at_utc,
        servicing_toc_url=servicing_toc_url,
        servicing_toc_json=servicing_toc_json,
        servicing_toc_entries=servicing_toc_entries,
        msrc_month_id_fallback_allowed=msrc_month_id_fallback_allowed,
    )
    combined_warnings = tuple(
        dict.fromkeys([*validation_warnings, *source_diagnostics.get("warnings", [])])
    )

    enriched = replace(
        base_policy,
        schema_version=SUPPORTED_POLICY_SCHEMA_VERSION,
        min_reader_schema_version=SUPPORTED_POLICY_SCHEMA_VERSION,
        max_reader_schema_version=SUPPORTED_POLICY_SCHEMA_VERSION,
        api_version="v1",
        compatibility={
            "additive_unknown_top_level_keys": "warning",
            "extension_namespaces": ["extensions", "x_*"],
            "required_core_schema_version": SUPPORTED_POLICY_SCHEMA_VERSION,
        },
        generated_at_utc=generated_at_utc,
        generator_version=GENERATOR_VERSION,
        source_urls=tuple(source_urls),
        published_urls=dict(published_urls or DEFAULT_PUBLISHED_POLICY_URLS),
        source_fetch_status=dict(source_fetch_status),
        source_diagnostics=source_diagnostics,
        current_versions=current_versions,
        release_history=release_history,
        special_releases=special_releases,
        supported_releases=current_versions,
        excluded_for_existing_devices=excluded,
        broad_target_existing_devices=target,
        quality_baselines=quality_baselines,
        preview_builds=preview_builds,
        out_of_band_builds=out_of_band_builds,
        known_notes=_known_notes(replace(base_policy, special_releases=special_releases)),
        validation_warnings=combined_warnings,
        metadata=metadata,
    )
    _raise_on_client_target_disagreement(enriched)
    return enriched

_CLIENT_TARGET_AGREEMENT_SCOPES = (
    EditionScope.UNKNOWN,
    EditionScope.HOME_PRO,
    EditionScope.ENTERPRISE_EDUCATION,
)

def _raise_on_client_target_disagreement(policy: ReleasePolicy) -> None:
    """Refuse to publish a feed whose runtime target selection disagrees with the signed target.

    Runtime clients re-derive their General Availability target from ``current_versions``
    instead of reading ``broad_target_existing_devices``, so both selections must agree.
    """

    target = policy.broad_target_existing_devices
    if target is None:
        return
    for scope in _CLIENT_TARGET_AGREEMENT_SCOPES:
        try:
            selected = select_broad_fleet_target(
                policy,
                edition_scope=scope,
                servicing_channel=ServicingChannel.GENERAL_AVAILABILITY,
            )
        except PolicyError as exc:
            raise PolicyParseError(
                f"Runtime clients cannot select a broad target for {scope.value} devices: {exc}"
            ) from exc
        if (selected.version, selected.build_family) != (target.version, target.build_family):
            raise PolicyParseError(
                f"Runtime clients would select {selected.version}/{selected.build_family} for {scope.value} "
                f"devices, but broad_target_existing_devices is {target.version}/{target.build_family}; "
                "refusing to publish a policy with a split target."
            )

def generate_policy(
    *,
    release_health_html: str,
    release_health_url: str = DEFAULT_RELEASE_HEALTH_URL,
    servicing_toc_json: str | None = None,
    servicing_toc_url: str | None = DEFAULT_SERVICING_TOC_URL,
    generated_at_utc: str | None = None,
    signature_status: str = "unsigned",
    source_fetch_status: Mapping[str, Any] | None = None,
    support_article_fetcher: SupportArticleFetcher | None = None,
    support_article_timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    msrc_cvrf_fetcher: MsrcCvrfFetcher | None = None,
    msrc_cvrf_timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    published_urls: Mapping[str, str] | None = None,
    windows_update_probe: WindowsUpdateProbe | None = None,
) -> ReleasePolicy:
    warnings: list[str] = []
    source_input_events: list[dict[str, Any]] = []
    generated = generated_at_utc or clock.utc_now()
    effective_source_fetch_status: dict[str, Any] = {
        "release_health_html": _source_status(
            source_fetch_status or {},
            "release_health_html",
            source_url=release_health_url,
            text=release_health_html,
            generated_at_utc=generated,
        ),
    }
    effective_source_fetch_status["servicing_toc"] = _source_status(
        source_fetch_status or {},
        "servicing_toc",
        source_url=servicing_toc_url,
        text=servicing_toc_json,
        generated_at_utc=generated,
    )
    base_policy = parse_windows11_release_health_html(release_health_html)
    servicing_entries: tuple[AtomFeedEntry, ...] = ()
    if servicing_toc_json:
        try:
            servicing_entries = _feed_entries_from_servicing_toc(parse_servicing_toc(servicing_toc_json))
        except PolicyParseError as exc:
            message = f"Servicing TOC could not be parsed: {exc}"
            warnings.append(message)
            source_input_events.append(_source_input_event("servicing_toc_parse_failed", message))
        if not servicing_entries:
            message = "Servicing TOC contained no usable entries."
            warnings.append(message)
            source_input_events.append(_source_input_event("servicing_toc_no_usable_entries", message))
    else:
        message = "Servicing TOC missing; preview/out-of-band enrichment unavailable."
        warnings.append(message)
        source_input_events.append(_source_input_event("servicing_toc_missing", message))

    source_input_events.extend(_windows_update_probe_events(windows_update_probe))

    release_history = _enrich_history(base_policy.release_history, servicing_entries)
    policy = _policy_with_enrichment(
        base_policy,
        release_history=release_history,
        atom_entries=servicing_entries,
        generated_at_utc=generated,
        release_health_url=release_health_url,
        release_health_html=release_health_html,
        source_fetch_status=effective_source_fetch_status,
        validation_warnings=tuple(dict.fromkeys(warnings)),
        source_input_events=tuple(source_input_events),
        servicing_toc_url=servicing_toc_url,
        servicing_toc_json=servicing_toc_json,
        servicing_toc_entries=servicing_entries,
        support_article_fetcher=support_article_fetcher,
        support_article_timeout=support_article_timeout,
        msrc_cvrf_fetcher=msrc_cvrf_fetcher,
        msrc_cvrf_timeout=msrc_cvrf_timeout,
        signature_status=signature_status,
        published_urls=published_urls,
    )
    validate_policy_document(policy.to_dict())
    return policy

def generate_policy_json(**kwargs: Any) -> str:
    policy = generate_policy(**kwargs)
    return policy_document_to_json(policy.to_dict())

def build_policy_from_sources(
    *,
    release_health_url: str = DEFAULT_RELEASE_HEALTH_URL,
    release_health_html_path: str | Path | None = None,
    servicing_toc_url: str = DEFAULT_SERVICING_TOC_URL,
    servicing_toc_path: str | Path | None = None,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    signature_status: str = "unsigned",
    support_article_fetcher: SupportArticleFetcher | None = None,
    msrc_cvrf_fetcher: MsrcCvrfFetcher | None = None,
    windows_update_probe: WindowsUpdateProbe | None = None,
) -> ReleasePolicy:
    release_health = load_source_text(
        url=release_health_url,
        fixture_path=release_health_html_path,
        source_name="release_health_html",
        timeout=timeout,
        required=True,
    )
    servicing_toc = load_source_text(
        url=servicing_toc_url,
        fixture_path=servicing_toc_path,
        source_name="servicing_toc",
        timeout=timeout,
        required=False,
        charset="utf-8",
        max_bytes=DEFAULT_MAX_SERVICING_TOC_BYTES,
    )
    source_fetch_status = {
        "release_health_html": dict(release_health.status),
        "servicing_toc": dict(servicing_toc.status),
    }
    return generate_policy(
        release_health_html=release_health.text,
        release_health_url=release_health_url,
        servicing_toc_json=servicing_toc.text or None,
        servicing_toc_url=servicing_toc_url,
        source_fetch_status=source_fetch_status,
        support_article_fetcher=support_article_fetcher or support_articles.default_support_article_fetcher,
        support_article_timeout=timeout,
        msrc_cvrf_fetcher=msrc_cvrf_fetcher or msrc_cvrf.default_msrc_cvrf_fetcher,
        msrc_cvrf_timeout=timeout,
        signature_status=signature_status,
        windows_update_probe=windows_update_probe,
    )
