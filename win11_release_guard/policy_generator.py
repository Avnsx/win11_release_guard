from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Mapping
from xml.etree import ElementTree

from .config import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    DEFAULT_POLICY_URL,
    DEFAULT_RELEASE_HEALTH_URL,
    DEFAULT_TRUSTED_POLICY_KEY_ID,
    DEFAULT_USER_AGENT,
)
from .exceptions import PolicyFetchError, PolicyParseError
from .models import QualityPolicy, ReleaseHistoryEntry, ReleasePolicy, ReleasePolicyEntry
from .policy_schema import GENERATOR_VERSION, policy_document_to_json, validate_policy_document
from .remote_policy import parse_windows11_release_health_html
from .signing import sign_policy_bytes as sign_ed25519_policy_bytes


DEFAULT_WINDOWS11_ATOM_FEED_URL = "https://support.microsoft.com/en-us/feed/atom/4ec863cc-2ecd-e187-6cb3-b50c6545db92"


@dataclass(frozen=True)
class SourceText:
    text: str
    status: Mapping[str, Any]


@dataclass(frozen=True)
class AtomFeedEntry:
    title: str
    link: str | None = None
    published: str | None = None
    updated: str | None = None
    content: str | None = None
    kb_article: str | None = None
    builds: tuple[str, ...] = ()
    preview: bool = False
    out_of_band: bool = False


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _fetch_url(url: str, *, timeout: float) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/atom+xml,application/xml,text/xml",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset, errors="replace")


def load_source_text(
    *,
    url: str,
    fixture_path: str | Path | None = None,
    source_name: str,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    required: bool = True,
) -> SourceText:
    if fixture_path is not None:
        path = Path(fixture_path)
        try:
            text = path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            if required:
                raise PolicyFetchError(f"{source_name} source failure: could not read {path}: {exc}") from exc
            return SourceText(
                text="",
                status={
                    "url": url,
                    "source": "fixture",
                    "path": str(path),
                    "status": "error",
                    "error": str(exc),
                },
            )
        return SourceText(
            text=text,
            status={
                "url": url,
                "source": "fixture",
                "path": str(path),
                "status": "ok",
                "bytes": len(text.encode("utf-8")),
            },
        )

    try:
        text = _fetch_url(url, timeout=timeout)
    except Exception as exc:
        if required:
            raise PolicyFetchError(f"{source_name} source failure: could not fetch {url}: {exc}") from exc
        return SourceText(
            text="",
            status={
                "url": url,
                "source": "network",
                "status": "error",
                "error": str(exc),
            },
        )
    return SourceText(
        text=text,
        status={
            "url": url,
            "source": "network",
            "status": "ok",
            "bytes": len(text.encode("utf-8")),
        },
    )


def _text(element: ElementTree.Element, name: str, ns: Mapping[str, str]) -> str | None:
    child = element.find(name, ns)
    if child is None or child.text is None:
        return None
    text = re.sub(r"\s+", " ", child.text).strip()
    return text or None


def _link(element: ElementTree.Element, ns: Mapping[str, str]) -> str | None:
    for link in element.findall("atom:link", ns):
        href = link.attrib.get("href")
        if href:
            return href
    return None


def _extract_kb(text: str | None) -> str | None:
    match = re.search(r"\bKB\d{6,8}\b", text or "", flags=re.IGNORECASE)
    return match.group(0).upper() if match else None


def _extract_builds(text: str | None) -> tuple[str, ...]:
    return tuple(dict.fromkeys(re.findall(r"\b\d{5}\.\d+\b", text or "")))


def _is_preview(text: str) -> bool:
    return "preview" in text.lower()


def _is_out_of_band(text: str) -> bool:
    normalized = text.lower().replace("_", "-")
    return "out-of-band" in normalized or "out of band" in normalized or re.search(r"\boob\b", normalized) is not None


def parse_atom_feed(xml_text: str) -> tuple[AtomFeedEntry, ...]:
    if not xml_text.strip():
        return ()

    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise PolicyParseError(f"Atom feed is malformed: {exc}") from exc

    ns = {"atom": "http://www.w3.org/2005/Atom"}
    entries = root.findall("atom:entry", ns)
    if not entries:
        entries = root.findall("entry")

    parsed: list[AtomFeedEntry] = []
    for entry in entries:
        title = _text(entry, "atom:title", ns) or _text(entry, "title", ns) or ""
        content = _text(entry, "atom:content", ns) or _text(entry, "content", ns)
        published = _text(entry, "atom:published", ns) or _text(entry, "published", ns)
        updated = _text(entry, "atom:updated", ns) or _text(entry, "updated", ns)
        link = _link(entry, ns)
        blob = " ".join(part for part in (title, content or "") if part)
        kb_article = _extract_kb(blob)
        parsed.append(
            AtomFeedEntry(
                title=title,
                link=link,
                published=published,
                updated=updated,
                content=content,
                kb_article=kb_article,
                builds=_extract_builds(blob),
                preview=_is_preview(blob),
                out_of_band=_is_out_of_band(blob),
            )
        )
    return tuple(parsed)


def _release_key(release: str | None) -> tuple[int, int]:
    match = re.fullmatch(r"(\d{2})H([12])", release or "", flags=re.IGNORECASE)
    if not match:
        return (-1, -1)
    return int(match.group(1)), int(match.group(2))


def _build_key(build: str | None) -> tuple[int, int]:
    if not build:
        return (-1, -1)
    try:
        major, minor = str(build).split(".", 1)
        return int(major), int(minor)
    except ValueError:
        return (-1, -1)


def _history_sort_key(row: ReleaseHistoryEntry) -> tuple[str, tuple[int, int]]:
    return row.availability_date or "", _build_key(row.build)


def _kb_url(kb_article: str | None, feed_entry: AtomFeedEntry | None = None) -> str | None:
    if feed_entry and feed_entry.link:
        return feed_entry.link
    kb = _extract_kb(kb_article)
    if not kb:
        return None
    return f"https://support.microsoft.com/help/{kb[2:]}"


def _catalog_url(kb_article: str | None) -> str | None:
    kb = _extract_kb(kb_article)
    if not kb:
        return None
    return f"https://www.catalog.update.microsoft.com/Search.aspx?q={kb}"


def _match_atom(row: ReleaseHistoryEntry, entries: tuple[AtomFeedEntry, ...]) -> AtomFeedEntry | None:
    row_kb = _extract_kb(row.kb_article)
    if row_kb:
        for entry in entries:
            if entry.kb_article == row_kb:
                return entry
    for entry in entries:
        if row.build in entry.builds:
            return entry
    return None


def _enrich_history(
    release_history: tuple[ReleaseHistoryEntry, ...],
    atom_entries: tuple[AtomFeedEntry, ...],
) -> tuple[ReleaseHistoryEntry, ...]:
    enriched: list[ReleaseHistoryEntry] = []
    for row in release_history:
        atom_entry = _match_atom(row, atom_entries)
        preview = row.preview or bool(atom_entry and atom_entry.preview)
        out_of_band = row.out_of_band or bool(atom_entry and atom_entry.out_of_band)
        update_type_letter = row.update_type_letter
        if out_of_band:
            update_type_letter = "OOB"
        elif preview and not update_type_letter:
            update_type_letter = "D"

        metadata = dict(row.metadata)
        if atom_entry:
            metadata.update(
                {
                    "atom_enriched": True,
                    "atom_feed_title": atom_entry.title,
                    "atom_feed_url": atom_entry.link,
                    "atom_published": atom_entry.published,
                    "atom_updated": atom_entry.updated,
                }
            )

        enriched.append(
            replace(
                row,
                preview=preview,
                out_of_band=out_of_band,
                update_type_letter=update_type_letter,
                kb_url=_kb_url(row.kb_article, atom_entry) or row.kb_url,
                catalog_url=_catalog_url(row.kb_article) or row.catalog_url,
                metadata=metadata,
            )
        )
    return tuple(enriched)


def _entry_with_special_flag(entry: ReleasePolicyEntry) -> ReleasePolicyEntry:
    metadata = dict(entry.metadata)
    if metadata.get("not_broad_target"):
        metadata["not_broad_target_existing_devices"] = True
    return replace(entry, metadata=metadata)


def _baseline_for(
    rows: tuple[ReleaseHistoryEntry, ...],
    release: str,
    policy: QualityPolicy,
) -> ReleaseHistoryEntry | None:
    release_rows = [row for row in rows if row.release == release.upper()]
    if policy is QualityPolicy.B_RELEASE_ONLY:
        candidates = [
            row
            for row in release_rows
            if row.update_type_letter == "B" and not row.preview
        ]
    elif policy is QualityPolicy.LATEST_NON_PREVIEW:
        candidates = [row for row in release_rows if not row.preview]
    else:
        candidates = release_rows
    if not candidates:
        return None
    return max(candidates, key=_history_sort_key)


def _quality_baselines(release_history: tuple[ReleaseHistoryEntry, ...]) -> dict[str, dict[str, dict[str, Any]]]:
    releases = sorted({row.release for row in release_history}, key=_release_key)
    baselines: dict[str, dict[str, dict[str, Any]]] = {}
    for release in releases:
        release_baselines: dict[str, dict[str, Any]] = {}
        for policy in (
            QualityPolicy.B_RELEASE_ONLY,
            QualityPolicy.LATEST_NON_PREVIEW,
            QualityPolicy.LATEST_ANYTHING,
        ):
            baseline = _baseline_for(release_history, release, policy)
            if baseline is not None:
                release_baselines[policy.value] = baseline.to_dict()
        if release_baselines:
            baselines[release] = release_baselines
    return baselines


def _known_notes(policy: ReleasePolicy) -> tuple[dict[str, Any], ...]:
    notes: list[dict[str, Any]] = []
    for entry in policy.special_releases:
        flags = [
            flag
            for flag in (
                "special_release",
                "new_devices_only",
                "not_broad_target_existing_devices",
            )
            if entry.metadata.get(flag)
        ]
        notes.append(
            {
                "type": "special_release",
                "release": entry.version,
                "build_family": entry.build_family,
                "note": entry.reason,
                "flags": flags,
            }
        )
    return tuple(notes)


def _policy_with_enrichment(
    base_policy: ReleasePolicy,
    *,
    release_history: tuple[ReleaseHistoryEntry, ...],
    generated_at_utc: str,
    release_health_url: str,
    atom_feed_url: str | None,
    source_fetch_status: Mapping[str, Any],
    validation_warnings: tuple[str, ...],
    signature_status: str,
) -> ReleasePolicy:
    special_releases = tuple(_entry_with_special_flag(entry) for entry in base_policy.special_releases)
    excluded = tuple(_entry_with_special_flag(entry) for entry in base_policy.excluded_for_existing_devices)
    current_versions = tuple(
        _entry_with_special_flag(entry)
        for entry in base_policy.current_versions
    )
    quality_baselines = _quality_baselines(release_history)
    preview_builds = tuple(row.to_dict() for row in release_history if row.preview)
    out_of_band_builds = tuple(row.to_dict() for row in release_history if row.out_of_band)
    source_urls = [release_health_url]
    if atom_feed_url:
        source_urls.append(atom_feed_url)

    target = base_policy.broad_target_existing_devices
    if target is not None:
        baseline = quality_baselines.get(target.version, {}).get(QualityPolicy.B_RELEASE_ONLY.value)
        if isinstance(baseline, Mapping):
            target = replace(target, baseline_build=str(baseline.get("build")))

    metadata = dict(base_policy.metadata)
    metadata["signature_status"] = signature_status
    metadata["generator"] = GENERATOR_VERSION

    enriched = replace(
        base_policy,
        schema_version=1,
        generated_at_utc=generated_at_utc,
        generator_version=GENERATOR_VERSION,
        source_urls=tuple(source_urls),
        source_fetch_status=dict(source_fetch_status),
        current_versions=current_versions,
        release_history=release_history,
        special_releases=special_releases,
        excluded_for_existing_devices=excluded,
        broad_target_existing_devices=target,
        quality_baselines=quality_baselines,
        preview_builds=preview_builds,
        out_of_band_builds=out_of_band_builds,
        known_notes=_known_notes(replace(base_policy, special_releases=special_releases)),
        validation_warnings=validation_warnings,
        metadata=metadata,
    )
    return enriched


def generate_policy(
    *,
    release_health_html: str,
    atom_feed_xml: str | None = None,
    release_health_url: str = DEFAULT_RELEASE_HEALTH_URL,
    atom_feed_url: str | None = DEFAULT_WINDOWS11_ATOM_FEED_URL,
    generated_at_utc: str | None = None,
    signature_status: str = "unsigned",
    source_fetch_status: Mapping[str, Any] | None = None,
) -> ReleasePolicy:
    warnings: list[str] = []
    base_policy = parse_windows11_release_health_html(release_health_html)
    atom_entries: tuple[AtomFeedEntry, ...] = ()
    if atom_feed_xml:
        try:
            atom_entries = parse_atom_feed(atom_feed_xml)
        except PolicyParseError as exc:
            warnings.append(f"Atom feed could not be parsed: {exc}")
    else:
        warnings.append("Atom feed missing; preview/out-of-band enrichment unavailable.")

    if atom_feed_xml and not atom_entries:
        warnings.append("Atom feed contained no usable entries.")

    release_history = _enrich_history(base_policy.release_history, atom_entries)
    policy = _policy_with_enrichment(
        base_policy,
        release_history=release_history,
        generated_at_utc=generated_at_utc or _utc_now(),
        release_health_url=release_health_url,
        atom_feed_url=atom_feed_url,
        source_fetch_status=source_fetch_status or {},
        validation_warnings=tuple(dict.fromkeys(warnings)),
        signature_status=signature_status,
    )
    validate_policy_document(policy.to_dict())
    return policy


def generate_policy_json(**kwargs: Any) -> str:
    policy = generate_policy(**kwargs)
    return policy_document_to_json(policy.to_dict())


def sign_policy_bytes(
    data: bytes,
    signing_key: str | bytes,
    *,
    key_id: str = DEFAULT_TRUSTED_POLICY_KEY_ID,
) -> dict[str, str]:
    signature = sign_ed25519_policy_bytes(data, signing_key, key_id=key_id)
    signature["signed_at_utc"] = _utc_now()
    return signature


def write_policy_outputs(
    policy: ReleasePolicy,
    *,
    output_dir: str | Path,
    signing_key: str | bytes | None = None,
    key_id: str = DEFAULT_TRUSTED_POLICY_KEY_ID,
    write_index: bool = False,
    write_robots: bool = False,
    write_sitemap: bool = False,
    write_manifest: bool = False,
) -> dict[str, Path]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    policy_file = output_path / "windows-release-policy.json"
    json_text = policy_document_to_json(policy.to_dict())
    policy_file.write_bytes(json_text.encode("utf-8"))
    written = {"policy": policy_file}

    if signing_key:
        signature = sign_policy_bytes(json_text.encode("utf-8"), signing_key, key_id=key_id)
        signature_file = output_path / "windows-release-policy.json.sig"
        signature_file.write_bytes((json.dumps(signature, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        written["signature"] = signature_file

    if write_index:
        index_file = output_path / "index.html"
        index_file.write_text(render_policy_index(policy), encoding="utf-8")
        written["index"] = index_file

    if write_robots:
        robots_file = output_path / "robots.txt"
        robots_file.write_text(render_robots_txt(), encoding="utf-8", newline="\n")
        written["robots"] = robots_file

    if write_sitemap:
        sitemap_file = output_path / "sitemap.xml"
        sitemap_file.write_text(render_sitemap_xml(policy), encoding="utf-8", newline="\n")
        written["sitemap"] = sitemap_file

    if write_manifest:
        manifest_file = output_path / "manifest.json"
        manifest_file.write_text(render_policy_manifest(policy), encoding="utf-8", newline="\n")
        written["manifest"] = manifest_file

    return written


def _site_base_url(policy_url: str = DEFAULT_POLICY_URL) -> str:
    return policy_url.rsplit("/", 1)[0].rstrip("/")


def render_policy_index(policy: ReleasePolicy) -> str:
    target = policy.broad_target_existing_devices
    target_text = (
        f"{target.version} build {target.effective_baseline_build or target.latest_build}"
        if target
        else "unknown"
    )
    warnings = "".join(f"<li>{warning}</li>" for warning in policy.validation_warnings)
    return (
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        "<head><meta charset=\"utf-8\"><title>Windows release policy</title></head>\n"
        "<body>\n"
        "<h1>Windows release policy</h1>\n"
        f"<p>Generated at: {policy.generated_at_utc}</p>\n"
        f"<p>Broad target for existing devices: {target_text}</p>\n"
        f"<p>Generator: {policy.generator_version}</p>\n"
        "<h2>Warnings</h2>\n"
        f"<ul>{warnings}</ul>\n"
        "</body>\n"
        "</html>\n"
    )


def render_robots_txt(*, base_url: str = _site_base_url()) -> str:
    return (
        "User-agent: *\n"
        "Allow: /\n"
        f"Sitemap: {base_url}/sitemap.xml\n"
    )


def render_sitemap_xml(policy: ReleasePolicy, *, base_url: str = _site_base_url()) -> str:
    generated_at = escape(policy.generated_at_utc or _utc_now())
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
        "  <url>\n"
        f"    <loc>{escape(base_url)}/</loc>\n"
        f"    <lastmod>{generated_at}</lastmod>\n"
        "  </url>\n"
        "  <url>\n"
        f"    <loc>{escape(base_url)}/windows-release-policy.json</loc>\n"
        f"    <lastmod>{generated_at}</lastmod>\n"
        "  </url>\n"
        "  <url>\n"
        f"    <loc>{escape(base_url)}/windows-release-policy.json.sig</loc>\n"
        f"    <lastmod>{generated_at}</lastmod>\n"
        "  </url>\n"
        "</urlset>\n"
    )


def render_policy_manifest(policy: ReleasePolicy, *, base_url: str = _site_base_url()) -> str:
    target = policy.broad_target_existing_devices
    manifest = {
        "name": "win-release-guard policy feed",
        "generated_at_utc": policy.generated_at_utc,
        "generator_version": policy.generator_version,
        "policy_url": f"{base_url}/windows-release-policy.json",
        "signature_url": f"{base_url}/windows-release-policy.json.sig",
        "sitemap_url": f"{base_url}/sitemap.xml",
        "broad_target_existing_devices": (
            {
                "version": target.version,
                "build_family": target.build_family,
                "latest_build": target.latest_build,
                "baseline_build": target.effective_baseline_build,
            }
            if target
            else None
        ),
    }
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def build_policy_from_sources(
    *,
    release_health_url: str = DEFAULT_RELEASE_HEALTH_URL,
    atom_feed_url: str = DEFAULT_WINDOWS11_ATOM_FEED_URL,
    release_health_html_path: str | Path | None = None,
    atom_feed_path: str | Path | None = None,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    signature_status: str = "unsigned",
) -> ReleasePolicy:
    release_health = load_source_text(
        url=release_health_url,
        fixture_path=release_health_html_path,
        source_name="release_health_html",
        timeout=timeout,
        required=True,
    )
    atom_feed = load_source_text(
        url=atom_feed_url,
        fixture_path=atom_feed_path,
        source_name="atom_feed",
        timeout=timeout,
        required=False,
    )
    source_fetch_status = {
        "release_health_html": dict(release_health.status),
        "atom_feed": dict(atom_feed.status),
    }
    return generate_policy(
        release_health_html=release_health.text,
        atom_feed_xml=atom_feed.text or None,
        release_health_url=release_health_url,
        atom_feed_url=atom_feed_url,
        source_fetch_status=source_fetch_status,
        signature_status=signature_status,
    )


__all__ = [
    "DEFAULT_WINDOWS11_ATOM_FEED_URL",
    "AtomFeedEntry",
    "SourceText",
    "build_policy_from_sources",
    "generate_policy",
    "generate_policy_json",
    "load_source_text",
    "parse_atom_feed",
    "render_policy_index",
    "render_policy_manifest",
    "render_robots_txt",
    "render_sitemap_xml",
    "sign_policy_bytes",
    "write_policy_outputs",
]
