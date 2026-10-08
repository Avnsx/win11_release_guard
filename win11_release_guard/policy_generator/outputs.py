"""Writing the policy, signature, manifest, and every Pages page."""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Mapping
from ..config import DEFAULT_PAGES_BASE_URL, DEFAULT_TRUSTED_POLICY_KEY_ID
from ..freshness import freshness_policy_metadata, freshness_thresholds
from ..models import ReleasePolicy
from ..policy_schema import policy_document_to_json
from ..signing import sign_policy_bytes as sign_ed25519_policy_bytes
from .artifacts import (
    _public_verification_metadata,
    _sha256_hex,
    _write_public_artifact_bytes,
    _write_public_artifact_text,
)
from .pages.changelog import _changelog_sitemap_urls, _wiki_sitemap_urls, write_changelog_pages
from .constants import PAGES_TIMEZONE, PYPI_DOWNLOAD_IMAGE_PATH, ROBOTS_TXT
from .pages.dashboard import render_policy_index
from .pages.dashboard_text import _latest_observed_evidence_metadata, _status_text
from .diagnostic_ids import _signature_field
from .time_format import _generated_at_human
from .pages.wiki_page import write_wiki_pages
from . import clock


def sign_policy_bytes(
    data: bytes,
    signing_key: str | bytes,
    *,
    key_id: str = DEFAULT_TRUSTED_POLICY_KEY_ID,
) -> dict[str, str]:
    signature = sign_ed25519_policy_bytes(data, signing_key, key_id=key_id)
    signature["signed_at_utc"] = clock.utc_now()
    return signature

def _copy_pypi_download_image(output_dir: Path) -> Path:
    source_path = PYPI_DOWNLOAD_IMAGE_PATH
    if not source_path.is_file():
        raise FileNotFoundError(f"Required Pages image asset is missing: {source_path.as_posix()}")
    target_path = output_dir / PYPI_DOWNLOAD_IMAGE_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_path, target_path)
    return target_path

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
    generated_age_reference: datetime | None = None,
) -> dict[str, Path]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    policy_file = output_path / "windows-release-policy.json"
    json_text = policy_document_to_json(policy.to_dict())
    policy_bytes = json_text.encode("utf-8")
    _write_public_artifact_bytes(policy_file, policy_bytes)
    written = {"policy": policy_file}

    signature: dict[str, str] | None = None
    signature_bytes: bytes | None = None
    verification_metadata: dict[str, str] | None = None
    if signing_key:
        signature = sign_policy_bytes(policy_bytes, signing_key, key_id=key_id)
        verification_metadata = _public_verification_metadata(signature)
        signature_file = output_path / "windows-release-policy.json.sig"
        signature_bytes = (json.dumps(signature, indent=2, sort_keys=True) + "\n").encode("utf-8")
        _write_public_artifact_bytes(signature_file, signature_bytes)
        written["signature"] = signature_file

    manifest_text: str | None = None
    if write_index:
        index_file = output_path / "index.html"
        _write_public_artifact_text(
            index_file,
            render_policy_index(
                policy,
                policy_bytes=policy_bytes,
                verification_metadata=verification_metadata,
                generated_age_reference=generated_age_reference,
            ),
        )
        written["index"] = index_file
        written["asset:pypi_download"] = _copy_pypi_download_image(output_path)
        for relative_path, wiki_file in write_wiki_pages(output_path).items():
            written[f"wiki:{relative_path}"] = wiki_file
        for relative_path, changelog_file in write_changelog_pages(output_path).items():
            written[f"changelog:{relative_path}"] = changelog_file

    if write_robots:
        robots_file = output_path / "robots.txt"
        _write_public_artifact_text(robots_file, render_robots_txt())
        written["robots"] = robots_file

    if write_sitemap:
        sitemap_file = output_path / "sitemap.xml"
        _write_public_artifact_text(sitemap_file, render_sitemap_xml(policy))
        written["sitemap"] = sitemap_file

    if write_manifest:
        manifest_file = output_path / "policy-manifest.json"
        manifest_text = render_policy_manifest(
            policy,
            policy_bytes=policy_bytes,
            signature_bytes=signature_bytes,
            verification_metadata=verification_metadata,
        )
        _write_public_artifact_text(manifest_file, manifest_text)
        written["manifest"] = manifest_file

    if any((write_index, write_robots, write_sitemap, write_manifest)):
        nojekyll_file = output_path / ".nojekyll"
        _write_public_artifact_text(nojekyll_file, "")
        written["nojekyll"] = nojekyll_file

    if write_manifest:
        api_dir = output_path / "api" / "v1"
        api_dir.mkdir(parents=True, exist_ok=True)
        policy_alias = api_dir / "policy.json"
        shutil.copyfile(policy_file, policy_alias)
        written["api_policy"] = policy_alias
        if signature_bytes is not None:
            signature_alias = api_dir / "policy.sig"
            _write_public_artifact_bytes(signature_alias, signature_bytes)
            written["api_signature"] = signature_alias
        if manifest_text is not None:
            manifest_alias = api_dir / "manifest.json"
            _write_public_artifact_text(manifest_alias, manifest_text)
            written["api_manifest"] = manifest_alias

    return written

def render_robots_txt() -> str:
    return ROBOTS_TXT

def render_sitemap_xml(policy: ReleasePolicy, *, base_url: str = DEFAULT_PAGES_BASE_URL) -> str:
    generated_at = escape(policy.generated_at_utc or clock.utc_now())
    urls = tuple(
        dict.fromkeys(
            (
                f"{base_url}/",
                f"{base_url}/windows-release-policy.json",
                f"{base_url}/policy-manifest.json",
                *_wiki_sitemap_urls(base_url=base_url),
                *_changelog_sitemap_urls(base_url=base_url),
            )
        )
    )
    entries = "\n".join(
        (
            "  <url>\n"
            f"    <loc>{escape(url)}</loc>\n"
            f"    <lastmod>{generated_at}</lastmod>\n"
            "  </url>"
        )
        for url in urls
    )
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
        f"{entries}\n"
        "</urlset>\n"
    )

def _published_urls_for_base_url(base_url: str) -> dict[str, str]:
    normalized = base_url.rstrip("/")
    return {
        "landing": f"{normalized}/",
        "policy": f"{normalized}/windows-release-policy.json",
        "signature": f"{normalized}/windows-release-policy.json.sig",
        "manifest": f"{normalized}/policy-manifest.json",
        "api_policy": f"{normalized}/api/v1/policy.json",
        "api_signature": f"{normalized}/api/v1/policy.sig",
        "api_manifest": f"{normalized}/api/v1/manifest.json",
    }

def render_policy_manifest(
    policy: ReleasePolicy,
    *,
    policy_bytes: bytes,
    signature_bytes: bytes | None,
    signature: Mapping[str, Any] | None = None,
    verification_metadata: Mapping[str, Any] | None = None,
    base_url: str = DEFAULT_PAGES_BASE_URL,
) -> str:
    target = policy.broad_target_existing_devices
    latest_observed_evidence = _latest_observed_evidence_metadata(target)
    policy_sha256 = _sha256_hex(policy_bytes)
    signature_sha256 = _sha256_hex(signature_bytes)
    verification = verification_metadata if verification_metadata is not None else _public_verification_metadata(signature)
    status = _status_text(policy)
    manifest = {
        "schema_version": 1,
        "generated_at_utc": policy.generated_at_utc,
        "generated_at_human": _generated_at_human(policy.generated_at_utc),
        "timezone": PAGES_TIMEZONE,
        **freshness_thresholds(policy.generated_at_utc),
        "freshness_policy": freshness_policy_metadata(),
        "generator_version": policy.generator_version,
        "policy_schema_version": policy.schema_version,
        "min_reader_schema_version": policy.min_reader_schema_version,
        "max_reader_schema_version": policy.max_reader_schema_version,
        "api_version": policy.api_version,
        "compatibility": dict(policy.compatibility),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "commit_sha": os.environ.get("GITHUB_SHA"),
        "policy_sha256": policy_sha256,
        "signature_sha256": signature_sha256,
        "signature_algorithm": _signature_field(verification, "algorithm"),
        "key_id": _signature_field(verification, "key_id"),
        "source_urls": list(policy.source_urls),
        "source_diagnostics": dict(policy.source_diagnostics),
        "published_urls": dict(policy.published_urls or _published_urls_for_base_url(base_url)),
        "broad_target_existing_devices": (
            {
                "version": target.version,
                "build_family": target.build_family,
                "latest_build": target.latest_build,
                "latest_observed_build": target.latest_observed_build,
                "latest_observed_evidence": latest_observed_evidence,
                "baseline_build": target.baseline_build,
                "required_baseline_build": target.required_baseline_build,
            }
            if target
            else None
        ),
        "latest_observed_build": target.latest_observed_build if target else None,
        "latest_observed_evidence": latest_observed_evidence,
        "baseline": target.required_baseline_build if target else None,
        "required_baseline_build": target.required_baseline_build if target else None,
        "warnings": list(policy.validation_warnings),
        "status": status,
    }
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"
