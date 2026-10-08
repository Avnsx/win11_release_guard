"""Deterministic Source Diagnostic IDs, labels, and tags."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse
from ..broad_target_hold import PENDING_B_RELEASE_KIND
from ..exceptions import PolicyParseError
from ..policy_schema import is_source_diagnostic_id
from .baseline_notice import _security_evidence_display_label
from .constants import (
    SOURCE_DIAGNOSTIC_ID_HASH_LENGTH,
    SOURCE_DIAGNOSTIC_ID_PREFIX,
    _SOURCE_DIAGNOSTIC_KB_TAG_RE,
    _SOURCE_DIAGNOSTIC_TIMESTAMP_TAG_RE,
)
from .keys import _build_key
from .support_articles import _SUPPORT_ARTICLE_VALIDATION_STATUSES
from .time_format import _dual_zone_time_human


def _signature_field(signature: Mapping[str, Any] | None, key: str) -> str | None:
    if not signature:
        return None
    value = signature.get(key)
    return str(value) if value not in (None, "") else None

def _signature_trust_class(*, signature_attached: bool, signature_status: str) -> str:
    normalized = signature_status.strip().lower()
    if normalized == "valid":
        return ""
    if not signature_attached and normalized in {"unsigned", "unsigned local preview"}:
        return " warning"
    return " error"

def _short_diagnostic_text(value: Any, *, max_length: int = 150) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= max_length:
        return text
    boundary = text.rfind(" ", 0, max_length - 1)
    if boundary < max_length // 2:
        boundary = max_length - 1
    return text[:boundary].rstrip(" ,;:-.") + "."

def _source_diagnostic_event_severity(value: Any) -> str:
    severity = str(value or "").strip().lower()
    return severity if severity in {"notice", "warning", "error"} else "warning"

def _source_diagnostic_id_text(value: Any) -> str:
    try:
        text = str(value or "")
    except Exception:
        return ""
    return re.sub(r"\s+", " ", text).strip()

def _source_diagnostic_id_component(value: Any) -> dict[str, Any]:
    text = _source_diagnostic_id_text(value)
    return {
        "length": len(text),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }

def _source_diagnostic_id_tag_values(tags: Any) -> tuple[str, ...]:
    if tags in (None, ""):
        return ()
    if isinstance(tags, Mapping):
        raw_items = (
            f"{key}: {value}"
            for key, value in sorted(tags.items(), key=lambda item: str(item[0]))
        )
    elif isinstance(tags, (str, bytes)):
        raw_items = (tags,)
    else:
        try:
            raw_items = iter(tags)
        except TypeError:
            raw_items = (tags,)
    normalized: list[str] = []
    for tag in raw_items:
        text = _source_diagnostic_id_text(tag)
        if text:
            normalized.append(text)
    return tuple(normalized)

def _source_diagnostic_id_field(value: Any) -> str | None:
    text = _source_diagnostic_id_text(value)
    return text or None

def _source_diagnostic_id_kb(value: Any) -> str | None:
    text = _source_diagnostic_id_text(value)
    if not text:
        return None
    compact = re.sub(r"\s+", "", text).upper()
    match = _SOURCE_DIAGNOSTIC_KB_TAG_RE.fullmatch(compact)
    return f"KB{match.group(1)}" if match else compact

def _source_diagnostic_id_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return None
    text = _source_diagnostic_id_text(value).lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return None

def _source_diagnostic_id_url_host_path(value: Any) -> str | None:
    text = _source_diagnostic_id_text(value)
    if not text:
        return None
    parsed = urlparse(text)
    if not parsed.netloc:
        return None
    path = re.sub(r"/+", "/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")
    return f"{parsed.netloc.lower()}{path}"

def _source_diagnostic_id_tag_fields(tags: Any) -> dict[str, Any]:
    candidates: dict[str, list[Any]] = {}

    def add_candidate(key: str, value: Any) -> None:
        candidates.setdefault(key, []).append(value)

    for tag in _source_diagnostic_id_tag_values(tags):
        if _SOURCE_DIAGNOSTIC_TIMESTAMP_TAG_RE.fullmatch(tag):
            continue
        lower = tag.lower()
        for prefix, field_name in (
            ("release ", "release"),
            ("build ", "build"),
            ("family ", "build_family"),
        ):
            if lower.startswith(prefix):
                value = _source_diagnostic_id_field(tag[len(prefix) :])
                if value is not None:
                    add_candidate(field_name, value)
                break
        else:
            kb_article = _source_diagnostic_id_kb(tag)
            if kb_article and _SOURCE_DIAGNOSTIC_KB_TAG_RE.fullmatch(kb_article):
                add_candidate("kb_article", kb_article)
            elif lower == "required baseline":
                add_candidate("affects_broad_target", True)
                add_candidate("affects_required_baseline", True)
            elif lower == "broad target":
                add_candidate("affects_broad_target", True)
            elif lower == "not broad target":
                add_candidate("affects_broad_target", False)
    return {
        key: sorted(set(values), key=lambda value: json.dumps(value, sort_keys=True))[0]
        for key, values in sorted(candidates.items())
        if values
    }

def _source_diagnostic_has_id_value(value: Any) -> bool:
    return value not in (None, "")

def _source_diagnostic_id_payload_field(value: Any) -> dict[str, Any]:
    return _source_diagnostic_id_component(_source_diagnostic_id_field(value) or "")

def _source_diagnostic_id(
    *,
    severity: Any,
    source: Any,
    title: Any,
    message: Any,
    tags: Any,
    kind: Any = None,
    release: Any = None,
    build_family: Any = None,
    build: Any = None,
    kb_article: Any = None,
    affects_broad_target: Any = None,
    affects_required_baseline: Any = None,
    source_url: Any = None,
    allow_message_fallback: bool = False,
    extra_identity_fields: Mapping[str, Any] | None = None,
) -> str:
    tag_fields = _source_diagnostic_id_tag_fields(tags)
    category = kind if _source_diagnostic_has_id_value(kind) else title
    fields: dict[str, Any] = {
        "category": _source_diagnostic_id_payload_field(category),
        "source": _source_diagnostic_id_payload_field(source),
    }
    for key, value in (
        ("release", release),
        ("build_family", build_family),
        ("build", build),
        ("kb_article", kb_article),
    ):
        selected = value if _source_diagnostic_has_id_value(value) else tag_fields.get(key)
        if key == "kb_article":
            normalized = _source_diagnostic_id_kb(selected)
        else:
            normalized = _source_diagnostic_id_field(selected)
        if normalized:
            fields[key] = _source_diagnostic_id_payload_field(normalized)

    for key, value in (
        ("affects_broad_target", affects_broad_target),
        ("affects_required_baseline", affects_required_baseline),
    ):
        selected = value if _source_diagnostic_has_id_value(value) else tag_fields.get(key)
        normalized_bool = _source_diagnostic_id_bool(selected)
        if normalized_bool is not None:
            fields[key] = normalized_bool

    normalized_source_url = _source_diagnostic_id_url_host_path(source_url)
    if normalized_source_url:
        fields["source_url"] = _source_diagnostic_id_payload_field(normalized_source_url)

    for key, value in sorted((extra_identity_fields or {}).items(), key=lambda item: str(item[0])):
        if value in (None, ""):
            continue
        fields[f"extra_{key}"] = _source_diagnostic_id_payload_field(value)

    if allow_message_fallback and not any(
        key in fields
        for key in (
            "release",
            "build_family",
            "build",
            "kb_article",
            "affects_broad_target",
            "affects_required_baseline",
            "source_url",
        )
    ):
        fields["message_fallback"] = _source_diagnostic_id_payload_field(message)

    payload = {
        "severity": _source_diagnostic_event_severity(severity),
        "fields": fields,
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(payload_bytes).hexdigest()[:SOURCE_DIAGNOSTIC_ID_HASH_LENGTH]
    return f"{SOURCE_DIAGNOSTIC_ID_PREFIX}:{digest}"

def _source_diagnostic_event_label(kind: Any) -> str:
    text = re.sub(r"[_-]+", " ", str(kind or "source diagnostic")).strip()
    if not text:
        return "Source diagnostic"
    acronyms = {"kb", "oob", "esu", "lcu"}
    return " ".join(part.upper() if part.lower() in acronyms else part.capitalize() for part in text.split())

def _source_diagnostic_display_title(event: Mapping[str, Any]) -> str:
    kind = str(event.get("kind") or "").strip().lower()
    release = str(event.get("release") or "").strip()
    build = str(event.get("build") or "").strip()
    release_text = f"Windows 11 {release}" if release else "Windows 11"
    if kind == "required_baseline_matched_latest_observed":
        return f"New baseline for {release_text}" if release else "New Windows baseline"
    if kind == "atom_newer_than_release_history":
        if event.get("affects_required_baseline"):
            return f"New baseline candidate for {release_text}" if release else "New baseline candidate"
        if event.get("is_security") is True:
            return f"Security update spotted for {release_text}" if release else "Security update spotted"
        return f"Microsoft update spotted for {release_text}" if release else "Microsoft update spotted"
    if kind == "current_versions_lag_release_history" and release:
        return f"Release Health lag for {release_text}"
    if kind == "missing_broad_target_baseline" and release:
        return f"Missing baseline for {release_text}"
    if kind == PENDING_B_RELEASE_KIND and release:
        return f"{release_text} awaits its first B release"
    if build and release:
        return f"{_source_diagnostic_event_label(kind)} for {release_text} build {build}"
    return _source_diagnostic_event_label(kind)

def _source_diagnostic_source_label(kind: Any) -> str:
    text = str(kind or "").strip().lower()
    if text == PENDING_B_RELEASE_KIND:
        return "Release policy"
    if "atom" in text:
        return "Servicing index"
    if "manifest" in text:
        return "Manifest"
    if (
        "freshness" in text
        or "stale" in text
        or "aging" in text
        or "currency" in text
        or "refresh" in text
        or "policy_feed" in text
    ):
        return "Policy feed currency"
    if "parser" in text or "parse" in text:
        return "Parser"
    if "release_health" in text or "current_versions" in text or "release_history" in text:
        return "Release Health"
    if "signature" in text:
        return "Signature"
    return "Source"

def _source_diagnostic_timestamp(event: Mapping[str, Any]) -> str | None:
    for key in ("occurred_at_utc", "fetched_at_utc", "published", "updated", "timestamp", "generated_at_utc"):
        value = event.get(key)
        if value not in (None, ""):
            return str(value)
    return None

def _source_diagnostic_event_tags(event: Mapping[str, Any]) -> tuple[str, ...]:
    tags: list[str] = []
    for key, label in (
        ("release", "Release"),
        ("build", "Build"),
    ):
        value = event.get(key)
        if value not in (None, ""):
            tags.append(f"{label} {value}")
    kb_article = event.get("kb_article")
    if kb_article not in (None, ""):
        kb_text = str(kb_article)
        tags.append(kb_text if kb_text.upper().startswith("KB") else f"KB {kb_text}")
    if event.get("is_security") is True:
        tags.append("Security patch")
    security_label = _security_evidence_display_label(
        is_security=event.get("is_security"),
        evidence_source=event.get("security_evidence_source"),
    )
    if security_label and security_label not in tags:
        tags.append(security_label)
    validation_status = str(event.get("support_article_validation_status") or "")
    if validation_status in _SUPPORT_ARTICLE_VALIDATION_STATUSES and validation_status != "ok":
        tags.append(f"Support article {validation_status}")
    build_family = event.get("build_family")
    if build_family not in (None, ""):
        tags.append(f"Family {build_family}")
    if event.get("affects_required_baseline"):
        tags.append("Required baseline")
    elif event.get("affects_broad_target"):
        tags.append("Broad target")
    public_id = event.get("atom_support_article_id") or event.get("support_article_id")
    if public_id not in (None, ""):
        tags.append(f"id={public_id}")
    timestamp = _source_diagnostic_timestamp(event)
    if timestamp:
        tags.append(_dual_zone_time_human(timestamp) or timestamp)
    return tuple(tags)

def _source_diagnostic_id_hint_for_event(event: Mapping[str, Any]) -> str | None:
    for key in ("diagnostic_id_hint", "id"):
        diagnostic_id = _source_diagnostic_id_text(event.get(key))
        if _is_source_diagnostic_id(diagnostic_id):
            return diagnostic_id
    return None

def _atom_diagnostic_id_from_event(event: Mapping[str, Any]) -> str | None:
    for key in ("diagnostic_id_hint", "id"):
        diagnostic_id = _source_diagnostic_id_text(event.get(key))
        if (
            diagnostic_id.startswith(f"{SOURCE_DIAGNOSTIC_ID_PREFIX}:uuid:")
            and _is_source_diagnostic_id(diagnostic_id)
        ):
            return diagnostic_id
    atom_entry_id = _source_diagnostic_id_text(event.get("atom_entry_id"))
    if atom_entry_id:
        diagnostic_id = f"{SOURCE_DIAGNOSTIC_ID_PREFIX}:{atom_entry_id}"
        if (
            diagnostic_id.startswith(f"{SOURCE_DIAGNOSTIC_ID_PREFIX}:uuid:")
            and _is_source_diagnostic_id(diagnostic_id)
        ):
            return diagnostic_id
    return None

def _source_diagnostic_hash_id_for_event(
    event: Mapping[str, Any],
    *,
    extra_identity_fields: Mapping[str, Any] | None = None,
) -> str:
    kind = event.get("kind")
    severity = _source_diagnostic_event_severity(event.get("severity"))
    title = _source_diagnostic_event_label(kind)
    message = _short_diagnostic_text(event.get("message") or event.get("title") or title)
    return _source_diagnostic_id(
        severity=severity,
        source=_source_diagnostic_source_label(kind),
        title=title,
        message=message,
        tags=_source_diagnostic_event_tags(event),
        kind=kind,
        release=event.get("release"),
        build_family=event.get("build_family"),
        build=event.get("build"),
        kb_article=event.get("kb_article"),
        affects_broad_target=event.get("affects_broad_target"),
        affects_required_baseline=event.get("affects_required_baseline"),
        source_url=event.get("source_url") or event.get("url") or event.get("atom_feed_url"),
        extra_identity_fields=extra_identity_fields,
    )

def _source_diagnostic_id_for_event(event: Mapping[str, Any]) -> str:
    hint = _source_diagnostic_id_hint_for_event(event)
    if hint is not None:
        return hint
    return _source_diagnostic_hash_id_for_event(event)

def _atom_canonical_event_key(index: int, event: Mapping[str, Any]) -> tuple[Any, ...]:
    severity = _source_diagnostic_event_severity(event.get("severity"))
    build_major, build_minor = _build_key(str(event.get("build") or ""))
    return (
        0 if severity == "warning" else 1 if severity == "error" else 2,
        0 if _source_diagnostic_id_bool(event.get("affects_required_baseline")) is True else 1,
        0 if _source_diagnostic_id_bool(event.get("affects_broad_target")) is True else 1,
        -build_major,
        -build_minor,
        _source_diagnostic_id_text(event.get("kind")),
        _source_diagnostic_id_text(event.get("release")),
        _source_diagnostic_id_text(event.get("build")),
        index,
    )

def _canonical_atom_event_indexes(events: Sequence[Mapping[str, Any]]) -> dict[int, str]:
    groups: dict[str, list[tuple[int, Mapping[str, Any]]]] = {}
    for index, event in enumerate(events):
        atom_diagnostic_id = _atom_diagnostic_id_from_event(event)
        if atom_diagnostic_id is not None:
            groups.setdefault(atom_diagnostic_id, []).append((index, event))

    canonical: dict[int, str] = {}
    for atom_diagnostic_id, candidates in groups.items():
        index, _ = min(candidates, key=lambda item: _atom_canonical_event_key(item[0], item[1]))
        canonical[index] = atom_diagnostic_id
    return canonical

def _event_atom_entry_identity(event: Mapping[str, Any]) -> str | None:
    atom_entry_id = _source_diagnostic_id_text(event.get("atom_entry_id"))
    if atom_entry_id:
        return atom_entry_id
    atom_diagnostic_id = _atom_diagnostic_id_from_event(event)
    if atom_diagnostic_id:
        return atom_diagnostic_id.removeprefix(f"{SOURCE_DIAGNOSTIC_ID_PREFIX}:")
    return None

def _source_diagnostic_collision_hash_id(
    event: Mapping[str, Any],
    *,
    event_index: int,
    collision_id: str,
    collision_round: int,
) -> str:
    return _source_diagnostic_hash_id_for_event(
        event,
        extra_identity_fields={
            "atom_entry_id": _event_atom_entry_identity(event),
            "collision_id": collision_id,
            "collision_round": collision_round,
            "event_index": event_index,
            "diagnostic_id_hint": event.get("diagnostic_id_hint"),
        },
    )

def _resolve_source_diagnostic_id_collisions(
    events: list[dict[str, Any]],
    *,
    protected_indexes: set[int],
) -> list[dict[str, Any]]:
    for collision_round in range(1, 6):
        by_id: dict[str, list[int]] = {}
        for index, event in enumerate(events):
            by_id.setdefault(str(event.get("id") or ""), []).append(index)
        collisions = {diagnostic_id: indexes for diagnostic_id, indexes in by_id.items() if len(indexes) > 1}
        if not collisions:
            return events
        for diagnostic_id, indexes in sorted(collisions.items()):
            protected = [index for index in indexes if index in protected_indexes]
            keep = min(protected or indexes)
            for index in indexes:
                if index == keep:
                    continue
                events[index]["id"] = _source_diagnostic_collision_hash_id(
                    events[index],
                    event_index=index,
                    collision_id=diagnostic_id,
                    collision_round=collision_round,
                )
    raise PolicyParseError("Could not assign unique source diagnostic IDs.")

def _source_diagnostic_events_with_ids(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = [dict(event) for event in events]
    canonical_atom_indexes = _canonical_atom_event_indexes(items)
    for index, item in enumerate(items):
        atom_diagnostic_id = _atom_diagnostic_id_from_event(item)
        if index in canonical_atom_indexes:
            item["id"] = canonical_atom_indexes[index]
        elif atom_diagnostic_id is not None:
            item["id"] = _source_diagnostic_hash_id_for_event(
                item,
                extra_identity_fields={"atom_entry_id": _event_atom_entry_identity(item)},
            )
        else:
            item["id"] = _source_diagnostic_id_for_event(item)
    return _resolve_source_diagnostic_id_collisions(
        items,
        protected_indexes=set(canonical_atom_indexes),
    )

def _is_source_diagnostic_id(value: str) -> bool:
    return is_source_diagnostic_id(value)
