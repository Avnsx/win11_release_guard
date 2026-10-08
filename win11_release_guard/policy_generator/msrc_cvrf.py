"""MSRC CVRF fetching, parsing, and KB joins."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Iterable, Mapping, Sequence
from ..exceptions import PolicyFetchError
from .. import http_client
from ..update_text import _extract_kb
from .constants import (
    MSRC_CVRF_API_BASE_URL,
    MSRC_CVRF_CVE_LIMIT,
    MSRC_CVRF_PRODUCT_LIMIT,
    MSRC_CVRF_SEVERITY_LIMIT,
)


MsrcCvrfFetcher = Callable[[str, float, int], Any]


def _msrc_cvrf_url(month_id: str) -> str:
    return f"{MSRC_CVRF_API_BASE_URL}/{month_id}"


def default_msrc_cvrf_fetcher(url: str, timeout: float, max_bytes: int) -> Mapping[str, Any]:
    result = http_client.request(
        url,
        headers={"Accept": "application/json"},
        timeout=timeout,
        max_bytes=max_bytes,
        label="MSRC CVRF response",
    )
    content_type = http_client.get_header(result.headers, "Content-Type")
    charset = http_client.charset_from_content_type(content_type) or "utf-8"
    decoded = json.loads(result.content.decode(charset, errors="replace"))
    if not isinstance(decoded, Mapping):
        raise PolicyFetchError("MSRC CVRF response must be a JSON object.")
    return decoded


def _as_sequence(value: Any) -> tuple[Any, ...]:
    if value in (None, ""):
        return ()
    if isinstance(value, (str, bytes)):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(value)
    return (value,)


def _dict_value(mapping: Mapping[str, Any], *keys: str) -> Any:
    lower_keys = {key.lower(): key for key in mapping}
    for key in keys:
        actual = lower_keys.get(key.lower())
        if actual is not None:
            return mapping.get(actual)
    return None


def _nested_text_values(value: Any) -> tuple[str, ...]:
    values: list[str] = []
    if isinstance(value, Mapping):
        for item in value.values():
            values.extend(_nested_text_values(item))
    elif isinstance(value, (str, bytes)):
        text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
        if text:
            values.append(text)
    elif isinstance(value, Sequence):
        for item in value:
            values.extend(_nested_text_values(item))
    elif value not in (None, ""):
        values.append(str(value))
    return tuple(values)


def _cvrf_description_value(value: Any) -> str | None:
    if isinstance(value, Mapping):
        for key in ("Value", "value", "Text", "text", "Description", "description"):
            candidate = value.get(key)
            if candidate not in (None, ""):
                if isinstance(candidate, Mapping):
                    nested = _cvrf_description_value(candidate)
                    if nested:
                        return nested
                return str(candidate)
    if value not in (None, ""):
        return str(value)
    return None


def _cvrf_vulnerabilities(cvrf: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    raw = _dict_value(cvrf, "Vulnerability", "Vulnerabilities")
    return tuple(item for item in _as_sequence(raw) if isinstance(item, Mapping))


def _cvrf_remediations(vulnerability: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    raw = _dict_value(vulnerability, "Remediations", "Remediation")
    return tuple(item for item in _as_sequence(raw) if isinstance(item, Mapping))


def _cvrf_product_ids(remediation: Mapping[str, Any]) -> tuple[str, ...]:
    products: list[str] = []
    for key, value in remediation.items():
        normalized = str(key).lower().replace("_", "")
        if normalized in {"productid", "productids", "product"} or normalized.endswith("productid"):
            for item in _as_sequence(value):
                if isinstance(item, (str, int)):
                    text = str(item).strip()
                    if text:
                        products.append(text)
    return tuple(dict.fromkeys(products))


def _cvrf_product_names_by_id(cvrf: Mapping[str, Any], *, max_depth: int = 12) -> dict[str, str]:
    names: dict[str, str] = {}
    seen: set[int] = set()

    def visit(node: Any, depth: int) -> None:
        if depth > max_depth:
            return
        if isinstance(node, Mapping):
            if id(node) in seen:
                return
            seen.add(id(node))
            product_id = _dict_value(node, "ProductID", "ProductId")
            value = _dict_value(node, "Value")
            if isinstance(product_id, (str, int)) and isinstance(value, str):
                key = str(product_id).strip()
                text = re.sub(r"\s+", " ", value).strip()
                if key and text and key not in names:
                    names[key] = text
            for child in node.values():
                visit(child, depth + 1)
            return
        if isinstance(node, Sequence) and not isinstance(node, (str, bytes)):
            if id(node) in seen:
                return
            seen.add(id(node))
            for item in node:
                visit(item, depth + 1)

    if isinstance(cvrf, Mapping):
        visit(_dict_value(cvrf, "ProductTree", "Producttree"), 0)
    return names


def _cvrf_resolved_product_names(
    product_ids: Iterable[str],
    names_by_id: Mapping[str, str],
) -> tuple[str, ...]:
    resolved = [str(names_by_id.get(str(product_id), product_id)).strip() for product_id in product_ids]
    return tuple(sorted(dict.fromkeys(name for name in resolved if name)))


def _cvrf_client_product_names(product_names: Iterable[str]) -> tuple[str, ...]:
    return tuple(
        name for name in product_names if str(name).strip().lower().startswith("windows 11")
    )


def _cvrf_vulnerability_severities(vulnerability: Mapping[str, Any]) -> tuple[str, ...]:
    severities: list[str] = []
    direct = _dict_value(vulnerability, "Severity")
    if isinstance(direct, (str, int)):
        severities.append(str(direct).strip())
    threats = _as_sequence(_dict_value(vulnerability, "Threats", "Threat"))
    for threat in threats:
        if not isinstance(threat, Mapping):
            continue
        threat_type = str(_dict_value(threat, "Type") or "").lower()
        if "severity" not in threat_type:
            continue
        description = _cvrf_description_value(_dict_value(threat, "Description", "Value"))
        if description:
            severities.append(description.strip())
    return tuple(dict.fromkeys(item for item in severities if item))


def _normalize_cvrf_kb_article(value: str | None) -> str | None:
    text = str(value or "").strip()
    match = re.fullmatch(r"(?:KB)?([1-9][0-9]{5,7})", text, flags=re.IGNORECASE)
    if match:
        return f"KB{match.group(1)}"
    return _extract_kb(text)


def _cvrf_text_matches_kb(text: str, kb: str) -> bool:
    bare_kb = kb[2:]
    pattern = re.compile(rf"(?<![A-Za-z0-9])(?:{re.escape(kb)}|{re.escape(bare_kb)})(?![A-Za-z0-9])", re.IGNORECASE)
    return pattern.search(text) is not None


def _cvrf_kb_join(cvrf: Mapping[str, Any], kb_article: str | None) -> dict[str, Any]:
    if not isinstance(cvrf, Mapping):
        return {
            "is_security": None,
            "cves": [],
            "severities": [],
            "products": [],
            "client_products": [],
            "evidence_source": "unavailable",
        }
    kb = _normalize_cvrf_kb_article(kb_article)
    if not kb:
        return {
            "is_security": False,
            "cves": [],
            "severities": [],
            "products": [],
            "client_products": [],
            "evidence_source": "none",
        }
    cves: list[str] = []
    severities: list[str] = []
    products: list[str] = []
    matched_kb = False
    for vulnerability in _cvrf_vulnerabilities(cvrf):
        matching_remediations = []
        for remediation in _cvrf_remediations(vulnerability):
            text = " ".join(_nested_text_values(remediation))
            if _cvrf_text_matches_kb(text, kb):
                matching_remediations.append(remediation)
        if not matching_remediations:
            continue
        matched_kb = True
        cve = str(_dict_value(vulnerability, "CVE", "Cve", "cve") or "").strip()
        if not cve:
            match = re.search(r"\bCVE-\d{4}-\d{4,}\b", " ".join(_nested_text_values(vulnerability)))
            cve = match.group(0) if match else ""
        if cve:
            cves.append(cve)
        severities.extend(_cvrf_vulnerability_severities(vulnerability))
        for remediation in matching_remediations:
            products.extend(_cvrf_product_ids(remediation))
    resolved_products = _cvrf_resolved_product_names(products, _cvrf_product_names_by_id(cvrf))
    deduped_cves = sorted(dict.fromkeys(cves))[:MSRC_CVRF_CVE_LIMIT]
    deduped_severities = sorted(dict.fromkeys(severities))[:MSRC_CVRF_SEVERITY_LIMIT]
    deduped_products = list(resolved_products)[:MSRC_CVRF_PRODUCT_LIMIT]
    return {
        "is_security": matched_kb,
        "cves": deduped_cves,
        "severities": deduped_severities,
        "products": deduped_products,
        "client_products": list(_cvrf_client_product_names(deduped_products)),
        "evidence_source": "msrc_cvrf" if matched_kb else "none",
    }
