from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

DEFAULT_MAX_JSON_BYTES = 5 * 1024 * 1024


class StrictJSONError(ValueError):
    """Raised when JSON input is syntactically valid enough to parse but not accepted."""


def _json_size(value: str | bytes | bytearray) -> int:
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    return len(value)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError(f"Duplicate JSON object key {key!r} is not allowed.")
        result[key] = value
    return result


def _reject_non_finite_constant(value: str) -> None:
    raise StrictJSONError(f"Non-finite JSON numeric value {value!r} is not allowed.")


def strict_json_loads(
    data: str | bytes | bytearray,
    *,
    label: str = "JSON",
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
) -> Any:
    """Load JSON using deterministic policy-feed semantics.

    Python's stdlib JSON parser accepts duplicate object names by keeping the
    last value and accepts NaN/Infinity by default. That is dangerous for signed
    policy feeds and public manifest/signature checks because different readers
    can disagree about the effective document. This helper rejects both cases
    and optionally bounds input size.
    """

    size = _json_size(data)
    if max_bytes >= 0 and size > max_bytes:
        raise StrictJSONError(f"{label} is too large: {size} bytes exceeds {max_bytes} bytes.")

    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise StrictJSONError(f"{label} is not valid UTF-8 JSON: {exc}") from exc
    else:
        text = data.lstrip("\ufeff")

    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
    except json.JSONDecodeError as exc:
        raise StrictJSONError(f"{label} is malformed JSON: {exc}") from exc


def strict_json_object(
    data: str | bytes | bytearray,
    *,
    label: str = "JSON",
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
) -> Mapping[str, Any]:
    decoded = strict_json_loads(data, label=label, max_bytes=max_bytes)
    if not isinstance(decoded, Mapping):
        raise StrictJSONError(f"{label} top-level value must be an object.")
    return decoded


__all__ = [
    "DEFAULT_MAX_JSON_BYTES",
    "StrictJSONError",
    "strict_json_loads",
    "strict_json_object",
]
