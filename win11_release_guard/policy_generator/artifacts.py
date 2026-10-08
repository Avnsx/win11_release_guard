"""Writing public Pages artifacts and their verification metadata."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping


def _write_public_artifact_bytes(path: Path, data: bytes) -> None:
    # Detached signatures and policy manifests are public Pages artifacts, not secrets.
    # codeql[py/clear-text-storage-sensitive-data]
    path.write_bytes(data)

def _write_public_artifact_text(path: Path, text: str) -> None:
    # Generated Pages text files contain public policy metadata only.
    # codeql[py/clear-text-storage-sensitive-data]
    path.write_text(text, encoding="utf-8", newline="\n")

def _public_verification_metadata(record: Mapping[str, Any] | None) -> dict[str, str] | None:
    if not record:
        return None
    metadata: dict[str, str] = {}
    for field in ("algorithm", "key_id", "signed_at_utc"):
        value = record.get(field)
        if value is not None:
            metadata[field] = str(value)
    return metadata or None

def _sha256_hex(data: bytes | None) -> str | None:
    if data is None:
        return None
    return hashlib.sha256(data).hexdigest()

def _short_hash(value: str | None) -> str:
    return value[:12] if value else "unavailable"
