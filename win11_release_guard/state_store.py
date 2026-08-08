"""Non-permanent on-disk state for win11_release_guard.

This module is the sole owner of state-path derivation, layout selection, the
compact record codec, the one atomic write primitive, the self-healing read
path, the single deletion rule, legacy retirement, and the purge/describe/
embedder API. State is strictly an optimisation: it never changes the
compliance verdict, never changes the exit code, and never raises out of the
evaluation.

The record format is compact because it stores two exact byte blobs and a
digest. It is not a confidentiality mechanism and provides no protection
against inspection of any kind.

Deletion rule (the single deletion sentence): The tool unlinks a record only
at a path it derived itself, only after it has opened that file and confirmed
its first eight bytes equal STATE_MAGIC, and only because the file did not
yield a signature-verified policy. The one carve-out: a role == "staging" path
is unlinked with no magic check.

Test seams: the only host interaction points, private but test-visible, are
_first_existing_dir, _host_uid, _replace, _unlink and _read_all. Tests patch
these five names and nothing else; no other function performs I/O behind them.

Codec testing law: Decode of a checked-in vector may be pinned. Encode may only
be tested by round-trip. Never assert on compressed bytes or on file size.
"""

from __future__ import annotations

import hashlib
import os
import struct
import zlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Any

from .json_utils import DEFAULT_MAX_SIGNATURE_BYTES

STATE_NAMESPACE: bytes = b"w11rg-state"  # digest input only; NEVER written to disk
STATE_FORMAT_VERSION: int = 1
STATE_MAGIC: bytes = b"\xdb\xa7\x0d\x0aSTR1"     # DB A7 CR LF 'S' 'T' 'R' '1'
STATE_HEADER_LEN: int = 50
MAX_STATE_FILE_BYTES: int = 8 * 1024 * 1024      # on-disk cap, fixed, never configurable
MAX_STATE_BODY_BYTES: int = 32 * 1024 * 1024     # inflated cap, fixed, never configurable


def temp_dir_candidates(os_name: str, env: Mapping[str, str]) -> tuple[str, ...]:
    """PURE. Ordered absolute directory candidates; no I/O, no os.environ, no CWD."""
    raw: list[str] = []
    for key in ("TMPDIR", "TEMP", "TMP"):
        value = env.get(key)
        if value is not None:
            raw.append(value)
    if os_name == "nt":
        system_root = env.get("SystemRoot")
        if system_root is not None:
            raw.append(str(PureWindowsPath(system_root) / "Temp"))
    else:
        raw.append("/tmp")
        raw.append("/var/tmp")
    flavour = PureWindowsPath if os_name == "nt" else PurePosixPath
    kept: list[str] = []
    for candidate in raw:
        stripped = candidate.strip()
        if not stripped:
            continue
        if not flavour(stripped).is_absolute():
            continue
        kept.append(stripped)
    return tuple(dict.fromkeys(kept))


def state_user_token(os_name: str, env: Mapping[str, str], uid: int | None) -> str:
    """PURE. domain\\user on nt, str(uid) otherwise. Never calls os.getuid, never
    reads os.environ; both nt lookups are .get(..., "") so a service context that
    has neither variable yields an empty side rather than raising KeyError."""
    if os_name == "nt":
        return f'{env.get("USERDOMAIN", "")}\\{env.get("USERNAME", "")}'
    return str(uid)


def derive_state_name(
    *,
    policy_url: str,
    os_name: str,
    env: Mapping[str, str],
    uid: int | None,
    trusted_public_key: str | None,
    allow_unsigned_policy: bool,
    format_version: int = STATE_FORMAT_VERSION,
) -> str:
    """PURE. No Path, no I/O, no os.environ, no getuid. Returns 'tmp<16 hex>.tmp'.
    Component 5 hashes (trusted_public_key or "") — NOT `or DEFAULT` — so at this
    layer None and the bundled default derive DIFFERENT names; default resolution
    lives one level up in resolve_state_scope (§2.4)."""
    components = (
        STATE_NAMESPACE,
        str(format_version).encode("ascii"),
        policy_url.encode("utf-8", "replace"),
        state_user_token(os_name, env, uid).encode("utf-8", "replace"),
        hashlib.sha256(
            (trusted_public_key or "").encode("utf-8", "replace"),
            usedforsecurity=False,
        ).digest(),
        str(bool(allow_unsigned_policy)).encode("ascii"),
    )
    material = b"\x00".join(components)
    digest = hashlib.sha256(material, usedforsecurity=False).hexdigest()[:16]
    return f"tmp{digest}.tmp"


def staging_name(name: str) -> str:
    """PURE. f'{name}.staging.tmp' — one rule for every writer, a pure function of
    the destination name and nothing else. INJECTIVE: distinct destination names in
    one directory always yield distinct staging names, and no pid/counter/random."""
    return f"{name}.staging.tmp"


def state_path_for(os_name: str, directory: str, name: str) -> PurePath:
    """PURE join returning PureWindowsPath for 'nt' and PurePosixPath otherwise, so
    the Windows layout is assertable from Linux CI."""
    flavour = PureWindowsPath if os_name == "nt" else PurePosixPath
    return flavour(directory) / name


@dataclass(frozen=True)
class StateScope:
    layout: str                      # "container" | "legacy_pair" | "none"
    path: PurePath | None            # the file this run may read and write
    signature_path: PurePath | None  # only for "legacy_pair"; None otherwise
    staging_path: PurePath | None    # None when layout == "none"
    source: str                      # "cache_file" | "state_dir" | "default_temp" | "stateless"
                                     # | "no_temp_dir" | "state_dir_not_absolute" | "path_not_nameable"


@dataclass(frozen=True)
class StateRead:
    status: str                      # "absent" | "foreign" | "unusable" | "usable"
    policy_bytes: bytes | None = None
    signature_bytes: bytes | None = None
    modified_epoch: float | None = None
    detail: str | None = None


_HEADER = struct.Struct("<8sHII32s")  # magic, format_version, policy_len, signature_len, body_digest


def encode_state(policy_bytes: bytes, signature_bytes: bytes | None) -> bytes:
    """PURE bytes -> bytes. Header + zlib.compress(policy + signature, 9); the digest
    is over the UNCOMPRESSED body so the two CI legs' compressors may differ."""
    signature = signature_bytes or b""
    body = policy_bytes + signature
    header = _HEADER.pack(
        STATE_MAGIC,
        STATE_FORMAT_VERSION,
        len(policy_bytes),
        len(signature),
        hashlib.sha256(body).digest(),
    )
    return header + zlib.compress(body, 9)


def decode_state(raw: bytes) -> StateRead:
    """PURE bytes -> StateRead. Never raises. Nine ordered checks, first failure wins."""
    if raw[:8] != STATE_MAGIC:
        return StateRead("foreign")
    if len(raw) < STATE_HEADER_LEN:
        return StateRead("unusable", detail="short header")
    _magic, format_version, policy_len, signature_len, body_digest = _HEADER.unpack(
        raw[:STATE_HEADER_LEN]
    )
    if format_version != STATE_FORMAT_VERSION:
        return StateRead("unusable", detail=f"format version {format_version}")
    if (
        policy_len == 0
        or policy_len > MAX_STATE_BODY_BYTES
        or signature_len > DEFAULT_MAX_SIGNATURE_BYTES
    ):
        return StateRead("unusable", detail="declared length out of range")
    decompressor = zlib.decompressobj()
    try:
        body = decompressor.decompress(
            raw[STATE_HEADER_LEN:], max_length=policy_len + signature_len
        )
    except zlib.error:
        return StateRead("unusable", detail="inflate failed")
    if decompressor.unconsumed_tail or decompressor.unused_data or not decompressor.eof:
        return StateRead("unusable", detail="stream boundary mismatch")
    if len(body) != policy_len + signature_len:
        return StateRead("unusable", detail="length mismatch")
    if hashlib.sha256(body).digest() != body_digest:
        return StateRead("unusable", detail="digest mismatch")
    return StateRead(
        "usable",
        policy_bytes=body[:policy_len],
        signature_bytes=body[policy_len:] if signature_len else None,
    )


@dataclass(frozen=True)
class StateEvent:
    action: str            # "write" | "discard" | "purge" | "retire"
    outcome: str           # "written" | "removed" | "absent" | "skipped" | "failed"
    path: str | None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "outcome": self.outcome,
            "path": self.path,
            "detail": self.detail,
        }


def _reason(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def _replace(source: str, destination: str) -> None:
    """I/O SEAM. os.replace, isolated so tests can force a swap failure portably."""
    os.replace(source, destination)


def _unlink(path: str) -> None:
    """I/O SEAM. os.unlink, isolated so tests can force a delete failure portably."""
    os.unlink(path)


_WRITE_FLAGS: int = os.O_CREAT | os.O_WRONLY | os.O_TRUNC | getattr(os, "O_BINARY", 0)


def write_bytes_atomically(path: Path, data: bytes) -> StateEvent:
    """Write `data` to `path` atomically. Touches disk. NEVER raises.

    Every writer in this package goes through this function. It does not inspect the
    destination, does not create directories, does not retry, and does not fsync.
    """
    staging = None
    opened = False
    try:
        staging = path.with_name(staging_name(path.name))
        fd = os.open(str(staging), _WRITE_FLAGS, 0o666)
        opened = True
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        _replace(str(staging), str(path))
        return StateEvent("write", "written", str(path), None)
    except (OSError, ValueError) as exc:
        if opened and staging is not None:
            try:
                _unlink(str(staging))
            except (OSError, ValueError):
                pass
        return StateEvent("write", "failed", str(path), _reason(exc))


def write_state(
    scope: StateScope,
    policy_bytes: bytes,
    signature_bytes: bytes | None,
) -> StateEvent:
    """The single state writer. Touches disk. NEVER raises. Layout-aware:

    * "container" -> one encoded record through the primitive, size-guarded on THIS branch only.
    * "legacy_pair" -> two raw primitive writes (policy, then .sig when present), byte-identical
      to today, no mkdir; returns the policy write's event.
    * "none"/stateless -> "skipped" carrying scope.source as the detail, before any filesystem
      call (§6.4). scope.source is one of "stateless" | "no_temp_dir" | "state_dir_not_absolute"
      | "path_not_nameable"; _persist_policy maps every value except "stateless" to one
      cache_write_failed.
    """
    if scope.layout == "none" or scope.path is None:
        return StateEvent("write", "skipped", None, scope.source)
    if scope.layout == "container":
        record = encode_state(policy_bytes, signature_bytes)
        if (
            not policy_bytes
            or len(signature_bytes or b"") > DEFAULT_MAX_SIGNATURE_BYTES
            or len(record) > MAX_STATE_FILE_BYTES
        ):
            return StateEvent("write", "skipped", str(scope.path), "record too large")
        return write_bytes_atomically(Path(scope.path), record)
    # "legacy_pair": two raw files, byte-identical to today, no encode_state, no mkdir.
    event = write_bytes_atomically(Path(scope.path), policy_bytes)
    if signature_bytes is not None and scope.signature_path is not None:
        write_bytes_atomically(Path(scope.signature_path), signature_bytes)
    return event
