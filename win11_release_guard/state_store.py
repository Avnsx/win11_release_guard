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
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePath, PurePosixPath, PureWindowsPath

STATE_NAMESPACE: bytes = b"w11rg-state"  # digest input only; NEVER written to disk
STATE_FORMAT_VERSION: int = 1


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
