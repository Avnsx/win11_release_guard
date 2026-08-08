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

import contextlib
import hashlib
import os
import stat
import struct
import zlib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Any

from .config import (
    DEFAULT_TRUSTED_POLICY_PUBLIC_KEY,
    ReleaseCheckerConfig,
    resolve_policy_url,
)
from .json_utils import DEFAULT_MAX_SIGNATURE_BYTES, strict_json_object

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


def _first_existing_dir(candidates: tuple[str, ...]) -> str | None:
    """I/O SEAM. First candidate for which os.path.isdir is True, else None. Never creates,
    never writes, never probes; every OSError/ValueError yields the next candidate."""
    for candidate in candidates:
        try:
            if os.path.isdir(candidate):
                return candidate
        except (OSError, ValueError):
            continue
    return None


def _host_uid() -> int | None:
    """I/O SEAM. The only os.getuid call site in the package; None on Windows."""
    getuid = getattr(os, "getuid", None)
    if getuid is None:
        return None
    try:
        return getuid()
    except (OSError, ValueError):
        return None


# O_NOFOLLOW is what keeps every open in this module on a path the tool derived itself. The
# default state path is a derived name in a shared, world-writable temp directory, so a local
# attacker who derives it can plant a symlink there; without this flag the O_TRUNC open below
# follows the link and destroys its target, and _replace then moves the link over the state
# path so every later run rewrites it. The same flag on the read side stops a planted link
# from choosing which file the magic gate approves. getattr yields 0 on Windows, which has no
# such flag, so both words stay byte-identical to the ones that shipped before it.
_WRITE_FLAGS: int = (
    os.O_CREAT | os.O_WRONLY | os.O_TRUNC | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
)
_READ_FLAGS: int = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)


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
        # The writer's caps mirror decode_state's, or a record is written that no read can
        # ever accept: MAX_STATE_BODY_BYTES bounds the uncompressed body (decode_state
        # check 4) and MAX_STATE_FILE_BYTES bounds the encoded record. The body cap is
        # checked before encode_state so an over-cap body is never compressed. Both arms
        # keep the one detail string _STATE_WRITE_SKIP_PHRASES keys off.
        if (
            not policy_bytes
            or len(policy_bytes) > MAX_STATE_BODY_BYTES
            or len(signature_bytes or b"") > DEFAULT_MAX_SIGNATURE_BYTES
        ):
            return StateEvent("write", "skipped", str(scope.path), "record too large")
        record = encode_state(policy_bytes, signature_bytes)
        if len(record) > MAX_STATE_FILE_BYTES:
            return StateEvent("write", "skipped", str(scope.path), "record too large")
        return write_bytes_atomically(Path(scope.path), record)
    # "legacy_pair": two raw files, byte-identical to today, no encode_state, no mkdir.
    event = write_bytes_atomically(Path(scope.path), policy_bytes)
    if signature_bytes is not None and scope.signature_path is not None:
        write_bytes_atomically(Path(scope.signature_path), signature_bytes)
    return event


def _read_all(fd: int, size: int) -> bytes:
    """I/O SEAM. os.read in a loop until EOF or `size` bytes (§6.1 step 6). Factored
    out so a test can force a SHORT read portably; adds no runtime mechanism."""
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = os.read(fd, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_state(scope: StateScope) -> StateRead:
    """Read and decode the one derived container. Touches disk. NEVER raises.
    Called AT MOST ONCE PER EVALUATION RUN. (--show-state is not an evaluation run: it
    never calls check_current_system, and its own single read is named in §9.2.)"""
    if scope.layout != "container":
        return StateRead("absent")
    try:
        fd = os.open(str(scope.path), _READ_FLAGS)
    except (OSError, ValueError):
        return StateRead("absent")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return StateRead("foreign")
        head = os.read(fd, 8)
        if head[:8] != STATE_MAGIC:
            return StateRead("foreign")
        if st.st_size > MAX_STATE_FILE_BYTES:
            return StateRead("unusable", detail="file too large")
        rest = _read_all(fd, st.st_size - len(head))
        raw = head + rest
    except (OSError, ValueError):
        return StateRead("absent")
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if len(raw) != st.st_size:
        return StateRead("absent", detail="short read")
    decoded = decode_state(raw)
    return StateRead(
        decoded.status,
        policy_bytes=decoded.policy_bytes,
        signature_bytes=decoded.signature_bytes,
        modified_epoch=st.st_mtime,
        detail=decoded.detail,
    )


def discard_state(scope: StateScope) -> StateEvent:
    """Remove the derived container because it did not yield a verified policy.
    Touches disk. NEVER raises. Returns outcome 'removed' | 'absent' | 'skipped' | 'failed'.

    The tool unlinks a record only at a path it derived itself, only after it has
    opened that file and confirmed its first eight bytes equal STATE_MAGIC, and only
    because the file did not yield a signature-verified policy. A role == "staging"
    path is unlinked with no magic check; that carve-out is exercised only by
    write_bytes_atomically's failure-path cleanup and by purge_state, never here.
    """
    if scope.layout != "container":
        return StateEvent("discard", "skipped", None, scope.source)
    path = str(scope.path)
    try:
        fd = os.open(path, _READ_FLAGS)
    except FileNotFoundError:
        return StateEvent("discard", "absent", path, None)
    except (OSError, ValueError) as exc:
        return StateEvent("discard", "failed", path, _reason(exc))
    try:
        head = os.read(fd, 8)
    except (OSError, ValueError):
        head = b""
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if head[:8] != STATE_MAGIC:
        return StateEvent("discard", "skipped", path, "not our format")
    try:
        _unlink(path)
    except FileNotFoundError:
        return StateEvent("discard", "absent", path, None)
    except (OSError, ValueError) as exc:
        return StateEvent("discard", "failed", path, _reason(exc))
    return StateEvent("discard", "removed", path, None)


def plan_state_scope(
    *,
    os_name: str,
    env: Mapping[str, str],
    temp_dir: str | None,
    uid: int | None,
    policy_url: str,
    trusted_public_key: str | None,
    allow_unsigned_policy: bool,
    cache_file: str | None,
    state_dir: str | None,
    stateless: bool,
) -> StateScope:
    """PURE. Total: returns a StateScope for every input combination and never raises.
    Precedence: stateless > cache_file > state_dir > default temp derivation (§10.4).
    Takes no pid and calls no os.getpid(), so both derived paths are deterministic and the
    §16.2 matrix is assertable for both os_name flavours from either CI leg. trusted_public_key
    and allow_unsigned_policy are threaded straight to derive_state_name (§2.3)."""
    if stateless:
        return StateScope("none", None, None, None, "stateless")
    flavour = PureWindowsPath if os_name == "nt" else PurePosixPath
    if cache_file is not None:
        try:
            path = flavour(cache_file)
            staging = path.with_name(staging_name(path.name))
            signature = path.with_name(path.name + ".sig")  # NOT with_suffix (§2.4 rule 2)
        except ValueError:
            return StateScope("none", None, None, None, "path_not_nameable")
        return StateScope("legacy_pair", path, signature, staging, "cache_file")
    if state_dir is not None:
        if not flavour(state_dir).is_absolute():
            return StateScope("none", None, None, None, "state_dir_not_absolute")
        directory, source = state_dir, "state_dir"
    elif temp_dir is not None:
        directory, source = temp_dir, "default_temp"
    else:
        return StateScope("none", None, None, None, "no_temp_dir")
    name = derive_state_name(
        policy_url=policy_url,
        os_name=os_name,
        env=env,
        uid=uid,
        trusted_public_key=trusted_public_key,
        allow_unsigned_policy=allow_unsigned_policy,
    )
    try:
        path = state_path_for(os_name, directory, name)
        staging = path.with_name(staging_name(path.name))
    except ValueError:
        return StateScope("none", None, None, None, "path_not_nameable")
    return StateScope("container", path, None, staging, source)


def resolve_state_scope(config: ReleaseCheckerConfig) -> StateScope:
    """The single I/O entry point. Never creates anything, never raises. Stateless short-circuits
    before any seam runs (§2.4); otherwise gathers os.name/os.environ and the two seams, resolves
    the effective URL and trusted key, and threads allow_unsigned_policy to plan_state_scope."""
    if config.stateless:
        return StateScope("none", None, None, None, "stateless")
    os_name = os.name
    env = os.environ
    temp_dir = _first_existing_dir(temp_dir_candidates(os_name, env))
    uid = _host_uid()
    policy_url = resolve_policy_url(config.policy_url) or ""
    trusted_public_key = config.trusted_policy_public_key or DEFAULT_TRUSTED_POLICY_PUBLIC_KEY
    return plan_state_scope(
        os_name=os_name,
        env=env,
        temp_dir=temp_dir,
        uid=uid,
        policy_url=policy_url,
        trusted_public_key=trusted_public_key,
        allow_unsigned_policy=config.allow_unsigned_policy,
        cache_file=config.cache_file,
        state_dir=config.state_dir,
        stateless=config.stateless,
    )


def legacy_state_paths(os_name: str, env: Mapping[str, str]) -> tuple[PurePath, ...]:
    """PURE, no I/O. (policy, signature) as PureWindowsPath when os_name == 'nt' and LOCALAPPDATA
    is set and non-empty; () otherwise."""
    if os_name != "nt":
        return ()
    localappdata = env.get("LOCALAPPDATA", "")
    if not localappdata:
        return ()
    base = PureWindowsPath(localappdata) / "win11_release_guard"
    return (
        base / "windows-release-policy.json",
        base / "windows-release-policy.json.sig",
    )


def _legacy_dir_is_retirable(directory: str, env: Mapping[str, str]) -> bool:
    """PURE, no I/O. Built on PureWindowsPath unconditionally on both CI legs; path-equality,
    never string-equality."""
    d = PureWindowsPath(directory)
    return d.name == "win11_release_guard" and d.parent == PureWindowsPath(
        env.get("LOCALAPPDATA", "") or "\\\\"
    )


def retire_legacy_state(cache_file: str | None, state_dir: str | None) -> tuple[StateEvent, ...]:
    """Touches disk. NEVER raises. Runs only on the default temp path: returns () immediately when
    an explicit location is configured (cache_file is not None OR state_dir is not None, any value).
    Otherwise unlinks the two known legacy files, then os.rmdir's their parent — the design's ONLY
    os.rmdir (R-1) — only when _legacy_dir_is_retirable AND os.listdir is then empty. Every OSError
    is swallowed."""
    if cache_file is not None or state_dir is not None:
        return ()
    env = os.environ
    paths = legacy_state_paths(os.name, env)
    if not paths:
        return ()
    events: list[StateEvent] = []
    parent: PurePath | None = None
    for path in paths:
        parent = path.parent
        target = str(path)
        try:
            _unlink(target)
            events.append(StateEvent("retire", "removed", target, None))
        except FileNotFoundError:
            events.append(StateEvent("retire", "absent", target, None))
        except (OSError, ValueError) as exc:
            events.append(StateEvent("retire", "failed", target, _reason(exc)))
    if parent is not None and _legacy_dir_is_retirable(str(parent), env):
        with contextlib.suppress(OSError, ValueError):
            if not os.listdir(str(parent)):
                os.rmdir(str(parent))
                events.append(StateEvent("retire", "removed", str(parent), None))
    return tuple(events)


def _state_entries(config: ReleaseCheckerConfig) -> tuple[tuple[str, Path], ...]:
    """The single (role, path) producer and the only PurePath -> Path enumeration site. Forces
    stateless=False (§9.2 rule 3). container -> (state, staging); legacy_pair -> (cache_file,
    staging, signature, staging); plus the two legacy paths on Windows for any non-'none' layout."""
    scope = resolve_state_scope(replace(config, stateless=False))
    entries: list[tuple[str, Path]] = []
    if scope.layout == "container" and scope.path is not None:
        entries.append(("state", Path(scope.path)))
        if scope.staging_path is not None:
            entries.append(("staging", Path(scope.staging_path)))
    elif scope.layout == "legacy_pair" and scope.path is not None:
        entries.append(("cache_file", Path(scope.path)))
        if scope.staging_path is not None:
            entries.append(("staging", Path(scope.staging_path)))
        if scope.signature_path is not None:
            entries.append(("signature", Path(scope.signature_path)))
            sig_staging = scope.signature_path.with_name(staging_name(scope.signature_path.name))
            entries.append(("staging", Path(sig_staging)))
    if scope.layout != "none":
        for legacy in legacy_state_paths(os.name, os.environ):
            entries.append(("legacy", Path(legacy)))
    return tuple(entries)


def purge_state(config: ReleaseCheckerConfig) -> tuple[StateEvent, ...]:
    """One StateEvent per path this configuration may have written. Magic-gated for the derived
    'state' record only; no magic check for staging/cache_file/signature/legacy (§7.2). Closes the
    magic-check descriptor before unlink. layout 'none' -> one skipped event. Never rmdirs (R-1).
    Never raises.

    Role 'legacy' is not gated because the gate could never pass: those two paths hold the plain
    JSON cache.save_policy_cache wrote plus its raw detached signature, so neither ever carries
    STATE_MAGIC. Gating them would leave the pre-container cache permanently unremovable by the
    shipped CLI while retire_legacy_state unlinks the very same paths unread (O-1, §8.1, §8.2),
    against §8's own statement that --purge-state removes them.
    """
    scope = resolve_state_scope(replace(config, stateless=False))
    if scope.layout == "none":
        return (StateEvent("purge", "skipped", None, scope.source),)
    magic_roles = {"state"}
    events: list[StateEvent] = []
    for role, path in _state_entries(config):
        target = str(path)
        if role in magic_roles:
            try:
                fd = os.open(target, _READ_FLAGS)
            except FileNotFoundError:
                events.append(StateEvent("purge", "absent", target, None))
                continue
            except (OSError, ValueError) as exc:
                events.append(StateEvent("purge", "failed", target, _reason(exc)))
                continue
            try:
                head = _read_all(fd, len(STATE_MAGIC))
            except (OSError, ValueError):
                head = b""
            finally:
                # Swallowed exactly as in read_state and discard_state: a close that
                # fails on a descriptor already read cannot be allowed out of a
                # function documented NEVER raises.
                try:
                    os.close(fd)
                except OSError:
                    pass
            if head != STATE_MAGIC:
                events.append(StateEvent("purge", "skipped", target, "not our format"))
                continue
        try:
            _unlink(target)
            events.append(StateEvent("purge", "removed", target, None))
        except FileNotFoundError:
            events.append(StateEvent("purge", "absent", target, None))
        except (OSError, ValueError) as exc:
            events.append(StateEvent("purge", "failed", target, _reason(exc)))
    return tuple(events)


def describe_state(config: ReleaseCheckerConfig) -> dict[str, Any]:
    """The --show-state payload (§12.1). Read-only. NEVER raises. layout/source describe the
    inspected location (forced stateless=False); 'stateless' is config.stateless verbatim. Every
    per-path os.stat is guarded; status is StateRead.status for role == 'state' only, else null."""
    inspected = replace(config, stateless=False)
    scope = resolve_state_scope(inspected)
    state_read = read_state(scope)
    entries: list[dict[str, Any]] = []
    for role, path in _state_entries(config):
        entry: dict[str, Any] = {
            "path": str(path),
            "role": role,
            "exists": False,
            "status": None,
            "size_bytes": None,
            "modified_utc": None,
            "policy_generated_at_utc": None,
            "policy_bytes": None,
            "policy_sha256": None,
            "signature_present": None,
            "detail": None,
        }
        try:
            st = os.stat(str(path))
            entry["exists"] = True
            entry["size_bytes"] = st.st_size
            entry["modified_utc"] = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            # OverflowError is not a ValueError — it is an ArithmeticError — and it is
            # what CPython raises for an st_mtime outside the platform time_t range, so
            # dropping it from this tuple breaks the NEVER-raises contract above.
            pass
        if role == "state":
            entry["status"] = state_read.status
            entry["detail"] = state_read.detail
            if state_read.status == "usable":
                policy_bytes = state_read.policy_bytes or b""
                signature_bytes = state_read.signature_bytes
                entry["policy_bytes"] = len(policy_bytes)
                entry["policy_sha256"] = hashlib.sha256(policy_bytes).hexdigest()
                entry["signature_present"] = bool(signature_bytes)
                try:
                    document = strict_json_object(policy_bytes)
                    generated = document.get("generated_at_utc")
                    entry["policy_generated_at_utc"] = generated if isinstance(generated, str) else None
                except (OSError, ValueError):
                    entry["policy_generated_at_utc"] = None
        entries.append(entry)
    return {
        "layout": scope.layout,
        "source": scope.source,
        "stateless": config.stateless,
        "state_format_version": STATE_FORMAT_VERSION,
        "entries": entries,
    }


def read_state_bytes(config: ReleaseCheckerConfig) -> bytes | None:
    """I/O, read-only. NEVER raises. The exact stored policy bytes, or None."""
    read = read_state(resolve_state_scope(replace(config, stateless=False)))
    return read.policy_bytes if read.status == "usable" else None
