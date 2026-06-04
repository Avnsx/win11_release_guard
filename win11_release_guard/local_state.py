from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
from ctypes import wintypes
from pathlib import Path
from typing import Any, Mapping

from .config import (
    DEFAULT_DISM_TIMEOUT_SECONDS,
    DEFAULT_PANTHER_TAIL_MAX_BYTES,
    DEFAULT_POWERSHELL_TIMEOUT_SECONDS,
)
from .models import EditionScope, LocalWindowsState, ServicingChannel


CURRENT_VERSION_REGISTRY_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
KERNEL_IMAGE_PATH = r"C:\Windows\System32\ntoskrnl.exe"
PANTHER_LOG_PATHS = (
    r"C:\Windows\Panther\setupact.log",
    r"C:\Windows\Panther\setuperr.log",
)

DEFAULT_BUILD_FAMILY_RELEASES: Mapping[int, str] = {
    22000: "21H2",
    22621: "22H2",
    22631: "23H2",
    26100: "24H2",
    26200: "25H2",
    28000: "26H1",
}

BUILD_SIGNAL_TRUST: Mapping[str, dict[str, int | str]] = {
    "rtl": {"trust": "runtime_truth", "weight": 120, "priority": 0},
    "dism_image": {"trust": "dism_image", "weight": 80, "priority": 1},
    "kernel": {"trust": "runtime_file", "weight": 60, "priority": 2},
    "registry": {"trust": "registry_metadata", "weight": 35, "priority": 3},
    "wmi": {"trust": "wmi_metadata", "weight": 35, "priority": 4},
}

PRODUCT_INFO_EDITION_SCOPES: Mapping[int, EditionScope] = {
    0x00000002: EditionScope.HOME_PRO,
    0x00000003: EditionScope.HOME_PRO,
    0x00000005: EditionScope.HOME_PRO,
    0x00000030: EditionScope.HOME_PRO,
    0x00000031: EditionScope.HOME_PRO,
    0x00000062: EditionScope.HOME_PRO,
    0x00000063: EditionScope.HOME_PRO,
    0x00000064: EditionScope.HOME_PRO,
    0x00000065: EditionScope.HOME_PRO,
    0x000000A1: EditionScope.HOME_PRO,
    0x000000A2: EditionScope.HOME_PRO,
    0x000000A4: EditionScope.HOME_PRO,
    0x000000A5: EditionScope.HOME_PRO,
    0x00000004: EditionScope.ENTERPRISE_EDUCATION,
    0x0000001B: EditionScope.ENTERPRISE_EDUCATION,
    0x00000046: EditionScope.ENTERPRISE_EDUCATION,
    0x00000048: EditionScope.ENTERPRISE_EDUCATION,
    0x00000079: EditionScope.ENTERPRISE_EDUCATION,
    0x0000007A: EditionScope.ENTERPRISE_EDUCATION,
    0x0000007D: EditionScope.ENTERPRISE_LTSC,
    0x0000007E: EditionScope.ENTERPRISE_LTSC,
    0x00000081: EditionScope.ENTERPRISE_LTSC,
    0x00000082: EditionScope.ENTERPRISE_LTSC,
    0x000000BC: EditionScope.ENTERPRISE_EDUCATION,
    0x000000BF: EditionScope.IOT_ENTERPRISE_LTSC,
}

SERVER_PRODUCT_INFO_CODES: frozenset[int] = frozenset(
    {
        0x00000007,
        0x00000008,
        0x00000009,
        0x0000000A,
        0x0000000C,
        0x0000000D,
        0x0000000E,
        0x00000011,
        0x00000012,
        0x00000013,
        0x00000014,
        0x00000015,
        0x00000016,
        0x00000017,
        0x00000018,
        0x00000019,
        0x00000021,
        0x00000022,
        0x00000024,
        0x00000025,
        0x00000026,
        0x00000027,
        0x00000028,
        0x00000029,
        0x0000002A,
        0x0000002B,
        0x0000002C,
        0x0000002D,
        0x0000002E,
        0x00000032,
        0x00000033,
        0x00000034,
        0x00000035,
        0x00000036,
        0x00000037,
        0x00000038,
        0x0000003F,
        0x00000040,
        0x0000004F,
        0x00000050,
        0x00000078,
        0x00000091,
        0x00000092,
        0x00000095,
        0x00000096,
    }
)


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def extract_release(value: str | None) -> str | None:
    match = re.search(r"\b(\d{2}H[12])\b", value or "", flags=re.IGNORECASE)
    return match.group(1).upper() if match else None


def infer_release_from_build_family(
    build_family: int | None,
    build_family_map: Mapping[int, str] = DEFAULT_BUILD_FAMILY_RELEASES,
) -> str | None:
    if build_family is None:
        return None
    release = build_family_map.get(int(build_family))
    return release.upper() if release else None


def _full_build(build: int | None, ubr: int | None) -> str | None:
    if build is None:
        return None
    return f"{build}.{ubr}" if ubr is not None else str(build)


def _version_build(value: str | None) -> int | None:
    if not value:
        return None
    parts = str(value).split(".")
    try:
        if len(parts) >= 3:
            return int(parts[2])
        return int(parts[0])
    except ValueError:
        return None


def _version_ubr(value: str | None) -> int | None:
    if not value:
        return None
    parts = str(value).split(".")
    if len(parts) < 2:
        return None
    try:
        return int(parts[3] if len(parts) >= 4 else parts[1])
    except ValueError:
        return None


def _is_plausible_windows_version(value: str | None) -> bool:
    if not value:
        return False
    parts = str(value).strip().split(".")
    if len(parts) not in {3, 4}:
        return False
    try:
        numbers = [int(part) for part in parts]
    except ValueError:
        return False
    major = numbers[0]
    build = numbers[2]
    revision = numbers[3] if len(numbers) == 4 else 0
    return major >= 6 and build >= 10240 and revision >= 0


def _build_signal_metadata(source: str) -> dict[str, int | str]:
    return dict(BUILD_SIGNAL_TRUST.get(source, {"trust": "diagnostic", "weight": 10, "priority": 99}))


def _build_signal_decision(candidates: list[tuple[str, int | None]]) -> dict[str, Any]:
    signals: list[dict[str, Any]] = []
    grouped: dict[int, dict[str, Any]] = {}
    for source, value in candidates:
        if value is None:
            continue
        metadata = _build_signal_metadata(source)
        build = int(value)
        signal = {
            "source": source,
            "build": build,
            "trust": metadata["trust"],
            "weight": metadata["weight"],
            "priority": metadata["priority"],
        }
        signals.append(signal)
        group = grouped.setdefault(
            build,
            {
                "build": build,
                "sources": [],
                "trust_classes": [],
                "score": 0,
                "highest_signal_weight": 0,
                "best_priority": 99,
            },
        )
        group["sources"].append(source)
        group["trust_classes"].append(metadata["trust"])
        group["score"] += int(metadata["weight"])
        group["highest_signal_weight"] = max(int(group["highest_signal_weight"]), int(metadata["weight"]))
        group["best_priority"] = min(int(group["best_priority"]), int(metadata["priority"]))

    if not grouped:
        return {
            "selected_build": None,
            "selection_method": "weighted_trust",
            "selected_sources": [],
            "selected_trust_classes": [],
            "conflict": False,
            "signals": [],
            "conflicting_builds": {},
        }

    selected = max(
        grouped.values(),
        key=lambda group: (
            int(group["score"]),
            int(group["highest_signal_weight"]),
            -int(group["best_priority"]),
            int(group["build"]),
        ),
    )
    selected_build = int(selected["build"])
    for signal in signals:
        signal["selected"] = int(signal["build"]) == selected_build

    return {
        "selected_build": selected_build,
        "selection_method": "weighted_trust",
        "selected_sources": list(selected["sources"]),
        "selected_trust_classes": list(dict.fromkeys(str(item) for item in selected["trust_classes"])),
        "conflict": len(grouped) > 1,
        "signals": signals,
        "conflicting_builds": {
            str(build): {
                "sources": list(group["sources"]),
                "trust_classes": list(dict.fromkeys(str(item) for item in group["trust_classes"])),
                "score": int(group["score"]),
                "highest_signal_weight": int(group["highest_signal_weight"]),
            }
            for build, group in sorted(grouped.items())
        },
    }


def _choose_build(candidates: list[tuple[str, int | None]]) -> int | None:
    decision = _build_signal_decision(candidates)
    selected = decision.get("selected_build")
    return int(selected) if selected is not None else None


def _build_signal_conflicts(
    candidates: list[tuple[str, int | None]],
    *,
    selected_build: int | None,
    decision: Mapping[str, Any] | None = None,
) -> tuple[str, ...]:
    present = [(source, value) for source, value in candidates if value is not None]
    values = {value for _, value in present}
    if len(values) <= 1:
        return ()
    signals = ", ".join(f"{source}={value}" for source, value in present)
    selected_sources = ", ".join(str(source) for source in (decision or {}).get("selected_sources", []))
    selected_by = f" via weighted_trust from {selected_sources}" if selected_sources else ""
    return (
        f"LOCAL_BUILD_SIGNAL_CONFLICT: build signals disagree ({signals}); "
        f"selected current_build={selected_build}{selected_by}.",
    )


def _read_registry_current_version() -> dict[str, Any]:
    import winreg

    names = (
        "CurrentBuildNumber",
        "CurrentBuild",
        "UBR",
        "DisplayVersion",
        "ReleaseId",
        "EditionID",
        "InstallationType",
        "ProductName",
        "CompositionEditionID",
    )
    values: dict[str, Any] = {}
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CURRENT_VERSION_REGISTRY_PATH) as key:
        for name in names:
            try:
                values[name] = winreg.QueryValueEx(key, name)[0]
            except OSError:
                values[name] = None
    return values


class _RtlOsVersionInfoExW(ctypes.Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", wintypes.DWORD),
        ("dwMajorVersion", wintypes.DWORD),
        ("dwMinorVersion", wintypes.DWORD),
        ("dwBuildNumber", wintypes.DWORD),
        ("dwPlatformId", wintypes.DWORD),
        ("szCSDVersion", wintypes.WCHAR * 128),
        ("wServicePackMajor", wintypes.WORD),
        ("wServicePackMinor", wintypes.WORD),
        ("wSuiteMask", wintypes.WORD),
        ("wProductType", ctypes.c_ubyte),
        ("wReserved", ctypes.c_ubyte),
    ]


def _read_rtl_get_version() -> dict[str, Any]:
    info = _RtlOsVersionInfoExW()
    info.dwOSVersionInfoSize = ctypes.sizeof(info)

    func = ctypes.WinDLL("ntdll").RtlGetVersion
    func.argtypes = [ctypes.POINTER(_RtlOsVersionInfoExW)]
    func.restype = wintypes.ULONG

    status = func(ctypes.byref(info))
    if status != 0:
        raise OSError(f"RtlGetVersion failed with NTSTATUS={status}")

    return {
        "major": int(info.dwMajorVersion),
        "minor": int(info.dwMinorVersion),
        "build": int(info.dwBuildNumber),
        "version": f"{info.dwMajorVersion}.{info.dwMinorVersion}.{info.dwBuildNumber}",
    }


def _read_product_info(major_version: int = 10, minor_version: int = 0) -> int | None:
    product_type = wintypes.DWORD()
    func = ctypes.WinDLL("kernel32", use_last_error=True).GetProductInfo
    func.argtypes = [
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    func.restype = wintypes.BOOL
    ok = func(
        wintypes.DWORD(int(major_version or 10)),
        wintypes.DWORD(int(minor_version or 0)),
        wintypes.DWORD(0),
        wintypes.DWORD(0),
        ctypes.byref(product_type),
    )
    if not ok:
        raise OSError(f"GetProductInfo failed with Win32 error {ctypes.get_last_error()}.")
    return int(product_type.value)


def _read_wmi_operating_system(
    timeout_seconds: float = DEFAULT_POWERSHELL_TIMEOUT_SECONDS,
) -> dict[str, Any] | None:
    command = (
        "$os = Get-CimInstance Win32_OperatingSystem; "
        "[pscustomobject]@{"
        "Caption=$os.Caption;"
        "Version=$os.Version;"
        "BuildNumber=$os.BuildNumber;"
        "OperatingSystemSKU=$os.OperatingSystemSKU;"
        "OSArchitecture=$os.OSArchitecture"
        "} | ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"Get-CimInstance Win32_OperatingSystem timed out after {timeout_seconds:g} seconds."
        ) from exc
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise RuntimeError(f"Get-CimInstance Win32_OperatingSystem failed: {stderr}")
    if not proc.stdout.strip():
        return None

    data = json.loads(proc.stdout)
    if isinstance(data, list):
        data = data[0] if data else None
    return data if isinstance(data, dict) else None


def _edition_scope_from_text(value: str | None) -> EditionScope:
    if not value:
        return EditionScope.UNKNOWN
    text = value.lower()
    compact = re.sub(r"[^a-z0-9]+", "", text)
    if "server" in compact:
        return EditionScope.SERVER
    if "iotenterprises" in compact or ("iot" in compact and "enterprise" in compact and "ltsc" in compact):
        return EditionScope.IOT_ENTERPRISE_LTSC
    if "enterprises" in compact or "enterpriseltsc" in compact or "ltsc" in compact or "ltsb" in compact:
        return EditionScope.ENTERPRISE_LTSC
    if "enterprise" in compact or "education" in compact:
        return EditionScope.ENTERPRISE_EDUCATION
    if "professional" in compact or re.search(r"\bpro\b", text) or "workstation" in compact or "core" in compact or "home" in compact:
        return EditionScope.HOME_PRO
    return EditionScope.UNKNOWN


def _edition_scope_from_product_info(product_info_code: int | None) -> EditionScope:
    if product_info_code is None:
        return EditionScope.UNKNOWN
    code = int(product_info_code)
    if code in SERVER_PRODUCT_INFO_CODES:
        return EditionScope.SERVER
    return PRODUCT_INFO_EDITION_SCOPES.get(code, EditionScope.UNKNOWN)


def _edition_scope_from_signals(
    *,
    dism_edition: str | None,
    edition_id: str | None,
    product_info_code: int | None,
    installation_type: str | None,
    product_name: str | None,
    caption: str | None,
) -> EditionScope:
    for value in (dism_edition, edition_id):
        scope = _edition_scope_from_text(value)
        if scope is not EditionScope.UNKNOWN:
            return scope
    product_info_scope = _edition_scope_from_product_info(product_info_code)
    if product_info_scope is not EditionScope.UNKNOWN:
        return product_info_scope
    for value in (installation_type, product_name, caption):
        scope = _edition_scope_from_text(value)
        if scope is not EditionScope.UNKNOWN:
            return scope
    return EditionScope.UNKNOWN


def _servicing_channel_from_signals(
    edition_scope: EditionScope,
    *,
    edition_id: str | None,
    dism_edition: str | None,
    product_name: str | None,
    caption: str | None,
) -> ServicingChannel:
    if edition_scope in {EditionScope.ENTERPRISE_LTSC, EditionScope.IOT_ENTERPRISE_LTSC}:
        return ServicingChannel.LTSC
    text = " ".join(str(value).lower() for value in (edition_id, dism_edition, product_name, caption) if value)
    if "hotpatch" in text or "hot patch" in text:
        return ServicingChannel.HOTPATCH
    if "ltsc" in text or "ltsb" in text:
        return ServicingChannel.LTSC
    if edition_scope in {EditionScope.HOME_PRO, EditionScope.ENTERPRISE_EDUCATION}:
        return ServicingChannel.GENERAL_AVAILABILITY
    return ServicingChannel.UNKNOWN


def _parse_dism_current_edition_output(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for pattern in (r"Current Edition\s*:\s*(\S+)", r"Aktuelle Edition\s*:\s*(\S+)"):
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            data["current_edition"] = match.group(1).strip()
            break

    for pattern in (r"^\s*Image Version\s*:\s*(\S+)", r"^\s*Abbildversion\s*:\s*(\S+)"):
        match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
        if match:
            data["image_version"] = match.group(1).strip()
            break

    image_match_start = None
    image_match = re.search(r"^\s*(?:Image Version|Abbildversion)\s*:", text, flags=re.IGNORECASE | re.MULTILINE)
    if image_match:
        image_match_start = image_match.start()
    tool_text = text if image_match_start is None else text[:image_match_start]
    match = re.search(r"^\s*Version\s*:\s*(\S+)", tool_text, flags=re.IGNORECASE | re.MULTILINE)
    if match:
        data["dism_tool_version"] = match.group(1).strip()
    return data


def _normalize_dism_current_edition_info(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        data = {
            "current_edition": _optional_str(value.get("current_edition") or value.get("CurrentEdition")),
            "image_version": _optional_str(value.get("image_version") or value.get("ImageVersion")),
            "dism_tool_version": _optional_str(value.get("dism_tool_version") or value.get("DismToolVersion")),
        }
        return {key: item for key, item in data.items() if item}
    text = _optional_str(value)
    return {"current_edition": text} if text else {}


def _read_dism_current_edition(
    timeout_seconds: float = DEFAULT_DISM_TIMEOUT_SECONDS,
) -> dict[str, str] | None:
    try:
        proc = subprocess.run(
            ["dism.exe", "/Online", "/Get-CurrentEdition"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"DISM Get-CurrentEdition timed out after {timeout_seconds:g} seconds."
        ) from exc
    text = f"{proc.stdout}\n{proc.stderr}"
    if proc.returncode != 0:
        raise RuntimeError(f"DISM Get-CurrentEdition failed with exit code {proc.returncode}.")
    data = _parse_dism_current_edition_output(text)
    return data or None


class _VsFixedFileInfo(ctypes.Structure):
    _fields_ = [
        ("dwSignature", wintypes.DWORD),
        ("dwStrucVersion", wintypes.DWORD),
        ("dwFileVersionMS", wintypes.DWORD),
        ("dwFileVersionLS", wintypes.DWORD),
        ("dwProductVersionMS", wintypes.DWORD),
        ("dwProductVersionLS", wintypes.DWORD),
        ("dwFileFlagsMask", wintypes.DWORD),
        ("dwFileFlags", wintypes.DWORD),
        ("dwFileOS", wintypes.DWORD),
        ("dwFileType", wintypes.DWORD),
        ("dwFileSubtype", wintypes.DWORD),
        ("dwFileDateMS", wintypes.DWORD),
        ("dwFileDateLS", wintypes.DWORD),
    ]


def _read_kernel_file_version(path: str = KERNEL_IMAGE_PATH) -> str | None:
    kernel = Path(path)
    if not kernel.exists():
        return None

    size = ctypes.windll.version.GetFileVersionInfoSizeW(str(kernel), None)
    if not size:
        return None

    buffer = ctypes.create_string_buffer(size)
    ok = ctypes.windll.version.GetFileVersionInfoW(str(kernel), 0, size, buffer)
    if not ok:
        return None

    pointer = ctypes.c_void_p()
    length = wintypes.UINT()
    ok = ctypes.windll.version.VerQueryValueW(
        buffer,
        "\\",
        ctypes.byref(pointer),
        ctypes.byref(length),
    )
    if not ok:
        return None

    info = ctypes.cast(pointer, ctypes.POINTER(_VsFixedFileInfo)).contents
    if info.dwSignature != 0xFEEF04BD:
        return None

    major = (info.dwFileVersionMS >> 16) & 0xFFFF
    minor = info.dwFileVersionMS & 0xFFFF
    build = (info.dwFileVersionLS >> 16) & 0xFFFF
    revision = info.dwFileVersionLS & 0xFFFF
    return f"{major}.{minor}.{build}.{revision}"


def _read_file_tail(
    path: str | Path,
    max_bytes: int = DEFAULT_PANTHER_TAIL_MAX_BYTES,
) -> str:
    log_path = Path(path)
    size = log_path.stat().st_size
    bytes_to_read = max(0, min(int(max_bytes), int(size)))
    with log_path.open("rb") as handle:
        if bytes_to_read and size > bytes_to_read:
            handle.seek(-bytes_to_read, os.SEEK_END)
        data = handle.read(bytes_to_read)
    return data.decode("utf-8", errors="replace")


def _read_panther_logs(
    paths: tuple[str, ...] = PANTHER_LOG_PATHS,
    max_bytes: int = DEFAULT_PANTHER_TAIL_MAX_BYTES,
) -> dict[str, str]:
    logs: dict[str, str] = {}
    for path in paths:
        try:
            log_path = Path(path)
        except NotImplementedError:
            continue
        if not log_path.exists() or not log_path.is_file():
            continue
        logs[str(log_path)] = _read_file_tail(log_path, max_bytes=max_bytes)
    return logs


def _call_timeout_probe(func: Any, *, timeout_seconds: float) -> Any:
    try:
        return func(timeout_seconds=timeout_seconds)
    except TypeError as exc:
        if "unexpected keyword" not in str(exc):
            raise
        return func()


def get_local_windows_state(
    *,
    dism_timeout_seconds: float = DEFAULT_DISM_TIMEOUT_SECONDS,
    powershell_timeout_seconds: float = DEFAULT_POWERSHELL_TIMEOUT_SECONDS,
    panther_tail_max_bytes: int = DEFAULT_PANTHER_TAIL_MAX_BYTES,
) -> LocalWindowsState:
    """Read local Windows release state without network or mutation."""

    if os.name != "nt":
        return LocalWindowsState(
            available=False,
            source="unsupported_platform",
            errors=("Local Windows state collection requires Windows.",),
            raw={"platform": os.name},
        )

    errors: list[str] = []
    raw: dict[str, Any] = {}

    registry: dict[str, Any] = {}
    try:
        registry = _read_registry_current_version()
        raw["registry"] = registry
    except Exception as exc:
        errors.append(f"registry read failed: {exc}")
        raw["registry_error"] = str(exc)

    rtl: dict[str, Any] = {}
    try:
        rtl = _read_rtl_get_version()
        raw["rtl"] = rtl
    except Exception as exc:
        errors.append(f"RtlGetVersion failed: {exc}")
        raw["rtl_error"] = str(exc)

    wmi: dict[str, Any] | None = None
    try:
        wmi = _call_timeout_probe(
            _read_wmi_operating_system,
            timeout_seconds=powershell_timeout_seconds,
        )
        raw["wmi"] = wmi
    except Exception as exc:
        errors.append(f"WMI/CIM read failed: {exc}")
        raw["wmi_error"] = str(exc)

    dism_current_edition: str | None = None
    dism_image_version: str | None = None
    dism_tool_version: str | None = None
    try:
        dism_info = _normalize_dism_current_edition_info(
            _call_timeout_probe(
                _read_dism_current_edition,
                timeout_seconds=dism_timeout_seconds,
            )
        )
        dism_current_edition = dism_info.get("current_edition")
        dism_image_version = dism_info.get("image_version")
        dism_tool_version = dism_info.get("dism_tool_version")
        raw["dism"] = dism_info or None
        raw["dism_current_edition"] = dism_current_edition
        raw["dism_image_version"] = dism_image_version
        raw["dism_tool_version"] = dism_tool_version
    except Exception as exc:
        errors.append(f"DISM current edition read failed: {exc}")
        raw["dism_error"] = str(exc)

    kernel_file_version: str | None = None
    try:
        kernel_file_version = _read_kernel_file_version()
        raw["kernel_file_version"] = kernel_file_version
    except Exception as exc:
        errors.append(f"kernel file version read failed: {exc}")
        raw["kernel_file_version_error"] = str(exc)

    try:
        panther_logs = _read_panther_logs(max_bytes=panther_tail_max_bytes)
        if panther_logs:
            raw["panther_logs"] = panther_logs
    except Exception as exc:
        errors.append(f"Panther log read failed: {exc}")
        raw["panther_error"] = str(exc)

    registry_build = _optional_int(
        registry.get("CurrentBuildNumber") or registry.get("CurrentBuild")
    )
    rtl_build = _optional_int(rtl.get("build"))
    wmi_build = _optional_int((wmi or {}).get("BuildNumber"))
    kernel_build = _version_build(kernel_file_version)
    dism_build = _version_build(dism_image_version) if _is_plausible_windows_version(dism_image_version) else None
    build_candidates = [
        ("registry", registry_build),
        ("rtl", rtl_build),
        ("wmi", wmi_build),
        ("kernel", kernel_build),
        ("dism_image", dism_build),
    ]

    build_signal_decision = _build_signal_decision(build_candidates)
    selected_build = build_signal_decision.get("selected_build")
    current_build = int(selected_build) if selected_build is not None else None
    raw["build_signals"] = {source: value for source, value in build_candidates if value is not None}
    raw["build_signal_decision"] = build_signal_decision
    build_conflicts = _build_signal_conflicts(
        build_candidates,
        selected_build=current_build,
        decision=build_signal_decision,
    )
    if build_conflicts:
        raw["build_signal_conflicts"] = list(build_conflicts)
        errors.extend(build_conflicts)

    ubr = _optional_int(registry.get("UBR"))
    if ubr is None and kernel_build == current_build:
        ubr = _version_ubr(kernel_file_version)
    if ubr is None and dism_build == current_build:
        ubr = _version_ubr(dism_image_version)

    display_version = _optional_str(registry.get("DisplayVersion"))
    display_release = extract_release(display_version)
    build_release = infer_release_from_build_family(current_build)
    inferred_release = build_release or display_release
    if display_release and build_release and display_release != build_release:
        errors.append(
            f"DisplayVersion {display_release} differs from build-family inference {build_release}."
        )

    available = current_build is not None
    if not available:
        errors.append("No usable build signal was collected.")

    major_version = _optional_int(rtl.get("major"))
    if major_version is None:
        wmi_version = _optional_str((wmi or {}).get("Version"))
        try:
            major_version = int(wmi_version.split(".", 1)[0]) if wmi_version else None
        except ValueError:
            major_version = None
    if major_version is None and _is_plausible_windows_version(dism_image_version):
        try:
            major_version = int(str(dism_image_version).split(".", 1)[0])
        except ValueError:
            major_version = None
    rtl_minor_version = _optional_int(rtl.get("minor")) or 0
    product_info_code: int | None = None
    try:
        product_info_code = _read_product_info(major_version or 10, rtl_minor_version)
        raw["product_info_code"] = product_info_code
    except Exception as exc:
        errors.append(f"GetProductInfo failed: {exc}")
        raw["product_info_error"] = str(exc)

    installation_type = _optional_str(registry.get("InstallationType"))
    product_name = _optional_str(registry.get("ProductName"))
    caption = _optional_str((wmi or {}).get("Caption"))
    edition_id = _optional_str(registry.get("EditionID"))
    dism_edition = dism_current_edition
    edition_scope = _edition_scope_from_signals(
        dism_edition=dism_edition,
        edition_id=edition_id,
        product_info_code=product_info_code,
        installation_type=installation_type,
        product_name=product_name,
        caption=caption,
    )
    servicing_channel = _servicing_channel_from_signals(
        edition_scope,
        edition_id=edition_id,
        dism_edition=dism_edition,
        product_name=product_name,
        caption=caption,
    )
    server_markers = (installation_type, product_name, caption, edition_id, dism_edition)
    is_server = any("server" in str(value).lower() for value in server_markers if value)
    if edition_scope is EditionScope.SERVER:
        is_server = True
    is_windows_client = not is_server
    is_windows_11_or_newer = bool(is_windows_client and current_build is not None and current_build >= 22000)
    is_ltsc = servicing_channel is ServicingChannel.LTSC
    edition_source = (edition_id or dism_edition or "").lower()
    if "enterprise" in edition_source:
        edition_family = "enterprise"
    elif "education" in edition_source:
        edition_family = "education"
    elif "professional" in edition_source or edition_source == "pro":
        edition_family = "pro"
    elif "home" in edition_source or "core" in edition_source:
        edition_family = "home"
    else:
        edition_family = _optional_str(edition_id or dism_edition)

    return LocalWindowsState(
        current_build=current_build,
        ubr=ubr,
        full_build=_full_build(current_build, ubr),
        inferred_release=inferred_release,
        edition_id=edition_id,
        display_version=display_version,
        release_id=_optional_str(registry.get("ReleaseId")),
        installation_type=installation_type,
        product_name=product_name,
        caption=caption,
        os_version=_optional_str((wmi or {}).get("Version")),
        operating_system_sku=_optional_int((wmi or {}).get("OperatingSystemSKU")),
        major_version=major_version,
        product_family="server" if is_server else "client",
        is_windows_client=is_windows_client,
        is_windows_11_or_newer=is_windows_11_or_newer,
        is_server=is_server,
        is_ltsc=is_ltsc,
        edition_family=edition_family,
        edition_scope=edition_scope,
        servicing_channel=servicing_channel,
        build_family=current_build,
        architecture=_optional_str((wmi or {}).get("OSArchitecture")),
        rtl_version=_optional_str(rtl.get("version")),
        wmi_version=_optional_str((wmi or {}).get("Version")),
        kernel_file_version=kernel_file_version,
        dism_current_edition=dism_current_edition,
        dism_image_version=dism_image_version,
        dism_tool_version=dism_tool_version,
        product_info_code=product_info_code,
        source="local_windows_read_only",
        available=available,
        errors=tuple(errors),
        raw=raw,
    )


def collect_local_windows_state() -> LocalWindowsState:
    return get_local_windows_state()


__all__ = [
    "DEFAULT_BUILD_FAMILY_RELEASES",
    "LocalWindowsState",
    "collect_local_windows_state",
    "extract_release",
    "get_local_windows_state",
    "infer_release_from_build_family",
    "_read_file_tail",
]
