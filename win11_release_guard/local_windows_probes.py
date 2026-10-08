"""Read-only Windows probes: registry, RtlGetVersion, product info, DISM, kernel version."""

from __future__ import annotations

import ctypes
import re
import subprocess
from ctypes import wintypes
from pathlib import Path
from typing import Any, Mapping
from ._subprocess_util import hidden_console_kwargs
from .config import DEFAULT_DISM_TIMEOUT_SECONDS
from .local_build_signals import _optional_str


CURRENT_VERSION_REGISTRY_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


KERNEL_IMAGE_PATH = r"C:\Windows\System32\ntoskrnl.exe"


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


# Maps SYSTEM_INFO.wProcessorArchitecture (as populated by GetNativeSystemInfo)
# to the same strings Win32_OperatingSystem.OSArchitecture reports over WMI/CIM.
_PROCESSOR_ARCHITECTURE_INTEL = 0


_PROCESSOR_ARCHITECTURE_ARM = 5


_PROCESSOR_ARCHITECTURE_IA64 = 6


_PROCESSOR_ARCHITECTURE_AMD64 = 9


_PROCESSOR_ARCHITECTURE_ARM64 = 12


_PROCESSOR_ARCHITECTURE_TO_OS_ARCHITECTURE: Mapping[int, str] = {
    _PROCESSOR_ARCHITECTURE_INTEL: "32-bit",
    _PROCESSOR_ARCHITECTURE_AMD64: "64-bit",
    _PROCESSOR_ARCHITECTURE_ARM64: "ARM 64-bit Processor",
    _PROCESSOR_ARCHITECTURE_ARM: "ARM 32-bit Processor",
    _PROCESSOR_ARCHITECTURE_IA64: "IA64-based",
}


# The dict keys _read_wmi_operating_system (native or PowerShell) must
# populate for downstream code to treat the result as usable. "Caption" is
# deliberately excluded: the native read has no faithful source for it (see
# _read_native_operating_system), so requiring it here would force every
# native read to be judged incomplete and fall back to spawning powershell.exe
# on every run.
NATIVE_OS_INFO_KEYS = ("Version", "BuildNumber", "OperatingSystemSKU", "OSArchitecture")


# Only wProcessorArchitecture is used below; the rest of the fields exist so
# the struct layout (and therefore field offsets/alignment) matches the real
# Win32 SYSTEM_INFO that GetNativeSystemInfo writes into.
class _SystemInfo(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", wintypes.LPVOID),
        ("lpMaximumApplicationAddress", wintypes.LPVOID),
        ("dwActiveProcessorMask", wintypes.WPARAM),
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD),
    ]


def _os_architecture_from_processor_architecture(code: int | None) -> str | None:
    if code is None:
        return None
    return _PROCESSOR_ARCHITECTURE_TO_OS_ARCHITECTURE.get(int(code))


def _read_native_architecture() -> str | None:
    """Return the OSArchitecture string GetNativeSystemInfo implies, or None.

    None covers both an API failure and a processor architecture this module
    has no faithful WMI-style string for; either way the caller treats it as
    "could not confirm" rather than guessing.
    """
    try:
        info = _SystemInfo()
        ctypes.windll.kernel32.GetNativeSystemInfo(ctypes.byref(info))
    except (AttributeError, OSError, ValueError):
        return None
    return _os_architecture_from_processor_architecture(info.wProcessorArchitecture)


def _native_os_info_is_complete(data: Mapping[str, Any] | None) -> bool:
    """True when every field callers of _read_wmi_operating_system rely on is present.

    Anything less (a missing signal, a None field) means the native read could
    not faithfully reproduce what the PowerShell/CIM probe would have
    returned, so the caller falls back to it instead of shipping a partial or
    guessed value.
    """
    if not isinstance(data, Mapping):
        return False
    return all(data.get(key) is not None for key in NATIVE_OS_INFO_KEYS)


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
            **hidden_console_kwargs(),
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
