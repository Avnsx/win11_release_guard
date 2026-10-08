from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any
from ._subprocess_util import hidden_console_kwargs
from .config import DEFAULT_DISM_TIMEOUT_SECONDS, DEFAULT_PANTHER_TAIL_MAX_BYTES, DEFAULT_PANTHER_TOTAL_MAX_BYTES, DEFAULT_POWERSHELL_TIMEOUT_SECONDS
from .diagnostic_tail import read_diagnostic_tail, summarize_privacy_marker_entries, summarize_privacy_markers
from .models import EditionScope, LocalWindowsState, ServicingChannel
from .local_build_signals import (
    DEFAULT_BUILD_FAMILY_RELEASES,
    _build_signal_conflicts,
    _build_signal_decision,
    _full_build,
    _is_plausible_windows_version,
    _optional_int,
    _optional_str,
    _version_build,
    _version_ubr,
    extract_release,
    infer_release_from_build_family,
)
from .local_edition import _edition_scope_from_signals, _servicing_channel_from_signals
from .local_windows_probes import (
    NATIVE_OS_INFO_KEYS,  # ponytail: re-exported for tests until Task 12
    _native_os_info_is_complete,
    _normalize_dism_current_edition_info,
    _os_architecture_from_processor_architecture,  # ponytail: re-exported for tests until Task 12
    _parse_dism_current_edition_output,  # ponytail: re-exported for tests until Task 12
    _read_dism_current_edition,
    _read_kernel_file_version,
    _read_native_architecture,
    _read_product_info,
    _read_registry_current_version,
    _read_rtl_get_version,
)


PANTHER_LOG_PATHS = (
    r"C:\Windows\Panther\setupact.log",
    r"C:\Windows\Panther\setuperr.log",
    r"C:\Windows\Panther\UnattendGC\setupact.log",
    r"C:\Windows\Panther\UnattendGC\setuperr.log",
    r"C:\Windows\Panther\NewOS\Panther\setupact.log",
    r"C:\Windows\Panther\NewOS\Panther\setuperr.log",
    r"C:\$Windows.~BT\Sources\Panther\setupact.log",
    r"C:\$Windows.~BT\Sources\Panther\setuperr.log",
    r"C:\$Windows.~BT\Sources\Rollback\setupact.log",
    r"C:\$Windows.~BT\Sources\Rollback\setuperr.log",
    r"C:\$Windows.~BT\NewOS\Windows\Panther\setupact.log",
    r"C:\$Windows.~BT\NewOS\Windows\Panther\setuperr.log",
)


def _read_native_operating_system() -> dict[str, Any] | None:
    """Read OS identity fields natively (registry + ctypes), no process spawn.

    Returns the same dict shape as :func:`_read_wmi_operating_system_via_powershell`
    (``Caption``, ``Version``, ``BuildNumber``, ``OperatingSystemSKU``,
    ``OSArchitecture``), sourced from:

    * ``RtlGetVersion`` (via ntdll, immune to the GetVersionEx compatibility
      shim that misreports version on some hosts) for the accurate OS
      version/build.
    * ``GetNativeSystemInfo`` for processor architecture.
    * ``GetProductInfo`` for the SKU code. Per Microsoft's own
      Win32_OperatingSystem documentation, OperatingSystemSKU "values are the
      same as the PRODUCT_* constants ... used with the GetProductInfo
      function", so this is a direct, faithful passthrough rather than a
      guess.

    ``Caption`` is always ``None``: the registry's ``ProductName`` is known to
    go stale after some in-place upgrades (e.g. it can still read a "Windows
    10" name on an updated Windows 11 host), unlike Win32_OperatingSystem's
    CIM-computed ``Caption``. Synthesizing a ``Caption`` from it would ship a
    display-only value that looks authoritative but can contradict the
    build-derived release and misfire display-only conflict checks. Callers
    that need a caption get it from the PowerShell/CIM fallback instead.

    Returns ``None`` on non-Windows, or lets a read failure raise so the
    caller can fall back to the PowerShell probe. A dict missing any expected
    key's value is still returned as-is; :func:`_native_os_info_is_complete`
    is what decides whether it is usable.
    """
    if os.name != "nt":
        return None

    rtl = _read_rtl_get_version()

    build_number = rtl.get("build")

    product_info_code: int | None = None
    try:
        product_info_code = _read_product_info(
            int(rtl.get("major") or 10), int(rtl.get("minor") or 0)
        )
    except Exception:
        product_info_code = None

    return {
        "Caption": None,
        "Version": _optional_str(rtl.get("version")),
        "BuildNumber": str(build_number) if build_number is not None else None,
        "OperatingSystemSKU": product_info_code,
        "OSArchitecture": _read_native_architecture(),
    }


def _read_wmi_operating_system_via_powershell(
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
            **hidden_console_kwargs(),
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


def _read_wmi_operating_system(
    timeout_seconds: float = DEFAULT_POWERSHELL_TIMEOUT_SECONDS,
) -> dict[str, Any] | None:
    """Return Caption/Version/BuildNumber/OperatingSystemSKU/OSArchitecture.

    Tries the native registry+ctypes read first (near-instant, no process
    spawn); falls back to spawning ``powershell.exe`` to run
    ``Get-CimInstance Win32_OperatingSystem`` only if the native read raises,
    or comes back incomplete, so behaviour never regresses on an unusual
    machine. The native path is an optimisation, not a replacement.
    """
    try:
        native = _read_native_operating_system()
    except Exception:
        native = None
    if _native_os_info_is_complete(native):
        return native
    return _read_wmi_operating_system_via_powershell(timeout_seconds=timeout_seconds)


def _read_file_tail(
    path: str | Path,
    max_bytes: int = DEFAULT_PANTHER_TAIL_MAX_BYTES,
) -> str:
    return read_diagnostic_tail(path, max_bytes=max_bytes).content


def _read_panther_logs(
    paths: tuple[str, ...] = PANTHER_LOG_PATHS,
    max_bytes: int = DEFAULT_PANTHER_TAIL_MAX_BYTES,
    total_max_bytes: int = DEFAULT_PANTHER_TOTAL_MAX_BYTES,
    errors: list[str] | None = None,
) -> dict[str, dict[str, object]]:
    logs: dict[str, dict[str, object]] = {}
    try:
        per_file_cap_bytes = max(0, int(max_bytes))
    except (TypeError, ValueError):
        per_file_cap_bytes = DEFAULT_PANTHER_TAIL_MAX_BYTES
    try:
        total_cap_bytes = max(0, int(total_max_bytes))
    except (TypeError, ValueError):
        total_cap_bytes = DEFAULT_PANTHER_TOTAL_MAX_BYTES
    remaining_bytes = total_cap_bytes
    total_cap_reached = False
    for path in paths:
        try:
            log_path = Path(path)
        except NotImplementedError:
            continue
        if not log_path.exists() or not log_path.is_file():
            continue
        if remaining_bytes <= 0:
            total_cap_reached = True
            if errors is not None:
                errors.append(f"Panther log read skipped {log_path}: total cap of {total_cap_bytes} bytes reached.")
            continue
        read_limit = min(per_file_cap_bytes, remaining_bytes)
        try:
            tail = read_diagnostic_tail(log_path, max_bytes=read_limit)
        except OSError as exc:
            if errors is not None:
                errors.append(f"Panther log read failed {log_path}: {exc}")
            continue
        if read_limit < per_file_cap_bytes and tail.tail_truncated:
            total_cap_reached = True
        remaining_bytes = max(0, remaining_bytes - int(tail.tail_bytes))
        entry = tail.to_dict()
        entry.update(summarize_privacy_markers(tail.content))
        logs[str(log_path)] = entry
    if total_cap_reached and logs:
        for entry in logs.values():
            entry["collection_total_cap_bytes"] = total_cap_bytes
            entry["collection_total_cap_reached"] = True
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
    panther_total_max_bytes: int = DEFAULT_PANTHER_TOTAL_MAX_BYTES,
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
        panther_log_errors: list[str] = []
        panther_logs = _read_panther_logs(
            max_bytes=panther_tail_max_bytes,
            total_max_bytes=panther_total_max_bytes,
            errors=panther_log_errors,
        )
        if panther_logs:
            raw["panther_logs"] = panther_logs
            panther_privacy_summary = summarize_privacy_marker_entries(panther_logs.items())
            if panther_privacy_summary["privacy_findings_count"]:
                raw["panther_privacy_findings"] = panther_privacy_summary
        if panther_log_errors:
            errors.extend(panther_log_errors)
            raw["panther_log_errors"] = panther_log_errors
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
