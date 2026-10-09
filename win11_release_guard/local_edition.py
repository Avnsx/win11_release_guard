"""Edition scope and servicing channel classification from local signals."""

from __future__ import annotations

import re
from typing import Mapping
from .models import EditionScope, ServicingChannel


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
