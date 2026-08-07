from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html import escape, unescape
from pathlib import Path
from typing import Callable, Mapping
from xml.etree import ElementTree

from .exceptions import PolicyFetchError
from .freshness import parse_iso_utc_datetime
from . import http_client


WINDOWS_UPDATE_CLIENT_URL = "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx"
WINDOWS_UPDATE_SOAP_CONTENT_TYPE = "application/soap+xml; charset=utf-8"
WINDOWS_UPDATE_USER_AGENT = "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.0"
CLIENT_WEB_SERVICE_NS = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"
GET_COOKIE_ACTION = f"{CLIENT_WEB_SERVICE_NS}/GetCookie"
SYNC_UPDATES_ACTION = f"{CLIENT_WEB_SERVICE_NS}/SyncUpdates"
PRODUCT_NAME = "Client.OS.rs2.amd64"
PRODUCT_BRANCH = "ge_release"
CALLER_ATTRIBUTES = "E:Profile=AUv2&Acquisition=1&Interactive=1&IsSeeker=0&SheddingAware=1&Id=MoUpdateOrchestrator"

# The service answers HTTP 500 to a partial SyncUpdates request, so the full
# 75-entry installed-update set is sent on every call.
INSTALLED_NON_LEAF_UPDATE_IDS = (
    1, 105939029, 105995585, 106017178, 107825194, 10809856, 11, 117765322,
    129905029, 130040030, 130040031, 130040032, 130040033, 133399034,
    138372035, 138372036, 139536037, 139536038, 139536039, 139536040,
    142045136, 158941041, 158941042, 158941043, 158941044, 159776047,
    160733048, 160733049, 160733050, 160733051, 160733055, 160733056,
    161870057, 161870058, 161870059, 19, 2, 23110993, 23110994, 23110995,
    23110996, 23110999, 23111000, 23111001, 23111002, 23111003, 23111004,
    2359974, 2359977, 24513870, 28880263, 3, 30077688, 30486944, 5143990,
    5169043, 5169044, 5169047, 59830006, 59830007, 59830008, 60484010,
    62450018, 62450019, 62450020, 69801474, 8788830, 8806526, 9125350,
    9154769, 98959022, 98959023, 98959024, 98959025, 98959026,
)

_BUILD_RE = re.compile(r"\b(\d{5,6}\.\d{1,5})\b")
_RELEASE_VERSION_RE = re.compile(r'ReleaseVersion="([^"]{1,64})"')
_KB_ELEMENT_RE = re.compile(r"<KBArticleID>\s*(?:KB)?(\d{6,8})\s*</KBArticleID>", re.IGNORECASE)
_KB_TITLE_RE = re.compile(r"\bKB(\d{6,8})\b", re.IGNORECASE)
_TITLE_RE = re.compile(r"<Title>(.*?)</Title>", re.DOTALL | re.IGNORECASE)
_MORE_INFO_URL_RE = re.compile(r"<MoreInfoUrl>(.*?)</MoreInfoUrl>", re.DOTALL | re.IGNORECASE)
_SUPPORT_URL_RE = re.compile(r"^https://support\.microsoft\.com/[^\s\"'<>]*$")

DEFAULT_MAX_SYNC_UPDATES_BYTES = 24 * 1024 * 1024
DEFAULT_WINDOWS_UPDATE_PROBE_TIMEOUT_SECONDS = 20.0
DEFAULT_COOKIE_CACHE_PATH = Path(".tmp") / "windows-update-cookie.json"
DEFAULT_PROBE_OS_VERSION = "10.0.26200.8000"
COOKIE_SAFETY_MARGIN_SECONDS = 3600
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_FRACTION_RE = re.compile(r"\.(\d+)")

SoapPost = Callable[[str, float], str]


@dataclass(frozen=True)
class WindowsUpdateOffer:
    kb_article: str | None
    build: str | None
    release_version: str | None
    title: str | None
    support_url: str | None
    is_preview: bool


@dataclass(frozen=True)
class WindowsUpdateCookie:
    expiration: str
    encrypted_data: str


def _local_name(tag: object) -> str:
    return str(tag).rsplit("}", 1)[-1]


def parse_get_cookie(xml_text: str) -> WindowsUpdateCookie | None:
    if not xml_text:
        return None
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return None
    if any(_local_name(node.tag) == "Fault" for node in root.iter()):
        return None
    expiration = ""
    encrypted_data = ""
    for node in root.iter():
        local = _local_name(node.tag)
        if local == "Expiration" and not expiration and node.text:
            expiration = node.text.strip()
        elif local == "EncryptedData" and not encrypted_data and node.text:
            encrypted_data = node.text.strip()
    if not expiration or not encrypted_data:
        return None
    return WindowsUpdateCookie(expiration=expiration, encrypted_data=encrypted_data)


def _cookie_expiry(value: str) -> datetime | None:
    return parse_iso_utc_datetime(_FRACTION_RE.sub(lambda match: "." + match.group(1)[:6], str(value), count=1))


def load_cached_cookie(path: str | Path, *, now: datetime) -> WindowsUpdateCookie | None:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, Mapping):
        return None
    expiration = str(raw.get("expiration") or "").strip()
    encrypted_data = str(raw.get("encrypted_data") or "").strip()
    if not expiration or not encrypted_data:
        return None
    expires_at = _cookie_expiry(expiration)
    if expires_at is None or expires_at <= now + timedelta(seconds=COOKIE_SAFETY_MARGIN_SECONDS):
        return None
    return WindowsUpdateCookie(expiration=expiration, encrypted_data=encrypted_data)


def store_cached_cookie(path: str | Path, cookie: WindowsUpdateCookie) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps({"expiration": cookie.expiration, "encrypted_data": cookie.encrypted_data}, indent=2) + "\n",
        encoding="utf-8",
    )


def _security_header(*, created: str, expires: str) -> str:
    return (
        '<o:Security s:mustUnderstand="1" '
        'xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">'
        '<Timestamp xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
        f"<Created>{escape(created)}</Created>"
        f"<Expires>{escape(expires)}</Expires>"
        "</Timestamp>"
        '<wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" '
        'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" '
        'xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization">'
        "</wuws:WindowsUpdateTicketsToken>"
        "</o:Security>"
    )


def _envelope_header(*, action: str, created: str, expires: str, message_id: str) -> str:
    return (
        "<s:Header>"
        f'<a:Action s:mustUnderstand="1">{action}</a:Action>'
        f"<a:MessageID>urn:uuid:{escape(message_id)}</a:MessageID>"
        f'<a:To s:mustUnderstand="1">{WINDOWS_UPDATE_CLIENT_URL}</a:To>'
        f"{_security_header(created=created, expires=expires)}"
        "</s:Header>"
    )


def _device_attributes(os_version: str) -> str:
    return "E:" + "&".join(
        (
            "App=WU_OS",
            f"AppVer={os_version}",
            "AttrDataVer=247",
            "BranchReadinessLevel=CB",
            f"CurrentBranch={PRODUCT_BRANCH}",
            "DeviceFamily=Windows.Desktop",
            "FlightRing=Retail",
            "InstallLanguage=en-US",
            "InstallationType=Client",
            "IsFlightingEnabled=0",
            "IsRetailOS=1",
            "OSArchitecture=AMD64",
            "OSSkuId=48",
            "OSUILocale=en-US",
            f"OSVersion={os_version}",
            "TelemetryLevel=3",
            "UpdateManagementGroup=2",
            f"WuClientVer={os_version}",
        )
    )


def build_get_cookie_envelope(*, created: str, expires: str, message_id: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" '
        'xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        f"{_envelope_header(action=GET_COOKIE_ACTION, created=created, expires=expires, message_id=message_id)}"
        "<s:Body>"
        f'<GetCookie xmlns="{CLIENT_WEB_SERVICE_NS}">'
        f"<oldCookie><Expiration>{escape(created)}</Expiration></oldCookie>"
        f"<lastChange>{escape(created)}</lastChange>"
        f"<currentTime>{escape(created)}</currentTime>"
        "<protocolVersion>2.0</protocolVersion>"
        "</GetCookie>"
        "</s:Body>"
        "</s:Envelope>"
    )


def build_sync_updates_envelope(
    *,
    cookie_expiration: str,
    encrypted_data: str,
    os_version: str,
    created: str,
    expires: str,
    message_id: str,
) -> str:
    installed = "".join(f"<int>{value}</int>" for value in INSTALLED_NON_LEAF_UPDATE_IDS)
    products = escape(
        f"PN={PRODUCT_NAME}&Branch={PRODUCT_BRANCH}&PrimaryOSProduct=1"
        f"&Repairable=1&V={os_version}&ReofferUpdate=1"
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" '
        'xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        f"{_envelope_header(action=SYNC_UPDATES_ACTION, created=created, expires=expires, message_id=message_id)}"
        "<s:Body>"
        f'<SyncUpdates xmlns="{CLIENT_WEB_SERVICE_NS}">'
        "<cookie>"
        f"<Expiration>{escape(cookie_expiration)}</Expiration>"
        f"<EncryptedData>{escape(encrypted_data)}</EncryptedData>"
        "</cookie>"
        "<parameters>"
        "<ExpressQuery>false</ExpressQuery>"
        f"<InstalledNonLeafUpdateIDs>{installed}</InstalledNonLeafUpdateIDs>"
        "<OtherCachedUpdateIDs/>"
        "<SkipSoftwareSync>false</SkipSoftwareSync>"
        "<NeedTwoGroupOutOfScopeUpdates>true</NeedTwoGroupOutOfScopeUpdates>"
        "<AlsoPerformRegularSync>true</AlsoPerformRegularSync>"
        "<ComputerSpec/>"
        "<ExtendedUpdateInfoParameters>"
        "<XmlUpdateFragmentTypes>"
        "<XmlUpdateFragmentType>Extended</XmlUpdateFragmentType>"
        "<XmlUpdateFragmentType>LocalizedProperties</XmlUpdateFragmentType>"
        "</XmlUpdateFragmentTypes>"
        "<Locales><string>en-US</string></Locales>"
        "</ExtendedUpdateInfoParameters>"
        "<ClientPreferredLanguages><string>en-US</string></ClientPreferredLanguages>"
        "<ProductsParameters>"
        "<SyncCurrentVersionOnly>false</SyncCurrentVersionOnly>"
        f"<DeviceAttributes>{escape(_device_attributes(os_version))}</DeviceAttributes>"
        f"<CallerAttributes>{escape(CALLER_ATTRIBUTES)}</CallerAttributes>"
        f"<Products>{products}</Products>"
        "</ProductsParameters>"
        "</parameters>"
        "</SyncUpdates>"
        "</s:Body>"
        "</s:Envelope>"
    )


def _merge_fragment_fields(record: dict[str, str], fragment: str) -> None:
    release_version = _RELEASE_VERSION_RE.search(fragment)
    if release_version and "release_version" not in record:
        record["release_version"] = release_version.group(1).strip()
    kb = _KB_ELEMENT_RE.search(fragment)
    if kb and "kb_article" not in record:
        record["kb_article"] = f"KB{kb.group(1)}"
    title = _TITLE_RE.search(fragment)
    if title and "title" not in record:
        record["title"] = unescape(title.group(1)).strip()
    more_info_url = _MORE_INFO_URL_RE.search(fragment)
    if more_info_url and "support_url" not in record:
        record["support_url"] = unescape(more_info_url.group(1)).strip()


def _offer_from_fields(record: Mapping[str, str]) -> WindowsUpdateOffer:
    title = record.get("title") or None
    release_version = record.get("release_version") or None
    build_source = _BUILD_RE.search(release_version or "") or _BUILD_RE.search(title or "")
    kb_article = record.get("kb_article")
    if not kb_article and title:
        kb_match = _KB_TITLE_RE.search(title)
        kb_article = f"KB{kb_match.group(1)}" if kb_match else None
    support_url = record.get("support_url") or ""
    return WindowsUpdateOffer(
        kb_article=kb_article or None,
        build=build_source.group(1) if build_source else None,
        release_version=release_version,
        title=title,
        support_url=support_url if _SUPPORT_URL_RE.match(support_url) else None,
        is_preview=bool(title) and "preview" in str(title).lower(),
    )


def parse_sync_updates(xml_text: str) -> tuple[WindowsUpdateOffer, ...]:
    if not xml_text:
        return ()
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return ()
    if any(_local_name(node.tag) == "Fault" for node in root.iter()):
        return ()
    records: dict[str, dict[str, str]] = {}
    order: list[str] = []
    for node in root.iter():
        if _local_name(node.tag) not in {"UpdateInfo", "Update"}:
            continue
        update_id = None
        fragments: list[str] = []
        for child in node:
            local = _local_name(child.tag)
            if local == "ID" and child.text:
                update_id = child.text.strip()
            elif local == "Xml" and child.text:
                fragments.append(unescape(child.text))
        if not update_id:
            continue
        record = records.setdefault(update_id, {})
        if update_id not in order:
            order.append(update_id)
        for fragment in fragments:
            _merge_fragment_fields(record, fragment)
    offers = tuple(_offer_from_fields(records[update_id]) for update_id in order)
    return tuple(offer for offer in offers if offer.build or offer.kb_article)


def _urlopen_soap_post(body: str, timeout: float) -> str:
    result = http_client.request(
        WINDOWS_UPDATE_CLIENT_URL,
        method="POST",
        data=body.encode("utf-8"),
        headers={"Content-Type": WINDOWS_UPDATE_SOAP_CONTENT_TYPE},
        timeout=timeout,
        max_bytes=DEFAULT_MAX_SYNC_UPDATES_BYTES,
        label="Windows Update response",
    )
    content_type = http_client.get_header(result.headers, "Content-Type")
    charset = http_client.charset_from_content_type(content_type) or "utf-8"
    return result.content.decode(charset, errors="replace")


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime(_TIMESTAMP_FORMAT)


def fetch_offers(
    *,
    post: SoapPost | None = None,
    cookie_cache_path: str | Path = DEFAULT_COOKIE_CACHE_PATH,
    os_version: str = DEFAULT_PROBE_OS_VERSION,
    now: datetime | None = None,
    timeout: float = DEFAULT_WINDOWS_UPDATE_PROBE_TIMEOUT_SECONDS,
) -> tuple[WindowsUpdateOffer, ...]:
    send = post or _urlopen_soap_post
    moment = now or datetime.now(timezone.utc)
    created = _timestamp(moment)
    expires = _timestamp(moment + timedelta(minutes=5))
    cookie = load_cached_cookie(cookie_cache_path, now=moment)
    if cookie is None:
        cookie = parse_get_cookie(
            send(build_get_cookie_envelope(created=created, expires=expires, message_id=str(uuid.uuid4())), timeout)
        )
        if cookie is None:
            raise PolicyFetchError("Windows Update GetCookie response carried no cookie.")
        store_cached_cookie(cookie_cache_path, cookie)
    return parse_sync_updates(
        send(
            build_sync_updates_envelope(
                cookie_expiration=cookie.expiration,
                encrypted_data=cookie.encrypted_data,
                os_version=os_version,
                created=created,
                expires=expires,
                message_id=str(uuid.uuid4()),
            ),
            timeout,
        )
    )


__all__ = [
    "CALLER_ATTRIBUTES",
    "CLIENT_WEB_SERVICE_NS",
    "DEFAULT_COOKIE_CACHE_PATH",
    "DEFAULT_MAX_SYNC_UPDATES_BYTES",
    "DEFAULT_PROBE_OS_VERSION",
    "DEFAULT_WINDOWS_UPDATE_PROBE_TIMEOUT_SECONDS",
    "GET_COOKIE_ACTION",
    "INSTALLED_NON_LEAF_UPDATE_IDS",
    "PRODUCT_BRANCH",
    "PRODUCT_NAME",
    "SYNC_UPDATES_ACTION",
    "SoapPost",
    "WINDOWS_UPDATE_CLIENT_URL",
    "WINDOWS_UPDATE_SOAP_CONTENT_TYPE",
    "WINDOWS_UPDATE_USER_AGENT",
    "WindowsUpdateCookie",
    "WindowsUpdateOffer",
    "build_get_cookie_envelope",
    "build_sync_updates_envelope",
    "fetch_offers",
    "load_cached_cookie",
    "parse_get_cookie",
    "parse_sync_updates",
    "store_cached_cookie",
]
