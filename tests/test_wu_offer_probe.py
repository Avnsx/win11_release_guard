from __future__ import annotations

from html import escape

from win11_release_guard.wu_offer_probe import (
    GET_COOKIE_ACTION,
    INSTALLED_NON_LEAF_UPDATE_IDS,
    SYNC_UPDATES_ACTION,
    WindowsUpdateOffer,
    build_get_cookie_envelope,
    build_sync_updates_envelope,
    parse_sync_updates,
)


CREATED = "2026-08-05T12:00:00Z"
EXPIRES = "2026-08-05T12:05:00Z"
MESSAGE_ID = "0f2c6b5a-1d4e-4a7b-9c33-2f0a5d8e6b41"


def _sync_updates_response(*offers: tuple[str, str, str, str]) -> str:
    new_updates = []
    extended = []
    for index, (release_version, kb, title, more_info_url) in enumerate(offers, start=1):
        core = (
            '<UpdateIdentity UpdateID="1a2b3c4d" RevisionNumber="1"/>'
            f'<Properties><ExtendedProperties ReleaseVersion="{release_version}"/></Properties>'
            f"<ApplicabilityRules><KBArticleID>{kb}</KBArticleID></ApplicabilityRules>"
        )
        localized = (
            "<LocalizedProperties>"
            f"<Title>{title}</Title>"
            f"<MoreInfoUrl>{more_info_url}</MoreInfoUrl>"
            "</LocalizedProperties>"
        )
        new_updates.append(f"<UpdateInfo><ID>{index}</ID><Xml>{escape(core)}</Xml></UpdateInfo>")
        extended.append(f"<Update><ID>{index}</ID><Xml>{escape(localized)}</Xml></Update>")
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
        '<SyncUpdatesResponse xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">'
        "<SyncUpdatesResult>"
        f"<NewUpdates>{''.join(new_updates)}</NewUpdates>"
        f"<ExtendedUpdateInfo><Updates>{''.join(extended)}</Updates></ExtendedUpdateInfo>"
        "</SyncUpdatesResult>"
        "</SyncUpdatesResponse></s:Body></s:Envelope>"
    )


def test_get_cookie_envelope_is_pure_and_carries_an_empty_ticket_token() -> None:
    envelope = build_get_cookie_envelope(created=CREATED, expires=EXPIRES, message_id=MESSAGE_ID)

    assert envelope == build_get_cookie_envelope(created=CREATED, expires=EXPIRES, message_id=MESSAGE_ID)
    assert GET_COOKIE_ACTION in envelope
    assert f"<a:MessageID>urn:uuid:{MESSAGE_ID}</a:MessageID>" in envelope
    assert f"<Created>{CREATED}</Created><Expires>{EXPIRES}</Expires>" in envelope
    assert 'wsu:id="ClientMSA"' in envelope
    assert "<TicketType" not in envelope
    assert envelope.count("</wuws:WindowsUpdateTicketsToken>") == 1
    assert "<protocolVersion>2.0</protocolVersion>" in envelope


def test_sync_updates_envelope_carries_cookie_products_and_full_installed_id_list() -> None:
    envelope = build_sync_updates_envelope(
        cookie_expiration="2026-11-03T12:00:00Z",
        encrypted_data="ZW5jcnlwdGVk",
        os_version="10.0.26200.8000",
        created=CREATED,
        expires=EXPIRES,
        message_id=MESSAGE_ID,
    )

    assert envelope == build_sync_updates_envelope(
        cookie_expiration="2026-11-03T12:00:00Z",
        encrypted_data="ZW5jcnlwdGVk",
        os_version="10.0.26200.8000",
        created=CREATED,
        expires=EXPIRES,
        message_id=MESSAGE_ID,
    )
    assert SYNC_UPDATES_ACTION in envelope
    assert "<Expiration>2026-11-03T12:00:00Z</Expiration>" in envelope
    assert "<EncryptedData>ZW5jcnlwdGVk</EncryptedData>" in envelope
    assert len(INSTALLED_NON_LEAF_UPDATE_IDS) == 75
    assert envelope.count("<int>") == 75
    assert "<SyncCurrentVersionOnly>false</SyncCurrentVersionOnly>" in envelope
    assert (
        "PN=Client.OS.rs2.amd64&amp;Branch=ge_release&amp;PrimaryOSProduct=1"
        "&amp;Repairable=1&amp;V=10.0.26200.8000&amp;ReofferUpdate=1"
    ) in envelope
    assert "<XmlUpdateFragmentType>Extended</XmlUpdateFragmentType>" in envelope
    assert "<XmlUpdateFragmentType>LocalizedProperties</XmlUpdateFragmentType>" in envelope
    assert "<Locales><string>en-US</string></Locales>" in envelope
    assert "OSVersion=10.0.26200.8000" in envelope


def test_parse_sync_updates_unescapes_fragments_and_extracts_offer_fields() -> None:
    response = _sync_updates_response(
        (
            "10.0.26200.8875",
            "5101650",
            "2026-07 Security Update (KB5101650) (26200.8875)",
            "https://support.microsoft.com/help/5101650",
        ),
        (
            "10.0.26200.8880",
            "5101651",
            "2026-07 Preview Update (KB5101651) (26200.8880)",
            "https://support.microsoft.com/help/5101651",
        ),
    )

    offers = parse_sync_updates(response)

    assert offers == (
        WindowsUpdateOffer(
            kb_article="KB5101650",
            build="26200.8875",
            release_version="10.0.26200.8875",
            title="2026-07 Security Update (KB5101650) (26200.8875)",
            support_url="https://support.microsoft.com/help/5101650",
            is_preview=False,
        ),
        WindowsUpdateOffer(
            kb_article="KB5101651",
            build="26200.8880",
            release_version="10.0.26200.8880",
            title="2026-07 Preview Update (KB5101651) (26200.8880)",
            support_url="https://support.microsoft.com/help/5101651",
            is_preview=True,
        ),
    )


def test_parse_sync_updates_returns_empty_for_faults_junk_and_unsafe_urls() -> None:
    fault = (
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault>'
        "<s:Code><s:Value>s:Receiver</s:Value></s:Code>"
        "<s:Reason><s:Text>Internal server error</s:Text></s:Reason>"
        "</s:Fault></s:Body></s:Envelope>"
    )
    unsafe = _sync_updates_response(
        (
            "10.0.26200.8875",
            "5101650",
            "2026-07 Security Update (KB5101650) (26200.8875)",
            "http://example.com/5101650",
        )
    )

    assert parse_sync_updates(fault) == ()
    assert parse_sync_updates("<s:Envelope") == ()
    assert parse_sync_updates("") == ()
    assert parse_sync_updates(unsafe)[0].support_url is None
