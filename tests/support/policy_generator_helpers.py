"""Helpers shared by the test_policy_generator test modules."""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from win11_release_guard.config import DEFAULT_POLICY_URL
from win11_release_guard.models import ReleasePolicy, ReleasePolicyEntry
import win11_release_guard.policy_generator as policy_generator_module
from win11_release_guard.policy_generator import msrc_cvrf as generator_msrc_cvrf
from win11_release_guard.policy_generator import support_articles as generator_support_articles
from win11_release_guard.policy_generator import build_policy_from_sources, generate_policy, write_policy_outputs
from win11_release_guard.remote_policy import load_policy_text
from win11_release_guard.policy_schema import validate_policy_document


FIXTURES = Path("tests/fixtures")


EXPECTED_ROBOTS_TXT = (
    "User-agent: *\n"
    "Allow: /\n"
    "Sitemap: https://avnsx.github.io/win11_release_guard/sitemap.xml\n"
)


ATOM_SOURCE_DIAGNOSTIC_ID = "wrg-source-diagnostic-v1:uuid:07747009-7264-44f2-86c2-1c3e09919af3;id=968480"


KB5094126_SUPPORT_URL = (
    "https://support.microsoft.com/en-us/servicing/os/windows-11/"
    "2026/06/june-9-2026-kb5094126-os-builds-26200-8655-and-26100-8655"
)


KB5094126_SUPPORT_HTML = """
<!doctype html>
<html>
  <head>
    <title>June 9, 2026-KB5094126 (OS Builds 26200.8655 and 26100.8655) - Microsoft Support</title>
    <script>window.secret = "ignored";</script>
    <style>.ignored{display:none}</style>
  </head>
  <body>
    <main>
      <h1>June 9, 2026-KB5094126 (OS Builds 26200.8655 and 26100.8655)</h1>
      <p>Applies to: Windows 11, version 25H2; Windows 11, version 24H2</p>
      <h2>Highlights</h2>
      <ul>
        <li>[Secure Boot] Updates hardening for startup components.</li>
        <li>[Virtualization] Improves reliability for protected workloads.</li>
        <li>[desktop.ini] Hardens desktop.ini processing.</li>
        <li>[AI components] Updates Windows AI components.</li>
      </ul>
      <p>This update includes the latest security fixes and addresses security vulnerabilities.</p>
      <h2>Known issues in this update</h2>
      <p>Microsoft is not currently aware of any issues in this update.</p>
    </main>
  </body>
</html>
"""


KB5094126_SUPPORT_HTML_NO_SECURITY = KB5094126_SUPPORT_HTML.replace(
    "<p>This update includes the latest security fixes and addresses security vulnerabilities.</p>",
    "<p>This update improves reliability and quality for Windows components.</p>",
)


FAKE_MSRC_CVRF_WITH_KB5094126 = {
    "Vulnerability": [
        {
            "CVE": "CVE-2026-0001",
            "Threats": [
                {
                    "Type": "Severity",
                    "Description": {"Value": "Important"},
                }
            ],
            "Remediations": [
                {
                    "Description": {"Value": "Security Update for KB5094126"},
                    "ProductID": ["11568", "11569"],
                }
            ],
        },
        {
            "CVE": "CVE-2026-0002",
            "Threats": [
                {
                    "Type": "Severity",
                    "Description": {"Value": "Critical"},
                }
            ],
            "Remediations": [
                {
                    "URL": "https://support.microsoft.com/help/5094126",
                    "ProductID": "11570",
                }
            ],
        },
        {
            "CVE": "CVE-2026-9999",
            "Threats": [
                {
                    "Type": "Severity",
                    "Description": {"Value": "Low"},
                }
            ],
            "Remediations": [
                {
                    "Description": {"Value": "Security Update for KB5000000"},
                    "ProductID": ["other"],
                }
            ],
        },
    ]
}


FAKE_MSRC_CVRF_WITHOUT_KB5094126 = {
    "Vulnerability": [
        {
            "CVE": "CVE-2026-9999",
            "Threats": [
                {
                    "Type": "Severity",
                    "Description": {"Value": "Important"},
                }
            ],
            "Remediations": [
                {
                    "Description": {"Value": "Security Update for KB5000000"},
                    "ProductID": ["other"],
                }
            ],
        }
    ]
}


def _html() -> str:
    return (FIXTURES / "windows11-release-health.html").read_text(encoding="utf-8")


def _html_file(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _toc() -> str:
    return (FIXTURES / "windows11-servicing-toc.json").read_text(encoding="utf-8")


def _kb5094126_toc_fixture() -> str:
    return (FIXTURES / "windows11-servicing-toc-kb5094126.json").read_text(encoding="utf-8")


def _kb5094126_support_fixture() -> str:
    return (FIXTURES / "support-kb5094126.html").read_text(encoding="utf-8")


def _kb5094126_msrc_fixture() -> dict[str, object]:
    return json.loads((FIXTURES / "msrc-cvrf-2026-Jun-kb5094126.json").read_text(encoding="utf-8"))


def _release_health_caught_up_to_kb5094126() -> str:
    html = _html_file("windows11-release-health-current-d-26h1.html")
    current_old = """      <tr>
        <td>25H2</td>
        <td>General Availability Channel</td>
        <td>2025-09-30</td>
        <td>2027-10-12</td>
        <td>2028-10-10</td>
        <td>2026-05-27</td>
        <td>26200.8524</td>
      </tr>"""
    current_new = """      <tr>
        <td>25H2</td>
        <td>General Availability Channel</td>
        <td>2025-09-30</td>
        <td>2027-10-12</td>
        <td>2028-10-10</td>
        <td>2026-06-09</td>
        <td>26200.8655</td>
      </tr>"""
    history_old = """      <tr>
        <td>General Availability Channel</td>
        <td>2026-05 B</td>
        <td>2026-05-12</td>
        <td>26200.8457</td>
        <td>KB5089549</td>
      </tr>"""
    history_new = """      <tr>
        <td>General Availability Channel</td>
        <td>2026-06 B</td>
        <td>2026-06-09</td>
        <td>26200.8655</td>
        <td>KB5094126</td>
      </tr>"""
    assert current_old in html
    assert history_old in html
    return html.replace(current_old, current_new, 1).replace(history_old, history_new, 1)


def _kb5094126_generated_fixture_policy(
    release_health_html: str,
    *,
    support_html: str | None = None,
    msrc_payload: object | None = None,
    msrc_error: Exception | None = None,
    generated_at_utc: str = "2026-06-11T18:00:00+00:00",
) -> ReleasePolicy:
    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        assert url == KB5094126_SUPPORT_URL
        return support_html if support_html is not None else _kb5094126_support_fixture()

    def msrc_fetcher(url: str, timeout: float, max_bytes: int) -> object:
        if not url.endswith("/2026-Jun"):
            return {"Vulnerability": []}
        if msrc_error is not None:
            raise msrc_error
        return msrc_payload if msrc_payload is not None else _kb5094126_msrc_fixture()

    return generate_policy(
        release_health_html=release_health_html,
        servicing_toc_json=_kb5094126_toc_fixture(),
        generated_at_utc=generated_at_utc,
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )


def _generated_output_bundle(policy: ReleasePolicy, output_dir: Path) -> dict[str, object]:
    write_policy_outputs(
        policy,
        output_dir=output_dir,
        write_index=True,
        write_manifest=True,
    )
    policy_path = output_dir / "windows-release-policy.json"
    manifest_path = output_dir / "policy-manifest.json"
    index_path = output_dir / "index.html"
    api_policy_path = output_dir / "api" / "v1" / "policy.json"
    api_manifest_path = output_dir / "api" / "v1" / "manifest.json"
    assert api_policy_path.read_bytes() == policy_path.read_bytes()
    assert api_manifest_path.read_bytes() == manifest_path.read_bytes()
    policy_data = json.loads(policy_path.read_text(encoding="utf-8"))
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    api_policy_data = json.loads(api_policy_path.read_text(encoding="utf-8"))
    api_manifest_data = json.loads(api_manifest_path.read_text(encoding="utf-8"))
    assert api_policy_data == policy_data
    assert api_manifest_data == manifest_data
    validate_policy_document(policy_data)
    parsed = load_policy_text(json.dumps(policy_data), source_url=DEFAULT_POLICY_URL)
    assert parsed.broad_target_existing_devices is not None
    return {
        "policy": policy_data,
        "manifest": manifest_data,
        "index": index_path.read_text(encoding="utf-8"),
        "policy_text": policy_path.read_text(encoding="utf-8"),
        "manifest_text": manifest_path.read_text(encoding="utf-8"),
    }


def _assert_no_raw_support_article_leakage(outputs: dict[str, object], support_html: str) -> None:
    combined = "\n".join(
        str(outputs[key])
        for key in ("policy_text", "manifest_text", "index")
    )
    assert support_html.strip() not in combined
    assert "window.secret" not in combined
    assert "Microsoft is not currently aware of any issues in this update." not in combined
    assert "https://support.microsoft.com/help/5094126" not in combined


def _support_article_html(
    *,
    kb_article: str = "KB5094126",
    builds: tuple[str, ...] = ("26200.8655", "26100.8655"),
    applies_to: str = "Windows 11, version 25H2; Windows 11, version 24H2",
    security: bool = True,
    labels: tuple[str, ...] = ("Secure Boot", "Virtualization"),
) -> str:
    build_label = ""
    if builds:
        build_word = "Build" if len(builds) == 1 else "Builds"
        build_label = f" (OS {build_word} {' and '.join(builds)})"
    label_items = "".join(f"<li>[{label}] Validated update note.</li>" for label in labels)
    security_text = (
        "<p>This update includes the latest security fixes and addresses security vulnerabilities.</p>"
        if security
        else "<p>This update improves reliability and quality for Windows components.</p>"
    )
    return f"""
<!doctype html>
<html>
  <head>
    <title>June 9, 2026-{kb_article}{build_label} - Microsoft Support</title>
    <script>window.secret = "ignored";</script>
  </head>
  <body>
    <main>
      <h1>June 9, 2026-{kb_article}{build_label}</h1>
      <p>Applies to: {applies_to}</p>
      <h2>Highlights</h2>
      <ul>{label_items}</ul>
      {security_text}
      <h2>Known issues in this update</h2>
      <p>Microsoft is not currently aware of any issues in this update.</p>
    </main>
  </body>
</html>
"""


def _kb5094126_policy_with_support_html(
    html_text: str,
    *,
    msrc_payload: dict[str, object] | None = None,
) -> ReleasePolicy:
    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        assert url == KB5094126_SUPPORT_URL
        return html_text

    msrc_fetcher = None
    if msrc_payload is not None:
        def msrc_fetcher(url: str, timeout: float, max_bytes: int) -> dict[str, object]:
            if url.endswith("/2026-Jun"):
                return msrc_payload
            return {"Vulnerability": []}

    return generate_policy(
        release_health_html=_html_file("windows11-release-health-header-variants.html"),
        servicing_toc_json=_kb5094126_toc_fixture(),
        generated_at_utc="2026-06-11T00:00:00+00:00",
        support_article_fetcher=support_fetcher,
        msrc_cvrf_fetcher=msrc_fetcher,
    )


def _kb5094126_atom_event(policy: ReleasePolicy, build: str = "26200.8655") -> dict[str, object]:
    return next(
        event
        for event in policy.source_diagnostics["events"]
        if event["kind"] == "atom_newer_than_release_history"
        and event["kb_article"] == "KB5094126"
        and event["build"] == build
    )


def _toc_entry(title: str, href: str) -> dict[str, object]:
    return {"href": href, "toc_title": title}


def _toc_document_with_extra(*entries: dict[str, object]) -> str:
    document = json.loads(_toc())
    document["items"][0]["children"] = [*entries, *document["items"][0]["children"]]
    return json.dumps(document)


def _toc_with_new_b_release() -> str:
    return _toc_document_with_extra(
        _toc_entry(
            "June 9, 2026—KB5089600 (OS Build 26200.8461)",
            "2026/06/june-9-2026-kb5089600-os-build-26200-8461",
        )
    )


def _with_oob_row(html: str) -> str:
    row = """      <tr>
        <td>General Availability Channel</td>
        <td>2026-05</td>
        <td>2026-05-16</td>
        <td>26200.8460</td>
        <td>KB5089550</td>
      </tr>
"""
    return html.replace("      <tr>\n        <td>General Availability Channel</td>\n        <td>2026-04 D</td>", row + "      <tr>\n        <td>General Availability Channel</td>\n        <td>2026-04 D</td>", 1)


def _with_25h2_current_latest_build(html: str, build: str) -> str:
    return html.replace("        <td>26200.8457</td>\n      </tr>", f"        <td>{build}</td>\n      </tr>", 1)


# ---------------------------------------------------------------------------
# Rebalanced KB-only Atom fallback: keep safe build-agnostic evidence while
# still refusing wrong-build, unsafe, or ambiguous attachment.
# ---------------------------------------------------------------------------


def _kb_row(build_family: int, build: str, kb: str = "KB5091111") -> "policy_generator_module.ReleaseHistoryEntry":
    return policy_generator_module.ReleaseHistoryEntry(
        release="24H2",
        build_family=build_family,
        build=build,
        update_type="2026-06 B",
        update_type_letter="B",
        kb_article=kb,
    )


def _kb_atom(entry_id: str, *, builds=(), url="https://support.microsoft.com/help/5091111",
             kb="KB5091111", preview=False, out_of_band=False, title="Update"):
    return policy_generator_module.AtomFeedEntry(
        title=title, entry_id=entry_id, link=url, kb_article=kb,
        builds=builds, preview=preview, out_of_band=out_of_band,
    )


KB5101650_SERVICING_URL = (
    "https://support.microsoft.com/en-us/servicing/os/windows-11/2026/07/"
    "july-14-2026-kb5101650-os-builds-26200-8875-and-26100-8875"
)


def _offline_support_article_fetcher(url: str, timeout: float, max_bytes: int) -> str:
    return (
        "<html><body><h1>May 12, 2026-KB5089549 "
        "(OS Builds 26200.8457 and 26100.8457)</h1></body></html>"
    )


def _offline_msrc_cvrf_fetcher(url: str, timeout: float, max_bytes: int) -> dict[str, object]:
    return {"Vulnerability": []}


@pytest.fixture
def offline_enrichment_fetchers(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[str]]:
    """Keep every generator entry point that resolves its own fetchers offline."""
    calls: dict[str, list[str]] = {"support": [], "msrc": []}

    def support_fetcher(url: str, timeout: float, max_bytes: int) -> str:
        calls["support"].append(url)
        return _offline_support_article_fetcher(url, timeout, max_bytes)

    def msrc_fetcher(url: str, timeout: float, max_bytes: int) -> dict[str, object]:
        calls["msrc"].append(url)
        return _offline_msrc_cvrf_fetcher(url, timeout, max_bytes)

    monkeypatch.setattr(generator_support_articles, "default_support_article_fetcher", support_fetcher)
    monkeypatch.setattr(generator_msrc_cvrf, "default_msrc_cvrf_fetcher", msrc_fetcher)
    return calls


def _broad_target_25h2() -> ReleasePolicyEntry:
    return ReleasePolicyEntry(
        version="25H2",
        build_family=26200,
        latest_build="26200.8875",
        baseline_build="26200.8875",
        required_baseline_build="26200.8875",
    )


def _release_history_25h2() -> tuple[object, ...]:
    return (
        policy_generator_module.ReleaseHistoryEntry(
            release="25H2",
            build_family=26200,
            build="26200.8875",
            availability_date="2026-07-14",
            update_type="2026-07 B",
            update_type_letter="B",
            kb_article="KB5101650",
            kb_url=KB5101650_SERVICING_URL,
            metadata={"atom_feed_url": KB5101650_SERVICING_URL},
        ),
        policy_generator_module.ReleaseHistoryEntry(
            release="25H2",
            build_family=26200,
            build="26200.8973",
            availability_date="2026-07-28",
            update_type="2026-07 D",
            update_type_letter="D",
            preview=True,
            kb_article="KB5101684",
        ),
        policy_generator_module.ReleaseHistoryEntry(
            release="25H2",
            build_family=26200,
            build="26200.8894",
            availability_date="2026-07-18",
            update_type="2026-07 OOB",
            update_type_letter="OOB",
            out_of_band=True,
            kb_article="KB5121767",
        ),
    )


PENDING_26H2_FIXTURE = FIXTURES / "windows11-release-health-26h2-pending-b.html"


def _pending_26h2_policy() -> ReleasePolicy:
    return build_policy_from_sources(
        release_health_html_path=PENDING_26H2_FIXTURE,
        servicing_toc_path=FIXTURES / "windows11-servicing-toc.json",
        signature_status="valid",
        support_article_fetcher=_offline_support_article_fetcher,
        msrc_cvrf_fetcher=_offline_msrc_cvrf_fetcher,
    )


def _pending_b_release_events(policy_data: dict[str, object]) -> list[dict[str, object]]:
    return [
        event
        for event in policy_data["source_diagnostics"]["events"]
        if event.get("kind") == "broad_target_pending_b_release"
    ]
