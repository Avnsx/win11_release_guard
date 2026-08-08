from __future__ import annotations

import ast
import json
from datetime import datetime, timezone
from pathlib import Path

from tools import generate_policy as generate_policy_cli
from win11_release_guard.policy_generator import generate_policy
from win11_release_guard.wu_offer_probe import (
    WindowsUpdateCookie,
    WindowsUpdateOffer,
    fetch_offers,
    load_cached_cookie,
    store_cached_cookie,
)


FIXTURES = Path("tests/fixtures")
GENERATED_AT = "2026-06-11T00:00:00+00:00"
PROBE_UNAVAILABLE_KIND = "windows_update_probe_unavailable"
PROBE_CORROBORATION_KIND = "windows_update_probe_corroboration"


def _html() -> str:
    return (FIXTURES / "windows11-release-health.html").read_text(encoding="utf-8")


def _toc() -> str:
    return (FIXTURES / "windows11-servicing-toc.json").read_text(encoding="utf-8")


def _policy(probe=None):
    return generate_policy(
        release_health_html=_html(),
        servicing_toc_json=_toc(),
        generated_at_utc=GENERATED_AT,
        windows_update_probe=probe,
    )


def _without_probe_diagnostics(document: dict) -> dict:
    data = json.loads(json.dumps(document))
    diagnostics = data["source_diagnostics"]
    diagnostics.pop("event_counts", None)
    diagnostics["events"] = [
        event
        for event in diagnostics["events"]
        if not str(event.get("kind") or "").startswith("windows_update_probe")
    ]
    diagnostics["notices"] = [
        notice for notice in diagnostics["notices"] if "Windows Update offer" not in notice
    ]
    return data


def test_probe_failure_adds_one_notice_and_leaves_the_policy_identical() -> None:
    def failing_probe() -> tuple[WindowsUpdateOffer, ...]:
        raise TimeoutError("timed out reading the SyncUpdates response")

    baseline = _policy().to_dict()
    probed = _policy(failing_probe).to_dict()

    added = [
        event
        for event in probed["source_diagnostics"]["events"]
        if event not in baseline["source_diagnostics"]["events"]
    ]
    assert [event["kind"] for event in added] == [PROBE_UNAVAILABLE_KIND]
    assert added[0]["severity"] == "notice"
    assert added[0]["affects_broad_target"] is False
    assert added[0]["affects_required_baseline"] is False
    assert added[0]["build"] is None
    assert "timed out reading the SyncUpdates response" in added[0]["message"]
    assert probed["source_diagnostics"]["event_counts"] == {
        **baseline["source_diagnostics"]["event_counts"],
        "notice": baseline["source_diagnostics"]["event_counts"]["notice"] + 1,
    }
    assert probed["validation_warnings"] == baseline["validation_warnings"]
    assert _without_probe_diagnostics(probed) == _without_probe_diagnostics(baseline)


def test_probe_build_newer_than_every_document_source_never_moves_the_baseline() -> None:
    newer = WindowsUpdateOffer(
        kb_article="KB5101650",
        build="26200.9999",
        release_version="10.0.26200.9999",
        title="2026-07 Security Update (KB5101650) (26200.9999)",
        support_url="https://support.microsoft.com/help/5101650",
        is_preview=False,
    )
    baseline = _policy()
    probed = _policy(lambda: (newer,))

    assert baseline.broad_target_existing_devices.latest_observed_build == "26200.8457"
    assert probed.broad_target_existing_devices.latest_observed_build == "26200.8457"
    assert probed.broad_target_existing_devices.required_baseline_build == "26200.8457"
    assert probed.broad_target_existing_devices.latest_build == "26200.8457"
    assert probed.current_versions == baseline.current_versions
    assert probed.release_history == baseline.release_history

    corroboration = [
        event
        for event in probed.source_diagnostics["events"]
        if event["kind"] == PROBE_CORROBORATION_KIND
    ]
    assert len(corroboration) == 1
    assert corroboration[0]["severity"] == "notice"
    assert corroboration[0]["affects_required_baseline"] is False
    assert "26200.9999 (KB5101650)" in corroboration[0]["message"]


SYNC_UPDATES_RESPONSE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
    '<SyncUpdatesResponse xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">'
    "<SyncUpdatesResult><NewUpdates><UpdateInfo><ID>1</ID><Xml>"
    "&lt;Properties&gt;&lt;ExtendedProperties ReleaseVersion=&quot;10.0.26200.8875&quot;/&gt;&lt;/Properties&gt;"
    "&lt;ApplicabilityRules&gt;&lt;KBArticleID&gt;5101650&lt;/KBArticleID&gt;&lt;/ApplicabilityRules&gt;"
    "</Xml></UpdateInfo></NewUpdates>"
    "<ExtendedUpdateInfo><Updates><Update><ID>1</ID><Xml>"
    "&lt;LocalizedProperties&gt;&lt;Title&gt;2026-07 Security Update (KB5101650) (26200.8875)&lt;/Title&gt;"
    "&lt;MoreInfoUrl&gt;https://support.microsoft.com/help/5101650&lt;/MoreInfoUrl&gt;"
    "&lt;/LocalizedProperties&gt;"
    "</Xml></Update></Updates></ExtendedUpdateInfo>"
    "</SyncUpdatesResult></SyncUpdatesResponse></s:Body></s:Envelope>"
)

GET_COOKIE_RESPONSE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
    '<GetCookieResponse xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">'
    "<GetCookieResult>"
    "<Expiration>2026-11-03T12:00:00Z</Expiration>"
    "<EncryptedData>ZW5jcnlwdGVk</EncryptedData>"
    "</GetCookieResult></GetCookieResponse></s:Body></s:Envelope>"
)


def test_cached_cookie_is_reused_until_its_expiration_passes(tmp_path) -> None:
    cache_path = tmp_path / "windows-update-cookie.json"
    cookie = WindowsUpdateCookie(expiration="2026-11-03T12:00:00Z", encrypted_data="ZW5jcnlwdGVk")
    store_cached_cookie(cache_path, cookie)

    assert load_cached_cookie(cache_path, now=datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)) == cookie
    assert load_cached_cookie(cache_path, now=datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)) is None
    assert load_cached_cookie(tmp_path / "missing.json", now=datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)) is None


def test_fetch_offers_reuses_the_cached_cookie_and_parses_the_offer_snapshot(tmp_path) -> None:
    cache_path = tmp_path / "windows-update-cookie.json"
    store_cached_cookie(
        cache_path, WindowsUpdateCookie(expiration="2026-11-03T12:00:00Z", encrypted_data="ZW5jcnlwdGVk")
    )
    bodies: list[str] = []

    def fake_post(body: str, timeout: float) -> str:
        bodies.append(body)
        return SYNC_UPDATES_RESPONSE

    offers = fetch_offers(
        post=fake_post,
        cookie_cache_path=cache_path,
        os_version="10.0.26200.8000",
        now=datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc),
    )

    assert len(bodies) == 1
    assert "<SyncUpdates" in bodies[0]
    assert "<EncryptedData>ZW5jcnlwdGVk</EncryptedData>" in bodies[0]
    assert offers[0].build == "26200.8875"
    assert offers[0].kb_article == "KB5101650"
    assert offers[0].is_preview is False


def test_cli_windows_update_probe_flag_is_optional_and_off_by_default() -> None:
    parser = generate_policy_cli._build_parser()

    assert parser.parse_args([]).windows_update_probe is False
    assert parser.parse_args(["--windows-update-probe"]).windows_update_probe is True
    assert generate_policy_cli._windows_update_probe(parser.parse_args([])) is None
    assert callable(generate_policy_cli._windows_update_probe(parser.parse_args(["--windows-update-probe"])))


def test_default_cookie_cache_path_constant_is_removed() -> None:
    import win11_release_guard.wu_offer_probe as wu

    assert not hasattr(wu, "DEFAULT_COOKIE_CACHE_PATH")
    assert "DEFAULT_COOKIE_CACHE_PATH" not in wu.__all__


def test_fetch_offers_without_a_cache_path_neither_reads_nor_writes_a_cookie(tmp_path, monkeypatch) -> None:
    work = tmp_path / "work"  # the autouse conftest already seeds tmp_path with "localappdata"
    work.mkdir()
    monkeypatch.chdir(work)
    bodies: list[str] = []

    def fake_post(body: str, timeout: float) -> str:
        bodies.append(body)
        return SYNC_UPDATES_RESPONSE if "<SyncUpdates " in body else GET_COOKIE_RESPONSE

    offers = fetch_offers(
        post=fake_post,
        os_version="10.0.26200.8000",
        now=datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc),
    )

    assert [("<GetCookie " in bodies[0]), ("<SyncUpdates " in bodies[1])] == [True, True]
    assert offers[0].build == "26200.8875"
    assert not (work / ".tmp").exists()
    assert list(work.iterdir()) == []


def test_store_cached_cookie_writes_lf_and_never_creates_parent_dirs(tmp_path) -> None:
    here = tmp_path / "windows-update-cookie.json"
    store_cached_cookie(here, WindowsUpdateCookie(expiration="2026-11-03T12:00:00Z", encrypted_data="ZW5jcnlwdGVk"))

    raw = here.read_bytes()
    assert b"\r\n" not in raw
    assert raw.endswith(b"\n")
    assert load_cached_cookie(here, now=datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)) == WindowsUpdateCookie(
        expiration="2026-11-03T12:00:00Z", encrypted_data="ZW5jcnlwdGVk"
    )

    missing = tmp_path / "missing" / "cookie.json"
    store_cached_cookie(missing, WindowsUpdateCookie(expiration="2026-11-03T12:00:00Z", encrypted_data="ZW5jcnlwdGVk"))
    assert not (tmp_path / "missing").exists()


def test_generator_probe_passes_the_explicit_cookie_cache_path(monkeypatch) -> None:
    from pathlib import Path as _Path

    assert generate_policy_cli.COOKIE_CACHE_PATH == _Path(".tmp") / "windows-update-cookie.json"

    captured: dict[str, object] = {}

    def fake_fetch_offers(**kwargs):
        captured.update(kwargs)
        return ()

    made: list[_Path] = []

    def spy_mkdir(self, *args, **kwargs):  # record only; never touch the real filesystem
        made.append(self)

    monkeypatch.setattr(generate_policy_cli, "fetch_offers", fake_fetch_offers)
    monkeypatch.setattr(_Path, "mkdir", spy_mkdir)

    parser = generate_policy_cli._build_parser()
    probe = generate_policy_cli._windows_update_probe(parser.parse_args(["--windows-update-probe"]))
    assert probe() == ()
    assert captured["cookie_cache_path"] == _Path(".tmp") / "windows-update-cookie.json"
    assert _Path(".tmp") in made


# --- wu_offer_probe.py source guard -------------------------------------------------------
# Same AST technique as tests/test_no_cwd_writes.py, kept local because `tests/` is not a
# package: importing that module by name would either duplicate it alongside the copy pytest
# already collected or lean on pytest's prepend-import-mode sys.path insertion.
#
# Attribute NAMES are matched whatever the value expression, so `Path(x).mkdir()` and
# `self._dir.mkdir()` fire alongside `os.mkdir`; `os.makedirs` is included because the previous
# substring guard silently missed it.
_PROBE_BANNED_ATTRS = frozenset({"cwd", "getcwd", "makedirs", "mkdir"})
_PROBE_BANNED_IMPORT_NAMES = frozenset({"getcwd", "makedirs", "mkdir"})
_PROBE_BANNED_MODULES = frozenset({"tempfile"})


def _probe_cwd_hits(source: str, filename: str) -> list[str]:
    """AST scan for CWD reads, directory creation and ``tempfile`` use in a client-runtime module."""
    tree = ast.parse(source, filename=filename)
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _PROBE_BANNED_ATTRS:
            hits.append(f"{filename}:{node.lineno} .{node.attr}")
        elif isinstance(node, ast.Import):
            hits.extend(
                f"{filename}:{node.lineno} import {alias.name}"
                for alias in node.names
                if alias.name.split(".")[0] in _PROBE_BANNED_MODULES
            )
        elif isinstance(node, ast.ImportFrom):
            if node.module is not None and node.module.split(".")[0] in _PROBE_BANNED_MODULES:
                hits.append(f"{filename}:{node.lineno} from {node.module} import ...")
            hits.extend(
                f"{filename}:{node.lineno} from {node.module} import {alias.name}"
                for alias in node.names
                if alias.name in _PROBE_BANNED_IMPORT_NAMES
            )
    return hits


def test_probe_matcher_flags_every_planted_write_primitive() -> None:
    for planted in (
        "os.makedirs('a')",
        "os.mkdir('b')",
        "Path.mkdir(p)",
        "Path('c').mkdir(parents=True)",
        "self._dir.mkdir()",
        "os.getcwd()",
        "Path.cwd()",
        "from os import makedirs",
        "import tempfile",
        "from tempfile import mkdtemp",
    ):
        assert _probe_cwd_hits(planted + "\n", "planted.py"), f"matcher missed {planted!r}"


def test_probe_matcher_spares_comments_docstrings_and_strings() -> None:
    # Every one of these lines contains a substring the previous grep-style guard tripped on.
    lookalike = (
        '"""This module never calls Path.cwd or os.getcwd."""\n'
        "import os\n"
        "# never call target.mkdir(parents=True) or reach for tempfile here\n"
        "MESSAGE = 'os.getcwd / .mkdir( / tempfile'\n"
        "os.path.join('a', 'b')\n"
        "os.name\n"
    )
    assert _probe_cwd_hits(lookalike, "legit.py") == []


def test_wu_offer_probe_module_has_no_cwd_write_primitives() -> None:
    module = Path(__file__).resolve().parents[1] / "win11_release_guard" / "wu_offer_probe.py"
    hits = _probe_cwd_hits(module.read_text(encoding="utf-8"), module.name)
    assert hits == [], f"CWD/dir-creation/tempfile sites in wu_offer_probe.py: {hits}"
