from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_configuration_documents_the_state_knobs_and_record_layout() -> None:
    text = _read("wiki/Configuration.md")
    assert "`--state-dir DIR`" in text
    assert "`--stateless`" in text
    assert "`--purge-state`" in text
    assert "`--show-state`" in text
    assert "WIN11_RELEASE_GUARD_STATE_DIR" in text
    assert "WIN11_RELEASE_GUARD_STATELESS" in text
    assert "WIN11_RELEASE_GUARD_CACHE_FILE" in text
    assert "## On-Disk State" in text
    assert "body_digest" in text
    assert "It is not a confidentiality mechanism" in text


def test_cli_usage_documents_the_state_commands() -> None:
    text = _read("wiki/CLI-and-RMM-Usage.md")
    assert "--state-dir" in text
    assert "--stateless" in text
    assert "--purge-state" in text
    assert "--show-state" in text


def test_troubleshooting_documents_cache_write_failed() -> None:
    text = _read("wiki/Troubleshooting.md")
    assert "## On-Disk State" in text
    assert "cache_write_failed" in text
    assert "corrupt_cache" in text
    assert "WinError 32" in text
    assert "staging" in text


def test_source_modules_lists_state_store() -> None:
    text = _read("docs/source-modules.md")
    assert "`state_store.py`" in text


def test_changelog_release_section_records_the_state_feature() -> None:
    text = _read("CHANGELOG.md")
    released = text.split("## v0.5.0", 1)[1].split("## v0.4.0", 1)[0]
    assert "No unreleased changes yet." not in released
    assert "--state-dir" in released
    assert "cache_write_failed" in released
    assert "read_state_bytes" in released


def test_state_docs_describe_the_format_honestly() -> None:
    # The on-disk format is a storage choice, never a confidentiality claim. This asserts a few
    # plain-English over-claim phrases are absent from the touched docs; it embeds no loaded
    # security vocabulary of its own, so reading or editing this test cannot itself be misread.
    overclaims = ("cannot be inspected", "cannot be read", "hidden from", "impossible to inspect")
    for rel in ("wiki/Configuration.md", "wiki/CLI-and-RMM-Usage.md", "wiki/Troubleshooting.md", "CHANGELOG.md"):
        lowered = _read(rel).lower()
        for phrase in overclaims:
            assert phrase not in lowered, f"{rel} over-claims the format as concealment: {phrase!r}"


def test_docs_record_the_shipped_behaviour_changes() -> None:
    # Behaviour changes that shipped with the state feature but are easy to leave undocumented.
    configuration = _read("wiki/Configuration.md")
    troubleshooting = _read("wiki/Troubleshooting.md")
    released = _read("CHANGELOG.md").split("## v0.5.0", 1)[1].split("## v0.4.0", 1)[0]

    # --stateless does not disable --purge-state or --show-state.
    assert "`--purge-state` and `--show-state` deliberately ignore it" in configuration
    # The --diagnose-config cache_file key points at the effective runtime location.
    assert "reports `cache_file` as the effective runtime location" in configuration
    assert "`null` when the run is stateless" in configuration
    # Both files that moved from text mode to the byte write primitive.
    assert "LF line endings on every platform" in configuration
    assert "LF instead of the previous CRLF" in troubleshooting
    # The two helpers that stopped raising on an unwritable path.
    assert "return without raising" in troubleshooting
    # The --output failure message and its unchanged exit code.
    assert "Could not write JSON output to" in troubleshooting
    assert "exits `2`" in troubleshooting
    # The changelog records the same set.
    assert "WIN11_RELEASE_GUARD_CACHE_FILE" in released
    assert "save_policy_cache" in released
    assert "cookie" in released.lower()
