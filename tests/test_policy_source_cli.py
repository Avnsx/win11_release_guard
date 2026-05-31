from __future__ import annotations

import json
from pathlib import Path

from win11_release_guard import __main__ as cli
from win11_release_guard.exceptions import PolicyFetchError
from win11_release_guard.signing import sign_policy_bytes


TEST_PRIVATE_KEY = "krtF2muLgucP7JDVNKk2g+YQfz92c7xM49dzszxHxjs="
TEST_PUBLIC_KEY = "45dOpVuYqoPkldNrzORHM5ZZUxs6ILVcvpKxRFxsu3s="


def _policy_json() -> dict:
    return {
        "schema_version": 1,
        "generated_at_utc": "2026-05-28T00:00:00Z",
        "source_urls": [
            "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information",
            "https://avnsx.github.io/win-release-guard/windows-release-policy.json",
        ],
        "current_versions": [
            {
                "version": "25H2",
                "build_family": 26200,
                "latest_build": "26200.8457",
                "baseline_build": "26200.8457",
                "servicing_option": "General Availability Channel",
            }
        ],
        "supported_build_families": {"26200": "25H2"},
        "broad_target_existing_devices": {
            "version": "25H2",
            "build_family": 26200,
            "latest_build": "26200.8457",
            "baseline_build": "26200.8457",
            "servicing_option": "General Availability Channel",
        },
        "release_history": [
            {
                "release": "25H2",
                "build_family": 26200,
                "build": "26200.8457",
                "availability_date": "2026-05-12",
                "servicing_option": "General Availability Channel",
                "update_type": "2026-05 B",
                "update_type_letter": "B",
                "kb_article": "KB5089549",
            }
        ],
        "excluded_for_existing_devices": [
            {
                "version": "26H1",
                "build_family": 28000,
                "reason": "new devices only",
                "servicing_option": "General Availability Channel",
            }
        ],
    }


def _write_policy_and_signature(path: Path, policy_bytes: bytes, *, valid_signature: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(policy_bytes)
    if valid_signature:
        signature = sign_policy_bytes(policy_bytes, TEST_PRIVATE_KEY)
        path.with_name(path.name + ".sig").write_bytes(
            (json.dumps(signature, indent=2, sort_keys=True) + "\n").encode("utf-8")
        )
    else:
        path.with_name(path.name + ".sig").write_bytes(
            b'{"algorithm":"ed25519","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}'
        )


def test_check_policy_source_local_signed_file_ok(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "check_current_system", lambda config: (_ for _ in ()).throw(AssertionError("local probe ran")))
    policy_file = tmp_path / "windows-release-policy.json"
    _write_policy_and_signature(
        policy_file,
        (json.dumps(_policy_json(), indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )

    code = cli.main([
        "--check-policy-source",
        "--policy-url",
        str(policy_file),
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == 0
    assert "Policy source: OK" in output
    assert "Signature: valid" in output
    assert "Generated at UTC: 2026-05-28T00:00:00Z" in output
    assert "Broad target: 25H2 / 26200 / 26200.8457" in output
    assert "Baseline: 26200.8457" in output
    assert "- 26H1 / 28000 / new devices only" in output


def test_check_policy_source_invalid_signature_fails(tmp_path, capsys):
    policy_file = tmp_path / "windows-release-policy.json"
    _write_policy_and_signature(
        policy_file,
        (json.dumps(_policy_json(), indent=2, sort_keys=True) + "\n").encode("utf-8"),
        valid_signature=False,
    )

    code = cli.main([
        "--check-policy-source",
        "--policy-url",
        str(policy_file),
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "Policy source: SIGNATURE_FAILED" in output
    assert "Policy signature invalid:" in output


def test_check_policy_source_malformed_policy_fails(tmp_path, capsys):
    policy_file = tmp_path / "windows-release-policy.json"
    _write_policy_and_signature(policy_file, b"{not-json")

    code = cli.main([
        "--check-policy-source",
        "--policy-url",
        str(policy_file),
        "--trusted-policy-public-key",
        TEST_PUBLIC_KEY,
    ])

    output = capsys.readouterr().out
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "Policy source: INVALID" in output
    assert "Malformed JSON policy" in output


def test_check_policy_source_network_unavailable_is_explicit(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "fetch_policy_bytes",
        lambda *args, **kwargs: (_ for _ in ()).throw(PolicyFetchError("network unavailable")),
    )

    code = cli.main([
        "--check-policy-source",
        "--policy-url",
        "https://example.invalid/windows-release-policy.json",
    ])

    output = capsys.readouterr().out
    assert code == cli.EXIT_UNKNOWN_OR_POLICY_ERROR
    assert "Policy source: UNAVAILABLE" in output
    assert "Policy source unavailable:" in output
    assert "network unavailable" in output
