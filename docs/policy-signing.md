# Policy Signing

How public policy JSON becomes trusted by runtime clients. The feed is public static data; trust comes from Ed25519 verification with committed public keys.

Related links: [maintainer guide](maintainer-guide.md) | [wiki trust model](../wiki/Policy-Feed-and-Trust-Model.md) | [security automation](security-automation.md)

## Artifacts

| Artifact | Path | Role |
| --- | --- | --- |
| Canonical policy | `windows-release-policy.json` | Signed JSON policy consumed by runtime clients. |
| Detached signature | `windows-release-policy.json.sig` | JSON signature metadata plus Ed25519 signature over exact policy bytes. |
| Manifest | `policy-manifest.json` | Hashes, freshness fields, source diagnostics, public endpoint metadata. |
| API aliases | `/api/v1/*` | Backward-compatible public integration lane. |
| Trusted keys | `win11_release_guard/data/trusted_policy_keys.json` | Public verification keys only. |

## Key Model

| Item | Rule |
| --- | --- |
| Private signing key | Exists only in GitHub Actions Secret `WIN11_RELEASE_GUARD_POLICY_SIGNING_KEY_B64`. |
| Runtime authentication | Runtime clients do not authenticate to GitHub. |
| Signature algorithm | Ed25519. |
| Key selection | Signature `key_id` selects a committed public key record. |
| Retiring keys | Must have `verify_not_after_utc`; verification overlap with the active key is at least 24 months. |
| Retired keys | Can verify old signatures inside their verification window only. |

## Signature Format

```json
{
  "algorithm": "ed25519",
  "key_id": "win11_release_guard-policy-2026-05",
  "signature": "base64-ed25519-signature",
  "signed_at_utc": "2026-05-31T00:00:00+00:00"
}
```

The signature covers only the exact policy JSON bytes. Signature metadata is not part of the signed payload.

## Generate Or Rotate A Key

```powershell
python tools/generate_signing_key.py --out-dir .tmp/signing-key
```

| Step | Action |
| --- | --- |
| 1 | Generate key material under ignored `.tmp/`. |
| 2 | Store the generated private key value in the GitHub Actions secret. |
| 3 | Review and commit only public key records. |
| 4 | Mark the previous key `retiring` with an adequate verification window. |
| 5 | Publish and verify the new signed feed. |

## Do / Do Not

| Do | Do not |
| --- | --- |
| Commit public verification keys. | Commit private signing keys, PEMs, or secret values. |
| Keep old public keys during rotation. | Delete retiring keys while old signed artifacts can exist. |
| Update bundled policy bytes and bundled signature together. | Accept unsigned production policy by default. |
| Check manifest hashes and API aliases. | Treat public hosting alone as a trust signal. |

## Verify

```powershell
python -m win11_release_guard --self-test
python -m win11_release_guard --check-policy-source
python -m win11_release_guard --check-public-pages
pytest -q tests/test_signing.py tests/test_signing_key_management.py tests/test_policy_source_cli*.py
python tools/scan_for_secret_material.py site win11_release_guard tests tools docs wiki README.md CHANGELOG.md AGENTS.md pyproject.toml .github
```
