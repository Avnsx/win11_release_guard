# Policy Signing

Detailed signing documentation now lives in the GitHub Wiki:

https://github.com/Avnsx/win11_release_guard/wiki/Policy-Feed-and-Signing

Repository invariants kept here for local agents and tests:

- Runtime clients never authenticate to GitHub and never need GitHub tokens.
- Private signing keys are never committed.
- The production private key is stored only as GitHub Actions secret
  `WIN11_RELEASE_GUARD_POLICY_SIGNING_KEY_B64`.
- Trusted public keys are committed in
  `win11_release_guard/data/trusted_policy_keys.json`.
- Signatures carry `key_id` and `signed_at_utc`; runtime verification selects
  the matching public key by `key_id`.
- Trusted key records carry `status`, `valid_from_utc`, and, for `retiring` or
  `retired` keys, `verify_not_after_utc`.
- `active` keys can verify current policy signatures inside their validity
  window.
- `retiring` keys can verify signatures only when `signed_at_utc` is present
  and not later than `verify_not_after_utc`.
- `retired` keys can verify only old signatures whose `signed_at_utc` is
  present and not later than `verify_not_after_utc`; they must not validate new
  production policy signatures.
- The signed bundled policy JSON must use the current `win11_release_guard`
  identity and must verify against its detached signature.

## Key Rotation Lifecycle

Trusted key records live in `win11_release_guard/data/trusted_policy_keys.json`.
Each record has a `key_id`, public key material, `status`, and optional validity
window fields:

- `valid_from_utc`: earliest signature time accepted for the key.
- `verify_not_after_utc`: last signature time accepted for retiring or retired
  keys.
- `status`: one of `active`, `retiring`, or `retired`.

Lifecycle rules:

- `active` keys are valid for new production policy signatures inside their
  validity window.
- `retiring` keys are accepted only for signatures with `signed_at_utc` present
  and not later than `verify_not_after_utc`.
- `retired` keys are accepted only for old/bundled policies whose
  `signed_at_utc` is present and not later than `verify_not_after_utc`.
- Missing `signed_at_utc` on retiring or retired keys is not trusted for fresh
  production policy validation.

## Bundled Fallback Policy

The bundled policy files in `win11_release_guard/data/` are last-known-good
fallback artifacts. They must verify against a committed trusted public key, but
they are not regenerated locally unless the production signing key is available
through the GitHub Actions workflow. Do not replace them with a test-key-signed
policy.

A bundled policy may remain in the older schema-1 JSON shape without
`api_version`, `compatibility`, `source_diagnostics`, `latest_observed_build`,
or `required_baseline_build` fields in the raw file. That legacy shape is
allowed only for the bundled fallback. Runtime loading must normalize it through
the model layer so current readers still expose `latest_observed_build`,
`required_baseline_build`, an empty `source_diagnostics` object, and no unknown
top-level compatibility warning.

The minimum bundled fallback contract is:

- the detached signature verifies against `trusted_policy_keys.json`;
- the JSON uses the current `win11_release_guard` identity and public
  `published_urls`;
- `schema_version` remains supported;
- `broad_target_existing_devices.baseline_build` matches the B-release
  `quality_baselines[version].b_release_only.build`;
- each `current_versions` row contains a parseable `latest_build`;
- no private signing key material is present in the tracked tree.

Operational rotation flow:

1. Generate a new key in ignored scratch space with
   `python tools/generate_signing_key.py --out-dir .tmp/signing-key`.
2. Add the new public key record as `active` with a clear `key_id`.
3. Move the old key to `retiring` and set `verify_not_after_utc`.
4. Update the GitHub Actions secret
   `WIN11_RELEASE_GUARD_POLICY_SIGNING_KEY_B64` with the new private key.
5. Publish and live-verify the feed.
6. After the verification window, move the old key to `retired`; do not delete
   it while bundled policies signed by that key still need verification.
