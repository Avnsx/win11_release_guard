# Windows 11 Release Guard

[![CI](https://github.com/Avnsx/win-release-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Avnsx/win-release-guard/actions/workflows/ci.yml)
[![Publish policy](https://github.com/Avnsx/win-release-guard/actions/workflows/publish-policy.yml/badge.svg)](https://github.com/Avnsx/win-release-guard/actions/workflows/publish-policy.yml)
[![CodeQL](https://github.com/Avnsx/win-release-guard/actions/workflows/codeql.yml/badge.svg)](https://github.com/Avnsx/win-release-guard/actions/workflows/codeql.yml)
[![Pylint](https://github.com/Avnsx/win-release-guard/actions/workflows/pylint.yml/badge.svg)](https://github.com/Avnsx/win-release-guard/actions/workflows/pylint.yml)
[![Dependency audit](https://github.com/Avnsx/win-release-guard/actions/workflows/dependency-audit.yml/badge.svg)](https://github.com/Avnsx/win-release-guard/actions/workflows/dependency-audit.yml)
[![Dependency freshness](https://github.com/Avnsx/win-release-guard/actions/workflows/dependency-freshness.yml/badge.svg)](https://github.com/Avnsx/win-release-guard/actions/workflows/dependency-freshness.yml)

Standalone Python mini-module for evaluating whether a Windows 11 device is on
the current broad-fleet target release and baseline build.

The repository, distribution package, and installed console command are named
`win-release-guard`. The Python import package remains `win11_release_guard`
because Python import statements cannot use hyphens.

## Project Goal

This module answers a practical admin question:

> Is this Windows 11 device on the current broad-fleet target, or is a feature
> update silently pending?

Typical case:

- Local device: Windows 11 24H2, build `26100.x`
- Broad-fleet target from policy: Windows 11 25H2, build `26200.x`
- Result: `FEATURE_UPDATE_REQUIRED`

Edition and servicing channel matter. Windows 11 Pro, Enterprise, and Education
non-LTSC devices follow the normal General Availability target path. Windows 11
Enterprise LTSC 2024 and IoT Enterprise LTSC stay on the LTSC target path and
are checked against LTSC quality baselines instead of being flagged for a normal
GA 25H2 feature update. Windows Server remains `OUT_OF_SCOPE` by default.

The library returns structured results for automation, dashboards, RMM checks,
or later WinMGT integration.

## What It Does Not Do

- It does not install updates.
- It does not trigger upgrades.
- It does not accept, download, schedule, or hide Windows Update offers.
- It does not guarantee Windows Update will offer the target feature update on
  a specific device. WUA availability is secondary diagnostic evidence only.

## Why Highest Version Does Not Win

The evaluator does not simply choose the numerically highest Windows release.
Microsoft documents Windows 11 26H1 as scoped for new devices and not offered as
an in-place feature update from 24H2 or 25H2 for existing devices. Therefore
26H1 can appear in release metadata but must not automatically become the
broad-fleet target for existing Windows 11 estates.

The policy layer marks releases such as 26H1 as special or excluded for existing
devices. Broad target selection then prefers supported General Availability H2
releases unless an explicit target is supplied.

Reference:

```text
https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
```

## Local Truth Model

Local state is build-first:

- `RtlGetVersion` build signal
- Registry build/UBR from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
- Optional CIM/WMI `Win32_OperatingSystem` build signal
- Optional `ntoskrnl.exe` file version
- Edition separately from DISM current edition, `EditionID`, WMI SKU, and
  `GetProductInfo`

Marketing fields such as `ProductName`, WMI `Caption`, and `DisplayVersion` are
kept as admin-facing diagnostics, but they are not the primary truth source.
This avoids treating stale local labels like `Windows 10 Pro` as authoritative
when build signals clearly identify a Windows 11 branch.

The result includes a local truth consensus with `display_os_name`,
`raw_product_name`, `edition_scope`, `servicing_channel`, raw local signals, and
conflict flags. For example, a machine reporting raw ProductName `Windows 10 Pro`
with build family `26200` and `EditionID=Professional` displays as
`Windows 11 Pro` and carries `LOCAL_PRODUCT_NAME_STALE`; the raw ProductName is
still serialized unchanged for administrator review.

Release inference is policy-aware. The signed policy build-family map wins over
local `DisplayVersion` and static fallback maps. Unknown syntactically valid
local labels are reported as unrecognized unless the policy explicitly knows the
release. Windows 10 client and Windows Server installs are `OUT_OF_SCOPE` by
default.

Edition inference is conservative. DISM current edition is the primary edition
signal, registry `EditionID` is next, and `GetProductInfo` is a secondary API
signal. Unknown editions produce a visible warning instead of being silently
treated as Home/Pro.

Installed build origin is also classified. When the local full build matches a
policy release-history row, the result records whether it came from a B release,
preview/D release, or out-of-band release, including KB and availability date.
If policy does not know the build, WUA history titles are used as secondary
evidence, including localized German preview titles such as `Vorschauupdate`.
By default, a preview build above the B baseline remains `COMPLIANT` but carries
`LOCAL_BUILD_IS_PREVIEW`; `--disallow-preview-installed` changes that verdict to
`PREVIEW_BUILD_INSTALLED`.

The optional WUA probe is read-only and disabled by default for integration
paths. When enabled, it performs a bounded software update search, bounded
`QueryHistory`, reads `ServiceEnabled`, preserves result codes, operations,
HResult values, update identity and support URLs, and classifies noise such as
Defender, .NET, driver, Store/runtime, and security platform updates separately
from relevant OS updates. It also performs bounded Setup and
Microsoft-Windows-Servicing event-log correlation by KB. WUA and event-log
diagnostics never override the policy verdict; unavailable or timed-out probes
become visible warnings.

Default live-probe bounds are: HTTP policy fetch `12s`, WUA subprocess `8s`,
DISM `10s`, PowerShell/CIM `8s`, Panther log tail `5 MB`, WUA history `50`
entries, relevant WUA OS update output `10` entries, and event-log reads `100`
entries.

When the policy says a feature update is required but WUA is available and does
not offer the target release, the result marks
`silent_feature_update_missing=true`. The guard then adds read-only audit
diagnostics: DISM package list parsing, bounded Panther/setup log tails, Windows
Update policy registry values, and pending-reboot evidence. These diagnostics
are used to explain likely causes such as WUfB target-release pins, WSUS/SCCM
management, feature-update deferral, pending reboot, setup rollback, safeguard
hold, staged rollout delay, WUA health, or unsupported/blocked hardware. They
do not override the policy verdict.

## Policy Sources

Runtime is JSON-first. By default, `check_current_system()` uses the production
signed policy endpoint published from this repository:

```text
https://avnsx.github.io/win-release-guard/windows-release-policy.json
```

If that endpoint is unavailable, runtime falls back to verified cache, stale
verified cache, and the bundled signed last-known-good policy with visible
warnings and structured source problems. If no valid policy is available, the
result is `CHECK_INCOMPLETE`, not `COMPLIANT`.

Generated JSON, cache, and bundled policies must carry valid signature metadata
unless `allow_unsigned_policy=True` or `--allow-unsigned-policy` is set. Runtime
Microsoft Release Health HTML parsing is disabled by default and is only used
when `allow_runtime_release_health_html=True`.

Trusted policy public keys are committed in
`win11_release_guard/data/trusted_policy_keys.json` and selected by signature
`key_id`. Runtime clients do not authenticate to GitHub; they fetch the public
GitHub Pages JSON plus `.sig` and verify the Ed25519 signature locally.

Policy documents keep upstream Microsoft evidence URLs and public hosting URLs
separate. `source_urls` is only for upstream Microsoft sources such as Release
Health and the Update History Atom feed. GitHub Pages endpoints are listed in
`published_urls`, including the landing page, canonical policy JSON, detached
signature, manifest, and `/api/v1/` aliases.

The generator path derives policy from Microsoft Windows 11 Release Health HTML
and enriches ambiguous update rows from the Microsoft Update History Atom feed.
The production generator uses public Microsoft Release Health and Atom sources only; it does not use token-authenticated Microsoft APIs.
The parser supports the public tables for current versions and release history:

- Version
- Servicing option
- Availability date
- Latest build
- Update type
- KB article

Current-version parsing keeps General Availability and LTSC rows as separate
policy entries. `ReleasePolicyEntry.edition_scopes` and
`ReleasePolicyEntry.servicing_channel` drive target selection for Home/Pro,
Enterprise/Education, Enterprise LTSC, IoT Enterprise LTSC, hotpatch, and
server/unknown scopes.

A generated JSON policy can be cached locally and reused if the live policy
fetch fails. Default cache path:

- Windows: `%LOCALAPPDATA%\win-release-guard\windows-release-policy.json`
- Other/fallback: `.cache/windows-release-policy.json` under the current working
  directory

Policy URLs can be overridden through `ReleaseCheckerConfig(policy_url=...)`,
`--policy-url`, or the `WIN11_RELEASE_GUARD_POLICY_URL` environment variable.
`--policy-url` wins over the environment variable, and both override the
production default. Local policy file paths are accepted and report
`policy_source_kind` as `local_json`. The raw checked-in last-known-good policy
is also available as a manual override:

```text
https://raw.githubusercontent.com/Avnsx/win-release-guard/main/win11_release_guard/data/windows-release-policy.json
```

## Readiness Checks

Library readiness and policy-feed readiness are separate.

Library readiness means the package imports, the bundled policy verifies, the
evaluator works, and tests pass. Check local package integrity without WUA or
remote fetch:

```powershell
python -m win11_release_guard --self-test
```

Policy feed readiness means a real hosted URL is configured, signed JSON is
available, the detached signature verifies, the schema validates, upstream
`source_urls` and public `published_urls` are listed, the generator workflow
passes, and an update schedule exists. Check the hosted or local signed policy
without local Windows probes:

```powershell
python -m win11_release_guard --check-policy-source
python -m win11_release_guard --check-public-pages
```

This prints the policy source status, upstream source URLs, published URLs,
manifest hash status, `generated_at_utc`, broad target, baseline, and excluded
releases. It exits `0` when the policy source is valid and `2` when the policy
or signature is unavailable, invalid, or untrusted. `--check-public-pages`
also checks the landing page, robots.txt, sitemap, canonical JSON/signature,
and `/api/v1/` aliases. These modes run no local Windows probes and no WUA.
Generator workflow health and the update schedule are verified through the
repository's GitHub Actions and Pages configuration.

Dependency freshness is checked by a scheduled workflow. If the badge is
passing, the latest run found that direct dependency specifiers in
`pyproject.toml` allow the latest stable PyPI releases. It is not a transitive
dependency audit; vulnerability checks are covered by the separate Dependency
audit workflow.

CodeQL code scanning is configured by `.github/workflows/codeql.yml`. If GitHub
code scanning is disabled in repository settings, enable it under Settings,
Code security and analysis.

Manual public endpoint checks:

```powershell
curl -I https://avnsx.github.io/win-release-guard/
curl -I https://avnsx.github.io/win-release-guard/windows-release-policy.json
curl -I https://avnsx.github.io/win-release-guard/windows-release-policy.json.sig
curl https://avnsx.github.io/win-release-guard/robots.txt
```

## Python Example

```python
from win11_release_guard import (
    ReleaseCheckerConfig,
    check_current_system,
)

result = check_current_system(
    ReleaseCheckerConfig(
        quality_policy="b_release_only",
        excluded_releases=frozenset({"26H1"}),
        enable_wua_probe=False,
    )
)

print(result.status.value)
print(result.summary)
print(result.to_dict())
```

No network, registry, WUA, or local Windows probes run on import. Active work
starts only when `check_current_system()` or lower-level probe/fetch functions
are called.

## CLI Examples

After installation, use the hyphenated command:

```powershell
win-release-guard --json
win-release-guard --json-pretty
win-release-guard --json --unicode
win-release-guard --json --output release-check.json
win-release-guard --pretty
win-release-guard --policy-url https://avnsx.github.io/win-release-guard/windows-release-policy.json
win-release-guard --diagnose-config
win-release-guard --allow-runtime-release-health-html
win-release-guard --allow-unsigned-policy
win-release-guard --trusted-policy-public-key <base64-ed25519-public-key>
win-release-guard --allow-major-upgrade-recommendation
win-release-guard --allow-server-evaluation
win-release-guard --disallow-preview-installed
win-release-guard --no-preview-installed-warning
win-release-guard --explicit-target-release 25H2
win-release-guard --quality-policy b_release_only
win-release-guard --timeout-seconds 12
win-release-guard --wua --wua-timeout-seconds 8
win-release-guard --with-wua
win-release-guard --no-wua
win-release-guard --json --include-raw-wua-history
win-release-guard --diagnose-config --check-source
win-release-guard --self-test
win-release-guard --check-policy-source
win-release-guard --check-public-pages
```

For source-tree use without installing the console script,
`python -m win11_release_guard` remains supported.

JSON stdout is ASCII-escaped by default (`ensure_ascii=True`) so redirected
machine output is codepage-safe. Use `--unicode` for human-readable UTF-8
stdout. `--output release-check.json` writes UTF-8 with LF line endings. WUA JSON is
compact by default: it contains category counts, relevant OS updates, the
latest three relevant history entries, WUA errors, `service_enabled`,
`target_feature_update_offered`, `target_feature_update_offer_expected`, and
`raw_output_truncated`. Use `--include-raw-wua-history` to include the full
bounded WUA history.

`--diagnose-config` reports the package version, effective policy URL and
source, cache path, bundled policy signature status, trusted public-key
fingerprint, probe defaults, source-check setting, and platform summary. It
does not fetch the remote policy unless `--check-source` is also passed.
`--self-test` imports the package, loads and verifies the bundled signed
policy, parses the policy schema, and performs no WUA or remote fetch by
default. `--check-policy-source` fetches only the configured policy JSON, its
`.sig` file, and the manifest when a public manifest URL is listed. It verifies
the signature, validates the schema, checks the manifest policy hash when the
manifest is reachable, and prints feed metadata without running local Windows
probes. `--check-public-pages` adds HTTP checks for the public GitHub Pages
landing page and API aliases.

## Creating a clean source archive

Use the export helper when sharing this repository as a source ZIP:

```powershell
python tools/export_clean_archive.py
```

It writes `dist/win-release-guard-source.zip` and self-checks the archive
manifest. The archive intentionally includes `win11_release_guard/`, `tests/`,
`tools/`, `docs/`, `README.md`, `pyproject.toml`, `.github/dependabot.yml`,
`.github/workflows/ci.yml`, `.github/workflows/publish-policy.yml`,
automation workflows, and the signed bundled policy in
`win11_release_guard/data/`. It excludes Git
metadata, pytest and Python bytecode caches, local `.cache/`, build/dist
artifacts, local temp files, `out*.json`, and the deleted prototype entry point.

## Policy Generator

Generate the enterprise JSON policy from Release Health HTML plus Atom feed
enrichment:

```powershell
python tools/generate_policy.py `
  --release-health-html tests/fixtures/windows11-release-health.html `
  --atom-feed tests/fixtures/windows11-atom.xml `
  --output-dir site `
  --write-index `
  --write-robots `
  --write-sitemap `
  --write-manifest
```

To emit `site/windows-release-policy.json.sig`, provide a signing key through
`--signing-key-env` or `--signing-key-file`. Signing uses Ed25519; the key input
can be PEM or a base64-encoded raw 32-byte Ed25519 seed. New signatures include
the trusted public-key `key_id`.

Create a signing key pair in ignored local scratch space:

```powershell
python tools/generate_signing_key.py --out-dir .tmp/signing-key
```

Copy the contents of the generated private key file into the GitHub Actions
Secret `WIN_RELEASE_GUARD_POLICY_SIGNING_KEY_B64`. Do not commit private key
material. Commit only reviewed public key records in
`win11_release_guard/data/trusted_policy_keys.json`.

Before publishing or exporting, scan source and generated Pages output for
committed secret material:

```powershell
python tools/scan_for_secret_material.py site win11_release_guard tests tools docs README.md AGENTS.md pyproject.toml .github
```

Generated Pages output includes the landing dashboard, policy JSON, detached
signature, `policy-manifest.json`, byte-identical API aliases under
`api/v1/`, `robots.txt`, `sitemap.xml`, and `.nojekyll`.

The repository includes `.github/workflows/publish-policy.yml`, which runs on a
twice-daily schedule and publishes `site/` to GitHub Pages through the same
repository's Pages artifact deployment. The workflow requires repository secret
`WIN_RELEASE_GUARD_POLICY_SIGNING_KEY_B64`; if that secret is absent, production
publishing fails before upload and the previous Pages deployment remains
untouched. It does not use PATs, `contents: write`, branch commits, or
`gh-pages` branch publishing.

## Trust Model

Remote generated JSON policies must have a valid adjacent
`windows-release-policy.json.sig` signature unless `allow_unsigned_policy=True`
or `--allow-unsigned-policy` is explicitly set. The runtime verifies the exact
JSON bytes before accepting or caching a policy.

The public Pages feed exposes these stable programmatic paths:

- `https://avnsx.github.io/win-release-guard/windows-release-policy.json`
- `https://avnsx.github.io/win-release-guard/windows-release-policy.json.sig`
- `https://avnsx.github.io/win-release-guard/policy-manifest.json`
- `https://avnsx.github.io/win-release-guard/api/v1/policy.json`
- `https://avnsx.github.io/win-release-guard/api/v1/policy.sig`
- `https://avnsx.github.io/win-release-guard/api/v1/manifest.json`

These public feed paths belong in `published_urls`, not `source_urls`.
`source_urls` remains reserved for upstream Microsoft pages and feeds used to
derive the signed policy.

Detached signatures are JSON objects with `algorithm`, `key_id`, and
`signature`. The runtime chooses the matching Ed25519 public key from
`win11_release_guard/data/trusted_policy_keys.json`; multiple records are
allowed for key rotation. Legacy signatures without `key_id` are accepted only
through the default trusted key during the transition.

Fallback order is:

1. Verified production/default remote policy.
2. Verified override remote/local policy when a URL or file path is configured.
3. Verified fresh cache when that configured source fails.
4. Verified stale cache with a visible warning.
5. Verified bundled last-known-good policy with a visible warning.
6. `CHECK_INCOMPLETE` when no valid policy exists.

The serialized result exposes `policy_signature_status`, `policy_source_kind`,
`source_status`, `warnings`, `errors`, and structured `source_problems` so
source failures are not hidden. Source statuses include
`REMOTE_POLICY_OK`, `USING_FRESH_CACHE`, `USING_STALE_CACHE`,
`USING_BUNDLED_POLICY`, `POLICY_UNAVAILABLE`, and
`RUNTIME_HTML_FALLBACK_USED`.

Exit codes:

```text
0  COMPLIANT
1  FEATURE_UPDATE_REQUIRED or QUALITY_UPDATE_REQUIRED
2  UNKNOWN_LOCAL_RELEASE, CHECK_INCOMPLETE, or policy problem
3  ABOVE_BROAD_TARGET_OR_SPECIAL_RELEASE
10 CLI argument error
```

## Example JSON Output

```json
{
  "status": "FEATURE_UPDATE_REQUIRED",
  "installed_release": "24H2",
  "installed_build": "26100.8457",
  "installed_build_origin": {
    "build": "26100.8457",
    "classification": "b_release",
    "diagnostic_flags": [
      "LOCAL_BUILD_IS_B_RELEASE"
    ],
    "evidence_source": "policy_release_history",
    "kb_article": "KB5089549"
  },
  "baseline_build": "26200.8457",
  "action": "Feature update required: update from 24H2 to 25H2.",
  "is_warning": true,
  "is_error": false,
  "source_status": "REMOTE_POLICY_OK",
  "is_source_check_complete": true,
  "policy_age_hours": 2.5,
  "policy_source_url": "https://avnsx.github.io/win-release-guard/windows-release-policy.json",
  "policy_source_kind": "remote_json",
  "policy_signature_status": "valid",
  "warnings": [],
  "errors": [],
  "source_problems": [],
  "notes": [],
  "target": {
    "version": "25H2",
    "build_family": 26200,
    "latest_build": "26200.8457"
  }
}
```

Actual JSON includes the full serialized `local`, `target`, `baseline`,
`details`, optional `wua_secondary`, and silent feature-update diagnostic
structures.

## Test Strategy

Tests are designed for fast, deterministic CI and local development:

- No real network calls.
- No system mutation.
- No update installation.
- No real WUA/COM dependency in tests.
- Registry, CIM, DISM, WUA, and policy fetch paths are monkeypatched or stubbed.
- WUA is read-only and optional in product code.
- Non-Windows behavior is explicitly tested.
- Import has no side effects.

Useful test commands:

```powershell
python -m compileall -q win11_release_guard tools
python tools/check_github_action_versions.py
pytest -q tests/test_evaluator.py
pytest -q tests/test_remote_policy.py
pytest -q tests/test_local_state.py
pytest -q tests/test_cli.py
pytest -q tests/test_cache.py tests/test_import_contract.py
pytest -q
```

Deployment-affecting changes require the live Pages gate before handover.
This includes workflow changes, policy generator changes, signing changes,
Pages landing page changes, manifest/API alias changes,
source URL or published URL changes, and CLI changes to `--check-policy-source` or
`--check-public-pages`.

```powershell
python -m compileall -q win11_release_guard tools
pytest -q
python tools/generate_policy.py --release-health-html tests/fixtures/windows11-release-health.html --atom-feed tests/fixtures/windows11-atom.xml --output-dir site --write-index --write-robots --write-sitemap --write-manifest --signing-key-file .tmp/signing-test/private-key.b64
python tools/scan_for_secret_material.py site win11_release_guard tests tools docs README.md AGENTS.md pyproject.toml .github
python -m win11_release_guard --check-policy-source
python -m win11_release_guard --check-public-pages
```

If live network is unavailable, record that explicitly, run the mocked test
suite, and do not claim live success. If a live check fails, fix the regression,
rerun the live check, and record the exact failing URL, status, and error.

CI runs on Ubuntu and Windows across Python 3.11 and 3.12. It runs compileall,
the GitHub action-version audit, the no-network pytest suite, fixture-based
policy generation with Pages support files, CLI JSON validation, clean source
archive export, and the secret-material scanner. Treat a build as
production-ready only when source failures are structured and visible,
signed/generated policy loading works, cache and bundled fallback work, WUA is
bounded, the German 25H2 live fixture passes, the edge-case suite passes, and
the archive/scanner checks remain clean.
