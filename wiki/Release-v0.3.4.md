# Release v0.3.4

Release notes for `0.3.4`, the source-evidence and release-tooling hardening release.

---

## Pick Your Path

| You are | Read | Why |
| --- | --- | --- |
| User | [Quick Start](Quick-Start) | Run the guard and understand output/exit codes. |
| Admin / RMM owner | [CLI and RMM Usage](CLI-and-RMM-Usage) | Integrate JSON output and strict-production checks. |
| Maintainer | [Build, Test and Release](Build-Test-and-Release) | Reproduce local gates and release checks. |
| Release manager | [Tagged Release Lane](Tagged-Release-Lane) | Publish a validated source archive and understand the separate PyPI lane. |
| Contributor | [Regression Chokepoints](Regression-Chokepoints) | Avoid known regression traps. |

## Highlights

| Area | 0.3.4 state |
| --- | --- |
| Versioning | Package/runtime/generator/WUA identity is centralized at `win11_release_guard/0.3.4`. |
| Baseline notice copy | Summary wording is source-aware: MSRC only for MSRC CVRF evidence, Microsoft Support for validated Support articles, neutral otherwise; no `B.;` artifact and no raw status enums in human copy. |
| Date parsing | Impossible/malformed Release Health dates degrade instead of crashing; non-padded dates normalize; date-only precision is preserved. |
| Atom fallback | Safe build-agnostic KB-only enrichment is kept while wrong-build, unsafe-URL, Preview/OOB, and ambiguous candidates are rejected; missing hrefs never synthesize `/help/<KB>`. |
| Archive validation | The inner pytest gate runs with plugin autoload disabled and with ambient `PYTEST_ADDOPTS`/`PYTEST_PLUGINS` removed; real failures stay fatal. |
| Pages wiki | The wiki/changelog visual scale and width match the dashboard at normal browser zoom with no zoom/transform/viewport hacks; tables and code blocks use the available width and code blocks gain a hover copy button. |
| PyPI lane | `pypi-publish.yml` builds wheel/sdist and publishes through Trusted Publishing / GitHub OIDC only after tag or published-release gates. |

## What Changed

The baseline-update notice summary is now built from complete, source-aware
sentences. It credits MSRC only when the evidence source is MSRC CVRF, attributes
validated Support article evidence to Microsoft Support, and stays neutral when
evidence is unavailable, unknown, or non-security. It no longer produces a `B.;`
punctuation artifact or exposes raw status enums in user-facing copy; the
machine JSON keeps the structured evidence fields.

Impossible or malformed ISO-shaped Release Health dates degrade to no active
notice instead of crashing generation, and non-zero-padded dates normalize.
Date-only Microsoft precision is preserved without inventing exact times.

Atom remains discovery for Support article hrefs. After exact KB+build and
build-only matching fail, a build-agnostic KB-only candidate may enrich a row
only when its KB matches, it has a safe canonical `support.microsoft.com` href,
it is not Preview/Out-of-band for a normal broad target, it is unambiguous, and
no same-family explicit candidate contradicts the row build. Wrong-build,
unsafe-URL, Preview/OOB, and ambiguous candidates are rejected, and the valid
KB5094126 multi-build case still enriches both explicit build rows.

## Generated Output Coverage

Generated-output regressions exercise the policy JSON, policy manifest, dashboard
HTML, `/api/v1` aliases, visible Source Diagnostics JSON export, and remote
parser acceptance, plus the Pages wiki visual scale, content width, responsive
tables/code blocks, and the absence of zoom/transform/viewport hacks or external
assets. They confirm source-aware security wording, no synthesized
`/help/5094126` fallback, and no raw Support HTML leakage.

## Release Gate Result

Local `0.3.4` gates passed compileall, identity/version/action audits, and the
targeted plus full pytest suites with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`. The
tagged release lane runs the full deployment gate; this release is prepared but
not yet published.

## Packaging And PyPI

| Item | State |
| --- | --- |
| PyPI project | [win11_release_guard](https://pypi.org/project/win11-release-guard/) |
| End-user install | `python -m pip install win11_release_guard` |
| Package metadata | `pyproject.toml` defines `win11_release_guard` version `0.3.4`, GPL-3.0-only license, console script, project URLs, and package data. |
| Build artifacts | wheel and sdist are generated in `dist/`, checked with `python -m twine check dist/*`, and never committed. |
| Publishing | `.github/workflows/pypi-publish.yml` uses PyPI Trusted Publishing / GitHub OIDC with environment `pypi`. |
| First publish | Pending Trusted Publisher setup is required if the project is absent; a PyPI 404 is not a name reservation. |

## Signed Policy Note

The local version bump does not regenerate the signed bundled production policy
or detached signature. Release packaging and Pages publishing must use the
existing secure signing workflow with the real policy signing key.

## Unchanged Boundaries

| Boundary | Rule |
| --- | --- |
| Verdict | Signed public policy remains the authority. |
| WUA | Optional read-only secondary probe; never decides the policy verdict. |
| Panther/setup logs | Administrator troubleshooting evidence only. |
| Source Diagnostics | Source-health evidence only; notices are dashboard-only and not issue-syncable. |
| Baseline notice | Informational dashboard output only, visible for 14 days. |
| 26H1 | New-devices-only / excluded for existing devices. |
| `/api/v1` | Existing public aliases remain compatible. |

## Verify Commands

```powershell
python -m compileall -q win11_release_guard tools tests
python tools/check_version_consistency.py
python tools/check_project_identity.py
python tools/check_github_action_versions.py
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"; python -m pytest -q
python -m win11_release_guard --self-test
python tools/scan_for_secret_material.py README.md CHANGELOG.md AGENTS.md docs wiki win11_release_guard tests tools pyproject.toml .github
python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip
python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip
python -m build
python -m twine check dist/*
```

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q
```

## Full Change Notes

The complete change list recorded for v0.3.4.

### Summary

Windows 11 Release Guard 0.3.4 is a polish and reliability release on top of 0.3.3.
It makes the dashboard's security wording match the evidence it actually has, reads
Microsoft's source dates and update links more defensively so unusual data degrades
gracefully instead of breaking, and gives the public wiki and changelog the same
comfortable, readable scale as the dashboard. Device compliance results are
unchanged: the signed policy verdict and required-baseline rules behave exactly as
before.

### Fixed

* Made the dashboard baseline-update notice security wording source-aware and
  punctuation-clean. The user-facing summary previously asserted "MSRC confirms
  it as a security update" whenever the baseline was security-classified, even
  when the only evidence was a validated Microsoft Support article (for example
  when MSRC CVRF was unavailable). It now credits MSRC only for exact MSRC CVRF
  evidence, attributes Support article evidence to Microsoft Support, uses
  neutral wording when evidence is unavailable or unknown, and uses clear
  non-alarmist wording when checked evidence does not classify the update as
  security. The summary is assembled from complete sentences, so it no longer
  emits the `B.;` punctuation artifact or leaks raw status enums such as
  `not_security` into human-facing copy; machine JSON fields still carry the
  structured `security_evidence_source`/`security_evidence_status` values.
* Hardened baseline-notice date parsing so impossible or malformed ISO-shaped
  source dates such as `2026-02-30` degrade to no active notice instead of
  raising `ValueError` and aborting policy, dashboard, and manifest generation.
  Non-zero-padded calendar dates such as `2026-6-9` are now accepted and
  normalized to `2026-06-09`; date-only precision is preserved and no time of
  day is invented.
* Rebalanced the KB-only Atom fallback so it keeps legitimate build-agnostic
  article evidence without attaching wrong-build metadata. It runs only after
  exact KB+build and build-only matching fail, and then attaches a build-agnostic
  candidate only when the candidate KB matches, the candidate has a safe
  canonical Atom support URL, it is not Preview/Out-of-band for a normal broad
  target, it is unambiguous, and no same-release-family explicit candidate
  contradicts the row build. An explicit candidate for a different build family
  no longer blocks an otherwise-safe build-agnostic fallback, while wrong-build,
  unsafe-URL, Preview/OOB, and ambiguous candidates are still rejected. Exact
  KB+build matches (including the KB5094126 multi-build case) are unaffected.
* Removed an unreachable `release_unmatched` support-article validation branch;
  applies-to compatibility only ever produces `compatible`, `incompatible`, or
  `unknown`.
* Guarded repo-controlled Markdown reads in Wiki and changelog Pages generation
  so invalid UTF-8 in a source file degrades to replacement characters instead
  of crashing the generator; valid Markdown rendering and links are unchanged.

### Changed

* Made clean-archive validation deterministic and resistant to ambient pytest
  configuration. `tools/export_clean_archive.py --validate` builds an isolated
  environment for its inner extracted-archive pytest gate: it sets
  `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, removes inherited `PYTEST_ADDOPTS` and
  `PYTEST_PLUGINS` (which otherwise inject options or force plugin imports even
  with autoload disabled), and preserves the recursion guard and required Python
  runtime variables. A developer shell exporting `--cov=...` via `PYTEST_ADDOPTS`
  or a stale `PYTEST_PLUGINS` can no longer change, fail, or hang validation. The
  project declares no required pytest plugins, so coverage is unchanged, and CI
  still runs the full suite separately and validates with `--skip-test-run`, so
  no duplicate full run is introduced.
* Added `docs/releases/v0.3.1.md` to the required clean-archive entries (alongside
  the existing `v0.3.2` and `v0.3.3` release notes) so release history stays
  protected by archive validation.
* Clarified that the Source Diagnostics issue-sync `include_notices` flag is
  retained only for CLI backward compatibility and is intentionally inert:
  `notice` events stay dashboard-only and are never synced as GitHub Issues
  regardless of the flag.
* Unified the generated Pages Wiki visual scale and layout width with the
  dashboard. The wiki and changelog theme is rem-based but had no explicit root
  size and a narrow content cap, so it rendered noticeably smaller and denser
  than the dashboard at normal browser zoom while wide gutters sat empty. The
  shared wiki shell now sets a responsive root `font-size`
  (`clamp(1.0625rem, 1rem + 0.45vw, 1.25rem)`) so `/wiki/`, every wiki subpage,
  and the generated changelog pages scale their typography, spacing, and gutters
  to the dashboard's reading size without any CSS/browser zoom, transform-scale,
  or viewport tricks, and stay responsive (smaller on narrow screens, capped on
  wide desktops). The content column now uses the available horizontal space (up
  to a generous cap) so tables get room without shrinking their text, and long
  code blocks wrap at argument/whitespace boundaries (`white-space: pre-wrap`)
  so commands stay fully visible instead of being clipped behind a horizontal
  scrollbar. Prose paragraphs stay readable at ~74ch, content wraps long
  words/URLs, narrow screens still stack cleanly, and `overflow-x: clip` contains
  any stray overflow without breaking the sticky sidebar. The dashboard scale is
  unchanged and the Pages output remains static with no external JS, CSS, fonts,
  CDNs, tokens, or runtime API calls.

### Tests

* Added regression coverage for source-aware and punctuation-clean baseline-notice
  wording (MSRC vs Microsoft Support vs neutral vs non-security, no `B.;`, no raw
  enums), impossible/malformed and non-zero-padded baseline dates, the rebalanced
  KB-only Atom fallback (safe build-agnostic accepted; wrong-build/unsafe/Preview/
  ambiguous rejected; multi-build KB enrichment intact), the applies-to
  compatibility status set, guarded Markdown reads, archive-validation isolation
  from `PYTEST_ADDOPTS`/`PYTEST_PLUGINS` plus autoload determinism, archive
  failure on a real test failure, `--skip-test-run` content validation, and
  required historical release-doc entries.
* Added Pages visual-scale coverage: wiki home, wiki subpages, and changelog
  pages carry the shared responsive root scale; the dashboard and wiki share the
  Segoe UI font stack and clamp-based scale system; no generated Pages HTML uses
  zoom/transform-scale/viewport hacks or external assets; and wiki code blocks,
  tables, and long links stay responsive.

### Packaging And Release

* Program/package version is `0.3.4`; runtime user-agent, generator identity, and
  WUA client application ID continue to derive from the shared version helper
  instead of hardcoded per-module strings.
* Release documentation now includes `docs/releases/v0.3.4.md` and
  `wiki/Release-v0.3.4.md`; clean archives require the new release-note files while
  keeping historical `v0.3.1`, `v0.3.2`, and `v0.3.3` material available.
* PyPI publishing remains handled by `.github/workflows/pypi-publish.yml` through
  Trusted Publishing / GitHub OIDC: it builds wheel and sdist artifacts, runs
  `python -m twine check dist/*`, and still requires Pending Trusted Publisher
  setup if the project is absent; no PyPI tokens, usernames, passwords, or
  credentialed repository URLs are introduced.
* The signed bundled production policy and detached signature are not regenerated
  by this local version bump; production packaging uses the existing secure signing
  workflow with the real policy signing key.

## Related Pages

[Home](Home) | [Architecture](Architecture) | [Policy Feed and Trust Model](Policy-Feed-and-Trust-Model) | [Source Diagnostics](Source-Diagnostics) | [Tagged Release Lane](Tagged-Release-Lane) | [Build, Test and Release](Build-Test-and-Release)
