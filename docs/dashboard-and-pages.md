# Dashboard And Pages

Purpose: document the generated static Pages surface and the public endpoint contract that maintainers must preserve.

Related links: [maintainer guide](maintainer-guide.md) | [wiki dashboard](../wiki/GitHub-Pages-Dashboard.md) | [anti-static freshness](anti-static-freshness.md)

## Generated Files

| File | Role |
| --- | --- |
| `site/index.html` | Static dashboard for humans. |
| `site/windows-release-policy.json` | Canonical signed policy JSON. |
| `site/windows-release-policy.json.sig` | Detached Ed25519 signature. |
| `site/policy-manifest.json` | Hashes, freshness, source diagnostics, public URL metadata. |
| `site/api/v1/policy.json` | Compatibility policy alias. |
| `site/api/v1/policy.sig` | Compatibility signature alias. |
| `site/api/v1/manifest.json` | Compatibility manifest alias. |
| `site/wiki/index.html` | Static Pages Wiki home rendered from `wiki/Home.md`. |
| `site/wiki/<slug>/index.html` | Static Pages Wiki pages rendered from `wiki/*.md`. |
| `site/wiki/changelog/index.html` | Static Pages changelog rendered from `CHANGELOG.md`. |
| `site/wiki/changelog/vX.Y.Z/index.html` | Per-version changelog page rendered from a historical `CHANGELOG.md` section. |
| `site/robots.txt`, `site/sitemap.xml`, `site/.nojekyll` | GitHub Pages support files. |

`site/` is generated output. Local `site/` is for testing and must not be committed; `.github/workflows/publish-policy.yml` regenerates it inside GitHub Actions, uploads it with `actions/upload-pages-artifact`, and deploys it with `actions/deploy-pages`. Use workflow_dispatch to refresh Pages manually. Pushes to `main` that touch `wiki/**` or `CHANGELOG.md` rebuild Pages. Tag pushes do not deploy Pages because the repository's `github-pages` environment is protected for the Pages lane; release tags rely on the already-published main Pages build or an explicit `publish-policy.yml` workflow_dispatch refresh. Wiki and changelog changes do require a Pages rebuild because `wiki/*.md` and `CHANGELOG.md` are rendered into static Pages HTML. Docs-only changes do not need a Pages rebuild unless they affect dashboard-rendered content, generated metadata, public URLs, or workflow path filters.

## Static Pages Wiki

The Pages Wiki renderer is first-party Python inside `win11_release_guard.policy_generator`. It keeps `wiki/*.md` compatible with GitHub's internal Wiki while rendering HTML for GitHub Pages:

- `wiki/Home.md` becomes `site/wiki/index.html`.
- Other non-helper `wiki/*.md` files become `site/wiki/<slug>/index.html`.
- `_Sidebar.md` and `_Footer.md` are reused as static navigation/footer sources only; they are not generated as standalone Pages Wiki HTML pages or sitemap URLs.
- GitHub Wiki links such as `[[Home]]`, `[[Page Name]]`, and `[[Label|Page-Name]]` become Pages Wiki links.
- Raw HTML in Markdown is escaped; no external JS, CSS, fonts, CDN, npm, or browser GitHub write path is used.
- The renderer may add a small number of first-party inline SVG topic icons to article headings. These icons are generated from local Python code, marked `aria-hidden`, omitted from sidebar/TOC text, and do not change the source Markdown used by the GitHub internal Wiki.
- Wiki pages use an inline SVG favicon data URL so browsers do not request an external favicon.
- Broken internal Wiki links, missing `wiki/Home.md`, missing `_Sidebar.md` or `_Footer.md`, missing/empty Wiki sources, and empty Wiki pages are rendered as visible generator warnings instead of being silently dropped. If `wiki/Home.md` is missing, the generator writes a fallback `site/wiki/index.html` so the Pages Wiki root stays reachable while source Markdown is repaired.
- Wiki and changelog pages mark the opened Wiki page in the generated `.wiki-sidebar` with `aria-current="page"` and a heavier link style. When `_Sidebar.md` groups related pages under a bold label such as `Architecture`, the group label is also strengthened for the current page. A small first-party, inline scroll helper only marks same-page hash links inside the sidebar; as readers scroll, the active section link becomes heavier and receives `aria-current="location"`. The helper stores the sidebar scroll position for the current tab before sidebar navigation, restores that position on the destination page, then aligns from that position to the current page/group or active section. If no stored position exists, initial alignment is instant instead of animating from the top of the sidebar. It respects reduced-motion preferences and recent manual sidebar scrolling. Without JavaScript, page navigation, group highlighting, and anchor links remain normal static HTML.

## Static Pages Changelog

`CHANGELOG.md` remains the manually maintained source of truth. The generator renders it into `/wiki/changelog/` and creates per-version pages such as `/wiki/changelog/v0.3.2/` for release sections with `vX.Y.Z` headers. `[Unreleased]` stays at the top when present; newer version sections are added above older version sections; historical sections remain visible for generated Pages changelog, release history, SEO, and auditability. Empty changelogs and h2 headings that do not match `[Unreleased]` or `vX.Y.Z` are kept in rendered HTML and surfaced as generator warnings; duplicate version headings receive duplicate-safe anchors.

## Indexing Metadata

Generated HTML pages include a `<title>`, a concise `meta description`, a canonical URL, Open Graph metadata, Twitter summary metadata, and semantic `<main>`, `<nav>`, and content structure. Descriptions are derived from real page content or concise page purpose text; the generator does not emit keyword stuffing, hidden text, cloaking, or external SEO scripts.

## Dashboard Contract

| Area | Must show |
| --- | --- |
| Target summary | Broad target, required baseline, latest observed build, and latest-observed evidence label. |
| Excluded releases | Data-driven 26H1 existing-device exclusion summary. |
| Feed currency | Latest generated/compiled timestamp for the parsed policy results, live age state, 14/45-day thresholds. |
| Source diagnostics | Keyboard-accessible severity filters, deterministic diagnostic IDs, counts, events, source health tiles, drift warnings. |
| Programmatic API | Canonical and `/api/v1` endpoint links. |

Source Diagnostics severities are source-health categories for maintainers, not
device-compliance verdicts. Notices are informational, warnings are
non-blocking source drift or enrichment problems, and errors are
publish-blocking generator/source failures.

Microsoft Release Health HTML, the public Atom/Update History feed,
Atom-linked public Microsoft Support articles, and unauthenticated public MSRC
CVRF data can be temporarily out of step. `latest_build` is the value from the
Release Health Current Versions table; `latest_observed_build` can move ahead
when the generator finds a newer non-preview broad-target build through an Atom
entry with a safe `support.microsoft.com` article href. That observed value is
informational until the signed baseline rules select it as
`required_baseline_build`. When Release Health catches up and baseline rules
select the same build, `latest_build`, `latest_observed_build`, and
`required_baseline_build` can all be the same value without indicating drift.

Atom is discovery, not a KB resolver. The generator selects only safe Atom
`alternate` links to `https://support.microsoft.com` article paths. It ignores
`self` links, feed/API/search/download/static paths, non-support hosts,
userinfo, fragments, traversal patterns, and overlong URLs; accepted evidence
URLs are canonicalized without tracking query strings. If an Atom KB row lacks a
usable Support article href, the generator records
`atom_support_article_href_missing` evidence instead of fetching `/help/<KB>`.
Legacy `/help/<digits>` paths remain valid only when they came directly from
Atom. MSRC CVRF and validated explicit Support article wording provide
higher-confidence security classification; Atom titles are kept as
low-confidence update buckets only. Source Diagnostics and enrichment can
explain observed builds and KB classification, but they do not override signed
policy verdicts or required baseline semantics.
`source_drift_unresolved_after_24h` is reserved for warning/error drift that
remains unresolved after the newest source timestamp, not for notice-only source
lag.

Support article enrichment is trusted only after the fetched article matches the
Atom record's selected support URL, KB, expected build, and parseable
applicability. Empty or unknown `Applies to` evidence is degraded, not treated
as proof of mismatch by itself. Mismatched article KB/build/release evidence
remains visible as Source Diagnostics validation metadata, but it is not used
for administrator summaries, Support-derived security labels, or `Security
patch` tags. MSRC CVRF joins use exact KB tokens only, so values such as
`KB50941260`, `15094126`, or `5094126a` do not classify `KB5094126` as security
evidence. If a partial article is compatible but incomplete, rows carry a
compact degraded reason and stay grounded in Atom KB/build/release facts.

Small info icons beside dashboard section labels are static links to the related
Pages Wiki sections. Their hover/focus panels contain a compact explanation plus
the final action line `Click to navigate to related wiki page`; they do not
fetch data, call GitHub APIs, or require browser credentials.

Policy validation warnings render as a compact full-width banner at the top of
the operations dashboard, before the `Policy Feed Currency` and `Source
Diagnostics` panels. They must not appear as a late footer-like panel after the
signature/API rows because warning state needs to be visible before readers scan
the lower operational details.

The Source Diagnostics count tiles for Notices, Warnings, and Errors are native
buttons. Selecting one filters the event feed to that severity, updates
`aria-pressed`, and reports the visible row count through the live status text.
The `View all` button resets only the selected severity filter and shows the
current diagnostic rows for all severities again. Rows can show a concise
administrator-facing summary above the technical message while keeping the
source, diagnostic ID, tags, and issue metadata visible. The copy button above
the diagnostic feed exports the currently visible Source Diagnostics rows to the
local clipboard as JSON. That JSON includes severity, deterministic diagnostic
ID, title, source, technical message, tags, optional static issue URL, visible
counts, the active filter, and a neutral context note for technical triage. When
present, it also adds fields such as `user_message`, `kb_update_bucket`,
`is_security`, `security_evidence_source`, `support_article_url`,
`support_article_validation_status`, `support_article_validation_reasons`,
`support_article_expected_kb`, `support_article_expected_build`,
`support_article_expected_release`, `atom_entry_id`, and
`atom_support_article_id`. It does not fetch GitHub, write to GitHub, or embed
credentials. The separate `Expand View`
button toggles the expanded diagnostic layout: while expanded, the Programmatic
API panel is hidden, the Source Diagnostics panel spans the dashboard space
where that panel normally sits, and the event feed gains additional vertical
room. Clicking `Expand View` again restores the normal dashboard layout without
changing the active severity filter. Without JavaScript, the dashboard stays in
the normal layout with Programmatic API visible. Diagnostic rows render in
severity order: errors first, then warnings, then notices, while preserving
source order inside the same severity. The feed may include derived
dashboard-only rows such as `No source issues reported`, existing-device
exclusion notes, or freshness notices. Those rows are filterable and may carry
deterministic DOM IDs, but they are not GitHub Issue-sync inputs.

Source Diagnostic IDs shown in row attributes and copied JSON can be either the
deterministic hash form or the durable Atom form. When one Atom entry produces
multiple build/release events, only the canonical event keeps the unambiguous
Atom-form ID; sibling rows use unique deterministic hash-form IDs while keeping
Atom entry and support-article metadata visible.

Optional source-diagnostic issue status must be static generated metadata, not
browser-fetched data. Issue sync tracks warning and error events only; notice
events remain dashboard-only. When `source_diagnostics.issue_status` maps a deterministic
ID for a real synced `source_diagnostics.events` warning/error entry to a GitHub issue number/state,
the dashboard may render a hover/focus-only `#Ticket <number>` link only to
`https://github.com/Avnsx/win11_release_guard/issues/<number>`. Derived
dashboard-only rows do not show ticket links without workflow-generated metadata
for a real synced event. Real source diagnostic rows with generated issue state
`closed` are suppressed from the dashboard entirely so resolved issue-backed
events no longer occupy visual diagnostic space. Invalid IDs, non-positive issue
numbers, and non-canonical issue URLs are ignored. Browser JavaScript must not
fetch GitHub issue state.

When the publish workflow cannot sync GitHub Issues, `source_diagnostics.issue_sync`
may report `status: unavailable`. The dashboard must render that degraded state
as static HTML so missing ticket links are visible without client-side API calls.

## Rules

| Do | Do not |
| --- | --- |
| Keep Pages static and GitHub-Pages-compatible. | Add external JS, CSS, fonts, CDN dependencies, or backend runtime assumptions. |
| Keep Source Diagnostics issue sync in GitHub Actions. | Create GitHub Issues from browser JavaScript or embed GitHub tokens in the dashboard. |
| Keep API aliases byte-equivalent unless manifest documents a compatible difference. | Break `/api/v1` paths. |
| Preserve no-JavaScript fallback text for feed age. | Rely only on render-time generated age. |

## Verify

```powershell
python tools/generate_policy.py --release-health-html tests/fixtures/windows11-release-health.html --atom-feed tests/fixtures/windows11-atom.xml --output-dir site --write-index --write-robots --write-sitemap --write-manifest
pytest -q tests/test_pages_landing.py tests/test_policy_generator.py tests/test_wiki_markdown_links.py tests/test_source_diagnostics_issue_metadata.py tests/test_policy_source_cli.py
python -m win11_release_guard --check-public-pages
```
