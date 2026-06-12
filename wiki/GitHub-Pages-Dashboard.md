# GitHub Pages Dashboard

Use this when changing the generated static dashboard or public Pages endpoint contract.

---

## Dashboard Sections

The dashboard is a static public control surface for humans and automation. The
top cards summarize the signed policy target, the currency panel explains feed
age, Source Diagnostics shows source/parser health, Signature confirms trust
state, and Programmatic API links expose the canonical policy artifacts.

The API section is intentionally boring and stable: scripts should use the
published JSON, detached signature, manifest, or `/api/v1` aliases rather than
scraping visual dashboard text. Browser code stays local and static; it can
filter diagnostics and update feed age, but it does not write to GitHub, fetch
private state, or decide signed policy semantics.

| Section | Shows |
| --- | --- |
| Header | Product display name, program version, dashboard/wiki/repo links. |
| Target cards | Broad target, required baseline, latest observed build, and latest-observed evidence label. |
| Baseline update notice | Dashboard-only notice when a real B-release required baseline catches up to latest observed evidence. |
| Feed currency | Generated time, live age state, thresholds. |
| Source diagnostics | Notice/warning/error filters, counts, source health tiles, drift or parser events. |
| Excluded releases | Data-driven existing-device exclusion summary. |
| Programmatic API | Canonical and `/api/v1` links. |

## Static Output Contract

| File | Required |
| --- | --- |
| `index.html` | Yes |
| `windows-release-policy.json` | Yes |
| `windows-release-policy.json.sig` | Yes when signing key exists in production |
| `policy-manifest.json` | Yes |
| `api/v1/policy.json` | Yes |
| `api/v1/policy.sig` | Yes |
| `api/v1/manifest.json` | Yes |
| `wiki/index.html` | Yes, rendered from `wiki/Home.md` |
| `wiki/<slug>/index.html` | Yes, rendered from `wiki/*.md` |
| `wiki/changelog/index.html` | Yes, rendered from `CHANGELOG.md` |
| `wiki/changelog/vX.Y.Z/index.html` | Yes, rendered from historical `CHANGELOG.md` version sections |
| `robots.txt`, `sitemap.xml`, `.nojekyll` | Yes for Pages support |

Local `site/` is generated output for testing and must not be committed. The Pages workflow regenerates `site/`, signs policy output, renders `wiki/*.md` into the static Pages Wiki, renders `CHANGELOG.md` into the static Pages changelog, uploads the Pages artifact, deploys it, and then verifies live endpoints. Use workflow_dispatch to refresh Pages manually. Wiki and changelog changes require a Pages rebuild because they become generated Pages HTML. Docs-only changes do not need a Pages rebuild unless they change dashboard-rendered content, generated metadata, public URLs, or workflow path filters.

## Static Pages Wiki

The same `wiki/*.md` files stay compatible with the GitHub internal Wiki and are rendered into GitHub Pages by first-party Python in `win11_release_guard.policy_generator`. `wiki/Home.md` becomes `wiki/index.html`; non-helper pages become `wiki/<slug>/index.html`; `_Sidebar.md` and `_Footer.md` provide static navigation/footer content only and are not published as standalone Pages Wiki pages. GitHub Wiki links like `[[Home]]` and `[[Quick Start|Quick-Start]]` are converted to Pages Wiki links.

The renderer escapes raw HTML from Markdown and uses no external JS, CSS, fonts, CDN, npm, or browser GitHub write path. It may add a small number of first-party inline SVG topic icons to article headings; those icons are generated from local Python code, marked `aria-hidden`, omitted from sidebar/TOC text, and never written back into the Markdown source used by the GitHub internal Wiki. Wiki pages also use an inline SVG favicon data URL so browsers do not request an external favicon.

The opened Wiki page is marked in the generated `.wiki-sidebar` with `aria-current="page"` and a heavier link style; if `_Sidebar.md` groups the page under a bold label such as `Architecture`, that group label is strengthened too. A small first-party inline scroll helper marks only same-page hash links inside the sidebar; as readers scroll through Wiki or changelog sections, the active section link becomes heavier and receives `aria-current="location"`. The helper stores the sidebar scroll position for the current tab before sidebar navigation, restores that position on the destination page, then aligns from that position to the current page/group or active section. If no stored position exists, initial alignment is instant instead of animating from the top of the sidebar. It respects reduced-motion preferences and recent manual sidebar scrolling. No-JavaScript navigation remains normal static links.

The renderer surfaces broken internal links, missing `wiki/Home.md`, missing `_Sidebar.md` or `_Footer.md`, missing/empty Wiki source sets, and empty Wiki pages as visible generator warnings. A missing `wiki/Home.md` produces a fallback `wiki/index.html` so the Pages Wiki root remains reachable while maintainers repair the Markdown source.

## Static Pages Changelog

`CHANGELOG.md` remains manually maintained source of truth. The generator renders `/wiki/changelog/` plus per-version routes such as `/wiki/changelog/v0.3.3/` and historical `/wiki/changelog/v0.3.2/`. `[Unreleased]` stays above release versions when present, newer versions are added above older versions, and historical sections remain visible for Pages changelog, release history, SEO, and auditability. Empty changelogs and non-standard h2 version headings stay visible in rendered HTML and are marked with generator warnings instead of being silently ignored.

## Indexing Metadata

Generated HTML pages include title, meta description, canonical link, Open Graph metadata, Twitter summary metadata, and semantic page structure. Metadata comes from actual page content or concise page-purpose descriptions. Do not add keyword stuffing, cloaking, hidden SEO text, external SEO scripts, CDN assets, or font dependencies.

## Source Diagnostics Controls

The Notices, Warnings, and Errors count tiles are keyboard-accessible filters for
the Source Diagnostics feed. `View all` resets the filter. Rows can expose a
small hover/focus-only `#Ticket <number>` link, but only when static
workflow-generated issue metadata contains a canonical
`https://github.com/Avnsx/win11_release_guard/issues/<number>` URL for a real
warning/error `source_diagnostics.events` row. Derived UI rows, clear-state
rows, and Notice events remain visible and filterable without ticket links.

Rows may show a concise administrator-facing summary above the technical
message. The technical message, source chip, tags, diagnostic ID, issue metadata,
and copy-to-clipboard data remain available for triage. Atom-derived rows can
carry fields such as `support_article_url`, `atom_entry_id`,
`atom_support_article_id`, `kb_update_bucket`, `is_security`, and
`security_evidence_source`.

The dashboard never creates GitHub Issues and never calls the GitHub Issues API
from browser JavaScript. Issue creation, update, reopen, and close operations
belong only to GitHub Actions issue-sync workflows using the built-in
`GITHUB_TOKEN` with minimal `issues: write` permission.

`latest_build` on the signed policy remains the Microsoft Release Health Current
Versions table value. The dashboard's `Latest observed` card can show a newer
`latest_observed_build` from an Atom-linked Support article and labels that
evidence source. This is informational context only; it does not change
`required_baseline_build`. Once Release Health has caught up and baseline rules
select the same build, all three build fields can legitimately show that same
value.

Atom is discovery for Support article hrefs, not a synthesized `/help/<KB>`
resolver. The generator uses safe Atom `alternate` support article links,
canonicalizes otherwise safe support URLs by stripping query strings and
fragments, validates fetched Support article URL, KB, build, and parseable applicability
before trusting article facts, and keeps mismatch/degraded status visible in
Source Diagnostics. MSRC CVRF joins require exact KB-token matches; substring
matches and malformed/unavailable CVRF data must not silently become
non-security proof.

When the broad target's required baseline is selected from a real non-preview,
non-OOB Release Health B-release row and catches up to
`latest_observed_build`, the dashboard can render a blue/white baseline-update
notice above `Policy Feed Currency` and `Source Diagnostics`. It is
informational only, lasts 14 days from the source-derived official baseline
date, labels Release Health date-only precision when Microsoft provides only a
date, keeps the expiry marker hidden from the UI, and uses deterministic local summary text from Release Health, Atom,
validated Support facts, and exact MSRC evidence. It never calls an LLM, cloud
API, GitHub runtime API, external JS/CSS/font/CDN, or changes the signed
policy verdict, required baseline selection, issue sync, runtime client
behavior, or `/api/v1` aliases.

## Rules

| Do | Do not |
| --- | --- |
| Keep dashboard static and no-token. | Add backend runtime dependencies. |
| Keep JavaScript inline and local. | Add external JS/CSS/fonts/CDNs. |
| Keep public endpoints stable. | Break API aliases or published URL fields. |
| Keep baseline-update notices informational. | Treat the notice as compliance logic or GitHub Issue input. |
| Preserve source diagnostics visibility. | Hide parser/source drift events. |

GitHub Actions schedules are best-effort platform automation and do not guarantee a refresh time. Treat live endpoint checks and generated timestamps as operational truth.

## Verify

```powershell
python tools/generate_policy.py --release-health-html tests/fixtures/windows11-release-health.html --atom-feed tests/fixtures/windows11-atom.xml --output-dir site --write-index --write-robots --write-sitemap --write-manifest
pytest -q tests/test_pages_landing.py tests/test_policy_generator.py tests/test_wiki_markdown_links.py tests/test_source_diagnostics_issue_metadata.py
python -m win11_release_guard --check-public-pages
```

## Related Pages

[Home](Home) | [Anti-Static Freshness](Anti-Static-Freshness) | [Source Diagnostics](Source-Diagnostics)
