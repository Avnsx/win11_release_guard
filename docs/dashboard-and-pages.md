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
- Other `wiki/*.md` files become `site/wiki/<slug>/index.html`.
- `_Sidebar.md` and `_Footer.md` are reused as static navigation/footer sources.
- GitHub Wiki links such as `[[Home]]`, `[[Page Name]]`, and `[[Label|Page-Name]]` become Pages Wiki links.
- Raw HTML in Markdown is escaped; no external JS, CSS, fonts, CDN, npm, or browser GitHub write path is used.
- Broken internal Wiki links, missing `wiki/Home.md`, missing `_Sidebar.md` or `_Footer.md`, missing/empty Wiki sources, and empty Wiki pages are rendered as visible generator warnings instead of being silently dropped. If `wiki/Home.md` is missing, the generator writes a fallback `site/wiki/index.html` so the Pages Wiki root stays reachable while source Markdown is repaired.
- Wiki and changelog pages include a small first-party, inline scroll helper that only marks same-page hash links inside the generated `.wiki-sidebar`. As readers scroll, the active sidebar section link becomes heavier and receives `aria-current="location"`. Without JavaScript, the sidebar and anchor links remain normal static navigation.

## Static Pages Changelog

`CHANGELOG.md` remains the manually maintained source of truth. The generator renders it into `/wiki/changelog/` and creates per-version pages such as `/wiki/changelog/v0.3.1/` for release sections with `vX.Y.Z` headers. `[Unreleased]` stays at the top when present; newer version sections are added above older version sections; historical sections remain visible for generated Pages changelog, release history, SEO, and auditability. Empty changelogs and h2 headings that do not match `[Unreleased]` or `vX.Y.Z` are kept in rendered HTML and surfaced as generator warnings; duplicate version headings receive duplicate-safe anchors.

## Indexing Metadata

Generated HTML pages include a `<title>`, a concise `meta description`, a canonical URL, Open Graph metadata, Twitter summary metadata, and semantic `<main>`, `<nav>`, and content structure. Descriptions are derived from real page content or concise page purpose text; the generator does not emit keyword stuffing, hidden text, cloaking, or external SEO scripts.

## Dashboard Contract

| Area | Must show |
| --- | --- |
| Target summary | Broad target, baseline, latest observed build. |
| Excluded releases | Data-driven 26H1 existing-device exclusion summary. |
| Feed currency | Generated time, live age state, 14/45-day thresholds. |
| Source diagnostics | Keyboard-accessible severity filters, deterministic diagnostic IDs, counts, events, source health tiles, drift warnings. |
| Programmatic API | Canonical and `/api/v1` endpoint links. |

The Source Diagnostics count tiles for Notices, Warnings, and Errors are native
buttons. Selecting one filters the event feed to that severity, updates
`aria-pressed`, and reports the visible row count through the live status text.
The `View all` button resets the filter and shows every diagnostic row again.
The feed may include derived dashboard-only rows such as `No source issues
reported`, existing-device exclusion notes, or freshness notices. Those rows are
filterable and may carry deterministic DOM IDs, but they are not GitHub
Issue-sync inputs.

Optional source-diagnostic issue status must be static generated metadata, not
browser-fetched data. When `source_diagnostics.issue_status` maps a deterministic
ID for a real `source_diagnostics.events` entry to a GitHub issue number/state,
the dashboard may render a hover/focus-only `#Ticket <number>` link only to
`https://github.com/Avnsx/win11_release_guard/issues/<number>`. Derived
dashboard-only rows do not show ticket links without workflow-generated metadata
for a real synced event. Invalid IDs, non-positive issue numbers, and
non-canonical issue URLs are ignored. Browser JavaScript must not fetch GitHub
issue state.

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
pytest -q tests/test_pages_landing.py tests/test_policy_generator.py tests/test_wiki_markdown_links.py tests/test_policy_source_cli.py
python -m win11_release_guard --check-public-pages
```
