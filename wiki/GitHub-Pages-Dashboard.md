# GitHub Pages Dashboard

Use this when changing the generated static dashboard or public Pages endpoint contract.

---

## Dashboard Sections

| Section | Shows |
| --- | --- |
| Header | Product display name, program version, dashboard/wiki/repo links. |
| Target cards | Broad target, required baseline, latest observed build. |
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

The same `wiki/*.md` files stay compatible with the GitHub internal Wiki and are rendered into GitHub Pages by first-party Python in `win11_release_guard.policy_generator`. `wiki/Home.md` becomes `wiki/index.html`; other pages become `wiki/<slug>/index.html`; `_Sidebar.md` and `_Footer.md` provide static navigation/footer content. GitHub Wiki links like `[[Home]]` and `[[Quick Start|Quick-Start]]` are converted to Pages Wiki links. Raw HTML is escaped, and the rendered Wiki uses no external JS, CSS, fonts, CDN, npm, or browser GitHub write path. A small first-party inline scroll helper marks only same-page hash links inside the generated `.wiki-sidebar`; as readers scroll through Wiki or changelog sections, the active sidebar link becomes heavier and receives `aria-current="location"`, while no-JavaScript navigation remains normal static links.

The renderer surfaces broken internal links, missing `wiki/Home.md`, missing `_Sidebar.md` or `_Footer.md`, missing/empty Wiki source sets, and empty Wiki pages as visible generator warnings. A missing `wiki/Home.md` produces a fallback `wiki/index.html` so the Pages Wiki root remains reachable while maintainers repair the Markdown source.

## Static Pages Changelog

`CHANGELOG.md` remains manually maintained source of truth. The generator renders `/wiki/changelog/` plus per-version routes such as `/wiki/changelog/v0.3.1/`. `[Unreleased]` stays above release versions when present, newer versions are added above older versions, and historical sections remain visible for Pages changelog, release history, SEO, and auditability. Empty changelogs and non-standard h2 version headings stay visible in rendered HTML and are marked with generator warnings instead of being silently ignored.

## Indexing Metadata

Generated HTML pages include title, meta description, canonical link, Open Graph metadata, Twitter summary metadata, and semantic page structure. Metadata comes from actual page content or concise page-purpose descriptions. Do not add keyword stuffing, cloaking, hidden SEO text, external SEO scripts, CDN assets, or font dependencies.

## Source Diagnostics Controls

The Notices, Warnings, and Errors count tiles are keyboard-accessible filters for
the Source Diagnostics feed. `View all` resets the filter. Rows can expose a
small hover/focus-only `#Ticket <number>` link, but only when static
workflow-generated issue metadata contains a canonical
`https://github.com/Avnsx/win11_release_guard/issues/<number>` URL.

The dashboard never creates GitHub Issues and never calls the GitHub Issues API
from browser JavaScript. Issue creation, update, reopen, and close operations
belong only to GitHub Actions issue-sync workflows using the built-in
`GITHUB_TOKEN` with minimal `issues: write` permission.

## Rules

| Do | Do not |
| --- | --- |
| Keep dashboard static and no-token. | Add backend runtime dependencies. |
| Keep JavaScript inline and local. | Add external JS/CSS/fonts/CDNs. |
| Keep public endpoints stable. | Break API aliases or published URL fields. |
| Preserve source diagnostics visibility. | Hide parser/source drift events. |

GitHub Actions schedules are best-effort platform automation and do not guarantee a refresh time. Treat live endpoint checks and generated timestamps as operational truth.

## Verify

```powershell
python tools/generate_policy.py --release-health-html tests/fixtures/windows11-release-health.html --atom-feed tests/fixtures/windows11-atom.xml --output-dir site --write-index --write-robots --write-sitemap --write-manifest
pytest -q tests/test_pages_landing.py tests/test_policy_generator.py tests/test_wiki_markdown_links.py
python -m win11_release_guard --check-public-pages
```

## Related Pages

[Home](Home) | [Anti-Static Freshness](Anti-Static-Freshness) | [Source Diagnostics](Source-Diagnostics)
