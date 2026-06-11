# Source Module Map

Purpose: provide a compact maintainer map of source modules, scripts, and tests without duplicating implementation details.

Related links: [maintainer guide](maintainer-guide.md) | [wiki architecture](../wiki/Architecture.md)

## Runtime Modules

| Module | Responsibility |
| --- | --- |
| `__main__.py` | CLI parsing, output formatting, self-test/source-check modes. |
| `api.py` | Top-level orchestration, policy source fallback, strict-production degradation. |
| `config.py` | Defaults, env vars, runtime knobs. |
| `models.py` | Result, policy, source, and diagnostic data models. |
| `evaluator.py` | Target selection and verdict computation. |
| `local_state.py` | Local Windows build/edition evidence. |
| `wua_probe.py` | Optional bounded read-only WUA probe. |
| `audit_probes.py`, `diagnostic_tail.py`, `policy_diagnostics.py` | Read-only blocker diagnostics, bounded Panther/setup tail decoding, privacy markers, and collection-cap metadata. |
| `remote_policy.py` | JSON loading plus generator-only Release Health parsing. |
| `policy_generator.py` | Policy/dashboard/manifest/API generation, Release Health/Atom parsing, safe Atom Support link selection, validated Support article enrichment, exact-token MSRC CVRF enrichment, unique Source Diagnostic IDs, and first-party static Pages Wiki/changelog rendering. |
| `signing.py`, `json_utils.py`, `policy_schema.py` | Trust, strict JSON, schema validation. |
| `cache.py`, `bundled_policy.py`, `freshness.py`, `version.py` | Cache, bundled fallback, age calculations, identity. |

## Tool Scripts

| Script | Responsibility |
| --- | --- |
| `generate_policy.py` | CLI wrapper for policy/dashboard generation from public Microsoft source data and unauthenticated enrichment sources. |
| `generate_signing_key.py` | Local key generation into ignored scratch space. |
| `export_clean_archive.py` | Clean source archive creation and validation. |
| `scan_for_secret_material.py` | Secret/private-key pattern scanner. |
| `check_project_identity.py` | Naming, legacy entrypoint, generated identity checks. |
| `check_version_consistency.py` | Version marker parity. |
| `check_github_action_versions.py` | Workflow action pinning audit. |
| `check_dependency_freshness.py` | Direct dependency freshness report. |
| `check_commit_message.py` | Commit message hygiene. |
| `sync_source_diagnostics_issues.py` | Workflow-side Source Diagnostics to GitHub Issues sync, dry-run planning, static issue-status metadata, and no-client-token reports. |
| `sync_github_wiki.py` | Workflow-side GitHub internal Wiki Markdown sync from `wiki/*.md`, dry-run artifact creation, and no-credentialed-URL Git push support. |
| `debug_panther_json_leaks.py` | Developer-only JSON leak debugger for raw Panther/setup strings and compaction fix recommendations. |
| `live_panther_json_regression.py` | Windows-only live JSON output regression for Panther/setup compaction and raw opt-in behavior. |

## Repository Legal File

| File | Responsibility |
| --- | --- |
| `LICENSE.txt` | GPL-3.0 license text for repository source distribution and validated clean archive consumers. |

## Test Layout

| Area | Representative tests |
| --- | --- |
| Runtime source fallback | `test_runtime_policy_sources.py`, `test_source_failures.py` |
| Evaluator and local truth | `test_evaluator.py`, `test_edge_cases.py`, `test_local_state.py` |
| Generator and Pages | `test_policy_generator.py`, `test_pages_landing.py`, `test_wiki_markdown_links.py`, `test_remote_policy.py` |
| Source diagnostics issue sync | `test_source_diagnostics_issue_metadata.py`, `test_source_diagnostics_issue_sync.py` |
| GitHub internal Wiki sync | `test_github_wiki_sync.py` |
| Signing and JSON hardening | `test_signing.py`, `test_signing_key_management.py`, `test_json_hardening.py` |
| Automation and release | `test_repository_automation.py`, `test_publish_policy_workflow.py`, `test_ci_workflow.py` |
| Identity and exports | `test_branding_contract.py`, `test_project_identity.py`, `test_export_clean_archive.py` |
