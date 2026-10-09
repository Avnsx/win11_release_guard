# Maintainer Guide

Purpose: this directory keeps compact technical documents for maintainers who change policy generation, signing, automation, release, or Pages behavior. The local `wiki/` folder is rendered into the static Pages Wiki and remains the long-form GitHub internal Wiki source; `CHANGELOG.md` is rendered into the static Pages changelog while staying manually maintained source of truth. Code, tests, workflows, and `AGENTS.md` remain source of truth.

Related links: [root README](../README.md) | [local wiki home](../wiki/Home.md) | [GitHub Wiki](https://github.com/Avnsx/win11_release_guard/wiki)

| Document | Audience | Contents |
| --- | --- | --- |
| [../LICENSE.txt](../LICENSE.txt) | Users, redistributors, release managers | MIT license text for repository source distribution |
| [../wiki/Build-Test-and-Release.md](../wiki/Build-Test-and-Release.md) | Maintainers, release managers | Editable install, smoke tests, package build checks, deployment-affecting gates |
| [releases/v0.3.4.md](releases/v0.3.4.md) | Maintainers, release managers, future agents | Detailed v0.3.4 release notes, source-evidence and release-tooling hardening, validation map |
| [releases/v0.3.3.md](releases/v0.3.3.md) | Maintainers, release managers, future agents | Historical v0.3.3 release notes, corrective source-evidence hardening, validation map |
| [architecture-insight.md](architecture-insight.md) | Maintainers and future agents | Runtime flow, policy hierarchy, local evidence boundaries, generator boundaries |
| [policy-signing.md](policy-signing.md) | Release and security maintainers | Ed25519 model, key rotation, signed bundled policy, verification commands |
| [security-automation.md](security-automation.md) | Repository maintainers | GitHub Actions pinning, permissions, CodeQL, Dependabot, publish security |
| [tagged-release-lane.md](tagged-release-lane.md) | Release managers | Tagged release workflow, version parity, archive attachment, rollback notes |
| [dashboard-and-pages.md](dashboard-and-pages.md) | Pages/dashboard maintainers | Static Pages artifacts, dashboard contract, public endpoint checks |
| [anti-static-freshness.md](anti-static-freshness.md) | Runtime and Pages maintainers | Feed age fields, browser recalculation, stale gates |
| [panther-support.md](panther-support.md) | Maintainers and support engineers | Panther/setup support model, entry points, output behavior, privacy notices, extension rules |
| [live-panther-json-regression.md](live-panther-json-regression.md) | Maintainers and support engineers | Windows-only live JSON regression for Panther/setup log compaction and raw opt-in behavior |
| [source-modules.md](source-modules.md) | Code maintainers | Source-module map for runtime, generator, probes, checks, tests |
| [agent-chokepoints.md](agent-chokepoints.md) | Future agents | Regression chokepoints, symptoms, do-not rules, required smoke tests |

## Rules

| Do | Do not |
| --- | --- |
| Keep maintainer facts traceable to code, tests, workflows, or `AGENTS.md`. | Use handover notes as source truth. |
| Link long-form explanations to `wiki/`. | Turn root README into the full manual. |
| Preserve exact commands and gates. | Hide source failures, signature failures, or generated artifact drift. |
| Keep `win11_release_guard` technical identity unchanged. | Rename package, feed paths, console command, or import namespace. |
