# Anti-Static Freshness

Use this when changing feed age display, strict-production freshness gates, or public Pages checks.

---

## Freshness Fields

| Field | Meaning |
| --- | --- |
| `generated_at_epoch_s` | Machine timestamp for generated feed age. |
| `generated_at_utc` | UTC timestamp for humans and logs. |
| `warn_after_epoch_s` | 14-day maintenance warning point. |
| `stale_after_epoch_s` | 45-day stale point. |
| `strict_stale_after_epoch_s` | Strict-production stale point. |
| `warning_age_seconds` | 14 days in seconds. |
| `strict_stale_age_seconds` | 45 days in seconds. |

## Dashboard Behavior

`Policy Feed Currency` displays the latest compilation timestamp for the
current policy results parsed by this repository's generator. In normal
publishing, that timestamp comes from the GitHub Actions Pages lane, so delayed
or failed workflow runs can make the dashboard age grow even when the source
Markdown and Python code are correct.

The responsible workflow is
[publish-policy.yml](https://github.com/Avnsx/win11_release_guard/actions/workflows/publish-policy.yml).
Use it to trace the most recent scheduled, manual, or selected `main` push run
that regenerated the public Pages output. The dashboard still recalculates the
visible age in the browser from the generated epoch timestamp, but the timestamp
itself represents when the current parsed results were last compiled.

The thresholds are operational: under 14 days is current, 14 days starts a
refresh-due warning, and 45 days is stale. Strict production checks use the same
signed freshness fields and fail stale feeds instead of silently treating an old
Pages artifact as acceptable. Without JavaScript, the page still shows the
generated timestamp and render-time age as fallback text.

| Condition | Label |
| --- | --- |
| Less than 14 days | `Current` |
| 14 days or older | `Refresh Due` |
| 45 days or older | `Stale` |

The dashboard embeds the generated epoch value and recalculates age in the browser with `Date.now()`. The no-JavaScript fallback still shows generated time and render-time age.

## CLI / Source Check Behavior

| Mode | Fresh signed feed | 14 days or older | 45 days or older |
| --- | --- | --- | --- |
| Normal runtime | Can evaluate. | Warns. | Warns. |
| Strict production | Can evaluate. | Warns. | Returns `CHECK_INCOMPLETE`. |
| `--check-public-pages` | Passes. | Fails freshness threshold. | Fails strict stale threshold. |

## Verify

```powershell
pytest -q tests/test_pages_landing*.py tests/test_policy_source_cli*.py tests/test_runtime_policy_sources*.py
python -m win11_release_guard --check-public-pages
```

## Related Pages

[Home](Home) | [GitHub Pages Dashboard](GitHub-Pages-Dashboard) | [Troubleshooting](Troubleshooting)
