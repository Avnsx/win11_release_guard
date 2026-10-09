# Anti-Static Freshness

How the runtime and the Pages dashboard avoid treating an old static feed as current production evidence.

Related links: [maintainer guide](maintainer-guide.md) | [wiki freshness](../wiki/Anti-Static-Freshness.md) | [dashboard docs](dashboard-and-pages.md)

## Fields

| Field | Meaning |
| --- | --- |
| `generated_at_epoch_s` | Signed/generated feed timestamp in Unix seconds. |
| `generated_at_utc` | Human-readable UTC timestamp. |
| `warn_after_epoch_s` | 14-day maintenance threshold. |
| `stale_after_epoch_s` / `strict_stale_after_epoch_s` | 45-day production-stale threshold. |
| `freshness_policy.warning_after_days` | Current warning age: `14`. |
| `freshness_policy.strict_stale_after_days` | Current strict stale age: `45`. |

## Runtime Behavior

| Mode | 14 days or older | 45 days or older |
| --- | --- | --- |
| Normal | Warning, verdict can still reflect signed policy. | Warning, verdict can still reflect signed policy. |
| Strict production | Warning. | `CHECK_INCOMPLETE`; candidate status remains visible. |
| Public Pages check | Fails freshness gate. | Fails strict stale gate. |

## Dashboard Behavior

The generated dashboard embeds freshness JSON and recalculates age in the browser using `Date.now()`. The static render also includes a no-JavaScript fallback so the page still explains its last generated timestamp.

## Verify

```powershell
pytest -q tests/test_pages_landing*.py tests/test_policy_source_cli*.py tests/test_runtime_policy_sources*.py
python -m win11_release_guard --check-public-pages
```
