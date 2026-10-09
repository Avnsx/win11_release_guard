# Safe Exports And Clean Archives

Use this when sharing source outside the repository or attaching release artifacts.

---

## Why This Exists

Raw worktree ZIPs can include `.git/`, `.tmp/`, generated Pages output, caches, build output, local notes, and private key scratch files. The project uses a curated export script instead.

## Clean Archive Command

```powershell
python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip
python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip
```

## Included / Excluded

| Included | Excluded |
| --- | --- |
| `win11_release_guard/` | `.git/` |
| `tests/` | `.tmp/` |
| `tools/` | `site/` |
| `docs/` | `dist/` except selected output target |
| `README.md`, `AGENTS.md`, `pyproject.toml` | caches, pycache, build output |
| `LICENSE.txt` | private key files, local notes |
| `.github/` automation files | private key files, local notes |

## License Mapping

`LICENSE.txt` is the repository MIT license file and is part of the curated clean source archive. Keep this mapping aligned with `pyproject.toml`, `tools/export_clean_archive.py`, and `tests/test_export_clean_archive.py`.

## Do / Do Not

| Do | Do not |
| --- | --- |
| Validate the archive before release. | Share raw local ZIPs. |
| Keep signed bundled public policy artifacts. | Include private signing material. |
| Keep `LICENSE.txt` with released source archives. | Replace the MIT text with a vague license note. |
| Run identity and secret scans. | Ignore stale identity findings. |

## Verify

```powershell
python tools/export_clean_archive.py --output dist/win11_release_guard-source.zip
python tools/export_clean_archive.py --validate dist/win11_release_guard-source.zip
python tools/scan_for_secret_material.py site win11_release_guard tests tools docs wiki README.md CHANGELOG.md AGENTS.md pyproject.toml .github
```

## Related Pages

[Home](Home) | [Tagged Release Lane](Tagged-Release-Lane) | [Regression Chokepoints](Regression-Chokepoints)
