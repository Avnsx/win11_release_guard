"""Static Pages assets (HTML, CSS, JavaScript) and the small renderer that fills them.

Assets live in ``assets/`` next to this module and ship as package data. ``{{name}}`` is replaced by
the keyword value ``name``; ``{{> other.css}}`` is replaced by the rendered asset ``other.css``.
Rendering is strict: a placeholder without a value, or a value no placeholder uses, raises. Values
are inserted verbatim and never scanned for placeholders, so page content cannot inject one. An asset
file's single trailing newline is not part of its content, so editors that add one change nothing.
"""

from __future__ import annotations

import re
from functools import lru_cache
from importlib import resources

_PLACEHOLDER = re.compile(r"\{\{(> )?([A-Za-z0-9_.-]+)\}\}")


def _asset_root():
    return resources.files(__package__).joinpath("assets")


@lru_cache(maxsize=None)
def asset_text(name: str) -> str:
    """Return the content of ``assets/<name>`` without its trailing newline."""
    text = _asset_root().joinpath(name).read_text(encoding="utf-8")
    return text[:-1] if text.endswith("\n") else text


def render_asset(name: str, **values: str) -> str:
    """Render ``assets/<name>``, filling ``{{placeholders}}`` and ``{{> includes}}``."""
    used: set[str] = set()

    def expand(asset: str) -> str:
        def replace(match: re.Match[str]) -> str:
            if match.group(1):
                return expand(match.group(2))
            key = match.group(2)
            if key not in values:
                raise KeyError(f"assets/{asset}: no value for placeholder {{{{{key}}}}}")
            used.add(key)
            return values[key]

        return _PLACEHOLDER.sub(replace, asset_text(asset))

    rendered = expand(name)
    unused = sorted(set(values) - used)
    if unused:
        raise ValueError(f"assets/{name}: values never used by a placeholder: {unused}")
    return rendered
