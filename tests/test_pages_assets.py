from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

import pytest

from win11_release_guard.policy_generator.pages import assets


@pytest.fixture
def asset_dir(tmp_path, monkeypatch):
    folder = tmp_path / "assets"
    folder.mkdir()
    monkeypatch.setattr(assets, "_asset_root", lambda: folder)
    assets.asset_text.cache_clear()
    yield folder
    assets.asset_text.cache_clear()


def test_render_fills_placeholders_and_includes(asset_dir) -> None:
    (asset_dir / "page.html").write_text("<style>{{> page.css}}</style><h1>{{title}}</h1>\n", encoding="utf-8")
    (asset_dir / "page.css").write_text("h1{color:{{colour}}}\n", encoding="utf-8")

    assert assets.render_asset("page.html", title="Hi", colour="red") == "<style>h1{color:red}</style><h1>Hi</h1>"


def test_render_rejects_a_missing_value(asset_dir) -> None:
    (asset_dir / "page.html").write_text("{{title}}", encoding="utf-8")

    with pytest.raises(KeyError, match="title"):
        assets.render_asset("page.html")


def test_render_rejects_an_unused_value(asset_dir) -> None:
    (asset_dir / "page.html").write_text("static", encoding="utf-8")

    with pytest.raises(ValueError, match="title"):
        assets.render_asset("page.html", title="x")


def test_inserted_values_are_never_expanded(asset_dir) -> None:
    (asset_dir / "page.html").write_text("{{title}}", encoding="utf-8")

    assert assets.render_asset("page.html", title="{{title}}") == "{{title}}"


def test_one_trailing_newline_is_not_content(asset_dir) -> None:
    (asset_dir / "a.html").write_text("x\n", encoding="utf-8")
    (asset_dir / "b.html").write_text("x\n\n", encoding="utf-8")

    assert assets.render_asset("a.html") == "x"
    assert assets.render_asset("b.html") == "x\n"


def test_every_page_asset_ships_as_package_data() -> None:
    pages = Path(assets.__file__).parent
    line = next(
        line for line in Path("pyproject.toml").read_text(encoding="utf-8").splitlines()
        if line.startswith('"win11_release_guard.policy_generator.pages" = ')
    )
    globs = [PurePosixPath(glob) for glob in re.findall(r'"([^"]+)"', line.split("=", 1)[1])]
    files = [PurePosixPath(path.relative_to(pages).as_posix()) for path in (pages / "assets").rglob("*") if path.is_file()]

    assert files
    unshipped = [str(f) for f in files if not any(len(f.parts) == len(g.parts) and f.match(str(g)) for g in globs)]
    assert unshipped == [], f"add a package-data glob in pyproject.toml for {unshipped}"
