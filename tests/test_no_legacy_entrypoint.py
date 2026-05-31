from __future__ import annotations

import importlib
from pathlib import Path

from win11_release_guard import __main__ as cli


def test_removed_root_entrypoint_is_not_present() -> None:
    legacy_name = "_".join(("windows", "releases", "info")) + ".py"
    assert not (Path(__file__).resolve().parents[1] / legacy_name).exists()


def test_package_import_works() -> None:
    module = importlib.import_module("win11_release_guard")
    assert hasattr(module, "check_current_system")


def test_cli_help_recommends_module_entrypoint(capsys) -> None:
    code = cli.main(["--help"])
    captured = capsys.readouterr()

    assert code == 0
    assert "python -m win11_release_guard" in captured.out
