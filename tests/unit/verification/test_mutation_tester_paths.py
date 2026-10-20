"""What bounds a mutation run's pytest: its rootdir/confcutdir and the sys.path it inherits (R-checks-59).

Pure path logic on tmp paths, so it runs on every OS; the temp root is tmp_path/"tmp" through
a patched tempfile.gettempdir, with a pyproject.toml above it the walk must never reach.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
from unittest.mock import patch

import pytest

from aegis_core.verification import mutation_tester
from tests.helpers_popen import install_fake_popen


@pytest.fixture
def temp_root(tmp_path, monkeypatch) -> Path:
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    root = tmp_path / "tmp"
    root.mkdir()
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(root))
    return root


def _file(path: Path, text: str = "def test_ok():\n    assert True\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _same(a: object, b: Path) -> bool:
    return a is not None and os.path.samefile(str(a), str(b))


def test_a_config_marker_wins_over_a_nearer_conftest(temp_root):
    _file(temp_root / "proj" / "setup.cfg", "")
    _file(temp_root / "proj" / "tests" / "conftest.py", "")
    test = _file(temp_root / "proj" / "tests" / "unit" / "test_a.py")
    assert _same(mutation_tester._resolve_test_rootdir([str(test)]), temp_root / "proj")


def test_without_a_marker_the_nearest_conftest_directory_is_the_root(temp_root):
    _file(temp_root / "proj" / "conftest.py", "")
    _file(temp_root / "proj" / "tests" / "conftest.py", "")
    test = _file(temp_root / "proj" / "tests" / "unit" / "test_a.py")
    assert _same(mutation_tester._resolve_test_rootdir([str(test)]), temp_root / "proj" / "tests")


def test_with_neither_the_common_test_directory_is_the_root_and_the_walk_stops_at_the_temp_root(temp_root):
    one = _file(temp_root / "proj" / "tests" / "a" / "test_a.py")
    two = _file(temp_root / "proj" / "tests" / "b" / "test_b.py")
    assert _same(mutation_tester._resolve_test_rootdir([str(one), str(two)]), temp_root / "proj" / "tests")


def test_a_missing_test_file_has_no_root(temp_root):
    assert mutation_tester._resolve_test_rootdir([str(temp_root / "nowhere" / "test_x.py"), ""]) is None


def test_a_temp_path_entry_is_dropped_unless_it_holds_a_test_file(temp_root, tmp_path):
    test = _file(temp_root / "proj" / "tests" / "test_a.py")
    holder = temp_root / "proj"
    stray = temp_root / "other"
    stray.mkdir()
    outside = tmp_path / "site"
    outside.mkdir()
    missing = tmp_path / "gone"
    entries = ["", str(stray), str(holder), str(outside), str(missing)]
    assert mutation_tester._filter_sys_path(entries, [str(test)], str(temp_root)) == [str(holder), str(outside)]


def test_with_no_test_file_every_temp_entry_is_dropped(temp_root, tmp_path):
    inside = temp_root / "proj"
    inside.mkdir()
    assert mutation_tester._filter_sys_path([str(inside), str(tmp_path)], [], str(temp_root)) == [str(tmp_path)]


@pytest.mark.parametrize("exists", [True, False], ids=["root", "no-root"])
def test_the_pytest_command_is_bounded_only_when_a_root_is_found(temp_root, monkeypatch, exists):
    _file(temp_root / "proj" / "pyproject.toml", "")
    test = temp_root / "proj" / "tests" / "test_a.py"
    if exists:
        _file(test)
    spawns = install_fake_popen(monkeypatch)
    with patch("aegis_core.verification.test_runner.resolve_pytest_cmd", return_value=["pytest"]):
        mutation_tester._check_tests([str(test)], timeout=60)
    (spawn,) = spawns
    bounds = [a for a in spawn["args"] if a.startswith(("--rootdir=", "--confcutdir="))]
    if exists:
        assert [a.split("=", 1)[0] for a in bounds] == ["--rootdir", "--confcutdir"]
        assert all(_same(a.split("=", 1)[1], temp_root / "proj") for a in bounds)
    else:
        assert bounds == []
