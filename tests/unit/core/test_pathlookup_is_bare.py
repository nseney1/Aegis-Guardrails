"""Program lookup never interprets a directory component or a Windows drive."""
import os

import pytest

from aegis_core import pathlookup


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for key in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for key in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(key, raising=False)


@pytest.mark.parametrize("name,posix,windows", [
    ("prog", True, True), ("a/b", False, False), ("a\\b", True, False),
    ("D:prog", True, False), ("..\\x", True, False),
])
def test_bare_name_rules_do_not_depend_on_test_platform(name, posix, windows):
    assert pathlookup.is_bare(name, windows=False) is posix
    assert pathlookup.is_bare(name, windows=True) is windows


def test_non_bare_name_never_searches_path_entries(tmp_path, monkeypatch):
    def unexpected(*args):
        pytest.fail("a non-bare name reached PATH")
    monkeypatch.setattr(pathlookup, "_programs", unexpected)
    assert pathlookup.which("sub/prog", str(tmp_path)) is None
    assert pathlookup.only_skipped("sub/prog", "", base=tmp_path) == []


@pytest.mark.skipif(os.name != "nt", reason="drive-relative names are Windows paths")
def test_drive_relative_lookup_is_refused(tmp_path):
    assert pathlookup.which("D:prog", str(tmp_path / "absent")) is None
    assert pathlookup.only_skipped("D:prog", "", base=tmp_path) == []
