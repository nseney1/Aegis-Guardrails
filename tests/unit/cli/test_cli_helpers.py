"""CLI helpers preserve display, terminal and installed-import behavior."""
import os
from pathlib import Path
import shlex
from types import SimpleNamespace

import pytest

import aegis_cli
from aegis_cli import approve, doctor, init, init_views, install_hosts
from aegis_cli.hooks import commitmsg, management
from aegis_core import primitives


def test_uncut_display_converts_objects_and_strips_escapes():
    assert aegis_cli.sanitize_display("x" * 5000 + "\x1b[31m", max_len=None) == "x" * 5000
    assert aegis_cli.sanitize_display("abcdef", max_len=3) == "..."
    assert aegis_cli.sanitize_display(ValueError("e\x1b[2Jv"), max_len=None) == "ev"


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


@pytest.mark.parametrize("error", [ValueError, OSError, AttributeError])
def test_broken_or_missing_stdin_is_not_a_tty(monkeypatch, error):
    def broken():
        raise error("closed")
    monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=broken) if error is not AttributeError else object())
    assert aegis_cli.stdin_is_tty() is False
    assert approve._stdin_is_tty() is False and doctor._stdin_is_tty() is False


def test_shared_import_root_is_installed_location_and_hook_default():
    root = aegis_cli.aegis_import_root()
    assert primitives.aegis_import_root() == root
    assert (Path(root) / "aegis_core").is_dir() and (Path(root) / "aegis_cli").is_dir()
    assert install_hosts.mcp_command(path="", scripts_dirs=[])[-1] == root
    shown = root.replace("\\", "/") if os.name == "nt" else root
    for script in (management.generate_hook_block(), commitmsg.generate_script()):
        assert "AEGIS_PATH=" + shlex.quote(shown) in script
    assert init.SCAFFOLD_LABEL is init_views.SCAFFOLD_LABEL
