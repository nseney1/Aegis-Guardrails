"""Hermetic defaults for every CLI unit test.

`aegis init` and `aegis uninstall` write the user plane (``~/.aegis/workspaces.json``,
host MCP configs) and call host CLIs (``codex``, ``claude``). The developer's real home
and the agent hosts installed on the machine must never be touched by a test, so every
test here gets an empty HOME (USERPROFILE on Windows) and a host-CLI runner that fails
loudly. A test that exercises registration installs its own fake runner.
"""
from __future__ import annotations

import os

import pytest

from tests.conftest import symlink_or_skip  # noqa: F401


@pytest.fixture(autouse=True)
def _isolated_user_plane(tmp_path_factory, monkeypatch):
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture(autouse=True)
def _nothing_above_the_test_tree(tmp_path_factory, monkeypatch):
    """Doctor looks for CLAUDE.md-family files in every directory above the workspace.
    Above pytest's base temp directory is the developer's machine (on Windows it sits
    under %USERPROFILE%, next to a real .claude/CLAUDE.md), so doctor finds nothing there.
    Tests that need such a file put it under their own tmp_path."""
    from aegis_cli import doctor_base

    base = os.path.normcase(os.path.realpath(str(tmp_path_factory.getbasetemp())))
    real = doctor_base._present

    def present(path):
        key = os.path.normcase(os.path.realpath(str(path)))
        return real(path) if key.startswith(base + os.sep) else False

    monkeypatch.setattr(doctor_base, "_present", present)


@pytest.fixture(autouse=True)
def _no_real_host_cli(monkeypatch):
    import aegis_cli.install_hosts as install_hosts

    def refuse(argv):
        raise AssertionError(f"a test tried to run a real host CLI: {argv!r}")

    monkeypatch.setattr(install_hosts, "_run_cli", refuse)


@pytest.fixture(autouse=True)
def _no_real_desktop_apps(monkeypatch):
    """Host detection also looks for desktop apps in machine-wide folders (/Applications,
    %LOCALAPPDATA%\\Programs). Those hold the developer's real apps, so no test sees them;
    a test that exercises app detection points ``hosts.APP_DIRS`` at its own tmp_path."""
    from aegis_core import hosts

    monkeypatch.setattr(hosts, "APP_DIRS", {})
