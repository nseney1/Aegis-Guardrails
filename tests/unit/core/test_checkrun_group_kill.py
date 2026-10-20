"""The Windows fallback of ``checkrun.kill_group`` and what the documentation says about it (R-trust-27).

Windows has no process groups to signal; ``taskkill /T`` needs the root alive, so the post-exit
sweep is POSIX-only, and ``taskkill`` itself is named by absolute path so no directory on ``PATH``
can substitute it.
"""
from __future__ import annotations

import ctypes  # noqa: F401  # imported before os.name is patched, as ctypes reads it at import
import os
from pathlib import Path
import subprocess

import pytest

from aegis_core import checkrun

ROOT = Path(__file__).resolve().parents[3]


class _Proc:
    def __init__(self, polled):
        self.pid = 4242
        self._polled = polled

    def poll(self):
        return self._polled


@pytest.fixture
def calls(monkeypatch):
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: seen.append(list(argv)))
    monkeypatch.setattr(os, "name", "nt")
    return seen


def test_a_live_run_is_killed_with_the_absolute_taskkill(monkeypatch, calls):
    monkeypatch.setenv("SystemRoot", "D:\\Win")
    checkrun.kill_group(_Proc(None))
    assert calls == [["D:\\Win\\System32\\taskkill.exe", "/T", "/F", "/PID", "4242"]]


@pytest.mark.parametrize("root", ["", "relative\\dir", "..\\Windows"])
def test_a_relative_or_empty_systemroot_falls_back_to_c_windows(monkeypatch, calls, root):
    monkeypatch.setenv("SystemRoot", root)
    checkrun.kill_group(_Proc(None))
    assert calls == [["C:\\Windows\\System32\\taskkill.exe", "/T", "/F", "/PID", "4242"]]


def test_an_exited_run_is_never_signalled(monkeypatch, calls):
    monkeypatch.setenv("SystemRoot", "D:\\Win")
    checkrun.kill_group(_Proc(0))
    assert calls == []


def test_the_docs_say_the_post_exit_sweep_is_posix_only():
    sentence = "descendants a test run leaves behind after a normal exit are not swept"
    assert sentence in " ".join((checkrun.__doc__ or "").split())
    assert sentence in (ROOT / "SECURITY.md").read_text(encoding="utf-8")
