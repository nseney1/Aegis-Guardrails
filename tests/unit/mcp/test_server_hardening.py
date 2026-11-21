"""The MCP server marks itself non-dumpable on Linux (v4.3 T1 hardening): same-uid siblings
cannot read its memory or inject through /proc/<pid>/fd, whatever Yama says."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from aegis_mcp import server
from tests.unit.mcp import conftest as mcp_conftest

PR_GET_DUMPABLE = 3
REAL_HARDEN_PROCESS = server.harden_process
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="prctl is Linux")


@linux_only
def test_harden_process_clears_the_dumpable_flag_in_a_fresh_process():
    code = (
        "import ctypes\n"
        "from aegis_mcp import server\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        f"before = libc.prctl({PR_GET_DUMPABLE}, 0, 0, 0, 0)\n"
        "assert server.harden_process() is True\n"
        f"print(before, libc.prctl({PR_GET_DUMPABLE}, 0, 0, 0, 0))\n"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert done.stdout.split() == ["1", "0"]


def test_hardening_is_stubbed_even_in_a_hardening_module():
    # Check identity before calling so a broken policy cannot harden this worker.
    assert server.harden_process is not REAL_HARDEN_PROCESS
    assert server.harden_process() is False


def test_policy_survives_renaming_the_hardening_module(tmp_path):
    source = Path(__file__)
    renamed = tmp_path / "test_moved_hardening.py"
    renamed.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "conftest.py").write_text(
        source.with_name("conftest.py").read_text(encoding="utf-8"), encoding="utf-8")
    nodes = [
        "test_hardening_is_stubbed_even_in_a_hardening_module",
        "test_harden_process_is_a_no_op_off_linux",
        "test_a_failing_prctl_never_stops_the_server",
        "test_a_missing_libc_never_stops_the_server",
    ]
    env = dict(os.environ, PYTHONPATH=str(source.resolve().parents[3]))
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *(f"{renamed}::{node}" for node in nodes)],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr


def test_harden_process_is_a_no_op_off_linux(monkeypatch, stub_hardening):
    calls = []

    def unexpected_libc(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("non-Linux hardening must not load libc")

    monkeypatch.setattr("ctypes.CDLL", unexpected_libc)
    monkeypatch.setattr(server, "sys", SimpleNamespace(platform="win32"))
    assert stub_hardening() is False
    assert calls == []


@pytest.mark.parametrize("attempts", [1, 2])
def test_a_failing_prctl_never_stops_the_server(monkeypatch, stub_hardening, attempts):
    calls = []

    class Broken:
        def prctl(self, *args):
            calls.append(args)
            return -1

    monkeypatch.setattr(server, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr("ctypes.CDLL", lambda *a, **k: Broken())
    for attempt in range(1, attempts + 1):
        assert stub_hardening() is False
        assert calls == [(4, 0, 0, 0, 0)] * attempt


@pytest.mark.parametrize("platform", ["linux", "win32"])
@pytest.mark.parametrize("attempts", [1, 2])
def test_a_missing_libc_never_stops_the_server(monkeypatch, stub_hardening, attempts, platform):
    calls = []

    def boom(*_a, **_k):
        calls.append((_a, _k))
        raise OSError("no libc")

    monkeypatch.setattr(server, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr("ctypes.CDLL", boom)
    for attempt in range(1, attempts + 1):
        assert stub_hardening() is False
        assert calls == ([((None,), {"use_errno": True})] * attempt if platform == "linux" else [])


def test_the_stdio_server_hardens_the_process_before_serving(monkeypatch):
    calls = []
    monkeypatch.setattr(server, "harden_process", lambda: calls.append("hardened") or True)
    monkeypatch.setattr(server, "sys", SimpleNamespace(**{**vars(sys), "stdin": iter(())}))
    assert server.run_stdio_server() == 0
    assert calls == ["hardened"]


@linux_only
@pytest.mark.skipif(
    os.environ.get("AEGIS_MCP_DUMPABILITY_PROBE_PID") != str(os.getpid()),
    reason="deliberate hardening runs only in a fresh subprocess",
)
def test_deliberate_worker_hardening_in_fresh_subprocess():
    import ctypes

    # Use the alternate loader route that bypasses the simulated CDLL seams.
    libc = ctypes.cdll.LoadLibrary(None)
    assert libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 1
    assert libc.prctl(4, 0, 0, 0, 0) == 0


@linux_only
def test_dumpability_guard_reports_alternate_libc_loader(tmp_path):
    source = Path(__file__).resolve()
    node = f"{source}::test_deliberate_worker_hardening_in_fresh_subprocess"
    code = (
        "import os, pytest\n"
        "os.environ['AEGIS_MCP_DUMPABILITY_PROBE_PID'] = str(os.getpid())\n"
        f"raise SystemExit(pytest.main([{node!r}, '-q', '-n', '0', "
        f"'--basetemp', {str(tmp_path / 'guard-child')!r}]))\n"
    )
    env = dict(os.environ, PYTHONPATH=str(source.parents[3]))
    done = subprocess.run([sys.executable, "-c", code], cwd=source.parents[3], env=env,
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "test_deliberate_worker_hardening_in_fresh_subprocess" in done.stdout
    assert "shared-worker dumpability changed: 1 -> 0" in done.stdout
    assert "1 passed, 1 error" in done.stdout


def test_dumpability_reader_is_a_no_op_off_linux(monkeypatch):
    calls = []

    def unexpected_libc(*args, **kwargs):
        calls.append((args, kwargs))
        pytest.fail("off-Linux dumpability probing must not load libc")

    monkeypatch.setattr(mcp_conftest, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(mcp_conftest, "ctypes", SimpleNamespace(CDLL=unexpected_libc))
    assert mcp_conftest.dumpability_reader() is None
    assert calls == []


@pytest.mark.parametrize("problem", ["loader", "symbol"])
def test_dumpability_reader_refuses_unavailable_probe(monkeypatch, problem):
    def unavailable(*args, **kwargs):
        if problem == "loader":
            raise OSError("HOSTILE_MARKER")
        return SimpleNamespace()

    monkeypatch.setattr(mcp_conftest, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(mcp_conftest, "ctypes", SimpleNamespace(CDLL=unavailable))
    with pytest.raises(pytest.fail.Exception, match="^Linux dumpability probe is unavailable$"):
        mcp_conftest.dumpability_reader()


def test_dumpability_reader_refuses_failed_query(monkeypatch):
    libc = SimpleNamespace(prctl=lambda *args: -1)
    monkeypatch.setattr(mcp_conftest, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(mcp_conftest, "ctypes", SimpleNamespace(CDLL=lambda *a, **k: libc))
    reader = mcp_conftest.dumpability_reader()
    with pytest.raises(pytest.fail.Exception, match="^cannot read shared-worker dumpability$"):
        reader()
