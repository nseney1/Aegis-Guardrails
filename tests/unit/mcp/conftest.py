"""Fresh server state and a dumpability guard for every test in tests/unit/mcp.

On Linux, before/after snapshots cover every route that changes the shared
worker's dumpable flag, regardless of libc loader name. They compare test-boundary
values: PR_SET_DUMPABLE -> 0 is harden_process's only hardening effect today, and
any future hardening effect must extend this guard. Fresh-child hardening does
not change the monitored worker. Off Linux the guard is a no-op.
"""
from __future__ import annotations

import ctypes
import sys

import pytest

import aegis_mcp.server as server


def dumpability_reader():
    if not sys.platform.startswith("linux"):
        return None
    try:
        # Capture the native reader before tests can replace any loader name.
        prctl = ctypes.CDLL(None, use_errno=True).prctl
    except (OSError, AttributeError):
        pytest.fail("Linux dumpability probe is unavailable", pytrace=False)

    def read():
        value = prctl(3, 0, 0, 0, 0)  # PR_GET_DUMPABLE
        if value < 0:
            pytest.fail("cannot read shared-worker dumpability", pytrace=False)
        return value

    return read


@pytest.fixture(autouse=True, scope="function")
def worker_dumpability_guard(request):
    reader = dumpability_reader()
    if reader is None:
        yield
        return
    before = reader()
    try:
        yield
    finally:
        after = reader()
        if after != before:
            pytest.fail(
                f"{request.node.nodeid}: shared-worker dumpability changed: {before} -> {after}",
                pytrace=False,
            )


@pytest.fixture
def stub_hardening(monkeypatch):
    """Always stub worker hardening; return the implementation for fake-libc tests.

    Real kernel hardening belongs only in a fresh subprocess. Tests requesting
    this fixture may call its value after installing a simulated libc boundary
    or selecting the non-Linux no-op path.
    """
    real_harden_process = server.harden_process
    monkeypatch.setattr(server, "harden_process", lambda: False)
    return real_harden_process


@pytest.fixture(autouse=True)
def fresh_server(worker_dumpability_guard, monkeypatch, stub_hardening):
    for name, value in server.fresh_state().items():
        monkeypatch.setattr(server, name, value)
    # Host-attested environment must come only from what a test sets.
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    server._tool_call_times.clear()
    yield
    server._tool_call_times.clear()
