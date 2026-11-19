"""Server state is per process; every test here starts from a fresh connection."""
from __future__ import annotations

import pytest

import aegis_mcp.server as server


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
def fresh_server(monkeypatch, stub_hardening):
    for name, value in server.fresh_state().items():
        monkeypatch.setattr(server, name, value)
    # Host-attested environment must come only from what a test sets.
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    server._tool_call_times.clear()
    yield
    server._tool_call_times.clear()
