"""Shared capability-gated homes, workspaces, and leases for writer-binding tests."""
from __future__ import annotations

import json
import os

import pytest

from aegis_core import storage_confined, team
from aegis_core import team_writer_binding as binding

__all__ = ["call_bind", "lease", "make_home", "make_store"]


def make_store(tmp_path):
    if not storage_confined.descriptor_supported():
        pytest.skip("requires descriptor-relative no-follow storage")
    root = tmp_path.resolve() / "workspace"
    (root / ".aegis").mkdir(parents=True)
    os.chmod(root, 0o700)
    return root


def make_home(tmp_path):
    if not storage_confined.descriptor_supported():
        pytest.skip("requires descriptor-relative no-follow storage")
    home = tmp_path.resolve() / "zzmarker-home"
    config = home / ".config" / "aegis"
    config.mkdir(parents=True)
    for path in (home, home / ".config", config):
        os.chmod(path, 0o700)
    return home


def lease(lane="writer", gen=1, claim=None, ts=50, ttl=100):
    claim_id = "a" * 16 if claim is None else claim
    raw = json.dumps({
        "v": 1, "lane": lane, "role": "implementer", "owner": "owner", "claim_id": claim_id,
        "gen": gen, "branch": "lane/writer", "paths": ["docs/**"], "ts": ts, "ttl_s": ttl,
    }).encode()
    return team.parse_lease(raw, lane, "b" * 40)


def call_bind(home, workspace, lane="writer", pid=None):
    return binding.bind(str(home), str(workspace), lane, os.getpid() if pid is None else pid)
