"""Shared capability-gated homes, workspaces, and leases for writer-binding tests."""
from __future__ import annotations

from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from aegis_core import storage_confined, team, team_claims
from aegis_core import team_writer_binding as binding

__all__ = ["call_bind", "install_passwd_home", "lease", "make_home", "make_store",
           "prepare_passwd_home", "root_binding_case"]


@pytest.fixture(params=[
    pytest.param((spelling, walked, as_path, missing, config_uid),
                 id=f"{label}-{kind}-{edge}")
    for label, spelling, walked in (("slash", "/", "/"), ("dot", "/.", "/"),
                                    ("dot-slash", "/./", "/"), ("triple", "///", "/"),
                                    ("double", "//", "//"))
    for kind, as_path in (("text", False), ("path", True))
    for edge, missing, config_uid in (("missing-config", ".config", None),
                                      ("caller-config", "aegis", 1001), ("root-config", "aegis", 0))
])
def root_binding_case(request, tmp_path, monkeypatch):
    """Supply root and config facts through descriptors backed by a disposable directory."""
    if not storage_confined.descriptor_supported():
        pytest.skip("requires descriptor-relative no-follow storage")
    spelling, walked, as_path, missing, config_uid = request.param
    home = Path(spelling) if as_path else spelling
    caller_uid = 1001
    home_fact = (1, 2, 0, stat.S_IFDIR | 0o755)
    config_fact = (1, 3, config_uid, stat.S_IFDIR | 0o755)
    paths, children, descriptors = [], [], []

    @contextmanager
    def open_home(_opener, path, **_kwargs):
        paths.append(path)
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            descriptors.append(fd)
            yield SimpleNamespace(fd=fd, observations=(home_fact,))
        finally:
            os.close(fd)

    def open_child(parent, name):
        children.append(name)
        if name == missing:
            raise FileNotFoundError(name)
        assert name == ".config"
        fd = os.dup(parent)
        descriptors.append(fd)
        return fd, config_fact

    def assert_walk_closed():
        assert paths == [Path(walked)]
        names = [".config"] if missing == ".config" else [".config", "aegis"]
        assert children == names
        assert len(descriptors) == len(names)
        for fd in descriptors:
            with pytest.raises(OSError) as error:
                os.fstat(fd)
            assert error.value.errno == errno.EBADF

    monkeypatch.setattr(binding, "_current_uid", lambda: caller_uid)
    monkeypatch.setattr(binding, "open_directory", open_home)
    monkeypatch.setattr(binding, "_open_config_child", open_child)
    allows_absence = walked == "/" and config_uid in (None, caller_uid)
    return home, allows_absence, assert_walk_closed


def prepare_passwd_home(path):
    """Create one mode-0700 home directory. Callers install it explicitly."""
    path.mkdir()
    if os.name == "posix":
        os.chmod(path, 0o700)
    return path


def install_passwd_home(home):
    """Point this process at ``home`` and return a restorer. Does not touch the environment."""
    previous = team_claims._passwd_home
    spelling = os.fspath(home)

    def current():
        return spelling

    team_claims._passwd_home = current

    def restore():
        team_claims._passwd_home = previous

    return restore


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
