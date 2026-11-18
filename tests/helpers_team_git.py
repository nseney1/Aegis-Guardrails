"""Shared capability-gated Git stores and independent custody repository copies."""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace

import pytest

from aegis_core import gitsafe_run, team, team_git, team_gitops, team_qualify

IDENTITY = team_git.CommitIdentity("Lane", "lane@example.com", "1700000000 +0000")
LANE_MODULES = frozenset({"aegis_core/team_git.py", "aegis_core/team_git_snapshot.py"})

__all__ = [
    "IDENTITY", "LANE_MODULES", "commit", "copied_rig", "filter_git_env", "git",
    "make_store", "new_store", "rig_template", "shared_bytes", "state",
    "strict_program", "strict_program_guard",
]


def strict_program_guard(*, optional=False, native_fixture=False):
    """One capability check, exposed as a fixture and for conditional helper setup."""
    supported = gitsafe_run._program_supported()
    reason = "strict runner requires descriptor-bound native executable support"
    if supported and native_fixture and shutil.which("cc") is None:
        supported = False
        reason = "native strict-effect fixture needs an installed C compiler"
    if not supported and not optional:
        pytest.skip(reason)
    return supported


@pytest.fixture
def strict_program():
    return strict_program_guard()


def filter_git_env(home):
    return {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "XDG_CONFIG_HOME": str(home / ".config"), "LC_ALL": "C"}


def git(repo, *args, data=None, env=None):
    if env is None:
        env = filter_git_env(Path(os.environ.get("HOME", os.path.expanduser("~"))))
    return subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
         "-c", "commit.gpgsign=false", *args], cwd=str(repo), input=data,
        capture_output=True, check=True, env=env).stdout


def commit(repo, name, content, *, env=None):
    (repo / name).write_bytes(content)
    git(repo, "add", "--", name, env=env)
    git(repo, "commit", "-qm", "change " + name, env=env)
    return git(repo, "rev-parse", "HEAD", env=env).decode().strip()


def make_store(repo):
    if not team_git.descriptor_support():
        pytest.skip("snapshot requires descriptor-relative no-follow opens and bound executables")
    strict_program_guard()
    return new_store(repo)


@contextmanager
def new_store(repo, *, require_program=True):
    # Custody service provisions scratch; tests own its creation and cleanup.
    # Refusal-only entries opt out so their checks still run before lookup.
    if require_program:
        strict_program_guard()
    with tempfile.TemporaryDirectory(dir=repo.parent) as directory:
        scratch = Path(directory)
        (scratch / "objects").mkdir(mode=0o700)
        with team_git.GitStore(repo, scratch) as store:
            yield store


def shared_bytes(repo):
    root = repo / ".git"
    return {str(p.relative_to(root)): p.read_bytes()
            for p in root.rglob("*") if p.is_file()}


@pytest.fixture(scope="module")
def rig_template(tmp_path_factory):
    """Build once per worker; tests only receive independent copies of these bytes."""
    if shutil.which("git") is None:
        pytest.skip("needs git")
    repo = tmp_path_factory.mktemp("custody-template") / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "lane/work")
    context = make_store(repo)  # Capability guard before descriptor-only work.
    if not team_qualify.descriptor_supported():
        pytest.skip("qualification requires descriptor custody")
    (repo / "src").mkdir()
    head = commit(repo, "src/a.py", b"base\n")
    lease = team.claim(repo, "work", ["/src/**", "/shared.txt"], owner="team-1",
                       branch="lane/work", now=100, ttl_s=60)
    (repo / "src/a.py").write_bytes(b"tested\n")
    with context as store:
        tree = team_git.snapshot_tree(store)
        journal = team_gitops.GitOpsJournal(repo / ".git")
        item = team_qualify.QualificationResult(tree, "unit", head, "run-1", True)
        team_qualify.record_pass(store, item, expected=None, identity=IDENTITY,
                                journal=journal, lane="work", request_id="pass-1", actor="custodian")
    # PASS publication includes the snapshot objects; no builder scratch survives.
    template = SimpleNamespace(repo=repo, head=head, tree=tree, lease=lease)
    template.baseline = state(template)
    yield template
    assert state(template) == template.baseline


@contextmanager
def copied_rig(template, directory):
    repo = directory / "repo"
    shutil.copytree(template.repo, repo)
    assert state(SimpleNamespace(repo=repo)) == template.baseline
    policy = team.parse_team(json.dumps({"v": 1, "shared": ["shared.txt"],
                                       "lanes": {"work": ["src/**"]}}).encode())
    with make_store(repo) as store:
        def paths(old, new):
            # Trusted adapter sees the private object directory. No repository history needed.
            return tuple(p.decode() for p in git(repo, "diff-tree", "-r", "--no-renames",
                                                "--name-only", "-z", old, new,
                                                env=store.env).split(b"\0") if p)
        options = dict(lane="work", owner="team-1", expected_head=template.head, tested_tree=template.tree,
                       required_legs=("unit",), message="Implement work\n\nDetails.\n", now=101,
                       read_branch=lambda: git(repo, "symbolic-ref", "--short", "HEAD").decode().strip(),
                       read_head=lambda: git(repo, "rev-parse", "HEAD").decode().strip(),
                       read_paths=paths, read_policy=lambda: policy)
        yield SimpleNamespace(repo=repo, store=store, options=options, lease=template.lease, policy=policy)


def state(rig):
    return (shared_bytes(rig.repo), {
        p.relative_to(rig.repo).as_posix(): ("link", str(p.readlink())) if p.is_symlink() else
        ("file", p.read_bytes()) if p.is_file() else ("directory",)
        for p in rig.repo.rglob("*") if ".git" not in p.parts})

