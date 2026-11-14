"""Doctor git and disk hygiene is a report: it never deletes, prunes, gc's or rewrites refs.

Approval trust tiers A, B and C are echoed. Git approval modes, signer presence, prune
expiry, prunable worktrees, leases, lane branches, disk budget and unreadable paths are
rows. Every row names an owner action. Warnings do not change doctor's exit code.
"""
from __future__ import annotations

import argparse
import ast
from contextlib import contextmanager
import errno
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import types

import pytest

from aegis_cli import doctor_git
from aegis_core import gitsafe, gitsafe_run, human_gate, primitives, team
from conftest import symlink_or_skip

REPO = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def acl_lookup_boundary(monkeypatch):
    def absent(fd, name):
        assert isinstance(fd, int)
        raise OSError(errno.ENODATA, "no extended ACL")

    monkeypatch.setattr(doctor_git, "os", types.SimpleNamespace(**{**vars(os), "getxattr": absent}))


def _codes(report):
    return [row["code"] for row in report["rows"]]


def _row(report, code):
    return next(row for row in report["rows"] if row["code"] == code)


def _blob(report):
    return json.dumps(report)


def _parse_team_action(owner_action):
    from aegis_cli.cli import _build_parser

    command = owner_action.split("(", 1)[0].strip()
    prefix = "owner action: "
    assert command.startswith(prefix)
    argv = command[len(prefix):].split()
    assert argv[:2] == ["aegis", "team"]
    parsed = _build_parser(prog="aegis").parse_args(argv[1:])
    assert parsed.command == "team"
    return parsed


def _assert_rows(report):
    assert report["schema"] == "aegis.doctor.git/v1"
    assert report["affects_exit"] is False
    assert report["exit_effect"] == "advisory"
    assert report["doctor_exit_effect"] == "unchanged"
    assert report["status"] in ("pass", "warn")
    for row in report["rows"]:
        assert row["status"] in ("pass", "warn")
        assert row["owner_action"].startswith("owner action:")
        assert "\n" not in row["detail"] and "\r" not in row["detail"]
        assert "\n" not in row["owner_action"] and "\r" not in row["owner_action"]


def _cp(args, out=b"", code=0):
    return types.SimpleNamespace(returncode=code, stdout=out, stderr=b"")


def _lease(lane, branch, ts, ttl):
    return team.Lease(
        lane=lane, role="implementer", owner="owner", claim_id="0123456789abcdef",
        gen=1, branch=branch, paths=("src/app.py",), ts=ts, ttl_s=ttl, oid="a" * 40,
    )


@contextmanager
def _scripted_hold(*args, **kwargs):
    yield types.SimpleNamespace()


def _quiet_tree(monkeypatch):
    monkeypatch.setattr(doctor_git, "_disk_usage", lambda path: types.SimpleNamespace(
        total=10 ** 15, used=1, free=doctor_git.RESERVE_BYTES + doctor_git.PEAK_BYTES * doctor_git.MAX_HEAVY))
    monkeypatch.setattr(doctor_git, "_scratch_choice", lambda: ("path", "/var/empty/aegis-scratch-outside"))
    monkeypatch.setattr(doctor_git, "_hold_scratch", lambda path: (-1, 1, 1))
    monkeypatch.setattr(doctor_git, "_scratch_ok", lambda root, fd, dev, ino: "/proc/self/fd/1")
    monkeypatch.setattr(doctor_git, "descriptor_support", lambda: True)
    monkeypatch.setattr(doctor_git, "_directory_identity", lambda root, parts: (1, 1))
    monkeypatch.setattr(doctor_git, "_scandir", lambda path: [])
    monkeypatch.setattr(doctor_git, "_confined", _scripted_hold)


def _install_git(monkeypatch, table, seams):
    def run(_root, args):
        return table[tuple(args)]

    monkeypatch.setattr(doctor_git, "_run_git", run)
    monkeypatch.setattr(doctor_git, "_head", seams["_head"])
    monkeypatch.setattr(doctor_git, "_policy", seams["_policy"])
    monkeypatch.setattr(doctor_git, "_signers", seams["_signers"])
    monkeypatch.setattr(doctor_git, "_leases", seams["_leases"])
    monkeypatch.setattr(doctor_git, "_refs", seams["_refs"])


def _clean_table(root):
    worktree = f"worktree {root}\0HEAD abc\0branch refs/heads/main\0\0".encode()
    return {
        ("rev-parse", "--is-inside-work-tree"): _cp(("rev-parse",), b"true\n"),
        ("rev-parse", "--abbrev-ref", "HEAD"): _cp(("rev-parse",), b"main\n"),
        ("config", "--get", "gc.worktreePruneExpire"): _cp(("config",), b"never\n"),
        ("worktree", "list", "--porcelain", "-z"): _cp(("worktree",), worktree),
        ("count-objects", "-v"): _cp(("count-objects",), b"count: 1\nsize: 1\nsize-pack: 0\n"),
    }


def _clean_seams():
    policy = {"main": "signature", "develop": "review", "release/**": "review", "*": "none"}
    return {
        "_head": lambda root: "a" * 40,
        "_policy": lambda root, commit: policy,
        "_signers": lambda root, commit: 2,
        "_leases": lambda root: team.LeaseSet((), ()),
        "_refs": lambda root, prefix: [],
    }


def test_display_refuses_multiline_before_join_then_redacts_then_truncates():
    shown, code = doctor_git.display("never\nevil")
    assert shown is None and code == "multiline_refused"
    token = "ghp_" + ("A" * 20)
    shown, code = doctor_git.display("\x1b[31m" + token + "\x1b[0m")
    assert code is None and token not in shown and "REDACTED" in shown
    shown, code = doctor_git.display("a" * (doctor_git.VALUE_MAX + 1))
    assert shown is None and code == "value_too_long"
    shown, code = doctor_git.display("b" * 200, max_len=16)
    assert code is None and shown.endswith("...") and len(shown) <= 16


def test_classify_git_failure_does_not_keep_the_message():
    secret = "/secret/hunter2path"
    assert doctor_git._classify_git(gitsafe.GitError(f"cannot run git: {secret}")) == "git_missing"
    assert doctor_git._classify_git(gitsafe.GitError("git is not installed or not on PATH")) == "git_missing"
    assert doctor_git._classify_git(gitsafe.GitError("git custody timed out", code="git_timeout")) == "git_timeout"
    assert doctor_git._classify_git(gitsafe.GitError("git custody output limit exceeded", code="git_output_limit")) == "git_output_limit"
    assert secret not in doctor_git._classify_git(gitsafe.GitError(f"cannot run git: {secret}"))


def test_parsers_bound_bytes_before_using_them():
    assert doctor_git._one_line(b"never\n") == ("never", None)
    assert doctor_git._one_line(b"never\nevil\n")[1] == "multiline_refused"
    assert doctor_git._one_line(b"n" * (doctor_git.VALUE_MAX + 1) + b"\n")[1] == "value_too_long"
    assert doctor_git._one_line(b"x" * (doctor_git.GIT_STDOUT_LIMIT + 1))[1] == "git_output_limit"
    over = b"worktree /tmp/a\0" * (doctor_git.MAX_WORKTREES + 5)
    assert doctor_git._parse_worktrees(over)[0] == "git_output_limit"
    prunable, paths, code = doctor_git._parse_worktrees(
        b"worktree /inside\0HEAD abc\0branch refs/heads/main\0\0"
        b"worktree /gone\0HEAD def\0prunable gone\0\0")
    assert code is None and prunable == 1 and paths == ["/inside", "/gone"]
    total, code = doctor_git._object_bytes(b"size: 2\nsize-pack: 3\n")
    assert code is None and total == 5 * 1024
    assert doctor_git._object_bytes(b"size: not-a-number\n")[1] == "git_failed"
    assert doctor_git._object_bytes(b"size: 1\n" * 80)[1] == "git_output_limit"


@pytest.mark.parametrize("tier", ["A", "B", "C"])
def test_matrix_clean_repo_is_advisory(tier, tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    _install_git(monkeypatch, _clean_table(tmp_path), _clean_seams())
    report = doctor_git.collect(tmp_path, tier=tier, now=10)
    _assert_rows(report)
    assert report["trust_tier"] == tier
    assert report["status"] == "pass"
    assert report["git"]["present"] is True
    assert report["git"]["worktree_prune_expire"] == "never"
    assert report["git"]["prunable_count"] == 0
    assert report["disk"]["budget_slots"] == doctor_git.MAX_HEAVY
    assert report["approval_modes"]["effective"] == "signature"
    assert "warn" not in {row["status"] for row in report["rows"]}
    assert _row(report, "trust_tier")["owner_action"] == "owner action: none"


@pytest.mark.parametrize("tier", ["A", "B", "C"])
def test_matrix_git_missing_stays_advisory(tier, tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    report = doctor_git.collect(tmp_path, tier=tier, now=10)
    _assert_rows(report)
    assert report["trust_tier"] == tier
    assert "git_missing" in _codes(report)
    assert report["git"]["present"] is False
    assert "invalid_approval_policy" not in _codes(report)
    blob = _blob(report)
    assert "cannot run git" not in blob


@pytest.mark.parametrize("tier", ["A", "B", "C"])
def test_matrix_stale_lane_branch_names_owner_delete(tier, tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    seams = _clean_seams()
    seams["_refs"] = lambda root, prefix: [("refs/heads/lane/old", "c" * 40)]
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier=tier, now=10)
    _assert_rows(report)
    row = _row(report, "stale_lane_branch")
    assert row["status"] == "warn"
    assert "does not delete" in row["owner_action"]
    assert report["affects_exit"] is False


@pytest.mark.parametrize("tier", ["A", "B", "C"])
def test_matrix_prunable_worktree_is_not_pruned(tier, tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    table = _clean_table(tmp_path)
    table[("worktree", "list", "--porcelain", "-z")] = _cp(
        ("worktree",),
        f"worktree {tmp_path}\0HEAD abc\0branch refs/heads/main\0\0".encode()
        + b"worktree /var/empty/gone\0HEAD def\0prunable gone\0\0")
    _install_git(monkeypatch, table, _clean_seams())
    report = doctor_git.collect(tmp_path, tier=tier, now=10)
    _assert_rows(report)
    assert report["git"]["prunable_count"] == 1
    assert "does not prune" in _row(report, "prunable_worktrees")["owner_action"]
    assert "outside_root" in _codes(report)
    assert "does not open" in _row(report, "outside_root")["owner_action"]
    assert report["affects_exit"] is False


@pytest.mark.parametrize("tier", ["A", "B", "C"])
@pytest.mark.parametrize("expired", [False, True])
def test_matrix_live_and_expired_leases(tier, expired, tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    lease = _lease("docs", "lane/docs", ts=1_000, ttl=50)
    seams = _clean_seams()
    seams["_leases"] = lambda root: team.LeaseSet((lease,), ())
    seams["_refs"] = lambda root, prefix: [("refs/heads/lane/docs", "d" * 40)]
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    now = lease.expires_at if expired else lease.ts
    report = doctor_git.collect(tmp_path, tier=tier, now=now)
    _assert_rows(report)
    if expired:
        row = _row(report, "expired_lease")
        assert "aegis team gc" in row["owner_action"]
        assert "lane done" not in row["owner_action"]
        assert "stale_lane_branch" not in _codes(report)
        _parse_team_action(row["owner_action"])
    else:
        assert "live_lease" in _codes(report)
        assert "stale_lane_branch" not in _codes(report)
        assert "expired_lease" not in _codes(report)
    assert report["affects_exit"] is False


@pytest.mark.parametrize("tier", ["A", "B", "C"])
def test_matrix_unreadable_lease_does_not_echo_the_error(tier, tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    secret = "password=hunter2hunter"
    bad = team.Unreadable("docs", "refs/aegis/lanes/docs", "b" * 40, secret)
    seams = _clean_seams()
    seams["_leases"] = lambda root: team.LeaseSet((), (bad,))
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier=tier, now=10)
    _assert_rows(report)
    assert "lease_unreadable" in _codes(report)
    assert secret not in _blob(report)
    parsed = _parse_team_action(_row(report, "lease_unreadable")["owner_action"])
    assert parsed.team_action == "release" and parsed.lane == "docs" and parsed.expect == "b" * 40
    assert "hunter2hunter" not in _blob(report)


@pytest.mark.parametrize("tier", ["A", "B", "C"])
def test_matrix_large_disk_consumer_and_disk_low_do_not_change_exit(tier, tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    monkeypatch.setattr(doctor_git, "LARGE_BYTES", 8)
    (tmp_path / "big.bin").write_bytes(b"password=hunter2hunter-body")
    monkeypatch.setattr(doctor_git, "_disk_usage", lambda path: types.SimpleNamespace(total=10, used=10, free=0))
    monkeypatch.setattr(doctor_git, "_directory_identity", lambda root, parts: (1, 1))
    monkeypatch.setattr(doctor_git, "_scandir", os.scandir)
    _install_git(monkeypatch, _clean_table(tmp_path), _clean_seams())
    report = doctor_git.collect(tmp_path, tier=tier, now=10)
    _assert_rows(report)
    assert "disk_low" in _codes(report)
    assert "large_path" in _codes(report)
    assert "hunter2hunter" not in _blob(report)
    assert report["disk"]["budget_slots"] == 0
    assert report["affects_exit"] is False


@pytest.mark.parametrize("tier", ["A", "B", "C"])
def test_matrix_unreadable_path_uses_a_fixed_code(tier, tmp_path, monkeypatch):
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("mode 000 is not a denial for this user")
    if not doctor_git.descriptor_support():
        pytest.skip("descriptor walk unsupported")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "note.txt").write_text("password=hunter2hunter\n", encoding="utf-8")
    os.chmod(locked, 0)
    real_identity, real_confined = doctor_git._directory_identity, doctor_git._confined
    try:
        _quiet_tree(monkeypatch)
        monkeypatch.setattr(doctor_git, "_directory_identity", real_identity)
        monkeypatch.setattr(doctor_git, "_scandir", os.scandir)
        monkeypatch.setattr(doctor_git, "_confined", real_confined)
        _install_git(monkeypatch, _clean_table(tmp_path), _clean_seams())
        report = doctor_git.collect(tmp_path, tier=tier, now=10)
    finally:
        os.chmod(locked, 0o700)
    _assert_rows(report)
    assert "unreadable_path" in _codes(report)
    assert "hunter2hunter" not in _blob(report)
    assert "Permission denied" not in _blob(report)
    assert report["trust_tier"] == tier


def test_no_approval_map_suggests_one_and_does_not_write(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    seams = _clean_seams()
    seams["_policy"] = lambda root, commit: None
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier="B", now=10)
    row = _row(report, "no_approval_map")
    assert row["status"] == "warn"
    assert "main" in row["owner_action"] and "signature" in row["owner_action"]
    assert "does not write" in row["owner_action"]
    assert report["approval_modes"] is None


def test_signature_mode_without_signers_warns_with_a_count_only(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    seams = _clean_seams()
    seams["_signers"] = lambda root, commit: 0
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    row = _row(report, "signers_absent")
    assert "allowed_signers" in row["owner_action"]
    assert "ssh-" not in _blob(report)


def test_malformed_and_unavailable_policy_are_fixed_codes(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    for code in ("invalid_approval_policy", "policy_unavailable"):
        seams = _clean_seams()
        seams["_policy"] = lambda root, commit, code=code: code
        _install_git(monkeypatch, _clean_table(tmp_path), seams)
        report = doctor_git.collect(tmp_path, tier="C", now=10)
        row = _row(report, code)
        assert "approvals" not in row["detail"]
        if code == "policy_unavailable":
            assert row["owner_action"] == doctor_git._RETRY
            assert "could not be read" in row["detail"]
        else:
            assert "commit" in row["owner_action"]


def test_unset_prune_expire_names_the_owner_config(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    table = _clean_table(tmp_path)
    table[("config", "--get", "gc.worktreePruneExpire")] = _cp(("config",), b"", 1)
    _install_git(monkeypatch, table, _clean_seams())
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    row = _row(report, "prune_expire_unset")
    assert "gc.worktreePruneExpire never" in row["owner_action"]
    assert "does not write" in row["owner_action"]


def test_multiline_prune_expire_is_refused_whole(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    table = _clean_table(tmp_path)
    table[("config", "--get", "gc.worktreePruneExpire")] = _cp(("config",), b"never\nevil\n")
    _install_git(monkeypatch, table, _clean_seams())
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "multiline_refused" in _codes(report)
    blob = _blob(report)
    assert "nevil" not in blob and "never evil" not in blob


def test_worktree_listing_over_the_cap_is_not_parsed(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    table = _clean_table(tmp_path)
    table[("worktree", "list", "--porcelain", "-z")] = _cp(("worktree",), b"z" * (doctor_git.GIT_STDOUT_LIMIT + 1))
    _install_git(monkeypatch, table, _clean_seams())
    report = doctor_git.collect(tmp_path, tier="B", now=10)
    assert "git_output_limit" in _codes(report)
    assert "zzzz" not in _blob(report)


def test_relative_and_multiline_scratch_are_refused(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    _install_git(monkeypatch, _clean_table(tmp_path), _clean_seams())
    monkeypatch.setattr(doctor_git, "_scratch_choice", lambda: ("code", "scratch_unusable"))
    report = doctor_git.collect(tmp_path, tier="C", now=10)
    assert "scratch_unusable" in _codes(report)
    monkeypatch.setattr(doctor_git, "_scratch_choice", lambda: ("code", "multiline_refused"))
    report = doctor_git.collect(tmp_path, tier="C", now=10)
    assert "multiline_refused" in _codes(report)
    assert "evil" not in _blob(report)


def test_scratch_choice_refuses_multiline_and_relative_values(monkeypatch):
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": "rel/scratch"})
    assert doctor_git._scratch_choice() == ("code", "scratch_unusable")
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": "/tmp/ok\nevil"})
    assert doctor_git._scratch_choice() == ("code", "multiline_refused")


def test_descriptor_probe_false_does_not_open(tmp_path, monkeypatch):
    opened = []
    monkeypatch.setattr(doctor_git, "descriptor_support", lambda: False)
    monkeypatch.setattr(doctor_git, "_confined", lambda *args, **kwargs: opened.append(args))
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    monkeypatch.setattr(doctor_git, "_disk_usage", lambda path: types.SimpleNamespace(
        total=10, used=1, free=doctor_git.RESERVE_BYTES + doctor_git.PEAK_BYTES))
    monkeypatch.setattr(doctor_git, "_scratch_choice", lambda: ("path", "/var/empty/aegis-scratch-outside"))
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert opened == []
    assert "descriptor_unsupported" in _codes(report)
    _assert_rows(report)


def test_symlink_refusal_closes_descriptors_and_hides_the_target(tmp_path, monkeypatch):
    if not doctor_git.descriptor_support():
        pytest.skip("descriptor walk unsupported")
    if not os.path.isdir("/proc/self/fd"):
        pytest.skip("no file-descriptor table")
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "note.txt").write_text("password=hunter2hunter\n", encoding="utf-8")
    symlink_or_skip(secret, tmp_path / "link")
    real_identity, real_confined = doctor_git._directory_identity, doctor_git._confined
    _quiet_tree(monkeypatch)
    monkeypatch.setattr(doctor_git, "_directory_identity", real_identity)
    monkeypatch.setattr(doctor_git, "_scandir", os.scandir)
    monkeypatch.setattr(doctor_git, "_confined", real_confined)
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    before = set(os.listdir("/proc/self/fd"))
    report = doctor_git.collect(tmp_path, tier="B", now=10)
    after = set(os.listdir("/proc/self/fd"))
    assert before == after
    assert "symlink_refused" in _codes(report)
    assert "hunter2hunter" not in _blob(report)


def test_identity_mismatch_retries_then_reports_path_changed(tmp_path, monkeypatch):
    secret = "password=hunter2hunter"
    state = {"n": 0, "stats": 0}

    class Entry:
        name = secret

        def is_symlink(self):
            return False

        def stat(self, follow_symlinks=True):
            state["stats"] += 1
            raise AssertionError("stat after a mismatched listing")

    def identity(root, parts):
        state["n"] += 1
        return (1, state["n"])

    _quiet_tree(monkeypatch)
    monkeypatch.setattr(doctor_git, "_directory_identity", identity)
    monkeypatch.setattr(doctor_git, "_scandir", lambda path: [Entry()])
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    report = doctor_git.collect(tmp_path, tier="C", now=10)
    assert "path_changed" in _codes(report)
    assert state["stats"] == 0
    assert secret not in _blob(report)
    assert state["n"] == 4


def test_identity_mismatch_then_a_stable_retry_lists_the_second_view(tmp_path, monkeypatch):
    state = {"n": 0}

    class Entry:
        def __init__(self, name, size):
            self.name = name
            self._size = size

        def is_symlink(self):
            return False

        def stat(self, follow_symlinks=True):
            return types.SimpleNamespace(st_mode=stat.S_IFREG, st_size=self._size, st_dev=1, st_ino=1)

    views = [[Entry("first.bin", 1)], [Entry("second.bin", 64)]]

    def identity(root, parts):
        state["n"] += 1
        if state["n"] <= 2:
            return (1, state["n"])
        return (1, 9)

    def listing(path):
        return views[0] if state["n"] <= 2 else views[1]

    _quiet_tree(monkeypatch)
    monkeypatch.setattr(doctor_git, "LARGE_BYTES", 32)
    monkeypatch.setattr(doctor_git, "_directory_identity", identity)
    monkeypatch.setattr(doctor_git, "_scandir", listing)
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "path_changed" not in _codes(report)
    assert "large_path" in _codes(report)
    assert "second.bin" in _blob(report)
    assert "first.bin" not in _blob(report)


def test_two_threads_collect_without_raising(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    _install_git(monkeypatch, _clean_table(tmp_path), _clean_seams())
    found = []
    errors = []

    def work():
        try:
            found.append(doctor_git.collect(tmp_path, tier="B", now=10))
        except Exception as exc:
            errors.append(type(exc).__name__)

    threads = [threading.Thread(target=work) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not any(thread.is_alive() for thread in threads)
    assert errors == []
    assert len(found) == 2
    assert all(report["affects_exit"] is False and report["status"] == "pass" for report in found)


def test_real_collect_on_a_non_repo_is_advisory(tmp_path, monkeypatch):
    outside = _outside_dir(tmp_path, "real-")
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})
    report = doctor_git.collect(tmp_path, tier="C", now=10)
    _assert_rows(report)
    blob = _blob(report)
    assert "Traceback" not in blob and "cannot run git" not in blob and "fatal:" not in blob
    if doctor_git.descriptor_support() and os.path.isdir("/proc/self/fd"):
        assert set(_codes(report)) & {"git_missing", "not_a_repository", "not_a_work_tree"}
    else:
        assert "scratch_unknown" in _codes(report)


def test_with_report_bumps_warnings_and_hides_failures(monkeypatch):
    payload = {"summary": {"passed": 5, "warnings": 1, "failed": 0, "total": 5}, "human_gate": {"tier": "B"}}

    def boom(root, tier=None, now=None):
        raise RuntimeError("password=hunter2hunter")

    monkeypatch.setattr(doctor_git, "collect", boom)
    out = doctor_git.with_report(dict(payload), Path("/tmp"), None, True)
    assert out["summary"]["failed"] == 0
    assert out["summary"]["warnings"] == payload["summary"]["warnings"] + 1
    assert payload["summary"]["warnings"] == 1
    assert out["git_hygiene"]["rows"][0]["code"] == "git_hygiene_unavailable"
    assert "hunter2hunter" not in _blob(out["git_hygiene"])
    assert out["human_gate"]["tier"] == "B"


def test_run_doctor_json_adds_hygiene_without_changing_exit(tmp_path, capsys):
    from aegis_cli import doctor

    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    args = argparse.Namespace(json=True, ws=types.SimpleNamespace(root=tmp_path))
    assert doctor.run_doctor(args) == 1
    raw = capsys.readouterr().out
    payload = json.loads(raw)
    assert payload["summary"]["failed"] >= 1
    hygiene = payload["git_hygiene"]
    assert hygiene["schema"] == "aegis.doctor.git/v1"
    assert hygiene["affects_exit"] is False
    assert "\x1b[" not in raw


def test_run_doctor_text_names_the_report_only_contract(tmp_path, capsys):
    from aegis_cli import doctor

    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    args = argparse.Namespace(ws=types.SimpleNamespace(root=tmp_path))
    assert doctor.run_doctor(args) == 1
    out = capsys.readouterr().out
    assert "doctor does not delete, prune, gc or rewrite refs" in out
    assert "No rules are served" in out


def test_product_git_calls_stay_on_the_read_only_allowlist():
    source = (REPO / "aegis_cli" / "doctor_git.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    allowed = {"rev-parse", "config", "worktree", "count-objects"}
    forbidden = {"prune", "gc", "update-ref", "branch", "clean", "reset", "checkout", "commit", "push"}
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Tuple, ast.List)) and node.elts and isinstance(node.elts[0], ast.Constant):
            if node.elts[0].value in allowed or node.elts[0].value in forbidden:
                calls.append(tuple(elt.value for elt in node.elts if isinstance(elt, ast.Constant)))
    assert calls
    for command in calls:
        assert command[0] in allowed, command
        assert command[0] not in forbidden
        if command[0] == "worktree":
            assert command[1] == "list"
        if command[0] == "config":
            assert command[1] == "--get"
    assert "os.open" not in source and "git_executable" not in source and "subprocess" not in source


def test_run_doctor_stays_inside_the_function_cap():
    tree = ast.parse((REPO / "aegis_cli" / "doctor.py").read_text(encoding="utf-8"))
    fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run_doctor")
    assert fn.end_lineno - fn.lineno + 1 <= 100
    assert sum(1 for _ in (REPO / "aegis_cli" / "doctor.py").read_text(encoding="utf-8").splitlines()) <= 1000
    assert sum(1 for _ in (REPO / "aegis_cli" / "doctor_git.py").read_text(encoding="utf-8").splitlines()) <= 1000


def test_token_branches_that_redact_together_keep_separate_policy_entries(tmp_path, monkeypatch):
    signature = "ghp_" + ("A" * 20)
    other = "ghp_" + ("B" * 20)
    shown_signature, signature_code = doctor_git.display(signature)
    shown_other, other_code = doctor_git.display(other)
    assert signature_code is None and other_code is None
    assert shown_signature == shown_other
    assert signature not in shown_signature and other not in shown_other
    _quiet_tree(monkeypatch)
    table = _clean_table(tmp_path)
    table[("rev-parse", "--abbrev-ref", "HEAD")] = _cp(("rev-parse",), signature.encode("ascii") + b"\n")
    seams = _clean_seams()
    seams["_policy"] = lambda root, commit: {signature: "signature", other: "none", "*": "none"}
    seams["_signers"] = lambda root, commit: 1
    _install_git(monkeypatch, table, seams)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    _assert_rows(report)
    patterns = report["approval_modes"]["patterns"]
    assert isinstance(patterns, list) and len(patterns) == 3
    assert patterns[0]["pattern"] != patterns[1]["pattern"]
    assert all(len(item["pattern"]) == 12 for item in patterns[:2])
    assert [item["mode"] for item in patterns] == ["signature", "none", "none"]
    assert report["approval_modes"]["effective"] == "signature"
    assert "signers_present" in _codes(report)
    blob = _blob(report)
    assert signature not in blob and other not in blob


def test_lease_listing_failure_suppresses_stale_advice(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    seams = _clean_seams()
    seams["_leases"] = lambda root: "git_failed"
    seams["_refs"] = lambda root, prefix: [("refs/heads/lane/old", "c" * 40)]
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier="B", now=10)
    _assert_rows(report)
    assert "git_failed" in _codes(report)
    assert "stale_lane_branch" not in _codes(report)
    assert not any("delete the stale" in row["owner_action"] for row in report["rows"])
    secret = "password=hunter2hunter"
    bad = team.Unreadable("docs", "refs/aegis/lanes/docs", "b" * 40, secret)
    seams["_leases"] = lambda root: team.LeaseSet((), (bad,))
    seams["_refs"] = lambda root, prefix: [("refs/heads/lane/docs", "d" * 40)]
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier="B", now=10)
    _assert_rows(report)
    assert "lease_unreadable" in _codes(report)
    assert "stale_lane_branch" not in _codes(report)
    assert secret not in _blob(report)
    assert not any("delete the stale" in row["owner_action"] for row in report["rows"])


def test_directory_swapped_for_an_outside_symlink_is_refused(tmp_path, monkeypatch):
    if not doctor_git.descriptor_support():
        pytest.skip("descriptor walk unsupported")
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("password=hunter2hunter\n", encoding="utf-8")
    symlink_or_skip(outside / "secret.txt", outside / "outside-secret")
    nested = workspace / "nested"
    nested.mkdir()
    (nested / "safe.txt").write_text("ok\n", encoding="utf-8")
    (workspace / "visible.bin").write_bytes(b"x" * 64)
    real_scandir = os.scandir

    def scandir(target):
        if isinstance(target, int):
            return real_scandir(target)
        if nested.exists() and not nested.is_symlink():
            nested.rename(workspace / "nested-real")
            nested.symlink_to(outside, target_is_directory=True)
        try:
            return real_scandir(outside)
        finally:
            if nested.is_symlink():
                nested.unlink()
                held = workspace / "nested-real"
                if held.exists():
                    held.rename(nested)

    monkeypatch.setattr(doctor_git, "LARGE_BYTES", 32)
    monkeypatch.setattr(doctor_git, "_disk_usage", lambda path: types.SimpleNamespace(
        total=10 ** 15, used=1, free=doctor_git.RESERVE_BYTES + doctor_git.PEAK_BYTES))
    monkeypatch.setattr(doctor_git, "_scratch_choice", lambda: ("path", "/var/empty/aegis-scratch-outside"))
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    monkeypatch.setattr(doctor_git, "_scandir", scandir)
    report = doctor_git.collect(workspace, tier="A", now=10)
    blob = _blob(report)
    assert "visible.bin" in blob
    assert "outside-secret" not in blob
    assert "hunter2hunter" not in blob


class _Million:
    """A million-entry directory that counts pulls and refuses to materialize them."""

    def __init__(self):
        self.n = 0

    def __iter__(self):
        return self

    def __next__(self):
        self.n += 1
        if self.n > doctor_git.MAX_ENTRIES + 2:
            raise RuntimeError("directory listing allocated past the entry cap")
        entry = types.SimpleNamespace(name="f%d" % self.n)

        def is_symlink():
            return False

        def file_stat(follow_symlinks=True):
            return types.SimpleNamespace(st_mode=stat.S_IFREG, st_size=1, st_dev=1, st_ino=1)

        entry.is_symlink = is_symlink
        entry.stat = file_stat
        return entry

    def close(self):
        return None


def test_million_entry_directory_stops_at_the_cap(tmp_path, monkeypatch):
    listing = _Million()
    _quiet_tree(monkeypatch)
    monkeypatch.setattr(doctor_git, "_scandir", lambda path: listing)
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    report = doctor_git.collect(tmp_path, tier="C", now=10)
    _assert_rows(report)
    assert "scan_capped" in _codes(report)
    assert listing.n <= doctor_git.MAX_ENTRIES + 1


def test_oversized_signer_blob_and_ref_list_are_capped(tmp_path, monkeypatch):
    if not doctor_git.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch descriptors unsupported")
    outside = _outside_dir(tmp_path, "sign-")
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})
    oid = "a" * 40
    reads = {"n": 0}

    def invoke(args, root, **kwargs):
        assert gitsafe_run.custody_active()
        line = b"100644 blob " + oid.encode("ascii") + b"\t" + human_gate.ALLOWED_SIGNERS.encode("ascii") + b"\0"
        return types.SimpleNamespace(returncode=0, stdout=line, stderr=b"")

    def blob_sizes(root, oids, **kwargs):
        assert gitsafe_run.custody_active()
        return {oid: doctor_git.GIT_STDOUT_LIMIT + 1}

    def read_object(root, blob, limit):
        reads["n"] += 1
        raise AssertionError("signer bytes were read after the cap")

    monkeypatch.setattr(doctor_git, "_invoke", invoke)
    monkeypatch.setattr(doctor_git, "_blob_sizes", blob_sizes)
    monkeypatch.setattr(doctor_git, "_read_object", read_object)
    assert doctor_git._signers(tmp_path, oid) == "git_output_limit"
    assert reads["n"] == 0

    class Huge:
        def __len__(self):
            return 1_000_000

        def __iter__(self):
            raise AssertionError("ref list was materialized")

    def list_refs(root, prefix):
        assert gitsafe_run.custody_active()
        return Huge()

    monkeypatch.setattr(doctor_git, "_list_refs", list_refs)
    assert doctor_git._refs(tmp_path, "refs/heads/lane") == "git_output_limit"


def test_secret_shaped_name_is_redacted_after_canonical_form(tmp_path, monkeypatch):
    secret = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL"
    shown, code = doctor_git.display(secret)
    assert code is None and secret not in shown and "REDACTED" in shown
    entry = types.SimpleNamespace(name=secret)
    entry.is_symlink = lambda: False
    entry.stat = lambda follow_symlinks=True: types.SimpleNamespace(
        st_mode=stat.S_IFREG, st_size=10 ** 9, st_dev=1, st_ino=1)
    _quiet_tree(monkeypatch)
    monkeypatch.setattr(doctor_git, "_scandir", lambda path: [entry])
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert secret not in _blob(report)
    assert "REDACTED" not in _row(report, "large_path")["detail"]
    assert len(_row(report, "large_path")["detail"].removeprefix("large file ")) == 12


def test_ref_prefixed_lease_matches_the_lane_branch(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    lease = _lease("docs", "refs/heads/lane/docs", ts=10, ttl=50)
    seams = _clean_seams()
    seams["_leases"] = lambda root: team.LeaseSet((lease,), ())
    seams["_refs"] = lambda root, prefix: [("refs/heads/lane/docs", "d" * 40)]
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "live_lease" in _codes(report)
    assert "stale_lane_branch" not in _codes(report)


def test_unresolvable_scratch_is_unknown(tmp_path, monkeypatch):
    if not doctor_git.descriptor_support():
        pytest.skip("scratch descriptors unsupported")
    link = tmp_path / "unresolvable-scratch"
    symlink_or_skip(link, link)
    try:
        monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(link)})
        monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
        report = doctor_git.collect(tmp_path, tier="B", now=10)
    finally:
        os.unlink(link)
    assert "scratch_outside" not in _codes(report)
    assert "scratch_inside" not in _codes(report)
    row = _row(report, "scratch_unknown")
    assert row["status"] == "warn" and "unknown" in row["detail"]


def test_scratch_dotdot_is_refused_and_empty_cache_uses_home(monkeypatch):
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": "/tmp/a/../../etc"})
    assert doctor_git._scratch_choice() == ("code", "scratch_unusable")
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"XDG_CACHE_HOME": "", "HOME": "/tmp/home"})
    assert doctor_git._scratch_choice() == ("path", str(Path("/tmp/home") / ".cache" / "aegis"))


def test_branch_failure_retries_without_a_passing_approval(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    table = _clean_table(tmp_path)

    def run(root, args):
        if tuple(args) == doctor_git._BRANCH:
            return "git_timeout"
        return table[tuple(args)]

    _install_git(monkeypatch, table, _clean_seams())
    monkeypatch.setattr(doctor_git, "_run_git", run)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    row = _row(report, "git_timeout")
    assert "retry" in row["owner_action"]
    assert "rename" not in row["owner_action"]
    assert "approval_mode" not in _codes(report)


def test_worktree_escape_stays_outside_on_the_original_path(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    escaped = str(tmp_path) + "\x1b[31m"
    table = _clean_table(tmp_path)
    table[("worktree", "list", "--porcelain", "-z")] = _cp(
        ("worktree",), b"worktree " + escaped.encode() + b"\0HEAD abc\0\0")
    _install_git(monkeypatch, table, _clean_seams())
    report = doctor_git.collect(tmp_path, tier="C", now=10)
    assert "outside_root" in _codes(report)
    assert "\x1b" not in _blob(report)


def test_human_gate_error_stays_inside_custody_as_a_fixed_code(tmp_path, monkeypatch):
    if not doctor_git.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch descriptors unsupported")
    outside = _outside_dir(tmp_path, "gate-")
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})
    secret = "password=hunter2hunter"

    def boom(root):
        assert gitsafe_run.custody_active()
        raise human_gate.HumanGateError(secret)

    monkeypatch.setattr(doctor_git, "_head_commit", boom)
    assert doctor_git._head(tmp_path) == "git_failed"
    assert secret not in "git_failed"


def _outside_dir(tmp_path, prefix):
    path = Path(tempfile.mkdtemp(dir=tmp_path.parent, prefix=prefix))
    if os.name == "posix":
        path.chmod(0o700)
    return path


@pytest.fixture(scope="module")
def outside_allocation_cases(tmp_path_factory):
    return tmp_path_factory.mktemp("outside-cases"), []


@pytest.mark.xdist_group(name="outside_dir_collision")
@pytest.mark.parametrize("case", ["first", "second"])
def test_outside_directories_are_unique_across_cases(outside_allocation_cases, case):
    parent, allocated = outside_allocation_cases
    workspace = parent / ("workspace-" + case)
    workspace.mkdir()
    outside = _outside_dir(workspace, "same-prefix-")
    assert outside.parent == workspace.parent
    assert outside.is_dir() and outside != workspace
    for previous, marker in allocated:
        assert outside != previous
        assert (previous / "marker").read_text(encoding="utf-8") == marker
    if os.name == "posix":
        info = outside.stat()
        assert info.st_uid == os.geteuid()
        assert stat.S_IMODE(info.st_mode) & 0o700 == 0o700
        assert not info.st_mode & stat.S_IWOTH
    (outside / "marker").write_text(case, encoding="utf-8")
    allocated.append((outside, case))


def test_scratch_inside_the_workspace_is_unknown(tmp_path, monkeypatch):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "scratch_inside" not in _codes(report)
    assert "scratch_outside" not in _codes(report)
    row = _row(report, "scratch_unknown")
    assert row["status"] == "warn" and "unknown" in row["detail"]
    assert row["owner_action"].startswith("owner action:")


def test_shared_missing_and_unreadable_scratch_are_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": "/tmp"})
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "scratch_outside" not in _codes(report)
    assert _row(report, "scratch_unknown")["status"] == "warn"

    missing = tmp_path.parent / ("missing-" + tmp_path.name)
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(missing)})
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "scratch_outside" not in _codes(report)
    assert "scratch_unknown" in _codes(report)

    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() == 0:
        return
    locked = _outside_dir(tmp_path, "locked-")
    os.chmod(locked, 0)
    try:
        monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(locked)})
        report = doctor_git.collect(tmp_path, tier="A", now=10)
    finally:
        os.chmod(locked, 0o700)
    assert "scratch_outside" not in _codes(report)
    assert "scratch_unknown" in _codes(report)


def test_symlink_loop_scratch_is_unknown(tmp_path, monkeypatch):
    link = tmp_path / "loop-scratch"
    symlink_or_skip(link, link)
    try:
        monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(link)})
        monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
        report = doctor_git.collect(tmp_path, tier="B", now=10)
    finally:
        os.unlink(link)
    assert "scratch_outside" not in _codes(report)
    assert "scratch_inside" not in _codes(report)
    assert "unknown" in _row(report, "scratch_unknown")["detail"]


def test_full_scratch_filesystem_does_not_admit_heavy_slots(tmp_path, monkeypatch):
    scratch = _outside_dir(tmp_path, "full-")
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")

    def usage(target):
        if isinstance(target, int) and not isinstance(target, bool):
            return types.SimpleNamespace(total=10, used=10, free=0)
        return types.SimpleNamespace(total=10 ** 15, used=1, free=10 ** 15)

    monkeypatch.setattr(doctor_git, "_disk_usage", usage)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "disk_budget" not in _codes(report)
    assert "disk_low" in _codes(report) or "disk_unknown" in _codes(report)


def test_sibling_listing_stops_at_the_entry_cap(tmp_path, monkeypatch):
    cap = doctor_git.MAX_ENTRIES
    stats = {"n": 0}

    class Entry:
        def __init__(self, name, directory):
            self.name = name
            self.directory = directory

        def is_symlink(self):
            return False

        def stat(self, follow_symlinks=True):
            stats["n"] += 1
            mode = stat.S_IFDIR if self.directory else stat.S_IFREG
            return types.SimpleNamespace(st_mode=mode, st_size=1, st_dev=1, st_ino=1)

    def listing(target):
        if Path(str(target)) == tmp_path:
            rows = [Entry("sub", True)]
            rows.extend(Entry("p%d" % index, False) for index in range(cap - 1))
            return rows
        return [Entry("c%d" % index, False) for index in range(cap - 1)]

    _quiet_tree(monkeypatch)
    monkeypatch.setattr(doctor_git, "_scandir", listing)
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    report = doctor_git.collect(tmp_path, tier="C", now=10)
    assert "scan_capped" in _codes(report)
    assert stats["n"] <= cap


def test_oversized_lease_set_is_refused_before_object_reads(tmp_path, monkeypatch):
    if not doctor_git.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch descriptors unsupported")
    outside = _outside_dir(tmp_path, "lease-")
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})
    reads = {"n": 0}

    class Huge:
        def __len__(self):
            return 1_000_000

        def __iter__(self):
            raise AssertionError("lease refs were materialized")

    def list_refs(root, prefix):
        assert gitsafe_run.custody_active()
        assert prefix == team.LANES_REF
        return Huge()

    def read_leases(root):
        reads["n"] += 1
        raise AssertionError("lease objects were read")

    monkeypatch.setattr(doctor_git, "_list_refs", list_refs)
    monkeypatch.setattr(doctor_git, "_read_leases", read_leases)
    assert doctor_git._leases(tmp_path) == "git_output_limit"
    assert reads["n"] == 0


def test_readonly_checkout_keeps_policy_signer_and_lease_knowledge(tmp_path, monkeypatch):
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("mode 555 is not a denial for this user")
    if not doctor_git.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch custody descriptors unsupported")
    workspace = tmp_path / "repo"
    workspace.mkdir()
    outside = _outside_dir(tmp_path, "own-")
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})
    policy = {"*": "none"}
    monkeypatch.setattr(doctor_git, "_read_policy", lambda root, commit, strict=True: policy)
    monkeypatch.setattr(doctor_git, "_head_commit", lambda root: "a" * 40)
    monkeypatch.setattr(doctor_git, "_list_refs", lambda root, prefix: [])
    monkeypatch.setattr(doctor_git, "_read_leases", lambda root: team.LeaseSet((), ()))
    def entry(args, root, **kwargs):
        path = args[-1]
        line = b"100644 blob " + b"b" * 40 + b"\t" + path.encode() + b"\0"
        return _cp(args, line)

    monkeypatch.setattr(doctor_git, "_invoke", entry)
    monkeypatch.setattr(doctor_git, "_blob_sizes", lambda root, oids: {"b" * 40: 0})
    monkeypatch.setattr(doctor_git, "_read_object", lambda *args: b"")

    def read_policy(root, commit, strict=True):
        held = gitsafe_run._CUSTODY.get()
        assert held is not None and Path(held.scratch) != workspace
        assert primitives.is_within(held.scratch, workspace, unresolvable=False) is False
        return policy

    monkeypatch.setattr(doctor_git, "_read_policy", read_policy)
    mode = workspace.stat().st_mode
    os.chmod(workspace, 0o555)
    try:
        readonly = (
            doctor_git._policy(workspace, "a" * 40),
            doctor_git._head(workspace),
            doctor_git._signers(workspace, "a" * 40),
            doctor_git._leases(workspace),
        )
    finally:
        os.chmod(workspace, mode)
    writable = (
        doctor_git._policy(workspace, "a" * 40),
        doctor_git._head(workspace),
        doctor_git._signers(workspace, "a" * 40),
        doctor_git._leases(workspace),
    )
    assert readonly[0] == writable[0] == policy
    assert readonly[1] == writable[1] == "a" * 40
    assert readonly[2] == writable[2] == 0
    assert readonly[3].leases == writable[3].leases == ()
    assert list(workspace.iterdir()) == []


def test_redacted_prefix_does_not_keep_a_secret_suffix():
    suffix = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL"
    shown, code = doctor_git.display("REDACTED_" + suffix)
    assert code is None and suffix not in shown and "REDACTED" in shown


def test_surrogate_name_survives_strict_utf8_output(tmp_path, monkeypatch):
    name = "file-\udc80.bin"
    shown, code = doctor_git.display(name)
    assert code is None and shown.encode("utf-8")
    entry = types.SimpleNamespace(name=name)
    entry.is_symlink = lambda: False
    entry.stat = lambda follow_symlinks=True: types.SimpleNamespace(
        st_mode=stat.S_IFREG, st_size=10 ** 9, st_dev=1, st_ino=1)
    _quiet_tree(monkeypatch)
    monkeypatch.setattr(doctor_git, "_scandir", lambda path: [entry])
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    buffer = io.BytesIO()
    stream = io.TextIOWrapper(buffer, encoding="utf-8", errors="strict")
    doctor_git._print_report(report, stream)
    stream.flush()
    printed = buffer.getvalue().decode("utf-8")
    assert "\udc80" not in printed
    assert "large file" in printed or "refused" in printed


def test_signer_transport_and_symlink_are_unavailable(tmp_path, monkeypatch):
    if not doctor_git.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch descriptors unsupported")
    outside = _outside_dir(tmp_path, "sign2-")
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})

    def invoke(args, root, **kwargs):
        raise gitsafe.GitError("timeout", code="git_timeout")

    monkeypatch.setattr(doctor_git, "_invoke", invoke)
    assert doctor_git._signers(tmp_path, "a" * 40) == "git_timeout"
    path = human_gate.ALLOWED_SIGNERS
    line = b"120000 blob " + (b"b" * 40) + b"\t" + path.encode("ascii") + b"\0"
    monkeypatch.setattr(
        doctor_git, "_invoke",
        lambda args, root, **kwargs: types.SimpleNamespace(returncode=0, stdout=line, stderr=b""))
    assert doctor_git._signers(tmp_path, "a" * 40) == "signers_unavailable"


def test_config_transport_failure_is_not_an_unset_expiry(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    table = _clean_table(tmp_path)
    table[("config", "--get", "gc.worktreePruneExpire")] = _cp(("config",), b"fatal\n", 128)
    _install_git(monkeypatch, table, _clean_seams())
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "prune_expire_unset" not in _codes(report)
    row = _row(report, "git_failed")
    assert row["owner_action"] == doctor_git._RETRY
    table[("config", "--get", "gc.worktreePruneExpire")] = "git_timeout"
    _install_git(monkeypatch, table, _clean_seams())
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    row = _row(report, "git_timeout")
    assert row["owner_action"] == doctor_git._RETRY
    assert "never" not in row["owner_action"]


def test_swap_between_hold_and_identity_is_refused(tmp_path, monkeypatch):
    if not doctor_git.descriptor_support():
        pytest.skip("scratch descriptors unsupported")
    workspace = tmp_path / "ws"
    sub = workspace / "sub"
    sub.mkdir(parents=True)
    (sub / "inside.bin").write_bytes(b"x" * 64)
    outside = tmp_path / "out"
    outside.mkdir()
    moved = {"done": False}
    real_identity = doctor_git._directory_identity

    def identity(root, parts):
        if tuple(parts or ()) == ("sub",) and not moved["done"]:
            moved["done"] = True
            sub.rename(outside / "was-sub")
            (outside / "was-sub" / "outside_injected.bin").write_bytes(b"y" * 80)
            replacement = workspace / "sub"
            replacement.mkdir()
            (replacement / "huge.bin").write_bytes(b"z" * 80)
        return real_identity(root, parts)

    monkeypatch.setattr(doctor_git, "LARGE_BYTES", 32)
    monkeypatch.setattr(doctor_git, "_disk_usage", lambda path: types.SimpleNamespace(
        total=1, used=0, free=10 ** 15))
    monkeypatch.setattr(doctor_git, "_scratch_choice", lambda: ("path", "/var/empty/aegis-scratch-outside"))
    monkeypatch.setattr(doctor_git, "_hold_scratch", lambda path: (None, 1, 1))
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    monkeypatch.setattr(doctor_git, "_directory_identity", identity)
    report = doctor_git.collect(workspace, tier="A", now=10)
    blob = _blob(report)
    assert "outside_injected" not in blob
    assert "huge.bin" not in blob
    assert "path_changed" in _codes(report)


def test_nested_redacted_marker_does_not_keep_a_secret_suffix():
    suffix = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL"
    for text in ("REREDACTEDDACTED_" + suffix, "REDACREDACTEDTED_" + suffix):
        shown, code = doctor_git.display(text)
        assert code is None and suffix not in shown and "REDACTED" in shown


def test_shared_alias_inside_and_unwritable_scratch_are_unknown(tmp_path, monkeypatch):
    if os.name != "posix" or not doctor_git.descriptor_support():
        pytest.skip("posix scratch descriptors required")
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    for candidate in ("//tmp", "/var/tmp", "/"):
        if not os.path.isdir(candidate):
            continue
        monkeypatch.setattr(doctor_git, "_scratch_env", lambda candidate=candidate: {"AEGIS_SCRATCH": candidate})
        report = doctor_git.collect(tmp_path, tier="A", now=10)
        assert "scratch_outside" not in _codes(report)
        assert "scratch_unknown" in _codes(report)
        assert "disk_budget" not in _codes(report)
    nested = tmp_path / "scratch"
    nested.mkdir()
    doubled = "/" + os.path.abspath(nested)
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": doubled})
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "scratch_outside" not in _codes(report)
    assert "scratch_unknown" in _codes(report)
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        return
    wide = _outside_dir(tmp_path, "wide-")
    os.chmod(wide, 0o1777)
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(wide)})
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "scratch_outside" not in _codes(report)
    assert "scratch_unknown" in _codes(report)
    cold = _outside_dir(tmp_path, "cold-")
    os.chmod(cold, 0o555)
    try:
        monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(cold)})
        report = doctor_git.collect(tmp_path, tier="A", now=10)
    finally:
        os.chmod(cold, 0o700)
    assert "scratch_outside" not in _codes(report)
    assert "scratch_unknown" in _codes(report)


def test_lease_cap_uses_the_checked_snapshot(tmp_path, monkeypatch):
    if not doctor_git.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch descriptors unsupported")
    outside = _outside_dir(tmp_path, "grow-")
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})
    reads = {"n": 0}

    class Grow:
        def __len__(self):
            return 1

        def __iter__(self):
            for index in range(doctor_git._REF_CAP + 1):
                yield ("refs/aegis/lanes/n%d" % index, "a" * 40)

    def list_refs(root, prefix):
        assert gitsafe_run.custody_active()
        return Grow()

    def read_leases(root):
        reads["n"] += 1
        raise AssertionError("lease objects were read from a second listing")

    monkeypatch.setattr(doctor_git, "_list_refs", list_refs)
    monkeypatch.setattr(doctor_git, "_read_leases", read_leases)
    assert doctor_git._leases(tmp_path) == "git_output_limit"
    assert reads["n"] == 0


def test_secret_lane_owner_action_is_redacted(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    secret = "ghp_" + ("a" * 20)
    bad = team.Unreadable(secret, "refs/aegis/lanes/" + secret, "c" * 40, "unreadable")
    seams = _clean_seams()
    seams["_leases"] = lambda root: team.LeaseSet((), (bad,))
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    blob = _blob(report)
    action = _row(report, "lease_unreadable")["owner_action"]
    assert secret not in blob and "ghp_" not in blob
    assert "release" not in action and "aegis team gc" not in action


def test_invalid_unreadable_lane_names_a_working_delete(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    ref = "refs/aegis/lanes/UPPER"
    oid = "d" * 40
    bad = team.Unreadable("UPPER", ref, oid, "not a lane name")
    seams = _clean_seams()
    seams["_leases"] = lambda root: team.LeaseSet((), (bad,))
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    action = _row(report, "lease_unreadable")["owner_action"]
    assert "update-ref -d" in action and ref in action and oid in action
    assert "aegis team gc" not in action and "aegis team release" not in action


@pytest.mark.parametrize("branch", [None, "", "lane/bad^ref", "lane/bad..ref", "refs/heads/"])
def test_expired_unknown_branch_suppresses_stale_deletion(tmp_path, monkeypatch, branch):
    _quiet_tree(monkeypatch)
    lease = _lease("docs", branch, ts=1_000, ttl=50)
    seams = _clean_seams()
    seams["_leases"] = lambda root: team.LeaseSet((lease,), ())
    seams["_refs"] = lambda root, prefix: [
        ("refs/heads/lane/docs", "d" * 40),
        ("refs/heads/lane/other", "e" * 40),
    ]
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier="A", now=lease.expires_at)
    assert "expired_lease" in _codes(report)
    assert "stale_lane_branch" not in _codes(report)


def test_custody_without_a_bound_descriptor_is_unknown(tmp_path, monkeypatch):
    seen = []

    @contextmanager
    def custody(**kwargs):
        seen.append(kwargs)
        yield

    monkeypatch.setattr(doctor_git, "_use_scratch", lambda root: (
        types.SimpleNamespace(code=None, path=str(tmp_path), fd=None, bind=None, owned=False), False))
    monkeypatch.setattr(doctor_git, "_custody", custody)
    assert doctor_git._run_git(tmp_path, doctor_git._PRESENCE) == "git_failed"
    assert seen == []


def test_nonregular_signers_are_unavailable(tmp_path, monkeypatch):
    if not doctor_git.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch descriptors unsupported")
    outside = _outside_dir(tmp_path, "kind-")
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})
    path = human_gate.ALLOWED_SIGNERS
    oid = "e" * 40
    scripted = {"out": b""}

    def invoke(args, root, **kwargs):
        assert gitsafe_run.custody_active()
        return types.SimpleNamespace(returncode=0, stdout=scripted["out"], stderr=b"")

    monkeypatch.setattr(doctor_git, "_invoke", invoke)
    scripted["out"] = b"040000 tree " + oid.encode() + b"\t" + path.encode() + b"\0"
    assert doctor_git._signers(tmp_path, "a" * 40) == "signers_unavailable"
    scripted["out"] = b"160000 commit " + oid.encode() + b"\t" + path.encode() + b"\0"
    assert doctor_git._signers(tmp_path, "a" * 40) == "signers_unavailable"
    scripted["out"] = b""
    assert doctor_git._signers(tmp_path, "a" * 40) == "signers_unavailable"


def test_reserved_parent_entries_are_still_checked(tmp_path, monkeypatch):
    cap = doctor_git.MAX_ENTRIES

    class Entry:
        def __init__(self, name, directory, size):
            self.name = name
            self.directory = directory
            self.size = size

        def is_symlink(self):
            return False

        def stat(self, follow_symlinks=True):
            mode = stat.S_IFDIR if self.directory else stat.S_IFREG
            return types.SimpleNamespace(st_mode=mode, st_size=self.size, st_dev=1, st_ino=1)

    def listing(target):
        if Path(str(target)) == tmp_path:
            rows = [Entry("sub", True, 1)]
            rows.extend(Entry("p%d" % index, False, 100 * 1024 * 1024 if index == cap - 2 else 1) for index in range(cap - 1))
            return rows
        return [Entry("child.bin", False, 1)]

    _quiet_tree(monkeypatch)
    monkeypatch.setattr(doctor_git, "_scandir", listing)
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    report = doctor_git.collect(tmp_path, tier="C", now=10)
    assert "large_path" in _codes(report)
    assert "p%d" % (cap - 2) in _row(report, "large_path")["detail"]


@pytest.mark.parametrize("branch", [b"", b"HEAD\n"])
def test_unknown_current_branch_never_passes_approvals(tmp_path, monkeypatch, branch):
    _quiet_tree(monkeypatch)
    table = _clean_table(tmp_path)
    table[doctor_git._BRANCH] = _cp(doctor_git._BRANCH, branch)
    _install_git(monkeypatch, table, _clean_seams())
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert report["approval_modes"] is None
    assert "approval_mode" not in _codes(report)
    assert any(row["id"] == "approvals" and row["status"] == "warn" for row in report["rows"])


@pytest.mark.parametrize("command,payload,row_id", [
    (doctor_git._WORKTREES, b"", "worktrees"),
    (doctor_git._WORKTREES, b"HEAD abc\0\0", "worktrees"),
    (doctor_git._WORKTREES, b"worktree \0HEAD abc\0\0", "worktrees"),
    (doctor_git._OBJECTS, b"", "git_objects"),
    (doctor_git._OBJECTS, b"size: 0\n", "git_objects"),
    (doctor_git._OBJECTS, b"size: 0\nsize: 1\nsize-pack: 0\n", "git_objects"),
])
def test_unestablished_git_objects_never_pass(tmp_path, monkeypatch, command, payload, row_id):
    _quiet_tree(monkeypatch)
    table = _clean_table(tmp_path)
    table[command] = _cp(command, payload)
    _install_git(monkeypatch, table, _clean_seams())
    rows = [row for row in doctor_git.collect(tmp_path, tier="A", now=10)["rows"] if row["id"] == row_id]
    assert rows and all(row["status"] == "warn" and row["code"] == "git_failed" for row in rows)


@pytest.mark.parametrize("branch", [None, "", "lane/bad^ref", "lane/bad..ref", "refs/heads/"])
def test_unknown_tier_and_live_null_branch_never_pass(tmp_path, monkeypatch, branch):
    _quiet_tree(monkeypatch)
    seams = _clean_seams()
    seams["_leases"] = lambda root: team.LeaseSet((_lease("docs", branch, 10, 50),), ())
    seams["_refs"] = lambda root, prefix: [("refs/heads/lane/old", "b" * 40)]
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier=None, now=10)
    assert _row(report, "trust_tier")["status"] == "warn"
    assert "live_lease" not in _codes(report)
    assert "stale_lane_branch" not in _codes(report)
    assert _row(report, "lease_branch_unknown")["status"] == "warn"


def test_signer_missing_entry_is_unknown_but_empty_regular_blob_is_absent(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    _install_git(monkeypatch, _clean_table(tmp_path), _clean_seams())
    monkeypatch.setattr(doctor_git, "_signers", lambda root, commit: doctor_git._signers_at(root, commit))
    monkeypatch.setattr(doctor_git, "_invoke", lambda *args: _cp(args, b""))
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "signers_absent" not in _codes(report)
    assert _row(report, "signers_unavailable")["status"] == "warn"
    line = b"100644 blob " + b"b" * 40 + b"\tallowed_signers\0"
    monkeypatch.setattr(doctor_git, "_invoke", lambda *args: _cp(args, line))
    monkeypatch.setattr(doctor_git, "_blob_sizes", lambda root, oids: {"b" * 40: 0})
    monkeypatch.setattr(doctor_git, "_read_object", lambda *args: b"")
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert _row(report, "signers_absent")["status"] == "warn"


def test_invalid_head_cannot_echo_a_raw_refusal_code(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    seams = _clean_seams()
    secret = "ghp_" + "a" * 20
    seams["_head"] = lambda root: secret
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert secret not in _blob(report)
    assert any(row["id"] == "approvals" and row["code"] == "git_failed" for row in report["rows"])


@pytest.mark.parametrize("lane", ["UPPER;echo${IFS}oops", "UPPER'quoted", "ghp_" + "a" * 20])
def test_unreadable_ref_action_is_shell_safe_or_uses_private_inspection(tmp_path, monkeypatch, lane):
    import shlex

    _quiet_tree(monkeypatch)
    ref, oid = "refs/aegis/lanes/" + lane, "d" * 40
    seams = _clean_seams()
    seams["_leases"] = lambda root: team.LeaseSet((), (team.Unreadable(lane, ref, oid, "bad"),))
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    action = _row(doctor_git.collect(tmp_path, tier="A", now=10), "lease_unreadable")["owner_action"]
    if lane.startswith("ghp_"):
        assert lane not in action and "git for-each-ref refs/aegis/lanes" in action
        assert "git update-ref -d REF OID" in action and oid in action
    else:
        command = action.removeprefix("owner action: ").split(" (doctor", 1)[0]
        assert shlex.split(command) == ["git", "update-ref", "-d", ref, oid]
        assert "'" in command


def test_lease_snapshot_cannot_grow_at_a_second_enumeration(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    _install_git(monkeypatch, _clean_table(tmp_path), _clean_seams())
    refs = [("refs/aegis/lanes/n%d" % i, "b" * 40) for i in range(1024)]
    listings, reads = [], []

    def list_refs(root, prefix):
        listings.append(prefix)
        assert len(listings) == 1, "lease refs were enumerated twice"
        return list(refs)

    def read_object(root, oid, limit):
        if not reads:
            refs.append(("refs/aegis/lanes/added", "c" * 40))
        lane = "n%d" % len(reads)
        reads.append(oid)
        return json.dumps(dict(v=1, lane=lane, role="implementer", owner="owner", claim_id="a" * 16,
                               gen=1, branch="lane/" + lane, paths=["src/app.py"], ts=1, ttl_s=50)).encode()

    monkeypatch.setattr(doctor_git, "_scoped", lambda root, produce: produce())
    monkeypatch.setattr(doctor_git, "_leases", lambda root: doctor_git._leases_at(root))
    monkeypatch.setattr(doctor_git, "_list_refs", list_refs)
    monkeypatch.setattr(doctor_git, "_read_object", read_object)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert len(refs) == 1025 and len(reads) == 1024 and len(listings) == 1
    assert _codes(report).count("live_lease") == 1024


def test_exact_budget_with_an_empty_first_subdirectory_has_no_false_cap(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    entries = [doctor_git._Snap("sub", stat.S_IFDIR, 0)] + [
        doctor_git._Snap("p%d" % i, stat.S_IFREG, 100 * 1024 * 1024 if i == 254 else 1)
        for i in range(255)]
    monkeypatch.setattr(doctor_git, "_scandir", lambda target: entries if Path(target) == tmp_path else [])
    monkeypatch.setattr(doctor_git, "_run_git", lambda *args: "git_missing")
    report = doctor_git.collect(tmp_path, tier="C", now=10)
    assert "large_path" in _codes(report)
    assert "scan_capped" not in _codes(report)


def test_scratch_duplicate_closes_when_the_anchor_context_fails(tmp_path, monkeypatch):
    if not doctor_git.descriptor_support():
        pytest.skip("directory descriptors unsupported")
    borrowed = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    duplicates = []

    def duplicate(fd):
        owned = os.dup(fd)
        duplicates.append(owned)
        return owned

    @contextmanager
    def failing_anchor(*args):
        yield types.SimpleNamespace(_parent=borrowed)
        raise doctor_git.ConfinedFileError("io")

    monkeypatch.setattr(doctor_git, "os", types.SimpleNamespace(**{**vars(os), "dup": duplicate}))
    monkeypatch.setattr(doctor_git, "_confined", failing_anchor)
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(tmp_path)})
    monkeypatch.setattr(doctor_git, "_run_git", lambda *args: "git_missing")
    monkeypatch.setattr(doctor_git, "_walk", lambda *args: None)
    try:
        report = doctor_git.collect(tmp_path, tier="A", now=10)
        assert "scratch_unknown" in _codes(report)
        assert len(duplicates) == 1
        with pytest.raises(OSError) as error:
            os.fstat(duplicates[0])
        assert error.value.errno == 9
    finally:
        os.close(borrowed)
        for fd in duplicates:
            try:
                os.close(fd)
            except OSError:
                pass


def test_missing_descriptor_binding_refuses_a_replaced_scratch(tmp_path, monkeypatch):
    if not doctor_git.descriptor_support():
        pytest.skip("directory descriptors unsupported")
    scratch = _outside_dir(tmp_path, "bind-")
    held = scratch.with_name(scratch.name + "-held")
    symlink_or_skip(tmp_path, tmp_path / "link-probe", target_is_directory=True)
    entered = []

    def unavailable(fd, dev, ino):
        scratch.rename(held)
        symlink_or_skip(tmp_path, scratch, target_is_directory=True)
        return None

    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git, "_bind_fd", unavailable)
    monkeypatch.setattr(doctor_git, "_custody", lambda **kwargs: entered.append(kwargs))
    monkeypatch.setattr(doctor_git, "_disk_usage", lambda target: pytest.fail("unbound scratch measured"))
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "scratch_unknown" in _codes(report) and "scratch_outside" not in _codes(report)
    assert report["disk"]["budget_slots"] is None and entered == []


def test_scratch_validation_error_is_a_refusal_and_closes_the_descriptor(tmp_path, monkeypatch):
    if not doctor_git.descriptor_support():
        pytest.skip("directory descriptors unsupported")
    scratch = _outside_dir(tmp_path, "error-")
    held = []

    def denied(root, fd, dev, ino):
        held.append(fd)
        raise OSError("password=hunter2hunter")

    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git, "_scratch_ok", denied)
    monkeypatch.setattr(doctor_git, "_run_git", lambda *args: "git_missing")
    try:
        report = doctor_git.collect(tmp_path, tier="A", now=10)
        assert "scratch_unknown" in _codes(report) and "hunter2hunter" not in _blob(report)
        assert len(held) == 1
        with pytest.raises(OSError) as error:
            os.fstat(held[0])
        assert error.value.errno == 9
    finally:
        for fd in held:
            try:
                os.close(fd)
            except OSError:
                pass


@pytest.mark.parametrize("count", [None, False, -1])
def test_untyped_signer_count_never_establishes_absence(tmp_path, monkeypatch, count):
    _quiet_tree(monkeypatch)
    seams = _clean_seams()
    seams["_signers"] = lambda *args: count
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "signers_absent" not in _codes(report)
    assert _row(report, "signers_unavailable")["status"] == "warn"


def test_empty_policy_is_unknown(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    seams = _clean_seams()
    seams["_policy"] = lambda *args: {}
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "approval_mode" not in _codes(report)
    assert report["approval_modes"] is None


@pytest.mark.parametrize("mode,kind", [("040000", "tree"), ("160000", "commit"), ("120000", "blob")])
def test_policy_exact_nonregular_entry_is_unknown(tmp_path, monkeypatch, mode, kind):
    _quiet_tree(monkeypatch)
    _install_git(monkeypatch, _clean_table(tmp_path), _clean_seams())
    monkeypatch.setattr(doctor_git, "_policy", lambda root, commit: doctor_git._policy_at(root, commit))
    path = doctor_git.approval_policy.CONFIG_PATH
    line = ("%s %s %s\t%s\0" % (mode, kind, "b" * 40, path)).encode()
    monkeypatch.setattr(doctor_git, "_invoke", lambda *args: _cp(args, line))
    monkeypatch.setattr(doctor_git, "_read_policy", lambda *args, **kwargs: pytest.fail("nonregular policy parsed"))
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "approval_mode" not in _codes(report)
    assert _row(report, "policy_unavailable")["status"] == "warn"


def test_unsafe_names_are_stable_hashes_and_text_keeps_the_whole_owner_action(tmp_path, monkeypatch):
    import re

    secret = "ghp_" + "a" * 20
    _quiet_tree(monkeypatch)
    table = _clean_table(tmp_path)
    table[doctor_git._BRANCH] = _cp(doctor_git._BRANCH, secret.encode() + b"\n")
    seams = _clean_seams()
    seams["_policy"] = lambda *args: {secret: "signature", "*": "none"}
    seams["_leases"] = lambda root: team.LeaseSet((), (team.Unreadable(secret, "refs/aegis/lanes/" + secret, "d" * 40, "bad"),))
    _install_git(monkeypatch, table, seams)
    monkeypatch.setattr(doctor_git, "_scandir", lambda target: [doctor_git._Snap(secret, stat.S_IFREG, 100 * 1024 * 1024)])
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    target = report["approval_modes"]["target"]
    assert re.fullmatch("[0-9a-f]{12}", target)
    assert report["approval_modes"]["patterns"][0]["pattern"] == target
    assert _row(report, "large_path")["detail"] == "large file " + target
    output = io.StringIO()
    doctor_git._print_report(report, output)
    assert _row(report, "lease_unreadable")["owner_action"] in output.getvalue()
    assert secret not in _blob(report) and secret not in output.getvalue()


def test_invalid_utf8_signer_blob_is_unknown(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    _install_git(monkeypatch, _clean_table(tmp_path), _clean_seams())
    monkeypatch.setattr(doctor_git, "_signers", lambda root, commit: doctor_git._signers_at(root, commit))
    monkeypatch.setattr(doctor_git, "_invoke", lambda *args: _cp(args, b"100644 blob " + b"b" * 40 + b"\tallowed_signers\0"))
    monkeypatch.setattr(doctor_git, "_blob_sizes", lambda root, oids: {"b" * 40: 1})
    monkeypatch.setattr(doctor_git, "_read_object", lambda *args: b"\xff")
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "signers_absent" not in _codes(report)
    assert _row(report, "signers_unavailable")["status"] == "warn"


def test_unknown_rows_name_recovery_instead_of_mutating_cleanup(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    table = _clean_table(tmp_path)
    table[doctor_git._WORKTREES] = "git_timeout"
    table[doctor_git._OBJECTS] = "git_failed"
    _install_git(monkeypatch, table, _clean_seams())
    monkeypatch.setattr(doctor_git, "_scratch_choice", lambda: ("code", "scratch_unusable"))
    rows = doctor_git.collect(tmp_path, tier="A", now=10)["rows"]
    for row in rows:
        if row["id"] in ("scratch", "disk_budget"):
            assert row["owner_action"] == doctor_git._SCRATCH_ACT
        if row["id"] in ("worktrees", "git_objects"):
            assert row["owner_action"] == doctor_git._RETRY


@pytest.mark.parametrize("reason", ["other_owner", "access_denied"])
def test_scratch_requires_ownership_and_actual_write_access(tmp_path, monkeypatch, reason):
    if not doctor_git.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch custody descriptors unsupported")
    scratch = _outside_dir(tmp_path, "access-")

    def file_stat(fd):
        info = os.fstat(fd)
        return types.SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino,
                                     st_mode=info.st_mode, st_uid=info.st_uid + 1)

    if reason == "other_owner":
        monkeypatch.setattr(doctor_git, "os", types.SimpleNamespace(**{**vars(os), "fstat": file_stat}))
    else:
        monkeypatch.setattr(doctor_git, "os", types.SimpleNamespace(**{**vars(os), "access": lambda *args, **kwargs: False}))
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git, "_run_git", lambda *args: "git_missing")
    monkeypatch.setattr(doctor_git, "_walk", lambda *args: None)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "scratch_unknown" in _codes(report) and "scratch_outside" not in _codes(report)
    assert report["disk"]["budget_slots"] is None


@pytest.mark.parametrize("case,mode,admitted", [
    ("shared_members", 0o770, False),
    ("shared_setgid", 0o2770, False),
    ("owner_supplementary_member", 0o770, False),
    ("private_770", 0o770, False),
    ("private_775", 0o775, False),
    ("private_setgid", 0o2770, False),
    ("partial_accounts_owner_present", 0o770, False),
    ("partial_accounts_owner_present", 0o775, False),
    ("partial_accounts_owner_present", 0o2770, False),
    ("partial_groups_owner_present", 0o770, False),
    ("partial_groups_owner_present", 0o775, False),
    ("partial_groups_owner_present", 0o2770, False),
    ("wrong_primary_gid", 0o770, False),
    ("wrong_group_name", 0o770, False),
    ("other_primary_account", 0o770, False),
    ("same_uid_other_account", 0o770, False),
    ("accounts_empty", 0o770, False),
    ("accounts_owner_missing", 0o770, False),
    ("duplicate_gid", 0o770, False),
    ("boolean_fields", 0o770, False),
    ("groups_lookup_error", 0o770, False),
    ("groups_api_unavailable", 0o770, False),
    ("foreign_owner_gid", 0o770, False),
    ("foreign_group_members", 0o770, False),
    ("foreign_account_gid", 0o770, False),
    ("foreign_accounts_none", 0o770, False),
    ("foreign_accounts_text", 0o770, False),
    ("foreign_accounts_mapping", 0o770, False),
    ("foreign_accounts_number", 0o770, False),
    ("group_lookup_missing", 0o770, False),
    ("group_lookup_error", 0o770, False),
    ("owner_lookup_error", 0o770, False),
    ("accounts_lookup_error", 0o770, False),
    ("group_api_unavailable", 0o770, False),
    ("passwd_api_unavailable", 0o770, False),
    ("world_writable", 0o777, False),
    ("sticky", 0o1770, False),
    ("owner_only", 0o700, True),
    ("owner_group_read", 0o750, True),
])
def test_scratch_group_privacy_covers_all_consumers(tmp_path, monkeypatch, case, mode, admitted):
    if not doctor_git.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch custody descriptors unsupported")
    scratch = _outside_dir(tmp_path, "shared-group-")
    scratch.chmod(mode)
    info = scratch.stat()
    if case == "boolean_fields":
        def file_stat(fd):
            raw = os.fstat(fd)
            return types.SimpleNamespace(st_dev=raw.st_dev, st_ino=raw.st_ino, st_mode=raw.st_mode,
                                         st_uid=1, st_gid=1, st_size=raw.st_size)

        def absent(fd, name):
            raise OSError(errno.ENODATA, "no extended ACL")

        info = types.SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino, st_uid=1, st_gid=1)
        monkeypatch.setattr(doctor_git, "os", types.SimpleNamespace(**{**vars(os), "fstat": file_stat,
                                                                     "geteuid": lambda: 1, "getxattr": absent}))
    owner = types.SimpleNamespace(pw_uid=info.st_uid, pw_gid=info.st_gid, pw_name="owner")
    group = types.SimpleNamespace(gr_gid=info.st_gid, gr_name="owner", gr_mem=[])
    accounts = [owner]
    groups = [group]
    seen = {"lookups": [], "custody": [], "disk": [], "invoke": []}
    secret = "password=hunter2hunter"
    if case in ("shared_members", "shared_setgid"):
        group.gr_mem = ["another"]
    elif case == "owner_supplementary_member":
        group.gr_mem = ["owner"]
    elif case == "wrong_primary_gid":
        owner.pw_gid += 1
    elif case == "wrong_group_name":
        group.gr_name = "shared"
    elif case in ("other_primary_account", "same_uid_other_account"):
        accounts.append(types.SimpleNamespace(pw_uid=info.st_uid + (case == "other_primary_account"),
                                              pw_gid=info.st_gid, pw_name="another"))
    elif case == "accounts_empty":
        accounts = []
    elif case == "accounts_owner_missing":
        accounts = [types.SimpleNamespace(pw_uid=info.st_uid + 1, pw_gid=info.st_gid + 1, pw_name="another")]
    elif case == "duplicate_gid":
        groups.append(types.SimpleNamespace(gr_gid=info.st_gid, gr_name="shared", gr_mem=["another"]))
    elif case == "boolean_fields":
        owner.pw_uid = True
        group.gr_gid = True
    elif case == "foreign_owner_gid":
        owner.pw_gid = str(info.st_gid)
    elif case == "foreign_group_members":
        group.gr_mem = None
    elif case == "foreign_account_gid":
        accounts = [types.SimpleNamespace(pw_uid=info.st_uid, pw_gid=str(info.st_gid), pw_name="owner")]
    elif case == "foreign_accounts_none":
        accounts = None
    elif case == "foreign_accounts_text":
        accounts = ""
    elif case == "foreign_accounts_mapping":
        accounts = {}
    elif case == "foreign_accounts_number":
        accounts = 42

    def owner_lookup(uid):
        seen["lookups"].append("owner")
        assert uid == info.st_uid
        if case == "owner_lookup_error":
            raise KeyError(secret)
        return owner

    def group_lookup(gid):
        seen["lookups"].append("group")
        assert gid == info.st_gid
        if case == "group_lookup_missing":
            raise KeyError(secret)
        if case == "group_lookup_error":
            raise OSError(secret)
        return group

    def account_lookup():
        seen["lookups"].append("accounts")
        if case == "accounts_lookup_error":
            raise OSError(secret)
        return accounts

    def group_enumeration():
        seen["lookups"].append("groups")
        if case == "groups_lookup_error":
            raise OSError(secret)
        return groups

    @contextmanager
    def custody(**kwargs):
        bound = Path(kwargs["scratch"]).stat()
        assert (bound.st_dev, bound.st_ino) == (info.st_dev, info.st_ino)
        seen["custody"].append(kwargs)
        yield

    def disk_usage(fd):
        bound = os.fstat(fd)
        assert (bound.st_dev, bound.st_ino) == (info.st_dev, info.st_ino)
        seen["disk"].append(fd)
        return types.SimpleNamespace(free=doctor_git.RESERVE_BYTES + doctor_git.PEAK_BYTES)

    def invoke(*args):
        seen["invoke"].append(args)
        return _cp(args, code=128)

    # Reproduce the former NSS boundary when present; the AST test below pins its removal.
    # Partial-enumeration cases expose just the owner despite omitted sharing records.
    if hasattr(doctor_git, "grp"):
        monkeypatch.setattr(doctor_git, "grp", None if case == "group_api_unavailable" else types.SimpleNamespace(getgrgid=group_lookup, getgrall=None if case == "groups_api_unavailable" else group_enumeration))
    if hasattr(doctor_git, "pwd"):
        monkeypatch.setattr(doctor_git, "pwd", None if case == "passwd_api_unavailable" else types.SimpleNamespace(getpwuid=owner_lookup, getpwall=account_lookup))
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git, "_invoke", invoke)
    monkeypatch.setattr(doctor_git, "_custody", custody)
    monkeypatch.setattr(doctor_git, "_disk_usage", disk_usage)
    try:
        report = doctor_git.collect(tmp_path, tier="A", now=10)
        standalone = doctor_git._run_git(tmp_path, doctor_git._PRESENCE)
        queries = {} if admitted else {
            "head": doctor_git._head(tmp_path),
            "policy": doctor_git._policy(tmp_path, "a" * 40),
            "signers": doctor_git._signers(tmp_path, "a" * 40),
            "leases": doctor_git._leases(tmp_path),
            "refs": doctor_git._refs(tmp_path, team.LANES_REF),
            "branch": doctor_git._branch_name(tmp_path),
        }
    finally:
        scratch.chmod(0o700)
    assert secret not in _blob(report)
    if admitted:
        assert "scratch_outside" in _codes(report) and "scratch_unknown" not in _codes(report)
        assert report["disk"]["budget_slots"] == 1
        assert len(seen["custody"]) == len(seen["invoke"]) == 2 and len(seen["disk"]) == 1
        assert standalone.returncode == 128
    else:
        assert "scratch_unknown" in _codes(report) and "scratch_outside" not in _codes(report)
        assert _row(report, "scratch_unknown")["owner_action"] == doctor_git._SCRATCH_ACT
        assert report["disk"]["budget_slots"] is None
        assert queries == {"head": "git_failed", "policy": "git_failed", "signers": "git_failed",
                           "leases": "git_failed", "refs": "git_failed", "branch": (None, "git_failed")}
        assert not seen["custody"] and not seen["disk"] and not seen["invoke"]
        assert standalone == "git_failed"
    assert not seen["lookups"]


def test_doctor_scratch_never_imports_account_or_group_databases():
    source = ast.parse((REPO / "aegis_cli" / "doctor_git.py").read_text(encoding="utf-8"))
    imports = []
    for node in ast.walk(source):
        if isinstance(node, ast.Import):
            imports.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append((node.module or "").split(".")[0])
    assert not {"pwd", "grp"}.intersection(imports)
    assert not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "_private_group"
                   for node in ast.walk(source))


@pytest.mark.parametrize("oid_size,quotes,plain,action_size", [
    (40, 77, 4, 511),
    (40, 78, 0, 512),
    (40, 78, 1, 513),
    (64, 73, 0, 511),
    (64, 73, 1, 512),
    (64, 73, 2, 513),
    (40, 100, 0, 622),
    (64, 100, 0, 646),
])
def test_quoted_repair_action_keeps_the_finding(tmp_path, monkeypatch, oid_size, quotes, plain, action_size):
    import shlex

    lane, oid = "q" * plain + "'" * quotes, "a" * oid_size
    ref = "refs/aegis/lanes/" + lane
    expected = "owner action: git update-ref -d %s %s (doctor does not delete refs)" % (shlex.quote(ref), oid)
    assert len(expected) == action_size
    _quiet_tree(monkeypatch)
    seams = _clean_seams()
    seams["_leases"] = lambda root: team.LeaseSet((), (team.Unreadable(lane, ref, oid, "bad"),))
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    rows = [row for row in report["rows"] if row["code"] == "lease_unreadable"]
    assert len(rows) == 1
    action = rows[0]["owner_action"]
    assert len(action) <= doctor_git.VALUE_MAX and action != doctor_git._RETRY
    if action_size <= doctor_git.VALUE_MAX:
        assert action == expected
        argv = shlex.split(action.removeprefix("owner action: ").split(" (doctor", 1)[0])
        assert argv == ["git", "update-ref", "-d", ref, oid]
    else:
        assert "git for-each-ref refs/aegis/lanes" in action
        assert "git update-ref -d REF OID" in action and oid in action
    output = io.StringIO()
    doctor_git._print_report(report, output)
    assert action in output.getvalue()


@pytest.mark.parametrize("mode", [0o700, 0o750, 0o770, 0o775, 0o2770])
@pytest.mark.parametrize("case,names,admitted", [
    ("named_user_access", ["system.posix_acl_access"], False),
    ("named_group_access", ["system.posix_acl_access"], False),
    ("default_acl", ["system.posix_acl_default"], False),
    ("lookup_error", [], False),
    ("missing_api", [], False),
    ("unsupported_platform", [], False),
    ("foreign_result", {}, False),
    ("acl_free", [], True),
    ("unrelated_xattr", ["user.note"], True),
])
def test_scratch_acl_privacy_covers_all_consumers(tmp_path, monkeypatch, mode, case, names, admitted):
    if not doctor_git.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch custody descriptors unsupported")
    scratch = _outside_dir(tmp_path, "acl-")
    scratch.chmod(mode)
    admitted = admitted and not mode & stat.S_IWGRP
    info = scratch.stat()
    owner = types.SimpleNamespace(pw_uid=info.st_uid, pw_gid=info.st_gid, pw_name="owner")
    group = types.SimpleNamespace(gr_gid=info.st_gid, gr_name="owner", gr_mem=[])
    seen = {"acl": [], "custody": [], "disk": [], "invoke": []}
    secret = "password=hunter2hunter"

    def attributes(fd, name):
        assert isinstance(fd, int)
        bound = os.fstat(fd)
        assert (bound.st_dev, bound.st_ino) == (info.st_dev, info.st_ino)
        seen["acl"].append(fd)
        if case == "lookup_error":
            raise OSError(errno.EACCES, secret)
        if case == "foreign_result":
            return None
        if name in names:
            return b"named-user or named-group ACL"
        raise OSError(errno.ENODATA, "no extended ACL")

    @contextmanager
    def custody(**kwargs):
        seen["custody"].append(kwargs)
        yield

    def usage(fd):
        seen["disk"].append(fd)
        return types.SimpleNamespace(free=doctor_git.RESERVE_BYTES + doctor_git.PEAK_BYTES)

    def invoke(*args):
        seen["invoke"].append(args)
        return _cp(args, code=128)

    monkeypatch.setattr(doctor_git, "os", types.SimpleNamespace(**{**vars(os), "getxattr": None if case == "missing_api" else attributes}))
    monkeypatch.setattr(doctor_git, "sys", types.SimpleNamespace(**{**vars(sys), "platform": "darwin" if case == "unsupported_platform" else "linux"}))
    if hasattr(doctor_git, "grp"):
        monkeypatch.setattr(doctor_git, "grp", types.SimpleNamespace(getgrgid=lambda gid: group, getgrall=lambda: [group]))
    if hasattr(doctor_git, "pwd"):
        monkeypatch.setattr(doctor_git, "pwd", types.SimpleNamespace(getpwuid=lambda uid: owner, getpwall=lambda: [owner]))
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git, "_custody", custody)
    monkeypatch.setattr(doctor_git, "_disk_usage", usage)
    monkeypatch.setattr(doctor_git, "_invoke", invoke)
    try:
        report = doctor_git.collect(tmp_path, tier="A", now=10)
        standalone = doctor_git._run_git(tmp_path, doctor_git._PRESENCE)
    finally:
        scratch.chmod(0o700)
    assert secret not in _blob(report)
    if admitted:
        assert "scratch_outside" in _codes(report) and report["disk"]["budget_slots"] == 1
        assert len(seen["custody"]) == len(seen["invoke"]) == 2 and len(seen["disk"]) == 1
        assert standalone.returncode == 128
    else:
        assert "scratch_unknown" in _codes(report) and "scratch_outside" not in _codes(report)
        assert _row(report, "scratch_unknown")["owner_action"] == doctor_git._SCRATCH_ACT
        assert report["disk"]["budget_slots"] is None
        assert not seen["custody"] and not seen["disk"] and not seen["invoke"]
        assert standalone == "git_failed"
    expected_probes = 0 if mode & stat.S_IWGRP or case in ("missing_api", "unsupported_platform") else 4 if case in ("default_acl", "acl_free", "unrelated_xattr") else 2
    assert len(seen["acl"]) == expected_probes


@pytest.mark.parametrize("oid_size", [40, 64])
@pytest.mark.parametrize("key", ["token=", "password=", "secret="])
@pytest.mark.parametrize("at_ref_limit", [False, True])
def test_contextual_redaction_uses_private_repair(tmp_path, monkeypatch, oid_size, key, at_ref_limit):
    prefix = "refs/aegis/lanes/"
    lane = "q" * (doctor_git.DISPLAY_MAX - len(prefix) - len(key) - 1) + "/" + key if at_ref_limit else key
    ref, oid = prefix + lane, "a" * oid_size
    _quiet_tree(monkeypatch)
    seams = _clean_seams()
    seams["_leases"] = lambda root: team.LeaseSet((), (team.Unreadable(lane, ref, oid, "bad"),))
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    action = _row(report, "lease_unreadable")["owner_action"]
    assert "git for-each-ref refs/aegis/lanes" in action
    assert "git update-ref -d REF OID" in action and oid in action
    assert doctor_git.display(action, max_len=doctor_git.VALUE_MAX) == (action, None)
    output = io.StringIO()
    doctor_git._print_report(report, output)
    assert action.encode("utf-8") in output.getvalue().encode("utf-8")


@pytest.mark.parametrize("oid_size,quotes,plain,action_size", [
    (40, 75, 1, 511),
    (40, 75, 2, 512),
    (40, 75, 3, 513),
    (64, 70, 2, 511),
    (64, 70, 3, 512),
    (64, 70, 4, 513),
])
def test_changed_action_at_length_boundary_uses_private_repair(tmp_path, monkeypatch, oid_size, quotes, plain, action_size):
    import shlex

    lane, oid = "q" * plain + "password=abcd" + "'" * quotes, "a" * oid_size
    ref = "refs/aegis/lanes/" + lane
    candidate = "owner action: git update-ref -d %s %s (doctor does not delete refs)" % (shlex.quote(ref), oid)
    assert len(candidate) == action_size
    assert doctor_git.display(candidate, max_len=doctor_git.VALUE_MAX) != (candidate, None)
    _quiet_tree(monkeypatch)
    seams = _clean_seams()
    seams["_leases"] = lambda root: team.LeaseSet((), (team.Unreadable(lane, ref, oid, "bad"),))
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    action = _row(doctor_git.collect(tmp_path, tier="A", now=10), "lease_unreadable")["owner_action"]
    assert "git for-each-ref refs/aegis/lanes" in action and oid in action
    assert doctor_git.display(action, max_len=doctor_git.VALUE_MAX) == (action, None)


@pytest.mark.parametrize("lane", ["token", "password", "secret"])
@pytest.mark.parametrize("state,code,detail", [
    ("expired", "expired_lease", "a lane lease is expired"),
    ("unreadable", "lease_unreadable", "a lane ref is not a readable lease"),
])
def test_contextual_redaction_uses_fixed_finding_text(tmp_path, monkeypatch, lane, state, code, detail):
    _quiet_tree(monkeypatch)
    seams = _clean_seams()
    found = team.LeaseSet((_lease(lane, "lane/" + lane, 1, 1),), ()) if state == "expired" else team.LeaseSet(
        (), (team.Unreadable(lane, "refs/aegis/lanes/" + lane, "a" * 40, "bad"),))
    seams["_leases"] = lambda root: found
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    row = _row(report, code)
    assert row["detail"] == detail
    assert "REDACTED" not in row["detail"]
    output = io.StringIO()
    doctor_git._print_report(report, output)
    assert detail in output.getvalue()


def test_token_assignment_ref_with_existing_object_uses_private_repair(tmp_path, monkeypatch):
    import shutil

    if not doctor_git.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch custody descriptors unsupported")
    if not shutil.which("git"):
        pytest.skip("git unavailable")
    scratch = _outside_dir(tmp_path, "token-ref-")
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    assert gitsafe.run(["init"], tmp_path).returncode == 0
    oid = gitsafe.run_checked(["hash-object", "-w", "--stdin"], tmp_path, stdin=b"malformed lease").stdout.decode().strip()
    ref = "refs/aegis/lanes/token="
    assert gitsafe.run(["check-ref-format", ref], tmp_path).returncode == 0
    assert gitsafe.run(["update-ref", ref, oid], tmp_path).returncode == 0
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    action = _row(report, "lease_unreadable")["owner_action"]
    assert "git for-each-ref refs/aegis/lanes" in action and oid in action
    assert "REDACTED" not in action
    assert gitsafe.read_ref(tmp_path, ref) == oid


@pytest.mark.parametrize("kind,code", [("large", "depth_capped"), ("symlink", "depth_capped"), ("unreadable", "unreadable_path")])
def test_unmeasured_directories_never_leave_the_report_passing(tmp_path, monkeypatch, kind, code):
    if not doctor_git.descriptor_support():
        pytest.skip("directory descriptors unsupported")
    if kind == "unreadable" and (os.name != "posix" or os.geteuid() == 0):
        pytest.skip("mode 000 is not a denial for this user")
    real_identity, real_confined = doctor_git._directory_identity, doctor_git._confined
    _quiet_tree(monkeypatch)
    monkeypatch.setattr(doctor_git, "_directory_identity", real_identity)
    monkeypatch.setattr(doctor_git, "_confined", real_confined)
    monkeypatch.setattr(doctor_git, "_scandir", os.scandir)
    _install_git(monkeypatch, _clean_table(tmp_path), _clean_seams())
    assert doctor_git.collect(tmp_path, tier="A", now=10)["status"] == "pass"
    if kind == "unreadable":
        locked = tmp_path / "locked"
        locked.mkdir()
        locked.chmod(0)
        try:
            report = doctor_git.collect(tmp_path, tier="A", now=10)
        finally:
            locked.chmod(0o700)
    else:
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        if kind == "large":
            with (deep / "blob.bin").open("wb") as handle:
                handle.truncate(doctor_git.LARGE_BYTES)
        else:
            target = tmp_path / "target"
            target.write_bytes(b"x")
            symlink_or_skip(target, deep / "blob.bin")
        report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert report["status"] == "warn"
    row = _row(report, code)
    assert row["status"] == "warn"
    assert row["owner_action"] == "owner action: inspect unmeasured workspace paths manually"


def test_custody_and_disk_keep_the_same_descriptor_after_path_replacement(tmp_path, monkeypatch):
    if not doctor_git.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch custody descriptors unsupported")
    scratch = _outside_dir(tmp_path, "identity-")
    symlink_or_skip(tmp_path, tmp_path / "link-probe", target_is_directory=True)
    original = scratch.stat()
    identity = (original.st_dev, original.st_ino)
    used = []

    @contextmanager
    def custody(**kwargs):
        if not used:
            scratch.rename(scratch.with_name(scratch.name + "-held"))
            symlink_or_skip(tmp_path, scratch, target_is_directory=True)
        info = Path(kwargs["scratch"]).stat()
        assert (info.st_dev, info.st_ino) == identity
        used.append(kwargs["scratch"])
        yield

    def usage(fd):
        assert isinstance(fd, int)
        info = os.fstat(fd)
        assert (info.st_dev, info.st_ino) == identity
        return types.SimpleNamespace(free=doctor_git.RESERVE_BYTES + doctor_git.PEAK_BYTES)

    table, seams = _clean_table(tmp_path), _clean_seams()
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git, "_custody", custody)
    monkeypatch.setattr(doctor_git, "_invoke", lambda args, root: table[tuple(args)])
    monkeypatch.setattr(doctor_git, "_head", seams["_head"])
    monkeypatch.setattr(doctor_git, "_policy", seams["_policy"])
    monkeypatch.setattr(doctor_git, "_signers", seams["_signers"])
    monkeypatch.setattr(doctor_git, "_leases", seams["_leases"])
    monkeypatch.setattr(doctor_git, "_refs", seams["_refs"])
    monkeypatch.setattr(doctor_git, "_disk_usage", usage)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert used and len(set(used)) == 1
    assert "scratch_outside" in _codes(report) and report["disk"]["budget_slots"] == 1
    assert sorted(path.name for path in tmp_path.iterdir()) == ["link-probe"]


def test_unreadable_invalid_ref_repair_command_works_in_a_fresh_repository(tmp_path, monkeypatch):
    import shlex
    import shutil

    if not doctor_git.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch custody descriptors unsupported")
    if not shutil.which("git"):
        pytest.skip("git unavailable")
    scratch = _outside_dir(tmp_path, "repair-")
    monkeypatch.setattr(doctor_git, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    assert gitsafe.run(["init"], tmp_path).returncode == 0
    oid = gitsafe.run_checked(["hash-object", "-w", "--stdin"], tmp_path, stdin=b"malformed lease").stdout.decode().strip()
    ref = "refs/aegis/lanes/UPPER;literal"
    assert gitsafe.run(["update-ref", ref, oid], tmp_path).returncode == 0
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    action = _row(report, "lease_unreadable")["owner_action"]
    argv = shlex.split(action.removeprefix("owner action: ").split(" (doctor", 1)[0])
    assert argv == ["git", "update-ref", "-d", ref, oid]
    assert gitsafe.read_ref(tmp_path, ref) == oid
    assert gitsafe.run(argv[1:], tmp_path).returncode == 0
    assert gitsafe.read_ref(tmp_path, ref) is None
