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

from aegis_cli import doctor_git, doctor_git_observe, doctor_git_report
from aegis_core import gitsafe, gitsafe_run, human_gate, primitives, team
from conftest import symlink_or_skip

REPO = Path(__file__).resolve().parents[3]
DOCTOR_GIT_MODULES = ("doctor_git.py", "doctor_git_observe.py", "doctor_git_report.py")


@pytest.fixture(autouse=True)
def acl_lookup_boundary(monkeypatch):
    def absent(fd, name):
        assert isinstance(fd, int)
        raise OSError(errno.ENODATA, "no extended ACL")

    monkeypatch.setattr(doctor_git_observe, "os", types.SimpleNamespace(**{**vars(os), "getxattr": absent}))


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
    monkeypatch.setattr(doctor_git_observe, "_disk_usage", lambda path: types.SimpleNamespace(
        total=10 ** 15, used=1, free=doctor_git_observe.RESERVE_BYTES + doctor_git_observe.PEAK_BYTES * doctor_git_observe.MAX_HEAVY))
    monkeypatch.setattr(doctor_git_observe, "_scratch_choice", lambda: ("path", "/var/empty/aegis-scratch-outside"))
    monkeypatch.setattr(doctor_git_observe, "_hold_scratch", lambda path: (-1, 1, 1))
    monkeypatch.setattr(doctor_git_observe, "_scratch_ok", lambda root, fd, dev, ino: "/proc/self/fd/1")
    monkeypatch.setattr(doctor_git_observe, "descriptor_support", lambda: True)
    monkeypatch.setattr(doctor_git_observe, "_directory_identity", lambda root, parts: (1, 1))
    monkeypatch.setattr(doctor_git_observe, "_scandir", lambda path: [])
    monkeypatch.setattr(doctor_git_observe, "_confined", _scripted_hold)


def _install_git(monkeypatch, table, seams):
    def run(_root, args):
        return table[tuple(args)]

    monkeypatch.setattr(doctor_git, "_run_git", run)
    monkeypatch.setattr(doctor_git, "_head", seams["_head"])
    monkeypatch.setattr(doctor_git, "_policy", seams["_policy"])
    monkeypatch.setattr(doctor_git, "_signers", seams["_signers"])
    monkeypatch.setattr(doctor_git, "_leases", seams["_leases"])
    monkeypatch.setattr(doctor_git, "_refs", seams["_refs"])
    if "_team_profile" in seams:
        monkeypatch.setattr(doctor_git, "_team_profile", seams["_team_profile"])


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
    shown, code = doctor_git_report.display("never\nevil")
    assert shown is None and code == "multiline_refused"
    # Existing fields keep the tip renderer: U+2028 stays, a vertical tab is stripped, not refused.
    shown, code = doctor_git_report.display("never\u2028evil")
    assert code is None and shown == "never\u2028evil"
    shown, code = doctor_git_report.display("never\vevil")
    assert code is None and shown == "neverevil"
    shown, code = doctor_git_report.display_target("never\u2028evil")
    assert shown is None and code == "multiline_refused"
    shown, code = doctor_git_report.display_target("never\vevil")
    assert shown is None and code == "multiline_refused"
    token = "ghp_" + ("A" * 20)
    shown, code = doctor_git_report.display("\x1b[31m" + token + "\x1b[0m")
    assert code is None and token not in shown and "REDACTED" in shown
    hidden = "ghp_\u202e" + ("A" * 20)
    shown, code = doctor_git_report.display_target(hidden)
    assert code is None and shown == "ghp_REDACTED" and hidden not in shown and "\u202e" not in shown
    shown, code = doctor_git_report.display("a" * (doctor_git.VALUE_MAX + 1))
    assert shown is None and code == "value_too_long"
    shown, code = doctor_git_report.display("b" * 200, max_len=16)
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
    assert report["status"] == "warn"
    assert report["git"]["present"] is True
    assert report["git"]["worktree_prune_expire"] == "never"
    assert report["git"]["prunable_count"] == 0
    assert report["disk"]["budget_slots"] == doctor_git_observe.MAX_HEAVY
    assert report["approval_modes"]["effective"] == "signature"
    assert {row["code"] for row in report["rows"] if row["status"] == "warn"} == {"approval_targets"}
    assert _row(report, "approval_mode")["status"] == "pass"
    assert _row(report, "approval_mode")["detail"] == "effective approval mode signature"
    assert _row(report, "approval_targets")["detail"] == "lose the gate: * none, develop review, release/** review"
    assert report["affects_exit"] is False
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
    monkeypatch.setattr(doctor_git_observe, "LARGE_BYTES", 8)
    (tmp_path / "big.bin").write_bytes(b"password=hunter2hunter-body")
    monkeypatch.setattr(doctor_git_observe, "_disk_usage", lambda path: types.SimpleNamespace(total=10, used=10, free=0))
    monkeypatch.setattr(doctor_git_observe, "_directory_identity", lambda root, parts: (1, 1))
    monkeypatch.setattr(doctor_git_observe, "_scandir", os.scandir)
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
    if not doctor_git_observe.descriptor_support():
        pytest.skip("descriptor walk unsupported")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "note.txt").write_text("password=hunter2hunter\n", encoding="utf-8")
    os.chmod(locked, 0)
    real_identity, real_confined = doctor_git_observe._directory_identity, doctor_git_observe._confined
    try:
        _quiet_tree(monkeypatch)
        monkeypatch.setattr(doctor_git_observe, "_directory_identity", real_identity)
        monkeypatch.setattr(doctor_git_observe, "_scandir", os.scandir)
        monkeypatch.setattr(doctor_git_observe, "_confined", real_confined)
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
    seams["_team_profile"] = lambda root, commit: True
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    report = doctor_git.collect(tmp_path, tier="B", now=10)
    row = _row(report, "no_approval_map")
    assert row["status"] == "pass"
    assert row["detail"] == "legacy gating (no map)"
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
            assert row["owner_action"] == doctor_git_report.RETRY
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
    monkeypatch.setattr(doctor_git_observe, "_scratch_choice", lambda: ("code", "scratch_unusable"))
    report = doctor_git.collect(tmp_path, tier="C", now=10)
    assert "scratch_unusable" in _codes(report)
    monkeypatch.setattr(doctor_git_observe, "_scratch_choice", lambda: ("code", "multiline_refused"))
    report = doctor_git.collect(tmp_path, tier="C", now=10)
    assert "multiline_refused" in _codes(report)
    assert "evil" not in _blob(report)


def test_scratch_choice_refuses_multiline_and_relative_values(monkeypatch):
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": "rel/scratch"})
    assert doctor_git_observe._scratch_choice() == ("code", "scratch_unusable")
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": "/tmp/ok\nevil"})
    assert doctor_git_observe._scratch_choice() == ("code", "multiline_refused")


def test_descriptor_probe_false_does_not_open(tmp_path, monkeypatch):
    opened = []
    monkeypatch.setattr(doctor_git_observe, "descriptor_support", lambda: False)
    monkeypatch.setattr(doctor_git_observe, "_confined", lambda *args, **kwargs: opened.append(args))
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    monkeypatch.setattr(doctor_git_observe, "_disk_usage", lambda path: types.SimpleNamespace(
        total=10, used=1, free=doctor_git_observe.RESERVE_BYTES + doctor_git_observe.PEAK_BYTES))
    monkeypatch.setattr(doctor_git_observe, "_scratch_choice", lambda: ("path", "/var/empty/aegis-scratch-outside"))
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert opened == []
    assert "descriptor_unsupported" in _codes(report)
    _assert_rows(report)


def test_symlink_refusal_closes_descriptors_and_hides_the_target(tmp_path, monkeypatch):
    if not doctor_git_observe.descriptor_support():
        pytest.skip("descriptor walk unsupported")
    if not os.path.isdir("/proc/self/fd"):
        pytest.skip("no file-descriptor table")
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "note.txt").write_text("password=hunter2hunter\n", encoding="utf-8")
    symlink_or_skip(secret, tmp_path / "link")
    real_identity, real_confined = doctor_git_observe._directory_identity, doctor_git_observe._confined
    _quiet_tree(monkeypatch)
    monkeypatch.setattr(doctor_git_observe, "_directory_identity", real_identity)
    monkeypatch.setattr(doctor_git_observe, "_scandir", os.scandir)
    monkeypatch.setattr(doctor_git_observe, "_confined", real_confined)
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
    monkeypatch.setattr(doctor_git_observe, "_directory_identity", identity)
    monkeypatch.setattr(doctor_git_observe, "_scandir", lambda path: [Entry()])
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
    monkeypatch.setattr(doctor_git_observe, "LARGE_BYTES", 32)
    monkeypatch.setattr(doctor_git_observe, "_directory_identity", identity)
    monkeypatch.setattr(doctor_git_observe, "_scandir", listing)
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
    assert found[0] == found[1]
    assert found[0]["affects_exit"] is False and found[0]["status"] == "warn"


def test_real_collect_on_a_non_repo_is_advisory(tmp_path, monkeypatch):
    outside = _outside_dir(tmp_path, "real-")
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})
    report = doctor_git.collect(tmp_path, tier="C", now=10)
    _assert_rows(report)
    blob = _blob(report)
    assert "Traceback" not in blob and "cannot run git" not in blob and "fatal:" not in blob
    if doctor_git_observe.descriptor_support() and os.path.isdir("/proc/self/fd"):
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


def test_product_git_calls_stay_on_the_read_only_allowlist(source_root=REPO):
    allowed = {"rev-parse", "config", "worktree", "count-objects"}
    forbidden = {"prune", "gc", "update-ref", "branch", "clean", "reset", "checkout", "commit", "push"}
    calls = []
    for module_name in DOCTOR_GIT_MODULES:
        source = (source_root / "aegis_cli" / module_name).read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, (ast.Tuple, ast.List)) and node.elts and isinstance(node.elts[0], ast.Constant):
                if node.elts[0].value in allowed or node.elts[0].value in forbidden:
                    calls.append(tuple(elt.value for elt in node.elts if isinstance(elt, ast.Constant)))
        assert "os.open" not in source and "git_executable" not in source and "subprocess" not in source
    assert {command[0] for command in calls} == allowed
    for command in calls:
        assert command[0] in allowed, command
        assert command[0] not in forbidden
        if command[0] == "worktree":
            assert command[1] == "list"
        if command[0] == "config":
            assert command[1] == "--get"


def test_run_doctor_stays_inside_the_function_cap():
    tree = ast.parse((REPO / "aegis_cli" / "doctor.py").read_text(encoding="utf-8"))
    fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run_doctor")
    assert fn.end_lineno - fn.lineno + 1 <= 100
    assert sum(1 for _ in (REPO / "aegis_cli" / "doctor.py").read_text(encoding="utf-8").splitlines()) <= 1000
    assert sum(1 for _ in (REPO / "aegis_cli" / "doctor_git.py").read_text(encoding="utf-8").splitlines()) <= 1000


def test_token_branches_that_redact_together_keep_separate_policy_entries(tmp_path, monkeypatch):
    signature = "ghp_" + ("A" * 20)
    other = "ghp_" + ("B" * 20)
    shown_signature, signature_code = doctor_git_report.display(signature)
    shown_other, other_code = doctor_git_report.display(other)
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
    if not doctor_git_observe.descriptor_support():
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

    monkeypatch.setattr(doctor_git_observe, "LARGE_BYTES", 32)
    monkeypatch.setattr(doctor_git_observe, "_disk_usage", lambda path: types.SimpleNamespace(
        total=10 ** 15, used=1, free=doctor_git_observe.RESERVE_BYTES + doctor_git_observe.PEAK_BYTES))
    monkeypatch.setattr(doctor_git_observe, "_scratch_choice", lambda: ("path", "/var/empty/aegis-scratch-outside"))
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    monkeypatch.setattr(doctor_git_observe, "_scandir", scandir)
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
        if self.n > doctor_git_observe.MAX_ENTRIES + 2:
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
    monkeypatch.setattr(doctor_git_observe, "_scandir", lambda path: listing)
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    report = doctor_git.collect(tmp_path, tier="C", now=10)
    _assert_rows(report)
    assert "scan_capped" in _codes(report)
    assert listing.n <= doctor_git_observe.MAX_ENTRIES + 1


def test_oversized_signer_blob_and_ref_list_are_capped(tmp_path, monkeypatch):
    if not doctor_git_observe.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch descriptors unsupported")
    outside = _outside_dir(tmp_path, "sign-")
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})
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
    shown, code = doctor_git_report.display(secret)
    assert code is None and secret not in shown and "REDACTED" in shown
    entry = types.SimpleNamespace(name=secret)
    entry.is_symlink = lambda: False
    entry.stat = lambda follow_symlinks=True: types.SimpleNamespace(
        st_mode=stat.S_IFREG, st_size=10 ** 9, st_dev=1, st_ino=1)
    _quiet_tree(monkeypatch)
    monkeypatch.setattr(doctor_git_observe, "_scandir", lambda path: [entry])
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
    if not doctor_git_observe.descriptor_support():
        pytest.skip("scratch descriptors unsupported")
    link = tmp_path / "unresolvable-scratch"
    symlink_or_skip(link, link)
    try:
        monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(link)})
        monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
        report = doctor_git.collect(tmp_path, tier="B", now=10)
    finally:
        os.unlink(link)
    assert "scratch_outside" not in _codes(report)
    assert "scratch_inside" not in _codes(report)
    row = _row(report, "scratch_unknown")
    assert row["status"] == "warn" and "unknown" in row["detail"]


def test_scratch_dotdot_is_refused_and_empty_cache_uses_home(monkeypatch):
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": "/tmp/a/../../etc"})
    assert doctor_git_observe._scratch_choice() == ("code", "scratch_unusable")
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"XDG_CACHE_HOME": "", "HOME": "/tmp/home"})
    assert doctor_git_observe._scratch_choice() == ("path", str(Path("/tmp/home") / ".cache" / "aegis"))


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
    if not doctor_git_observe.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch descriptors unsupported")
    outside = _outside_dir(tmp_path, "gate-")
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})
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
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "scratch_inside" not in _codes(report)
    assert "scratch_outside" not in _codes(report)
    row = _row(report, "scratch_unknown")
    assert row["status"] == "warn" and "unknown" in row["detail"]
    assert row["owner_action"].startswith("owner action:")


def test_shared_missing_and_unreadable_scratch_are_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": "/tmp"})
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "scratch_outside" not in _codes(report)
    assert _row(report, "scratch_unknown")["status"] == "warn"

    missing = tmp_path.parent / ("missing-" + tmp_path.name)
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(missing)})
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "scratch_outside" not in _codes(report)
    assert "scratch_unknown" in _codes(report)

    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() == 0:
        return
    locked = _outside_dir(tmp_path, "locked-")
    os.chmod(locked, 0)
    try:
        monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(locked)})
        report = doctor_git.collect(tmp_path, tier="A", now=10)
    finally:
        os.chmod(locked, 0o700)
    assert "scratch_outside" not in _codes(report)
    assert "scratch_unknown" in _codes(report)


def test_symlink_loop_scratch_is_unknown(tmp_path, monkeypatch):
    link = tmp_path / "loop-scratch"
    symlink_or_skip(link, link)
    try:
        monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(link)})
        monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
        report = doctor_git.collect(tmp_path, tier="B", now=10)
    finally:
        os.unlink(link)
    assert "scratch_outside" not in _codes(report)
    assert "scratch_inside" not in _codes(report)
    assert "unknown" in _row(report, "scratch_unknown")["detail"]


def test_full_scratch_filesystem_does_not_admit_heavy_slots(tmp_path, monkeypatch):
    scratch = _outside_dir(tmp_path, "full-")
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")

    def usage(target):
        if isinstance(target, int) and not isinstance(target, bool):
            return types.SimpleNamespace(total=10, used=10, free=0)
        return types.SimpleNamespace(total=10 ** 15, used=1, free=10 ** 15)

    monkeypatch.setattr(doctor_git_observe, "_disk_usage", usage)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "disk_budget" not in _codes(report)
    assert "disk_low" in _codes(report) or "disk_unknown" in _codes(report)


def test_sibling_listing_stops_at_the_entry_cap(tmp_path, monkeypatch):
    cap = doctor_git_observe.MAX_ENTRIES
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
    monkeypatch.setattr(doctor_git_observe, "_scandir", listing)
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    report = doctor_git.collect(tmp_path, tier="C", now=10)
    assert "scan_capped" in _codes(report)
    assert stats["n"] <= cap


def test_oversized_lease_set_is_refused_before_object_reads(tmp_path, monkeypatch):
    if not doctor_git_observe.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch descriptors unsupported")
    outside = _outside_dir(tmp_path, "lease-")
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})
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
    if not doctor_git_observe.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch custody descriptors unsupported")
    workspace = tmp_path / "repo"
    workspace.mkdir()
    outside = _outside_dir(tmp_path, "own-")
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})
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
    shown, code = doctor_git_report.display("REDACTED_" + suffix)
    assert code is None and suffix not in shown and "REDACTED" in shown


def test_surrogate_name_survives_strict_utf8_output(tmp_path, monkeypatch):
    name = "file-\udc80.bin"
    shown, code = doctor_git_report.display(name)
    assert code is None and shown.encode("utf-8")
    entry = types.SimpleNamespace(name=name)
    entry.is_symlink = lambda: False
    entry.stat = lambda follow_symlinks=True: types.SimpleNamespace(
        st_mode=stat.S_IFREG, st_size=10 ** 9, st_dev=1, st_ino=1)
    _quiet_tree(monkeypatch)
    monkeypatch.setattr(doctor_git_observe, "_scandir", lambda path: [entry])
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    buffer = io.BytesIO()
    stream = io.TextIOWrapper(buffer, encoding="utf-8", errors="strict")
    doctor_git_report.print_report(report, stream)
    stream.flush()
    printed = buffer.getvalue().decode("utf-8")
    assert "\udc80" not in printed
    assert "large file" in printed or "refused" in printed


def test_signer_transport_and_symlink_are_unavailable(tmp_path, monkeypatch):
    if not doctor_git_observe.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch descriptors unsupported")
    outside = _outside_dir(tmp_path, "sign2-")
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})

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
    assert row["owner_action"] == doctor_git_report.RETRY
    table[("config", "--get", "gc.worktreePruneExpire")] = "git_timeout"
    _install_git(monkeypatch, table, _clean_seams())
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    row = _row(report, "git_timeout")
    assert row["owner_action"] == doctor_git_report.RETRY
    assert "never" not in row["owner_action"]


def test_swap_between_hold_and_identity_is_refused(tmp_path, monkeypatch):
    if not doctor_git_observe.descriptor_support():
        pytest.skip("scratch descriptors unsupported")
    workspace = tmp_path / "ws"
    sub = workspace / "sub"
    sub.mkdir(parents=True)
    (sub / "inside.bin").write_bytes(b"x" * 64)
    outside = tmp_path / "out"
    outside.mkdir()
    moved = {"done": False}
    real_identity = doctor_git_observe._directory_identity

    def identity(root, parts):
        if tuple(parts or ()) == ("sub",) and not moved["done"]:
            moved["done"] = True
            sub.rename(outside / "was-sub")
            (outside / "was-sub" / "outside_injected.bin").write_bytes(b"y" * 80)
            replacement = workspace / "sub"
            replacement.mkdir()
            (replacement / "huge.bin").write_bytes(b"z" * 80)
        return real_identity(root, parts)

    monkeypatch.setattr(doctor_git_observe, "LARGE_BYTES", 32)
    monkeypatch.setattr(doctor_git_observe, "_disk_usage", lambda path: types.SimpleNamespace(
        total=1, used=0, free=10 ** 15))
    monkeypatch.setattr(doctor_git_observe, "_scratch_choice", lambda: ("path", "/var/empty/aegis-scratch-outside"))
    monkeypatch.setattr(doctor_git_observe, "_hold_scratch", lambda path: (None, 1, 1))
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    monkeypatch.setattr(doctor_git_observe, "_directory_identity", identity)
    report = doctor_git.collect(workspace, tier="A", now=10)
    blob = _blob(report)
    assert "outside_injected" not in blob
    assert "huge.bin" not in blob
    assert "path_changed" in _codes(report)


def test_nested_redacted_marker_does_not_keep_a_secret_suffix():
    suffix = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL"
    for text in ("REREDACTEDDACTED_" + suffix, "REDACREDACTEDTED_" + suffix):
        shown, code = doctor_git_report.display(text)
        assert code is None and suffix not in shown and "REDACTED" in shown


def test_shared_alias_inside_and_unwritable_scratch_are_unknown(tmp_path, monkeypatch):
    if os.name != "posix" or not doctor_git_observe.descriptor_support():
        pytest.skip("posix scratch descriptors required")
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: "git_missing")
    for candidate in ("//tmp", "/var/tmp", "/"):
        if not os.path.isdir(candidate):
            continue
        monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda candidate=candidate: {"AEGIS_SCRATCH": candidate})
        report = doctor_git.collect(tmp_path, tier="A", now=10)
        assert "scratch_outside" not in _codes(report)
        assert "scratch_unknown" in _codes(report)
        assert "disk_budget" not in _codes(report)
    nested = tmp_path / "scratch"
    nested.mkdir()
    doubled = "/" + os.path.abspath(nested)
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": doubled})
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "scratch_outside" not in _codes(report)
    assert "scratch_unknown" in _codes(report)
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        return
    wide = _outside_dir(tmp_path, "wide-")
    os.chmod(wide, 0o1777)
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(wide)})
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "scratch_outside" not in _codes(report)
    assert "scratch_unknown" in _codes(report)
    cold = _outside_dir(tmp_path, "cold-")
    os.chmod(cold, 0o555)
    try:
        monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(cold)})
        report = doctor_git.collect(tmp_path, tier="A", now=10)
    finally:
        os.chmod(cold, 0o700)
    assert "scratch_outside" not in _codes(report)
    assert "scratch_unknown" in _codes(report)


def test_lease_cap_uses_the_checked_snapshot(tmp_path, monkeypatch):
    if not doctor_git_observe.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch descriptors unsupported")
    outside = _outside_dir(tmp_path, "grow-")
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})
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

    monkeypatch.setattr(doctor_git_observe, "use_scratch", lambda root: (
        types.SimpleNamespace(code=None, path=str(tmp_path), fd=None, bind=None, owned=False), False))
    monkeypatch.setattr(doctor_git, "_custody", custody)
    assert doctor_git._run_git(tmp_path, doctor_git._PRESENCE) == "git_failed"
    assert seen == []


def test_nonregular_signers_are_unavailable(tmp_path, monkeypatch):
    if not doctor_git_observe.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch descriptors unsupported")
    outside = _outside_dir(tmp_path, "kind-")
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(outside)})
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
    cap = doctor_git_observe.MAX_ENTRIES

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
    monkeypatch.setattr(doctor_git_observe, "_scandir", listing)
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
    assert "approval_mode" not in _codes(report)
    assert _row(report, "branch_unknown")["status"] == "warn"
    assert _row(report, "branch_unknown")["detail"] == "the current branch is unknown"
    assert report["approval_modes"]["effective"] is None
    assert report["approval_modes"]["target"] is None
    assert [item["target"] + " " + item["mode"] for item in report["approval_modes"]["ungated"]] == [
        "* none", "develop review", "release/** review"]
    assert "develop review" in _row(report, "approval_targets")["detail"]
    assert report["affects_exit"] is False


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
    entries = [doctor_git_observe._Snap("sub", stat.S_IFDIR, 0)] + [
        doctor_git_observe._Snap("p%d" % i, stat.S_IFREG, 100 * 1024 * 1024 if i == 254 else 1)
        for i in range(255)]
    monkeypatch.setattr(doctor_git_observe, "_scandir", lambda target: entries if Path(target) == tmp_path else [])
    monkeypatch.setattr(doctor_git, "_run_git", lambda *args: "git_missing")
    report = doctor_git.collect(tmp_path, tier="C", now=10)
    assert "large_path" in _codes(report)
    assert "scan_capped" not in _codes(report)


def test_scratch_duplicate_closes_when_the_anchor_context_fails(tmp_path, monkeypatch):
    if not doctor_git_observe.descriptor_support():
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
        raise doctor_git_observe.ConfinedFileError("io")

    monkeypatch.setattr(doctor_git_observe, "os", types.SimpleNamespace(**{**vars(os), "dup": duplicate}))
    monkeypatch.setattr(doctor_git_observe, "_confined", failing_anchor)
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(tmp_path)})
    monkeypatch.setattr(doctor_git, "_run_git", lambda *args: "git_missing")
    monkeypatch.setattr(doctor_git_observe, "walk", lambda *args: None)
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
    if not doctor_git_observe.descriptor_support():
        pytest.skip("directory descriptors unsupported")
    scratch = _outside_dir(tmp_path, "bind-")
    held = scratch.with_name(scratch.name + "-held")
    symlink_or_skip(tmp_path, tmp_path / "link-probe", target_is_directory=True)
    entered = []

    def unavailable(fd, dev, ino):
        scratch.rename(held)
        symlink_or_skip(tmp_path, scratch, target_is_directory=True)
        return None

    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git_observe, "_bind_fd", unavailable)
    monkeypatch.setattr(doctor_git, "_custody", lambda **kwargs: entered.append(kwargs))
    monkeypatch.setattr(doctor_git_observe, "_disk_usage", lambda target: pytest.fail("unbound scratch measured"))
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "scratch_unknown" in _codes(report) and "scratch_outside" not in _codes(report)
    assert report["disk"]["budget_slots"] is None and entered == []


def test_scratch_validation_error_is_a_refusal_and_closes_the_descriptor(tmp_path, monkeypatch):
    if not doctor_git_observe.descriptor_support():
        pytest.skip("directory descriptors unsupported")
    scratch = _outside_dir(tmp_path, "error-")
    held = []

    def denied(root, fd, dev, ino):
        held.append(fd)
        raise OSError("password=hunter2hunter")

    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git_observe, "_scratch_ok", denied)
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
    monkeypatch.setattr(doctor_git_observe, "_scandir", lambda target: [doctor_git_observe._Snap(secret, stat.S_IFREG, 100 * 1024 * 1024)])
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    target = report["approval_modes"]["target"]
    assert re.fullmatch("[0-9a-f]{12}", target)
    assert report["approval_modes"]["patterns"][0]["pattern"] == target
    assert _row(report, "large_path")["detail"] == "large file " + target
    output = io.StringIO()
    doctor_git_report.print_report(report, output)
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
    monkeypatch.setattr(doctor_git_observe, "_scratch_choice", lambda: ("code", "scratch_unusable"))
    rows = doctor_git.collect(tmp_path, tier="A", now=10)["rows"]
    for row in rows:
        if row["id"] in ("scratch", "disk_budget"):
            assert row["owner_action"] == doctor_git_report.SCRATCH_ACT
        if row["id"] in ("worktrees", "git_objects"):
            assert row["owner_action"] == doctor_git_report.RETRY


@pytest.mark.parametrize("reason", ["other_owner", "access_denied"])
def test_scratch_requires_ownership_and_actual_write_access(tmp_path, monkeypatch, reason):
    if not doctor_git_observe.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch custody descriptors unsupported")
    scratch = _outside_dir(tmp_path, "access-")

    def file_stat(fd):
        info = os.fstat(fd)
        return types.SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino,
                                     st_mode=info.st_mode, st_uid=info.st_uid + 1)

    if reason == "other_owner":
        monkeypatch.setattr(doctor_git_observe, "os", types.SimpleNamespace(**{**vars(os), "fstat": file_stat}))
    else:
        monkeypatch.setattr(doctor_git_observe, "os", types.SimpleNamespace(**{**vars(os), "access": lambda *args, **kwargs: False}))
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git, "_run_git", lambda *args: "git_missing")
    monkeypatch.setattr(doctor_git_observe, "walk", lambda *args: None)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert "scratch_unknown" in _codes(report) and "scratch_outside" not in _codes(report)
    assert report["disk"]["budget_slots"] is None


@pytest.mark.parametrize("mode,admitted", [
    (0o770, False),
    (0o775, False),
    (0o2770, False),
    (0o777, False),
    (0o1770, False),
    (0o700, True),
    (0o750, True),
])
def test_scratch_group_privacy_covers_all_consumers(tmp_path, monkeypatch, mode, admitted):
    if not doctor_git_observe.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch custody descriptors unsupported")
    scratch = _outside_dir(tmp_path, "shared-group-")
    scratch.chmod(mode)
    info = scratch.stat()
    seen = {"custody": [], "disk": [], "invoke": []}

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
        return types.SimpleNamespace(free=doctor_git_observe.RESERVE_BYTES + doctor_git_observe.PEAK_BYTES)

    def invoke(*args):
        seen["invoke"].append(args)
        return _cp(args, code=128)

    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git, "_invoke", invoke)
    monkeypatch.setattr(doctor_git, "_custody", custody)
    monkeypatch.setattr(doctor_git_observe, "_disk_usage", disk_usage)
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
    if admitted:
        assert "scratch_outside" in _codes(report) and "scratch_unknown" not in _codes(report)
        assert report["disk"]["budget_slots"] == 1
        assert len(seen["custody"]) == len(seen["invoke"]) == 2 and len(seen["disk"]) == 1
        assert standalone.returncode == 128
    else:
        assert "scratch_unknown" in _codes(report) and "scratch_outside" not in _codes(report)
        assert _row(report, "scratch_unknown")["owner_action"] == doctor_git_report.SCRATCH_ACT
        assert report["disk"]["budget_slots"] is None
        assert queries == {"head": "git_failed", "policy": "git_failed", "signers": "git_failed",
                           "leases": "git_failed", "refs": "git_failed", "branch": (None, "git_failed")}
        assert not seen["custody"] and not seen["disk"] and not seen["invoke"]
        assert standalone == "git_failed"


def test_doctor_scratch_never_imports_account_or_group_databases(source_root=REPO):
    imports = []
    for module_name in DOCTOR_GIT_MODULES:
        source = ast.parse((source_root / "aegis_cli" / module_name).read_text(encoding="utf-8"))
        for node in ast.walk(source):
            if isinstance(node, ast.Import):
                imports.extend(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append((node.module or "").split(".")[0])
        assert not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "_private_group"
                       for node in ast.walk(source))
    assert not {"pwd", "grp"}.intersection(imports)


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
    assert len(action) <= doctor_git.VALUE_MAX and action != doctor_git_report.RETRY
    if action_size <= doctor_git.VALUE_MAX:
        assert action == expected
        argv = shlex.split(action.removeprefix("owner action: ").split(" (doctor", 1)[0])
        assert argv == ["git", "update-ref", "-d", ref, oid]
    else:
        assert "git for-each-ref refs/aegis/lanes" in action
        assert "git update-ref -d REF OID" in action and oid in action
    output = io.StringIO()
    doctor_git_report.print_report(report, output)
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
    if not doctor_git_observe.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch custody descriptors unsupported")
    scratch = _outside_dir(tmp_path, "acl-")
    scratch.chmod(mode)
    admitted = admitted and not mode & stat.S_IWGRP
    info = scratch.stat()
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
        return types.SimpleNamespace(free=doctor_git_observe.RESERVE_BYTES + doctor_git_observe.PEAK_BYTES)

    def invoke(*args):
        seen["invoke"].append(args)
        return _cp(args, code=128)

    monkeypatch.setattr(doctor_git_observe, "os", types.SimpleNamespace(**{**vars(os), "getxattr": None if case == "missing_api" else attributes}))
    monkeypatch.setattr(doctor_git_observe, "sys", types.SimpleNamespace(**{**vars(sys), "platform": "darwin" if case == "unsupported_platform" else "linux"}))
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git, "_custody", custody)
    monkeypatch.setattr(doctor_git_observe, "_disk_usage", usage)
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
        assert _row(report, "scratch_unknown")["owner_action"] == doctor_git_report.SCRATCH_ACT
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
    assert doctor_git_report.display(action, max_len=doctor_git.VALUE_MAX) == (action, None)
    output = io.StringIO()
    doctor_git_report.print_report(report, output)
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
    assert doctor_git_report.display(candidate, max_len=doctor_git.VALUE_MAX) != (candidate, None)
    _quiet_tree(monkeypatch)
    seams = _clean_seams()
    seams["_leases"] = lambda root: team.LeaseSet((), (team.Unreadable(lane, ref, oid, "bad"),))
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    action = _row(doctor_git.collect(tmp_path, tier="A", now=10), "lease_unreadable")["owner_action"]
    assert "git for-each-ref refs/aegis/lanes" in action and oid in action
    assert doctor_git_report.display(action, max_len=doctor_git.VALUE_MAX) == (action, None)


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
    doctor_git_report.print_report(report, output)
    assert detail in output.getvalue()


def test_token_assignment_ref_with_existing_object_uses_private_repair(tmp_path, monkeypatch):
    import shutil

    if not doctor_git_observe.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch custody descriptors unsupported")
    if not shutil.which("git"):
        pytest.skip("git unavailable")
    scratch = _outside_dir(tmp_path, "token-ref-")
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
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
    if not doctor_git_observe.descriptor_support():
        pytest.skip("directory descriptors unsupported")
    if kind == "unreadable" and (os.name != "posix" or os.geteuid() == 0):
        pytest.skip("mode 000 is not a denial for this user")
    real_identity, real_confined = doctor_git_observe._directory_identity, doctor_git_observe._confined
    _quiet_tree(monkeypatch)
    monkeypatch.setattr(doctor_git_observe, "_directory_identity", real_identity)
    monkeypatch.setattr(doctor_git_observe, "_confined", real_confined)
    monkeypatch.setattr(doctor_git_observe, "_scandir", os.scandir)
    seams = _clean_seams()
    seams["_policy"] = lambda root, commit: {"main": "signature", "*": "signature"}
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
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
                handle.truncate(doctor_git_observe.LARGE_BYTES)
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
    if not doctor_git_observe.descriptor_support() or not os.path.isdir("/proc/self/fd"):
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
        return types.SimpleNamespace(free=doctor_git_observe.RESERVE_BYTES + doctor_git_observe.PEAK_BYTES)

    table, seams = _clean_table(tmp_path), _clean_seams()
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    monkeypatch.setattr(doctor_git, "_custody", custody)
    monkeypatch.setattr(doctor_git, "_invoke", lambda args, root: table[tuple(args)])
    monkeypatch.setattr(doctor_git, "_head", seams["_head"])
    monkeypatch.setattr(doctor_git, "_policy", seams["_policy"])
    monkeypatch.setattr(doctor_git, "_signers", seams["_signers"])
    monkeypatch.setattr(doctor_git, "_leases", seams["_leases"])
    monkeypatch.setattr(doctor_git, "_refs", seams["_refs"])
    monkeypatch.setattr(doctor_git_observe, "_disk_usage", usage)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert used and len(set(used)) == 1
    assert "scratch_outside" in _codes(report) and report["disk"]["budget_slots"] == 1
    assert sorted(path.name for path in tmp_path.iterdir()) == ["link-probe"]


def test_unreadable_invalid_ref_repair_command_works_in_a_fresh_repository(tmp_path, monkeypatch):
    import shlex
    import shutil

    if not doctor_git_observe.descriptor_support() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("scratch custody descriptors unsupported")
    if not shutil.which("git"):
        pytest.skip("git unavailable")
    scratch = _outside_dir(tmp_path, "repair-")
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
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


# Whole-report bytes include the approval_targets row. Tests need no repository history.
_SPLIT_REPORT_BYTES = {'valid_scratch': ('ce67980c506d9555edcbcfdb0198ad522ff2dfd86338e8fdcdb1f18ca3413ded',
                   '6e38ff297896abd3cd5fe49716c20d79b8a01ac8b93e773834f4d7c0da382101'),
 'scratch_unavailable': ('75af40c5c2eb2c18582a56179a6ba6ec0fb9fbb00603874ecc85dcc6484aa530',
                         'ee533501e4bf6fbe1b8a7e2488ec862c2839fdcfcede180f82f5c4d9b5ecadfc'),
 'capped_scan': ('e7cb6e3e895756b0e9c185e4e365dd9d0e95caa6a4b784f2e5744a1cd3318ca1',
                 '707d10a1486842d15e8404e5b8fb4be74d88a13a7e599ce88b1a4d52d4f1243b'),
 'depth_cap': ('70d866c24293cbb9e18b897e28420d797350273518d809ecd202a3af653ee1a4',
               '72322b4b4a8244fb235a36ed76c8fac52c0918c5c70b5d5d0c8e3f5b99df88fa'),
 'swapped_path': ('cdfedc8c0aefca686d819abc0e502803342bf003a1db2901fcbf1d79ecb6c8bb',
                  'f77a64c54bba94e0081aa406c8b4688f3cf212c5a346c6ff9fe00ca04dae56c5'),
 'unavailable_report': ('29fe9401756a6b141be6e71f61ec8d395d1da5340df744dd694607a6678a235f',
                        '9f83b9406083b200822af61b9bf222ef35c2ed9e5dbb2bd17d9bedc655fb0f2a')}


class _ParityEntry:
    def __init__(self, name, mode):
        self.name, self.mode = name, mode

    def is_symlink(self):
        return False

    def stat(self, follow_symlinks=False):
        return types.SimpleNamespace(st_mode=self.mode, st_size=0)


def _split_parity_setup(root, monkeypatch, case):
    _quiet_tree(monkeypatch)
    _install_git(monkeypatch, _clean_table(root), _clean_seams())
    if case == "scratch_unavailable":
        monkeypatch.setattr(doctor_git_observe, "_scratch_choice", lambda: ("code", "scratch_unusable"))
    elif case == "capped_scan":
        monkeypatch.setattr(doctor_git_observe, "MAX_ENTRIES", 1)
        monkeypatch.setattr(doctor_git_observe, "_scandir", lambda fd: [_ParityEntry("a", stat.S_IFREG), _ParityEntry("b", stat.S_IFREG)])
    elif case == "depth_cap":
        monkeypatch.setattr(doctor_git_observe, "MAX_DEPTH", 1)
        monkeypatch.setattr(doctor_git_observe, "_scandir", lambda fd: [_ParityEntry("deep", stat.S_IFDIR)])
    elif case == "swapped_path":
        identities = iter([(1, 1), (2, 2), (3, 3), (4, 4)])
        monkeypatch.setattr(doctor_git_observe, "_directory_identity", lambda root, parts: next(identities))
    elif case == "unavailable_report":
        def unavailable(root):
            raise RuntimeError("private failure")
        monkeypatch.setattr(doctor_git_observe, "trusted_root", unavailable)


@pytest.mark.parametrize("caller", ["collect", "with_report"])
@pytest.mark.parametrize("case", ["valid_scratch", "scratch_unavailable", "capped_scan", "depth_cap", "swapped_path", "unavailable_report"])
def test_split_public_callers_keep_report_bytes(tmp_path, monkeypatch, capsys, caller, case):
    import hashlib

    _split_parity_setup(tmp_path, monkeypatch, case)
    if caller == "collect" and case == "unavailable_report":
        with pytest.raises(RuntimeError, match="^private failure$"):
            doctor_git.collect(tmp_path, tier="B", now=10)
        return
    if caller == "collect":
        report = doctor_git.collect(tmp_path, tier="B", now=10)
        doctor_git_report.print_report(report)
    else:
        payload = {"human_gate": {"tier": "B"}, "summary": {"failed": 2, "warnings": 3}}
        result = doctor_git.with_report(payload, tmp_path, None, False)
        report = result["git_hygiene"]
        assert result["summary"] == {"failed": 2, "warnings": 3 + sum(row["status"] == "warn" for row in report["rows"])}
        assert payload["summary"] == {"failed": 2, "warnings": 3}
    encoded = json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    text = capsys.readouterr().out.encode("utf-8")
    assert (hashlib.sha256(encoded).hexdigest(), hashlib.sha256(text).hexdigest()) == _SPLIT_REPORT_BYTES[case]


def test_split_modules_have_resolvable_exports_and_single_function_owners():
    for module in (doctor_git_observe, doctor_git_report):
        assert module.__all__
        assert all(hasattr(module, name) for name in module.__all__)
    assert doctor_git.collect.__module__ == "aegis_cli.doctor_git"
    assert doctor_git.with_report.__module__ == "aegis_cli.doctor_git"
    assert doctor_git.descriptor_support is doctor_git_observe.descriptor_support
    assert doctor_git.display is doctor_git_report.display


@pytest.mark.parametrize("module_name", DOCTOR_GIT_MODULES)
@pytest.mark.parametrize("mutation", [
    "import pwd\n", "import grp\n", "from grp import getgrgid\n", "def _private_group(): pass\n",
    "async def _private_group(): pass\n", "FORBIDDEN = ('push', 'origin')\n", "os.open(untrusted_path)\n",
])
def test_split_source_guards_reject_mutations_in_every_module(tmp_path, module_name, mutation):
    package = tmp_path / "aegis_cli"
    package.mkdir()
    for name in DOCTOR_GIT_MODULES:
        (package / name).write_text((REPO / "aegis_cli" / name).read_text(encoding="utf-8"), encoding="utf-8")
    guard = (test_product_git_calls_stay_on_the_read_only_allowlist if mutation.startswith(("FORBIDDEN", "os.open"))
             else test_doctor_scratch_never_imports_account_or_group_databases)
    guard(tmp_path)
    target = package / module_name
    target.write_text(target.read_text(encoding="utf-8") + "\n" + mutation, encoding="utf-8")
    with pytest.raises(AssertionError):
        guard(tmp_path)


_UNGATED_ACTION = (
    "owner action: set each listed target to signature and configure signers, "
    "or accept that weakenings to it need only its mode "
    "(doctor does not write configuration)"
)


def _text(report):
    buffer = io.StringIO()
    doctor_git_report.print_report(report, buffer)
    return buffer.getvalue()


def _collect(tmp_path, monkeypatch, policy, signers=2, profile=False, branch=b"main\n"):
    _quiet_tree(monkeypatch)
    table = _clean_table(tmp_path)
    table[doctor_git._BRANCH] = _cp(doctor_git._BRANCH, branch)
    seams = _clean_seams()
    seams["_policy"] = lambda root, commit: policy
    seams["_signers"] = lambda root, commit: signers
    seams["_team_profile"] = lambda root, commit: profile
    _install_git(monkeypatch, table, seams)
    return doctor_git.collect(tmp_path, tier="A", now=10)


def test_no_map_is_legacy_pass_and_suggests_only_with_a_team_profile(tmp_path, monkeypatch):
    report = _collect(tmp_path, monkeypatch, None, profile=False)
    row = _row(report, "no_approval_map")
    assert row == {
        "id": "approvals", "status": "pass", "code": "no_approval_map",
        "owner_action": "owner action: none", "detail": "legacy gating (no map)",
    }
    assert report["approval_modes"] is None
    assert report["affects_exit"] is False
    text = _text(report)
    assert "  [pass] approvals: legacy gating (no map); owner action: none\n" in text
    assert "commit an approvals map" not in text
    report = _collect(tmp_path, monkeypatch, None, profile=True)
    row = _row(report, "no_approval_map")
    assert row["status"] == "pass" and row["detail"] == "legacy gating (no map)"
    assert row["owner_action"] == doctor_git_report.SUGGEST
    assert "does not write" in row["owner_action"]
    text = _text(report)
    assert "  [pass] approvals: legacy gating (no map); " + doctor_git_report.SUGGEST + "\n" in text
    assert json.loads(_blob(report))["rows"][next(
        index for index, item in enumerate(report["rows"]) if item["code"] == "no_approval_map")]["detail"] == row["detail"]


def test_signature_targets_keep_the_gate_with_and_without_signers(tmp_path, monkeypatch, signers=None):
    for count in (0, 2):
        report = _collect(tmp_path, monkeypatch, {"main": "signature", "release/**": "signature"}, signers=count)
        assert report["approval_modes"]["ungated"] == []
        assert report["approval_modes"]["effective"] == "signature"
        row = _row(report, "approval_targets")
        assert row == {
            "id": "approvals", "status": "pass", "code": "approval_targets",
            "owner_action": "owner action: none", "detail": "every target keeps the gate",
        }
        mode = _row(report, "approval_mode")
        assert mode["status"] == "pass" and mode["detail"] == "effective approval mode signature"
        assert ("signers_absent" if count == 0 else "signers_present") in _codes(report)
        text = _text(report)
        assert "  [pass] approvals: every target keeps the gate; owner action: none\n" in text
        assert "lose the gate" not in text and "lose the gate" not in _blob(report)
        assert report["affects_exit"] is False and report["doctor_exit_effect"] == "unchanged"


def test_review_and_none_targets_are_named_in_order(tmp_path, monkeypatch):
    policy = {"zeta": "none", "main": "signature", "alpha": "review", "mid": "none"}
    report = _collect(tmp_path, monkeypatch, policy)
    ungated = [
        {"target": "alpha", "mode": "review"},
        {"target": "mid", "mode": "none"},
        {"target": "zeta", "mode": "none"},
    ]
    assert report["approval_modes"]["ungated"] == ungated
    assert report["approval_modes"]["effective"] == "signature"
    assert report["approval_modes"]["present"] is True
    row = _row(report, "approval_targets")
    detail = "lose the gate: alpha review, mid none, zeta none"
    assert row == {
        "id": "approvals", "status": "warn", "code": "approval_targets",
        "owner_action": _UNGATED_ACTION, "detail": detail,
    }
    assert _row(report, "approval_mode") == {
        "id": "approvals", "status": "pass", "code": "approval_mode",
        "owner_action": "owner action: none", "detail": "effective approval mode signature",
    }
    text = _text(report)
    assert f"  [warn] approvals: {detail}; {_UNGATED_ACTION}\n" in text
    encoded = json.loads(_blob(report))
    assert encoded["approval_modes"]["ungated"] == ungated
    for item in ungated:
        assert f"{item['target']} {item['mode']}" in row["detail"]
        assert f"{item['target']} {item['mode']}" in text
    assert report["affects_exit"] is False


def test_hostile_target_names_are_bounded_in_text_and_json(tmp_path, monkeypatch):
    control = "aa\x01bb"
    ansi = "\x1b[31mred\x1b[0m"
    osc = "\x1b]0;title\x07osc"
    bidi = "na\u202eme"
    wide = "W" * 200
    credential = "token=ghp_" + ("A" * 20)
    label = "approvals"
    policy = {
        control: "none", ansi: "review", osc: "none", bidi: "review", wide: "none",
        credential: "review", label: "none", "caf\u00e9": "none", "main": "signature",
    }
    report = _collect(tmp_path, monkeypatch, policy)
    ungated = report["approval_modes"]["ungated"]
    labels = [item["target"] for item in ungated]
    assert "caf\u00e9" in labels and label in labels
    blob = _blob(report)
    text = _text(report)
    for raw in (control, ansi, osc, wide, credential, "\x1b", "ghp_"):
        assert raw not in blob and raw not in text
    # Tip display() keeps U+202E on pattern rows. The lost-gate names use display_target.
    assert "\u202e" not in text
    assert all("\u202e" not in item["target"] for item in ungated)
    kept = [item for item in report["approval_modes"]["patterns"] if item["pattern"] == bidi]
    assert kept == [{"pattern": bidi, "mode": "review"}]
    published = {doctor_git_report.digest(raw) for raw in (control, ansi, osc, bidi, wide, credential)}
    assert published <= set(labels)
    assert [item["mode"] for item in ungated if item["target"] == "caf\u00e9"] == ["none"]
    assert [item["mode"] for item in ungated if item["target"] == "approvals"] == ["none"]
    row = _row(report, "approval_targets")
    assert row["status"] == "warn" and "\n" not in row["detail"] and len(row["detail"]) <= doctor_git_report.DISPLAY_MAX
    for item in ungated:
        if item["target"] in row["detail"]:
            assert item["target"] in text
    assert _row(report, "approval_mode")["detail"] == "effective approval mode signature"
    assert credential not in row["detail"] and "\x01" not in row["detail"]


def test_oversized_and_invalid_maps_are_refused_without_echo(tmp_path, monkeypatch):
    from aegis_core import approval_policy

    secret = "token=ghp_" + ("B" * 20)
    huge = "N" + ("Q" * 10000)
    cases = (
        {huge: "none", "main": "signature"},
        {f"p{index}": "none" for index in range(approval_policy.MAX_PATTERNS + 1)} | {secret: "review"},
        {"main": "not-a-mode"},
        {},
        {"bad\nname": "none"},
    )
    for policy in cases:
        report = _collect(tmp_path, monkeypatch, policy)
        assert "approval_targets" not in _codes(report)
        assert report["approval_modes"] is None
        blob = _blob(report)
        assert secret not in blob and huge not in blob and "not-a-mode" not in blob and "bad\nname" not in blob
        assert report["affects_exit"] is False
    report = _collect(tmp_path, monkeypatch, "policy_unavailable")
    assert _row(report, "policy_unavailable")["owner_action"] == doctor_git_report.RETRY
    assert "could not be read" in _row(report, "policy_unavailable")["detail"]
    assert "approval_targets" not in _codes(report)


def test_head_map_ignores_a_different_work_tree_config(tmp_path, monkeypatch):
    config = tmp_path / ".aegis"
    config.mkdir()
    (config / "config.json").write_text('{"approvals": {"*": "none", "develop": "review"}}', encoding="utf-8")
    real_policy = doctor_git._policy
    report = _collect(tmp_path, monkeypatch, {"main": "signature", "*": "signature"})
    assert report["approval_modes"]["ungated"] == []
    assert _row(report, "approval_targets")["detail"] == "every target keeps the gate"
    assert "lose the gate" not in _text(report)
    seen = []

    def read_policy(root, commit, strict=True):
        seen.append((str(commit), strict))
        return {"alpha": "none"}

    monkeypatch.setattr(doctor_git, "_policy", real_policy)
    monkeypatch.setattr(doctor_git, "_read_policy", read_policy)
    monkeypatch.setattr(doctor_git, "_regular_entry", lambda *args: ("100644", "b" * 40))
    monkeypatch.setattr(doctor_git, "_scoped", lambda root, produce: produce())
    assert doctor_git._policy(tmp_path, "a" * 40) == {"alpha": "none"}
    assert seen == [("a" * 40, True)]


def test_team_profile_presence_is_the_head_blob(tmp_path, monkeypatch):
    from aegis_core.team_profile import REPO_PATH

    path = "/".join(REPO_PATH)
    real_entry = doctor_git._regular_entry
    seen = []

    def entry(root, commit, name):
        seen.append((commit, name))
        return ("100644", "c" * 40)

    monkeypatch.setattr(doctor_git, "_regular_entry", entry)
    monkeypatch.setattr(doctor_git, "_scoped", lambda root, produce: produce())
    assert doctor_git._team_profile(tmp_path, "a" * 40) is True
    assert seen == [("a" * 40, path)]
    monkeypatch.setattr(doctor_git, "_regular_entry", lambda *args: None)
    assert doctor_git._team_profile(tmp_path, "a" * 40) is False
    monkeypatch.setattr(doctor_git, "_scoped", lambda root, produce: "git_failed")
    assert doctor_git._team_profile(tmp_path, "a" * 40) is False
    line = b"120000 blob " + b"b" * 40 + b"\t" + path.encode() + b"\0"
    monkeypatch.setattr(doctor_git, "_regular_entry", real_entry)
    monkeypatch.setattr(doctor_git, "_invoke", lambda *args: _cp(args, line))
    monkeypatch.setattr(doctor_git, "_scoped", lambda root, produce: produce())
    assert doctor_git._team_profile(tmp_path, "a" * 40) is False


def test_unborn_head_is_not_legacy_gating(tmp_path, monkeypatch):
    report = _collect(tmp_path, monkeypatch, None)
    monkeypatch.setattr(doctor_git, "_head", lambda root: None)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert _row(report, "no_head")["status"] == "warn"
    assert _row(report, "no_head")["detail"] == "HEAD has no commit"
    assert "no_approval_map" not in _codes(report)
    assert "legacy gating" not in _blob(report) and "legacy gating" not in _text(report)


def test_ungated_report_does_not_change_checks_or_exit(tmp_path, monkeypatch):
    _quiet_tree(monkeypatch)
    seams = _clean_seams()
    seams["_policy"] = lambda root, commit: {"develop": "review", "*": "none"}
    _install_git(monkeypatch, _clean_table(tmp_path), seams)
    payload = {"summary": {"passed": 3, "warnings": 1, "failed": 0, "total": 3}, "checks_ok": True}
    out = doctor_git.with_report(dict(payload), tmp_path, None, True)
    assert out["checks_ok"] is True and out["summary"]["failed"] == 0
    assert payload["checks_ok"] is True and payload["summary"]["failed"] == 0
    hygiene = out["git_hygiene"]
    assert hygiene["affects_exit"] is False and hygiene["doctor_exit_effect"] == "unchanged"
    assert _row(hygiene, "approval_targets")["status"] == "warn"
    assert hygiene["approval_modes"]["ungated"] == [
        {"target": "*", "mode": "none"}, {"target": "develop", "mode": "review"}]


def test_partial_doctor_modes_omit_gate_targets(tmp_path, capsys):
    from aegis_cli import doctor

    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")
    for kwargs in (
        {"drivers": True, "json": True, "workspace": str(tmp_path)},
        {"github": True, "json": True, "workspace": str(tmp_path)},
        {"release": "a" * 40, "json": True, "workspace": str(tmp_path)},
    ):
        doctor.run_doctor(argparse.Namespace(**kwargs))
        raw = capsys.readouterr().out
        assert "git_hygiene" not in raw
        assert "legacy gating" not in raw and "lose the gate" not in raw
        assert "approval_targets" not in raw


@pytest.mark.parametrize("mode", ["none", "review"])
@pytest.mark.parametrize("protected", ["n", "main"])
def test_many_ungated_targets_stay_sorted_and_one_line(tmp_path, monkeypatch, mode, protected):
    policy = {f"n{index:02d}": mode for index in range(30)}
    policy[protected] = "signature"
    report = _collect(tmp_path, monkeypatch, policy)
    ungated = report["approval_modes"]["ungated"]
    assert [item["target"] for item in ungated] == [f"n{index:02d}" for index in range(30)]
    assert all(item["mode"] == mode for item in ungated)
    row = _row(report, "approval_targets")
    assert len(row["detail"]) <= doctor_git_report.DISPLAY_MAX
    assert row["detail"].startswith("lose the gate: ") and "+" in row["detail"]
    shown, code = doctor_git_report.display(row["detail"])
    assert code is None and shown == row["detail"]
    text = _text(report)
    assert row["detail"] in text and "\n" not in row["detail"]
    encoded = json.loads(_blob(report))["approval_modes"]["ungated"]
    assert encoded == ungated
    body = row["detail"][len("lose the gate: "):]
    shown, separator, omitted = body.rpartition(" (+")
    assert separator and omitted.endswith(" more)")
    hidden = int(omitted[:-len(" more)")])
    named = [tuple(item.rsplit(" ", 1)) for item in shown.split(", ")]
    assert named and len(named) + hidden == len(ungated)
    for (identifier, shown_mode), item in zip(named, ungated):
        assert identifier in (item["target"], doctor_git_report.digest(item["target"]))
        assert identifier not in ("n", protected) and shown_mode == item["mode"]


def test_many_release_review_targets_keep_complete_identifiers(tmp_path, monkeypatch):
    policy = {f"release/v{index:02d}": "review" for index in range(20)}
    report = _collect(tmp_path, monkeypatch, policy)
    ungated = report["approval_modes"]["ungated"]
    assert ungated == [
        {"target": f"release/v{index:02d}", "mode": "review"} for index in range(20)]
    detail = _row(report, "approval_targets")["detail"]
    assert len(detail) <= doctor_git_report.DISPLAY_MAX
    assert detail.startswith("lose the gate: ")
    body = detail[len("lose the gate: "):]
    shown, separator, omitted = body.rpartition(" (+")
    assert separator and omitted.endswith(" more)")
    hidden = int(omitted[:-len(" more)")])
    named = [tuple(item.rsplit(" ", 1)) for item in shown.split(", ")]
    assert named and hidden > 0 and len(named) + hidden == len(ungated)
    for (identifier, mode), item in zip(named, ungated):
        assert identifier in (item["target"], doctor_git_report.digest(item["target"]))
        assert identifier not in ("main", "r", "re") and mode == "review"
    assert detail in _text(report)
    assert json.loads(_blob(report))["approval_modes"]["ungated"] == ungated


def test_gate_detail_keeps_argon_feature_and_develop_identifiers():
    pairs = [(f"feature/{index:02d}", "none") for index in range(13)] + [("develop", "review")]
    detail = doctor_git_report.gate_detail(pairs)
    assert len(detail) <= doctor_git_report.DISPLAY_MAX
    body = detail[len("lose the gate: "):]
    shown, separator, omitted = body.rpartition(" (+")
    assert separator and omitted.endswith(" more)")
    hidden = int(omitted[:-len(" more)")])
    named = [tuple(item.rsplit(" ", 1)) for item in shown.split(", ")]
    assert named and hidden > 0 and len(named) + hidden == len(pairs)
    for (identifier, mode), (target, expected_mode) in zip(named, pairs):
        assert identifier in (target, doctor_git_report.digest(target))
        assert identifier != "dev" and mode == expected_mode


def test_detached_head_still_names_ungated_targets(tmp_path, monkeypatch):
    policy = {"develop": "review", "main": "signature"}
    report = _collect(tmp_path, monkeypatch, policy, branch=b"HEAD\n")
    assert _row(report, "branch_unknown") == {
        "id": "approvals", "status": "warn", "code": "branch_unknown",
        "owner_action": "owner action: retry aegis doctor",
        "detail": "the current branch is unknown",
    }
    assert "approval_mode" not in _codes(report)
    detail = "lose the gate: develop review"
    assert _row(report, "approval_targets")["detail"] == detail
    assert _row(report, "approval_targets")["status"] == "warn"
    assert report["approval_modes"]["ungated"] == [{"target": "develop", "mode": "review"}]
    assert report["approval_modes"]["effective"] is None
    assert report["approval_modes"]["target"] is None
    assert report["approval_modes"]["present"] is True
    text = _text(report)
    blob = _blob(report)
    assert f"  [warn] approvals: {detail}; {_UNGATED_ACTION}\n" in text
    assert "develop review" in blob
    assert report["affects_exit"] is False
    refused = _collect(tmp_path, monkeypatch, policy, branch=b"bad\nname\n")
    assert _row(refused, "multiline_refused")["detail"] == "the current branch name was refused"
    assert _row(refused, "approval_targets")["detail"] == detail
    assert refused["approval_modes"]["ungated"] == [{"target": "develop", "mode": "review"}]
    assert "approval_mode" not in _codes(refused)


@pytest.mark.parametrize("branch", [b"HEAD\n", b"bad\nname\n"], ids=["detached", "refused"])
@pytest.mark.parametrize("policy,code,detail", [
    (None, "no_approval_map", "legacy gating (no map)"),
    ("policy_unavailable", "policy_unavailable", "the map could not be read"),
    ("invalid_approval_policy", "invalid_approval_policy", "the map was refused"),
    ({}, "invalid_approval_policy", "the map was refused"),
    ({"bad\nname": "none"}, "multiline_refused", "the map was refused"),
], ids=["absent", "unavailable", "invalid", "empty", "refused-name"])
def test_branch_refusal_keeps_map_diagnostics(tmp_path, monkeypatch, branch, policy, code, detail):
    report = _collect(tmp_path, monkeypatch, policy, profile=True, branch=branch)
    rows = [row for row in report["rows"] if row["code"] == code and row["detail"] == detail]
    assert len(rows) == 1
    assert rows[0]["status"] == ("pass" if policy is None else "warn")
    if policy is None:
        assert rows[0]["owner_action"] == doctor_git_report.SUGGEST
    assert detail in _text(report) and detail in _blob(report)
    assert "approval_mode" not in _codes(report) and report["approval_modes"] is None
    branch_code = "branch_unknown" if branch == b"HEAD\n" else "multiline_refused"
    assert branch_code in _codes(report)
    assert report["affects_exit"] is False


@pytest.mark.parametrize("branch", [b"HEAD\n", b"bad\nname\n"], ids=["detached", "refused"])
def test_branch_refusal_keeps_invalid_target_map_error(tmp_path, monkeypatch, branch):
    class Target(str):
        pass

    report = _collect(tmp_path, monkeypatch, {Target("develop"): "none"}, branch=branch)
    row = _row(report, "invalid_approval_policy")
    assert row["status"] == "warn" and row["detail"] == "the map was refused"
    assert row["detail"] in _text(report) and row["detail"] in _blob(report)
    assert "approval_mode" not in _codes(report) and report["approval_modes"] is None
    assert report["affects_exit"] is False


def _live_policy(monkeypatch, tmp_path, invoke):
    """Exercise _policy_at. The _policy seam stays the product function."""
    _quiet_tree(monkeypatch)
    table = _clean_table(tmp_path)
    monkeypatch.setattr(doctor_git, "_run_git", lambda root, args: table[tuple(args)])
    monkeypatch.setattr(doctor_git, "_head", lambda root: "a" * 40)
    monkeypatch.setattr(doctor_git, "_leases", lambda root: team.LeaseSet((), ()))
    monkeypatch.setattr(doctor_git, "_refs", lambda root, prefix: [])
    monkeypatch.setattr(doctor_git, "_signers", lambda root, commit: 0)
    monkeypatch.setattr(doctor_git, "_invoke", invoke)
    monkeypatch.setattr(doctor_git, "_scoped", lambda root, produce: produce())


def test_confirmed_absence_reaches_legacy_pass_without_mocking_policy(tmp_path, monkeypatch):
    from aegis_core.team_profile import REPO_PATH

    profile = "/".join(REPO_PATH)
    _live_policy(monkeypatch, tmp_path, lambda *args: _cp(args, b""))
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert _row(report, "no_approval_map") == {
        "id": "approvals", "status": "pass", "code": "no_approval_map",
        "owner_action": "owner action: none", "detail": "legacy gating (no map)",
    }
    assert "policy_unavailable" not in _codes(report)
    assert report["approval_modes"] is None
    assert "commit an approvals map" not in _text(report)

    def invoke(command, root):
        path = command[-1] if command else ""
        if path == profile:
            line = b"100644 blob " + (b"c" * 40) + b"\t" + profile.encode() + b"\0"
            return _cp(command, line)
        return _cp(command, b"")

    monkeypatch.setattr(doctor_git, "_invoke", invoke)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    row = _row(report, "no_approval_map")
    assert row["status"] == "pass" and row["detail"] == "legacy gating (no map)"
    assert row["owner_action"] == doctor_git_report.SUGGEST
    assert report["affects_exit"] is False


def test_regular_config_without_approvals_is_legacy_pass(tmp_path, monkeypatch):
    path = doctor_git.approval_policy.CONFIG_PATH
    line = b"100644 blob " + (b"b" * 40) + b"\t" + path.encode() + b"\0"
    _live_policy(monkeypatch, tmp_path, lambda *args: _cp(args, line))
    monkeypatch.setattr(doctor_git, "_read_policy", lambda *args, **kwargs: None)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert _row(report, "no_approval_map")["detail"] == "legacy gating (no map)"
    assert _row(report, "no_approval_map")["status"] == "pass"
    assert "policy_unavailable" not in _codes(report)


@pytest.mark.parametrize("mode", ["none", "review"])
def test_one_long_target_does_not_hide_the_others(tmp_path, monkeypatch, mode):
    long = "a" * 160
    policy = {long: mode, "develop": "review", "main": "signature"}
    report = _collect(tmp_path, monkeypatch, policy)
    detail = "lose the gate: " + doctor_git_report.digest(long) + f" {mode}, develop review"
    assert report["approval_modes"]["ungated"] == [
        {"target": long, "mode": mode},
        {"target": "develop", "mode": "review"},
    ]
    row = _row(report, "approval_targets")
    assert row["detail"] == detail
    assert len(row["detail"]) <= doctor_git_report.DISPLAY_MAX
    assert "develop review" in row["detail"] and long not in row["detail"]
    assert row["detail"] != "targets lose the gate"
    text = _text(report)
    blob = _blob(report)
    assert detail in text and detail in blob
    assert json.loads(blob)["approval_modes"]["ungated"][1] == {"target": "develop", "mode": "review"}
    shown, code = doctor_git_report.display(row["detail"])
    assert code is None and shown == row["detail"]


@pytest.mark.parametrize("mode", ["none", "review"])
def test_gate_detail_counts_every_target_when_no_identifier_fits(monkeypatch, mode):
    pairs = tuple((f"long-target-{index:02d}", mode) for index in range(31))
    expected = "lose the gate: (+31 more)"
    monkeypatch.setattr(doctor_git_report, "DISPLAY_MAX", len(expected))
    detail = doctor_git_report.gate_detail(pairs)
    assert detail == expected
    assert len(detail) <= doctor_git_report.DISPLAY_MAX


def test_existing_display_keeps_the_tip_separator_and_targets_do_not(tmp_path, monkeypatch):
    value = "ne\u00a0ver"
    shown, code = doctor_git_report.display(value)
    assert (shown, code) == (value, None)
    kept, kept_code = doctor_git_report.display("never\u2028evil")
    assert kept_code is None and "\u2028" in kept
    target, target_code = doctor_git_report.display_target("never\u2028evil")
    assert target is None and target_code == "multiline_refused"
    hidden = "ghp_\u202e" + ("A" * 20)
    redacted, redacted_code = doctor_git_report.display_target(hidden)
    assert redacted_code is None and redacted == "ghp_REDACTED" and "\u202e" not in redacted
    _quiet_tree(monkeypatch)
    table = _clean_table(tmp_path)
    table[doctor_git._EXPIRE] = _cp(doctor_git._EXPIRE, (value + "\n").encode("utf-8"))
    seams = _clean_seams()
    seams["_policy"] = lambda root, commit: {"main": "signature"}
    _install_git(monkeypatch, table, seams)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert report["git"]["worktree_prune_expire"] == value
    assert _row(report, "prune_expire_set")["detail"] == f"gc.worktreePruneExpire is {value}"
    assert value in _text(report)
    # JSON uses ensure_ascii, so the same character is the \\u00a0 escape, not a raw NBSP.
    assert "\\u00a0" in _blob(report) and "never" not in report["git"]["worktree_prune_expire"]


# Bytes of the git section at the integration tip, before the approvals-target row.
_TIP_REPORT_BYTES = {
    "valid_scratch": ("b995dd699643b23b6fb52b3f148a76927a4dc2773a3a1956a90f1be5ba26ab56",
                      "b2e7f36f4d8188d08efa7d4815a2eac24cc27db6d5c951c208ed39416b21da91"),
    "scratch_unavailable": ("4bd21b32b2780f6f243768afc44594d25517f579c9f3a4be0a636a34d5abab7d",
                            "95bf43c9e41ced93fad50d45fe211fc3b236ce939fb8ed13b348556a565442d8"),
    "capped_scan": ("e0db8329e61aa20d5dbcd917210e17c3974385cfc901b1be15ee7b41327d65cd",
                    "9f3687dca4764b78f65652dbaaf1d31122652aafe82be798fcc8c92cecc2e2da"),
    "depth_cap": ("d4d3a5fbd9a5d68031bd23ac1262ee725cd221a71f55b04ed3f376c1f31070fd",
                  "721e0f7b4c1d5ba69c96b692708a5f3108796084e3248ee81ff924641613e31c"),
    "swapped_path": ("36888513353b4d12c5efccd28518bc730bc98125a06de7469b03c47b82d9c2ef",
                     "80b0e1cb3ee3640f56d48f9801d77150b4aa74654eb622d8a406bc26e53d889e"),
    "unavailable_report": ("29fe9401756a6b141be6e71f61ec8d395d1da5340df744dd694607a6678a235f",
                           "9f83b9406083b200822af61b9bf222ef35c2ed9e5dbb2bd17d9bedc655fb0f2a"),
}


def _without_target_row(report, text):
    import hashlib
    body = json.loads(json.dumps(report))
    body["rows"] = [row for row in body["rows"] if row.get("code") != "approval_targets"]
    body["status"] = "warn" if any(row.get("status") == "warn" for row in body["rows"]) else "pass"
    modes = body.get("approval_modes")
    if isinstance(modes, dict):
        modes.pop("ungated", None)
    encoded = json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    kept = "".join(
        line for line in text.splitlines(keepends=True)
        if "lose the gate:" not in line and "every target keeps the gate" not in line
        and "legacy gating (no map)" not in line)
    return hashlib.sha256(encoded).hexdigest(), hashlib.sha256(kept.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("case", ["valid_scratch", "scratch_unavailable", "capped_scan", "depth_cap", "swapped_path", "unavailable_report"])
def test_existing_git_section_matches_the_tip(tmp_path, monkeypatch, capsys, case):
    _split_parity_setup(tmp_path, monkeypatch, case)
    if case == "unavailable_report":
        payload = {"human_gate": {"tier": "B"}, "summary": {"failed": 2, "warnings": 3}}
        result = doctor_git.with_report(payload, tmp_path, None, False)
        report = result["git_hygiene"]
        text = capsys.readouterr().out
    else:
        report = doctor_git.collect(tmp_path, tier="B", now=10)
        doctor_git_report.print_report(report)
        text = capsys.readouterr().out
    assert _without_target_row(report, text) == _TIP_REPORT_BYTES[case]


def _git_executable_is_regular():
    import shutil
    path = shutil.which("git")
    if not path:
        return False
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode) and os.access(path, os.X_OK)


def _identity_commit(repo, message):
    done = gitsafe.run(
        ["-c", "user.email=aegis-test@example.invalid", "-c", "user.name=Aegis Test",
         "-c", "commit.gpgsign=false", "commit", "-qm", message], repo)
    assert done.returncode == 0, done.stderr


@pytest.fixture
def real_git_repo(tmp_path, monkeypatch):
    if (os.name != "posix" or not doctor_git_observe.descriptor_support()
            or not os.path.isdir("/proc/self/fd")):
        pytest.skip("scratch custody descriptors unsupported")
    if not _git_executable_is_regular():
        pytest.skip("git executable unavailable")
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(scratch)})
    repo = tmp_path / "repo"
    repo.mkdir()
    assert gitsafe.run(["init", "-q"], repo).returncode == 0
    (repo / "README").write_text("pin\n", encoding="utf-8")
    assert gitsafe.run(["add", "--", "README"], repo).returncode == 0
    _identity_commit(repo, "pin")
    return repo


@pytest.fixture
def real_doctor_report(capsys):
    from aegis_cli.doctor import run_doctor

    def report(repo):
        args = argparse.Namespace(json=True, ws=types.SimpleNamespace(root=repo))
        code = run_doctor(args)
        payload = json.loads(capsys.readouterr().out)
        assert code == (1 if payload["summary"]["failed"] else 0)
        args.json = False
        assert run_doctor(args) == code
        text = capsys.readouterr().out
        hygiene = payload["git_hygiene"]
        assert hygiene["git"]["present"] is True, hygiene["rows"]
        assert "scratch_outside" in _codes(hygiene), hygiene["rows"]
        for row in hygiene["rows"]:
            if row["id"] == "approvals":
                assert row["detail"] in text
        return hygiene

    return report


def test_real_repo_probe_unsupported_stays_advisory(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor_git_observe, "descriptor_support", lambda: False)
    monkeypatch.setattr(doctor_git_observe, "_scratch_env", lambda: {"AEGIS_SCRATCH": str(tmp_path)})

    def refuse_git(*args, **kwargs):
        pytest.fail("git must not run without scratch custody descriptors")

    monkeypatch.setattr(doctor_git, "_invoke", refuse_git)
    report = doctor_git.collect(tmp_path, tier="A", now=10)
    assert _row(report, "scratch_unknown")["owner_action"] == doctor_git_report.SCRATCH_ACT
    assert _row(report, "git_failed")["status"] == "warn"
    assert "descriptor_unsupported" in _codes(report)
    assert report["approval_modes"] is None
    assert "no_approval_map" not in _codes(report)
    assert report["affects_exit"] is False and report["doctor_exit_effect"] == "unchanged"


def test_real_repo_without_config_is_legacy_pass(real_git_repo, real_doctor_report):
    report = real_doctor_report(real_git_repo)
    row = _row(report, "no_approval_map")
    assert row["status"] == "pass" and row["detail"] == "legacy gating (no map)"
    assert row["owner_action"] == "owner action: none"
    assert report["approval_modes"] is None
    assert report["affects_exit"] is False
    assert "legacy gating (no map)" in _text(report)


@pytest.mark.parametrize("profile", [False, True])
def test_real_repo_detached_without_config_is_legacy_pass(real_git_repo, real_doctor_report, profile):
    from aegis_core.team_profile import REPO_PATH

    repo = real_git_repo
    if profile:
        path = repo.joinpath(*REPO_PATH)
        path.parent.mkdir(parents=True)
        path.write_text("{}\n", encoding="utf-8")
        assert gitsafe.run(["add", "--", "/".join(REPO_PATH)], repo).returncode == 0
        _identity_commit(repo, "profile without config")
    assert gitsafe.run(["checkout", "--detach", "HEAD"], repo).returncode == 0
    report = real_doctor_report(repo)
    row = _row(report, "no_approval_map")
    assert row["status"] == "pass" and row["detail"] == "legacy gating (no map)"
    assert row["owner_action"] == (doctor_git_report.SUGGEST if profile else doctor_git_report.NONE)
    assert _row(report, "branch_unknown")["detail"] == "the current branch is unknown"
    assert "approval_mode" not in _codes(report) and report["approval_modes"] is None
    assert report["affects_exit"] is False


@pytest.mark.parametrize("detached", [False, True])
def test_real_repo_config_without_approvals_is_legacy_pass(real_git_repo, real_doctor_report, detached):
    repo = real_git_repo
    config = repo / ".aegis" / "config.json"
    config.parent.mkdir(parents=True)
    config.write_text('{"version": 1}\n', encoding="utf-8")
    assert gitsafe.run(["add", "--", ".aegis/config.json"], repo).returncode == 0
    _identity_commit(repo, "config")
    if detached:
        assert gitsafe.run(["checkout", "--detach", "HEAD"], repo).returncode == 0
    report = real_doctor_report(repo)
    row = _row(report, "no_approval_map")
    assert row["status"] == "pass" and row["detail"] == "legacy gating (no map)"
    assert "policy_unavailable" not in _codes(report)
    assert ("branch_unknown" in _codes(report)) is detached
    assert report["affects_exit"] is False


@pytest.mark.parametrize("detached", [False, True])
def test_real_repo_team_profile_suggests_a_map(real_git_repo, real_doctor_report, detached):
    from aegis_core.team_profile import REPO_PATH

    repo = real_git_repo
    config = repo / ".aegis" / "config.json"
    config.parent.mkdir(parents=True)
    config.write_text('{"version": 1}\n', encoding="utf-8")
    profile = repo.joinpath(*REPO_PATH)
    profile.parent.mkdir(parents=True)
    profile.write_text("{}\n", encoding="utf-8")
    assert gitsafe.run(["add", "--", ".aegis/config.json", "/".join(REPO_PATH)], repo).returncode == 0
    _identity_commit(repo, "profile")
    if detached:
        assert gitsafe.run(["checkout", "--detach", "HEAD"], repo).returncode == 0
    report = real_doctor_report(repo)
    row = _row(report, "no_approval_map")
    assert row["status"] == "pass" and row["detail"] == "legacy gating (no map)"
    assert row["owner_action"] == doctor_git_report.SUGGEST
    assert "commit an approvals map" in row["owner_action"]
    assert "does not write" in row["owner_action"]
    assert ("branch_unknown" in _codes(report)) is detached
    assert report["affects_exit"] is False


@pytest.mark.parametrize("detached", [False, True])
def test_real_repo_nonregular_config_stays_refused(real_git_repo, real_doctor_report, detached):
    repo = real_git_repo
    oid = gitsafe.run_checked(
        ["hash-object", "-w", "--stdin"], repo,
        stdin=b'{"approvals": {"develop": "review"}}\n').stdout.decode().strip()
    recorded = gitsafe.run(
        ["update-index", "--add", "--cacheinfo", f"120000,{oid},.aegis/config.json"], repo)
    assert recorded.returncode == 0, recorded.stderr
    _identity_commit(repo, "link")
    if detached:
        assert gitsafe.run(["checkout", "--detach", "HEAD"], repo).returncode == 0
    report = real_doctor_report(repo)
    assert _row(report, "policy_unavailable")["status"] == "warn"
    assert "could not be read" in _row(report, "policy_unavailable")["detail"]
    assert "legacy gating (no map)" not in _blob(report)
    assert "approval_targets" not in _codes(report)
    assert ("branch_unknown" in _codes(report)) is detached
    assert report["affects_exit"] is False


@pytest.mark.parametrize("oversized", [False, True])
def test_real_repo_detached_invalid_config_keeps_map_refusal(real_git_repo, real_doctor_report, oversized):
    from aegis_core.approval_policy import MAX_CONFIG_BYTES

    repo = real_git_repo
    config = repo / ".aegis" / "config.json"
    config.parent.mkdir(parents=True)
    content = {"approvals": {"main": "not-a-mode"}}
    if oversized:
        content = {"approvals": {"main": "none"}, "padding": "X" * (MAX_CONFIG_BYTES + 1)}
    config.write_text(json.dumps(content), encoding="utf-8")
    assert gitsafe.run(["add", "--", ".aegis/config.json"], repo).returncode == 0
    _identity_commit(repo, "invalid config")
    assert gitsafe.run(["checkout", "--detach", "HEAD"], repo).returncode == 0
    report = real_doctor_report(repo)
    row = _row(report, "invalid_approval_policy")
    assert row["status"] == "warn" and row["detail"] == "the map was refused"
    assert "not-a-mode" not in _blob(report)
    assert _row(report, "branch_unknown")["detail"] == "the current branch is unknown"
    assert "approval_mode" not in _codes(report) and report["approval_modes"] is None
    assert report["affects_exit"] is False


def test_real_repo_detached_head_names_ungated_targets(real_git_repo, real_doctor_report):
    repo = real_git_repo
    config = repo / ".aegis" / "config.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        '{"approvals": {"develop": "review", "main": "signature"}}\n', encoding="utf-8")
    assert gitsafe.run(["add", "--", ".aegis/config.json"], repo).returncode == 0
    _identity_commit(repo, "map")
    detached = gitsafe.run(["checkout", "--detach", "HEAD"], repo)
    assert detached.returncode == 0, detached.stderr
    payload = {"summary": {"passed": 1, "warnings": 0, "failed": 0, "total": 1}, "checks_ok": True}
    out = doctor_git.with_report(dict(payload), repo, None, True)
    assert out["checks_ok"] is True and out["summary"]["failed"] == 0
    report = real_doctor_report(repo)
    assert out["git_hygiene"]["approval_modes"] == report["approval_modes"]
    assert _row(report, "branch_unknown")["detail"] == "the current branch is unknown"
    assert "approval_mode" not in _codes(report)
    assert "develop review" in _row(report, "approval_targets")["detail"]
    assert {"target": "develop", "mode": "review"} in report["approval_modes"]["ungated"]
    text = _text(report)
    blob = _blob(report)
    assert "develop review" in text and "develop review" in blob
    assert report["affects_exit"] is False and report["doctor_exit_effect"] == "unchanged"


def test_target_row_spaces_unicode_whitespace_before_redaction(tmp_path, monkeypatch):
    password = "password\u00a0is\u00a0hunter22"
    bearer = "Bearer\u00a01" + ("a" * 19)
    shown, code = doctor_git_report.display_target(password)
    assert code is None and shown == "password is REDACTED" and "hunter22" not in shown
    assert "passwordishunter22" not in shown
    masked, masked_code = doctor_git_report.display_target(bearer)
    assert masked_code is None and masked == "Bearer REDACTED" and "1" + ("a" * 19) not in masked
    # Tip display() still keeps the prune-expire NBSP on the existing row.
    assert doctor_git_report.display("ne\u00a0ver") == ("ne\u00a0ver", None)
    report = _collect(tmp_path, monkeypatch, {password: "none", bearer: "review", "main": "signature"})
    blob = _blob(report)
    text = _text(report)
    assert "hunter22" not in blob and "hunter22" not in text
    assert "1" + ("a" * 19) not in blob and bearer not in text
    assert "passwordishunter22" not in blob and "passwordishunter22" not in text
    detail = _row(report, "approval_targets")["detail"]
    assert "hunter22" not in detail and ";" not in detail
    assert report["affects_exit"] is False


def test_splitlines_breaks_are_refused_and_do_not_pass_the_branch(tmp_path, monkeypatch):
    sample = "never\x85evil"
    assert doctor_git._accepted(sample) == (None, "multiline_refused")
    assert doctor_git._one_line(sample.encode("utf-8")) == (None, "multiline_refused")
    assert doctor_git_report.display_target(sample) == (None, "multiline_refused")
    # Existing fields keep the tip renderer, which strips U+0085 instead of refusing it.
    assert doctor_git_report.display(sample) == ("neverevil", None)
    for char in "\x1c\x1d\x1e\v\f\u2028\u2029":
        assert doctor_git._accepted("never" + char + "evil")[1] == "multiline_refused"
    found = set()
    for code_point in range(0x10000):
        char = chr(code_point)
        if len(("a" + char + "b").splitlines()) > 1:
            found.add(char)
    assert found <= set("\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029")
    report = _collect(
        tmp_path, monkeypatch, {"develop": "review", "main": "signature"},
        branch="feat\u2028evil".encode("utf-8") + b"\n")
    assert "approval_mode" not in _codes(report)
    assert _row(report, "multiline_refused")["status"] == "warn"
    assert _row(report, "multiline_refused")["detail"] == "the current branch name was refused"
    assert "develop review" in _row(report, "approval_targets")["detail"]
    swallowed = _collect(
        tmp_path, monkeypatch, {"develop": "review", "main": "signature"}, branch=b"\x01\n")
    assert "approval_mode" not in _codes(swallowed)
    assert _row(swallowed, "invalid_approval_policy")["status"] == "warn"
    assert "develop review" in _row(swallowed, "approval_targets")["detail"]


def test_forged_target_names_cannot_extend_the_detail(tmp_path, monkeypatch):
    assert doctor_git_report.gate_detail(iter(())) == doctor_git_report.GATED_DETAIL
    forged = ("alpha review, main", "alpha; owner action: evil")
    for name in forged:
        assert doctor_git_report.gate_detail(((name, "none"),)) == "targets lose the gate"
        report = _collect(tmp_path, monkeypatch, {name: "none", "main": "signature"})
        detail = _row(report, "approval_targets")["detail"]
        assert detail == "lose the gate: " + doctor_git_report.digest(name) + " none"
        assert name not in detail and ";" not in detail and "owner action: evil" not in detail
        assert name not in _text(report) and name not in _blob(report)
        assert report["affects_exit"] is False


@pytest.mark.parametrize("name", ["ghp_\u202e" + "A" * 20, "na\u202eme"], ids=["split-secret", "bidi"])
@pytest.mark.parametrize("mode", ["none", "review"])
def test_gate_detail_refuses_noncanonical_target_names(name, mode):
    assert doctor_git_report.gate_detail(((name, mode),)) == "targets lose the gate"
    assert doctor_git_report.gate_detail((("develop", "review"), (name, mode))) == "targets lose the gate"


@pytest.mark.parametrize("mode", ["none", "review"])
def test_gate_detail_keeps_valid_long_target_as_digest(mode):
    name = "feature/" + "a" * 200
    assert doctor_git_report.gate_detail(((name, mode),)) == (
        "lose the gate: " + doctor_git_report.digest(name) + " " + mode)
