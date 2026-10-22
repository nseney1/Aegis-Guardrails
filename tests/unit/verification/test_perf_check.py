"""Behavioral tests for paired interleaved performance regression check."""
from __future__ import annotations

import importlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

from aegis_core.verification import perf_check


class TestEvaluatePairedSamples:
    def test_rejects_fewer_than_15_rounds(self) -> None:
        with pytest.raises(ValueError, match="15"):
            perf_check.evaluate_paired_samples([0.01] * 14, [0.01] * 14, threshold=0.05)

    def test_aa_noise_floor_marks_noisy_benchmark_unverified(self) -> None:
        # Even indices ~10ms, odd indices ~12ms -> ~20% A/A drift > threshold / 2 (2.5%)
        base_samples = [0.010 if i % 2 == 0 else 0.012 for i in range(16)]
        head_samples = [0.015 for _ in range(16)]
        res = perf_check.evaluate_paired_samples(base_samples, head_samples, threshold=0.05)
        assert res["noisy"] is True
        assert res["status"] == "unverified"
        assert res["regressed"] is False
        assert res["aa_drift"] > 0.025

    def test_flags_regression_only_when_not_noisy_and_both_min_and_median_regress(self) -> None:
        # Stable base around 10.0ms, head around 11.0ms (+10% > 5% threshold)
        base_samples = [0.0100 + (0.00002 if i % 2 else 0.0) for i in range(15)]
        head_samples = [0.0110 + (0.00002 if i % 2 else 0.0) for i in range(15)]
        res = perf_check.evaluate_paired_samples(base_samples, head_samples, threshold=0.05)
        assert res["noisy"] is False
        assert res["regressed"] is True
        assert res["status"] == "fail"

    def test_passes_when_min_does_not_exceed_threshold_even_if_median_drifts(self) -> None:
        # min(head) == min(base) == 0.0100, even though median(head) is higher
        base_samples = [0.0100] * 15
        head_samples = [0.0100] + [0.0110] * 14
        res = perf_check.evaluate_paired_samples(base_samples, head_samples, threshold=0.05)
        assert res["noisy"] is False
        assert res["regressed"] is False
        assert res["status"] == "pass"


class TestRunPerfCheck:
    def test_rejects_rounds_below_15(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="15"):
            perf_check.run_perf_check(tmp_path, rounds=10, user_config_path=_cfg(tmp_path, ["python3", "-c", "pass"]))

    def test_reads_command_only_from_user_scope_never_repo_config(self, tmp_path: Path) -> None:
        repo_root = tmp_path / "repo"
        (repo_root / ".aegis").mkdir(parents=True)
        # Untrusted repo config tries to smuggle a perf command
        (repo_root / ".aegis" / "config.json").write_text(
            json.dumps({"v": 1, "perf": {"command": ["echo", "pwned"]}}),
            encoding="utf-8",
        )
        empty_user_cfg = tmp_path / "user_config.json"
        empty_user_cfg.write_text(json.dumps({"v": 1}), encoding="utf-8")

        executed: list[list[str]] = []

        def spy_runner(argv, cwd, env=None, timeout=60):
            executed.append(list(argv))
            return {"returncode": 0, "stdout": "", "stderr": "", "missing_binary": False, "timed_out": False, "duration_s": 0.01}

        res = perf_check.run_perf_check(
            repo_root,
            rounds=15,
            runner=spy_runner,
            user_config_path=empty_user_cfg,
        )
        assert res["status"] == "unverified"
        assert executed == []

    def test_interleaved_paired_execution_with_user_config_and_no_baseline_file(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        _git(repo_root, "init", "-q", "-b", "main")
        for n in (1, 2):
            (repo_root / "a.py").write_bytes(f"a = {n}\n".encode())
            _git(repo_root, "add", "a.py")
            _git(repo_root, "commit", "-q", "-m", f"c{n}")
        user_cfg = tmp_path / "user_aegis" / "config.json"
        user_cfg.parent.mkdir(parents=True)
        user_cfg.write_text(
            json.dumps({"v": 1, "perf": {"command": ["pytest", "-q"]}}),
            encoding="utf-8",
        )

        calls: list[str] = []

        def fake_runner(argv, cwd, env=None, timeout=60):
            is_head = Path(cwd).resolve() == repo_root.resolve()
            calls.append("head" if is_head else "base")
            dur = 0.020 if is_head else 0.010
            return {
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "missing_binary": False,
                "timed_out": False,
                "duration_s": dur,
            }

        res = perf_check.run_perf_check(
            repo_root,
            rounds=15,
            threshold=0.05,
            runner=fake_runner,
            user_config_path=user_cfg,
        )
        assert res["status"] == "fail"
        assert res["regressed"] is True
        assert calls.count("base") == 15
        assert calls.count("head") == 15
        # Verify interleaved pairs (each pair has 1 base and 1 head)
        for i in range(0, 30, 2):
            assert set(calls[i : i + 2]) == {"base", "head"}
        # Never writes a persistent baseline file
        assert list(repo_root.rglob("*baseline*")) == []

def _cfg(where: Path, command, *, raw: bytes = b"") -> Path:
    """A user-scope config file holding ``perf.command`` (``raw`` bytes are written as given)."""
    path = where / "user_cfg" / "config.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw or json.dumps({"v": 1, "perf": {"command": command}}).encode("utf-8"))
    return path


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                   cwd=str(repo), check=True, capture_output=True)


def _program(path: Path, body: str) -> Path:
    """A Python program PATH lookup finds as ``path.name`` (a .cmd launcher on Windows)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        script = path.with_name(path.name + "-script.py")
        script.write_bytes(body.encode("utf-8"))
        launcher = path.with_name(path.name + ".cmd")
        launcher.write_bytes(f'@"{sys.executable}" "{script}" %*\r\n'.encode("utf-8"))
        return launcher
    path.write_bytes(f"#!{sys.executable}\n{body}".encode("utf-8"))
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture
def bench_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A two-commit repository whose bench.py appends a line to a log outside it on every run."""
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    log = tmp_path / "bench.log"
    (root / "bench.py").write_bytes(f"open({str(log)!r}, 'a').write('x')\n".encode("utf-8"))
    _git(root, "add", "bench.py")
    _git(root, "commit", "-q", "-m", "one")
    (root / "a.py").write_bytes(b"a = 1\n")
    _git(root, "add", "a.py")
    _git(root, "commit", "-q", "-m", "two")
    monkeypatch.chdir(root)  # Windows' CreateProcess searches the parent's cwd, not cwd=
    return root


class TestPerfProgramLookup:
    """R-checks-15: a bare perf.command program is found only in an absolute PATH entry outside
    the workspace; an explicit path is the user's own choice and runs as written."""

    @pytest.mark.skipif(os.name == "nt", reason="POSIX PATH lookup; git is reached through a symlink")
    def test_a_program_the_repository_planted_never_runs(self, bench_repo, tmp_path, monkeypatch):
        marker = tmp_path / "planted-ran"
        _program(bench_repo / "python3", f"open({str(marker)!r}, 'w').close()\n")
        _git(bench_repo, "add", "python3")
        _git(bench_repo, "commit", "-q", "-m", "plant")  # both the base and the head hold it
        trusted = tmp_path / "trusted"  # git only: no python3 is installed outside the workspace
        trusted.mkdir()
        os.symlink(shutil.which("git"), trusted / "git")
        monkeypatch.setenv("PATH", os.pathsep.join([".", str(trusted)]))

        res = perf_check.run_perf_check(bench_repo, base_ref="HEAD", rounds=15,
                                        user_config_path=_cfg(tmp_path, ["python3", "bench.py"]))

        assert not marker.exists(), "a program the repository planted ran"
        assert res["status"] == "unverified" and "python3 not found" in res["reason"]

    def test_a_command_given_as_an_explicit_path_runs_unchanged(self, bench_repo, tmp_path):
        res = perf_check.run_perf_check(bench_repo, rounds=15, user_config_path=_cfg(tmp_path, [sys.executable, "bench.py"]))

        assert res["command"] == [sys.executable, "bench.py"]
        assert (tmp_path / "bench.log").read_text(encoding="utf-8") == "x" * 30


def _git_out(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=str(repo), check=True, capture_output=True, text=True).stdout


@pytest.fixture
def forked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Commit I (bench.txt 0.020); main then changes bench.txt to 0.010; the workspace is branch
    `feature`, which forked at I and only appends to b.py. Returns (workspace, I)."""
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    ws = tmp_path / "ws"
    ws.mkdir()
    _git(ws, "init", "-q", "-b", "main")
    for name, data in (("bench.txt", b"0.020\n"), ("a.py", b"a = 1\n"), ("b.py", b"b = 1\n")):
        (ws / name).write_bytes(data)
    _git(ws, "add", "-A")
    _git(ws, "commit", "-q", "-m", "I")
    fork = _git_out(ws, "rev-parse", "HEAD").strip()
    _git(ws, "branch", "feature")
    (ws / "bench.txt").write_bytes(b"0.010\n")
    _git(ws, "commit", "-q", "-am", "main gets faster")
    _git(ws, "checkout", "-q", "feature")
    (ws / "b.py").write_bytes(b"b = 1\nc = 2\n")
    _git(ws, "commit", "-q", "-am", "feature")
    return ws, fork


class TestPerfMergeBase:
    """R-checks-30: perf compares the working tree with merge-base(base, HEAD), exported with the
    repository's filters off; no git worktree is created and an unprovable base is unverified."""

    @staticmethod
    def _runner(ws: Path, seen: list):
        def run(argv, cwd, env=None, timeout=60):
            here = Path(cwd)
            if here.resolve() != ws.resolve():
                seen.append((here / "bench.txt").read_text(encoding="utf-8").strip())
                seen.append(len(_git_out(ws, "worktree", "list").splitlines()))
            return {"returncode": 0, "duration_s": float((here / "bench.txt").read_text(encoding="utf-8"))}
        return run

    @pytest.mark.parametrize("base", ["main", "FORK"])
    def test_the_base_side_is_the_merge_base_tree(self, forked, base):
        ws, fork = forked
        seen: list = []
        res = perf_check.run_perf_check(ws, base_ref=fork if base == "FORK" else base, rounds=15, user_config_path=_cfg(ws.parent, ["bench"]),
                                        runner=self._runner(ws, seen))
        assert set(seen[0::2]) == {"0.020"}  # I's bench.txt, not main's tip
        assert set(seen[1::2]) == {1}  # git worktree list: the workspace only, during the run
        assert (res["status"], res["regressed"]) == ("pass", False)
        assert len(_git_out(ws, "worktree", "list").splitlines()) == 1
        assert not (ws / ".git" / "worktrees").exists()

    def test_an_unrelated_base_is_unverified_and_nothing_runs(self, forked):
        ws, _ = forked
        _git(ws, "checkout", "-q", "--orphan", "orphan")
        _git(ws, "commit", "-q", "-m", "unrelated")
        _git(ws, "checkout", "-q", "feature")
        calls: list = []
        res = perf_check.run_perf_check(ws, base_ref="orphan", rounds=15, user_config_path=_cfg(ws.parent, ["bench"]),
                                        runner=lambda argv, cwd, **kw: calls.append(cwd) or {"returncode": 0})
        assert res["status"] == "unverified" and "share no history" in res["reason"]
        assert calls == []

    @pytest.mark.parametrize("base", ["--foo", "no-such-ref"])
    def test_a_base_that_does_not_resolve_never_reaches_git_argv(self, forked, base, monkeypatch):
        from aegis_core import gitsafe

        ws, _ = forked
        real_run, argvs = gitsafe.run, []
        monkeypatch.setattr(gitsafe, "run", lambda args, cwd, *a, **k: argvs.append(list(args)) or real_run(args, cwd, *a, **k))
        calls: list = []
        res = perf_check.run_perf_check(ws, base_ref=base, rounds=15, user_config_path=_cfg(ws.parent, ["bench"]),
                                        runner=lambda argv, cwd, **kw: calls.append(cwd) or {"returncode": 0})
        assert res["status"] == "unverified" and calls == []
        assert not any(arg == base for argv in argvs for arg in argv)

    @pytest.mark.skipif(os.name == "nt", reason="the marker filter is a POSIX shell script")
    def test_a_smudge_filter_from_the_repository_config_never_runs(self, forked, tmp_path):
        ws, _ = forked
        marker = tmp_path / "smudge-ran"
        script = tmp_path / "smudge.sh"
        script.write_bytes(f'#!/bin/sh\necho ran >> "{marker}"\ncat\n'.encode())
        script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        (ws / ".gitattributes").write_bytes(b"* filter=evil\n")
        _git(ws, "add", ".gitattributes")
        _git(ws, "commit", "-q", "-m", "attributes")
        _git(ws, "config", "filter.evil.smudge", str(script))
        _git(ws, "config", "filter.evil.required", "true")
        perf_check.run_perf_check(ws, base_ref="HEAD", rounds=15, user_config_path=_cfg(ws.parent, ["bench"]), runner=self._runner(ws, []))
        assert not marker.exists()


# ── R-checks-31: one hardened reader, unverified never a traceback, a pytest-benchmark default ──

BENCH_ARGV = [sys.executable, "-m", "pytest", "--benchmark-only", "-q", "-p", "no:cacheprovider", "-o", "addopts="]


def _spy(calls: list):
    def run(argv, cwd, env=None, timeout=60):
        calls.append(list(argv))
        return {"returncode": 0, "duration_s": 0.01}
    return run


@pytest.fixture
def two_commits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    for n in (1, 2):
        (root / "a.py").write_bytes(f"a = {n}\n".encode())
        _git(root, "add", "a.py")
        _git(root, "commit", "-q", "-m", f"c{n}")
    return root


class TestPerfCommandReading:
    def test_an_unbalanced_quote_is_unverified_and_nothing_runs(self, two_commits, tmp_path):
        calls: list = []
        res = perf_check.run_perf_check(two_commits, rounds=15, runner=_spy(calls),
                                        user_config_path=_cfg(tmp_path, 'pytest "-k foo'))
        assert (res["status"], res["passed"], calls) == ("unverified", True, [])
        assert "cannot be parsed" in res["reason"]

    def test_a_bom_prefixed_config_is_honoured(self, two_commits, tmp_path):
        calls: list = []
        raw = b"\xef\xbb\xbf" + json.dumps({"v": 1, "perf": {"command": "echo hi"}}).encode("utf-8")
        res = perf_check.run_perf_check(two_commits, rounds=15, runner=_spy(calls), user_config_path=_cfg(tmp_path, None, raw=raw))
        assert len(calls) == 30 and calls[0] == ["echo", "hi"]
        assert res["command"] == ["echo", "hi"] and "advisory" not in res
        assert res["passed"] is (res["status"] != "fail")

    def test_the_dotted_top_level_key_is_not_read(self, two_commits, tmp_path):
        calls: list = []
        raw = json.dumps({"v": 1, "perf.command": ["echo", "hi"]}).encode("utf-8")
        res = perf_check.run_perf_check(two_commits, rounds=15, runner=_spy(calls), user_config_path=_cfg(tmp_path, None, raw=raw))
        assert res["status"] == "unverified" and calls == []

    def test_a_config_over_the_size_cap_is_unverified(self, two_commits, tmp_path):
        from aegis_core.config import MAX_CONFIG_BYTES

        calls: list = []
        raw = json.dumps({"v": 1, "perf": {"command": "echo hi"}, "pad": "x" * MAX_CONFIG_BYTES}).encode("utf-8")
        res = perf_check.run_perf_check(two_commits, rounds=15, runner=_spy(calls), user_config_path=_cfg(tmp_path, None, raw=raw))
        assert (res["status"], calls) == ("unverified", [])

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO")
    def test_a_fifo_at_the_config_path_never_blocks(self, two_commits, tmp_path):
        import threading

        fifo = tmp_path / "cfg.fifo"
        os.mkfifo(fifo)
        calls: list = []
        out: dict = {}
        worker = threading.Thread(target=lambda: out.update(perf_check.run_perf_check(
            two_commits, rounds=15, runner=_spy(calls), user_config_path=fifo)), daemon=True)
        worker.start()
        worker.join(600)  # a hang ceiling, not a timing assertion
        assert not worker.is_alive(), "reading a FIFO config blocked"
        assert (out["status"], calls) == ("unverified", [])

    def test_a_home_inside_the_workspace_is_repository_content(self, two_commits, monkeypatch):
        home = two_commits / "home"
        (home / ".aegis").mkdir(parents=True)
        (home / ".aegis" / "config.json").write_bytes(json.dumps({"v": 1, "perf": {"command": "echo pwned"}}).encode())
        for name in ("HOME", "USERPROFILE"):
            monkeypatch.setenv(name, str(home))
        calls: list = []
        res = perf_check.run_perf_check(two_commits, rounds=15, runner=_spy(calls))
        assert (res["status"], calls) == ("unverified", [])

    @pytest.mark.skipif(importlib.util.find_spec("pytest_benchmark") is not None, reason="pytest-benchmark is installed")
    def test_no_command_and_no_benchmark_plugin_is_unverified(self, two_commits, tmp_path):
        calls: list = []
        res = perf_check.run_perf_check(two_commits, rounds=15, runner=_spy(calls),
                                        user_config_path=_cfg(tmp_path, None, raw=b'{"v": 1}'))
        assert (res["status"], calls) == ("unverified", [])
        assert res["reason"] == "no perf.command configured and pytest-benchmark is not installed"

    def test_no_command_with_the_benchmark_plugin_runs_the_pytest_benchmark_argv(self, two_commits, tmp_path, monkeypatch):
        stub = tmp_path / "stubs" / "pytest_benchmark"
        stub.mkdir(parents=True)
        (stub / "__init__.py").write_bytes(b"")
        monkeypatch.syspath_prepend(str(stub.parent))
        importlib.invalidate_caches()
        calls: list = []
        res = perf_check.run_perf_check(two_commits, rounds=15, runner=_spy(calls),
                                        user_config_path=_cfg(tmp_path, None, raw=b'{"v": 1}'))
        assert res["command"] == BENCH_ARGV and calls[0] == BENCH_ARGV

    def test_a_runner_that_raises_is_unverified(self, two_commits, tmp_path):
        def boom(argv, cwd, env=None, timeout=60):
            raise RuntimeError("runner broke")
        try:
            res = perf_check.run_perf_check(two_commits, rounds=15, runner=boom, user_config_path=_cfg(tmp_path, ["bench"]))
        except Exception as exc:  # the defect: a traceback out of check --ci --perf
            pytest.fail(f"run_perf_check raised {exc!r}")
        assert (res["status"], res["passed"]) == ("unverified", True)
        assert "RuntimeError" in res["reason"]

    def test_a_failed_export_is_unverified_whatever_the_runner(self, two_commits, tmp_path, monkeypatch):
        from aegis_core import gitsafe

        def no_export(*_a, **_k):
            raise gitsafe.GitError("export failed")
        monkeypatch.setattr(gitsafe, "export_tree", no_export)
        calls: list = []
        res = perf_check.run_perf_check(two_commits, rounds=15, runner=_spy(calls), user_config_path=_cfg(tmp_path, ["bench"]))
        assert (res["status"], calls) == ("unverified", [])

    def test_a_runner_returning_a_bare_number_is_not_a_sample(self, two_commits, tmp_path):
        res = perf_check.run_perf_check(two_commits, rounds=15, runner=lambda argv, cwd, **kw: 5.0,
                                        user_config_path=_cfg(tmp_path, ["bench"]))
        assert res["status"] == "unverified"


class TestCheckCiPerf:
    """`aegis check --ci --perf` never ends in a traceback."""

    @staticmethod
    def _run(root: Path, capsys, monkeypatch) -> tuple:
        from aegis_cli.cli import main

        monkeypatch.chdir(root)
        monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
        try:
            rc = main(["check", "--ci", "--base", "HEAD~1", "--perf", "--format", "json"])
        except SystemExit as exc:
            rc = exc.code
        cap = capsys.readouterr()
        return rc, cap.out, cap.err

    def test_a_malformed_perf_command_is_unverified_not_a_traceback(self, two_commits, capsys, monkeypatch):
        cfg = Path(os.environ["HOME"]) / ".aegis" / "config.json"
        cfg.parent.mkdir(parents=True)
        cfg.write_bytes(json.dumps({"v": 1, "perf": {"command": 'pytest "-k foo'}}).encode("utf-8"))
        rc, out, err = self._run(two_commits, capsys, monkeypatch)
        assert "Traceback" not in err
        perf = json.loads(out)["perf"]
        assert (rc, perf["status"]) == (0, "unverified") and "cannot be parsed" in perf["reason"]

    def test_a_perf_check_that_raises_is_unverified_naming_only_the_type(self, two_commits, capsys, monkeypatch):
        def boom(*_a, **_k):
            raise RuntimeError("/secret/path/inside")
        monkeypatch.setattr(perf_check, "run_perf_check", boom)
        rc, out, err = self._run(two_commits, capsys, monkeypatch)
        perf = json.loads(out)["perf"]
        assert (rc, perf["status"], perf["reason"]) == (0, "unverified", "perf check could not run (RuntimeError)")
        assert "/secret/path" not in out + err
