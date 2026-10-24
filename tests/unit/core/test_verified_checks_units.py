"""Edges of the tree identity, the hermetic run and the credit state machine."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from aegis_core import checkrun, credit, treeid
from tests import helpers_humangate as hg
from tests import helpers_verified as hv

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
posix_only = pytest.mark.skipif(os.name == "nt", reason="process groups and symlinks are POSIX here")
SHA = "a" * 40


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)


# ── tree identity ────────────────────────────────────────────────────────────

@needs_git
def test_the_tree_is_what_git_would_commit_and_the_real_index_is_untouched(tmp_path):
    repo = hv.make_project(tmp_path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    repo.write("new.txt", "untracked\n")
    index_before = (repo.root / ".git" / "index").read_bytes()
    binding = treeid.tree_of(repo.root)
    assert binding.status == "ok" and binding.tree == hv.tree_now(repo.root)
    assert (repo.root / ".git" / "index").read_bytes() == index_before
    assert repo.git("status", "--porcelain").count("new.txt") == 1  # still untracked: nothing was added


@needs_git
def test_the_state_directory_is_not_part_of_the_tree(tmp_path):
    repo = hv.make_project(tmp_path)
    before = treeid.tree_of(repo.root).tree
    repo.write(".aegis/state/ledger.jsonl", "{}\n")
    assert treeid.tree_of(repo.root).tree == before


@needs_git
def test_a_work_tree_that_reads_empty_while_head_is_not_is_unbindable(tmp_path):
    repo = hv.make_project(tmp_path)
    for path in [p for p in repo.root.iterdir() if p.name != ".git"]:
        subprocess.run(["rm", "-rf", str(path)], check=True)
    repo.git("rm", "-rq", "--cached", "-r", ".")
    binding = treeid.tree_of(repo.root)
    assert binding.status == "unbindable" and "empty" in binding.reason


@needs_git
def test_a_clean_filter_is_never_executed(tmp_path):
    marker = tmp_path / "filter-ran"
    repo = hv.make_project(tmp_path)
    repo.write(".gitattributes", "*.txt filter=evil\n")
    repo.git("config", "filter.evil.clean", f"touch {marker}; cat")
    repo.write("note.txt", "hello\n")
    binding = treeid.tree_of(repo.root)
    assert binding.status == "ok" and not marker.exists()


@needs_git
def test_a_dirty_submodule_makes_the_binding_partial(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    for args in (["init", "-q", "-b", "main"], ["-c", "user.email=a@b.c", "-c", "user.name=n", "commit", "-q",
                                              "--allow-empty", "-m", "s"]):
        subprocess.run(["git", *args], cwd=sub, check=True, capture_output=True)
    repo = hv.make_project(tmp_path)
    repo.git("-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "vendor/sub")
    repo.commit("add submodule")
    assert treeid.tree_of(repo.root).status == "ok"
    (repo.root / "vendor" / "sub" / "stray.txt").write_text("dirty\n")
    binding = treeid.tree_of(repo.root)
    assert binding.status == "partial" and binding.bound and binding.gitlinks == ("vendor/sub",)
    assert "vendor/sub" in binding.reason


def test_outside_a_work_tree_the_binding_says_so(tmp_path):
    binding = treeid.tree_of(tmp_path)
    assert binding.status == "unbindable" and binding.tree is None and "git work tree" in binding.reason


# ── the hermetic run ─────────────────────────────────────────────────────────

@needs_git
@posix_only
def test_a_symlink_that_leaves_the_snapshot_is_refused(tmp_path):
    repo = hv.make_project(tmp_path)
    os.symlink("/etc", repo.root / "escape")
    out = checkrun.record(repo.root, tests=True, base="main")
    assert out.status == "unbindable" and "symbolic link" in out.reason and "escape" in out.reason
    assert hv.rows_of(repo.root, "check") == []


@needs_git
@posix_only
def test_a_symlink_inside_the_tree_is_refused_too_and_nothing_runs(tmp_path):
    marker = tmp_path / "ran"
    repo = hv.make_project(tmp_path, runner=f"import pathlib\npathlib.Path({str(marker)!r}).write_text('x')\n"
                                            "print('1 passed in 0s')\n")
    hv.use_stub_runner(repo.home.path)
    os.symlink("app.py", repo.root / "src" / "alias.py")  # relative, stays inside the tree
    out = checkrun.record(repo.root, tests=True, base="main")
    assert out.status == "unbindable" and out.row is None and "src/alias.py" in out.reason
    assert not marker.exists() and hv.rows_of(repo.root, "check") == []


@needs_git
@posix_only
def test_a_committed_symlink_is_refused_as_well(tmp_path):
    repo = hv.make_project(tmp_path)
    os.symlink("README.md", repo.root / "docs-link")
    repo.commit("a committed link")
    out = checkrun.record(repo.root, base="main")
    assert out.status == "unbindable" and "docs-link" in out.reason


@needs_git
@posix_only
def test_a_timeout_kills_the_whole_process_group(tmp_path):
    pidfile = tmp_path / "child.pid"
    runner = ("import os, subprocess, sys, time\n"
              f"child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
              f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n"
              "time.sleep(60)\n")
    repo = hv.make_project(tmp_path, runner=runner)
    hv.use_stub_runner(repo.home.path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    started = time.monotonic()
    out = checkrun.record(repo.root, tests=True, base="main", timeout=2.0)
    assert time.monotonic() - started < 30
    assert out.row["tests"]["timed_out"] is True and out.row["passed"] is False
    pid = int(pidfile.read_text())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


@needs_git
@posix_only
def test_the_run_sees_a_fixed_environment(tmp_path, monkeypatch):
    dump = tmp_path / "env.json"
    runner = ("import json, os, sys\n"
              f"json.dump({{'env': dict(os.environ), 'cwd': os.getcwd(), 'stdin_tty': sys.stdin is not None and "
              f"sys.stdin.isatty(), 'flags': sys.flags.isolated}}, open({str(dump)!r}, 'w'))\n"
              "print('1 passed in 0s')\n")
    repo = hv.make_project(tmp_path, runner=runner)
    hv.use_stub_runner(repo.home.path)
    monkeypatch.setenv("PYTHONPATH", "/evil")
    monkeypatch.setenv("PYTEST_ADDOPTS", "--evil")
    monkeypatch.setenv("AEGIS_SECRET", "s3cret")
    repo.write("src/app.py", "def app():\n    return 2\n")
    out = checkrun.record(repo.root, tests=True, base="main")
    assert out.row["passed"] is True
    seen = json.loads(dump.read_text())
    env = seen["env"]
    assert env["PATH"] == "/usr/bin:/bin" and not [k for k in env if k.startswith(("PYTHON", "PYTEST", "AEGIS"))]
    assert env["HOME"] != str(repo.home.path) and str(repo.root) not in seen["cwd"]
    assert "evil" not in json.dumps(env) and seen["stdin_tty"] is False


@needs_git
def test_the_user_config_command_may_be_an_argv_list_and_the_digest_is_machine_independent(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.write_user_config(repo.home.path, tests={"command": ["python", "run_checks.py"]})
    assert checkrun.user_test_command(repo.root) == ["python", "run_checks.py"]
    first = checkrun.command_digest(["python", "run_checks.py"])
    argv, logical = checkrun.plan_command(["python", "run_checks.py"])
    assert argv[0] == sys.executable and logical == ["python", "run_checks.py"]
    assert checkrun.command_digest(logical) == first


def test_a_bare_pytest_runs_as_python_m_pytest_with_every_hermetic_flag(tmp_path):
    junit = tmp_path / "junit.xml"
    argv, logical = checkrun.plan_command(["pytest", "-q"], junit)
    assert argv[:6] == [sys.executable, "-s", "--check-hash-based-pycs", "always", "-m", "pytest"]
    at = argv.index("-p")
    assert argv[at:at + 4] == ["-p", "no:cacheprovider", "-o", "addopts="]
    assert f"--junitxml={junit}" in argv and "-q" in argv
    assert logical == ["pytest", "-q"]


@pytest.mark.parametrize("word", ["/opt/venv/bin/pytest", "py.test", "PYTEST.EXE"])
def test_any_pytest_program_runs_under_the_aegis_interpreter(word):
    argv, logical = checkrun.plan_command([word, "-q"])
    assert argv[0] == sys.executable and argv[4:6] == ["-m", "pytest"] and "addopts=" in argv
    assert logical == [word, "-q"]


def test_only_an_absolute_python_first_word_is_kept_as_the_interpreter(tmp_path):
    python = tmp_path / "python3"
    python.write_text("#!/bin/sh\nexit 0\n")
    python.chmod(0o755)
    argv, _ = checkrun.plan_command([str(python), "-m", "pytest"])
    assert argv[:4] == [str(python), "-s", "--check-hash-based-pycs", "always"] and "addopts=" in argv
    assert checkrun.plan_command(["python", "-m", "pytest"])[0][0] == sys.executable
    tool = str(tmp_path / "runtests")
    assert checkrun.plan_command([tool, "-x"])[0] == [tool, "-x"]


def test_a_missing_absolute_interpreter_exits_127(tmp_path):
    junit = tmp_path / "junit.xml"
    argv, _ = checkrun.plan_command([str(tmp_path / "nowhere" / "python3"), "-m", "pytest"], junit)
    run = checkrun.run_tests(argv, tmp_path, checkrun.hermetic_env(tmp_path), 60.0, junit, tmp_path / "out.txt")
    assert run.exit == 127 and not run.evidence


def test_the_default_command_keeps_its_digest():
    _argv, logical = checkrun.plan_command(None)
    assert checkrun.command_digest(logical) == "982597b8a8141596e8015b5c60700b600e69fc8873640cb98a23585cfff5b8ea"


def _record_with_stand_in(tmp_path, monkeypatch, capsys, script: str):
    from aegis_cli.cli import main

    repo = hv.make_project(tmp_path)
    hv.write_user_config(repo.home.path, tests={"command": ["pytest"]})
    stand_in = tmp_path / "stand-in-python"
    stand_in.write_text("#!/bin/sh\n" + script)
    stand_in.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(stand_in))
    repo.write("src/app.py", "def app():\n    return 2\n")
    monkeypatch.chdir(repo.root)
    capsys.readouterr()
    code = main(["check", "--record", "--tests"])
    return code, capsys.readouterr().out, hv.rows_of(repo.root, "check")


@needs_git
@posix_only
def test_a_run_whose_interpreter_has_no_pytest_prints_a_hint(tmp_path, monkeypatch, capsys):
    code, out, rows = _record_with_stand_in(tmp_path, monkeypatch, capsys,
                                            "echo \"$0: No module named pytest\" >&2\nexit 1\n")
    hint = [line for line in out.splitlines() if line.startswith("hint:")]
    assert code == 1 and len(hint) == 1 and "tests.command" in hint[0]
    assert rows[-1]["tests"]["collected"] == 0 and rows[-1]["passed"] is False


@needs_git
@posix_only
def test_a_failing_run_with_pytest_present_prints_no_hint(tmp_path, monkeypatch, capsys):
    code, out, rows = _record_with_stand_in(tmp_path, monkeypatch, capsys,
                                            "echo '2 passed, 1 failed in 0.01s'\nexit 1\n")
    assert code == 1 and "hint:" not in out and rows[-1]["passed"] is False


@needs_git
@pytest.mark.parametrize("config", ["not json", '{"tests": {"command": 5}}', '{"tests": {"command": ""}}', "[]"])
def test_an_unusable_user_config_falls_back_to_the_default(tmp_path, config):
    repo = hv.make_project(tmp_path)
    path = repo.home.path / ".aegis" / "config.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(config)
    assert checkrun.user_test_command(repo.root) is None


@needs_git
def test_a_layer_one_only_run_records_no_tests_and_passes(tmp_path):
    repo = hv.make_project(tmp_path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    out = checkrun.record(repo.root, base="main")
    assert out.status == "recorded" and out.row["tests"] is None and out.row["passed"] is True
    assert out.row["layer1"]["findings"] == 0 and out.row["run_ordinal"] == 1
    again = checkrun.record(repo.root, base="main")
    assert again.row["run_ordinal"] == 2 and again.row["id"] != out.row["id"]


@needs_git
def test_every_check_row_carries_the_envelope_and_the_v43_fields(tmp_path):
    repo = hv.make_project(tmp_path)
    row = checkrun.record(repo.root, base="main").row
    for field in ("source", "aegis_version", "checked_at", "scope", "tree", "head", "base", "tree_algo", "cmd_digest",
                  "layer1", "env_class", "protected_changed", "witness", "run_ordinal"):
        assert field in row, field
    assert "attempt" not in row and row["tree_algo"] == "v1" and row["checked_at"].endswith("Z")


@needs_git
def test_a_branch_with_no_base_is_an_error_not_a_row(tmp_path):
    repo = hv.make_project(tmp_path)
    out = checkrun.record(repo.root, base="no-such-branch")
    assert out.status == "error" and hv.rows_of(repo.root, "check") == []


NO_EVAL_GATE = "---\nid: no-eval\ntype: invariant\nenforcement: gate\nforbid_ast:\n  calls: [eval]\n---\n# No eval\n"


def _unrelated_repository(path: Path) -> Path:
    path.mkdir(parents=True)
    for args in (("init", "-q", "-b", "main"), ("-c", "user.email=t@example.com", "-c", "user.name=T",
                                               "commit", "-q", "--allow-empty", "-m", "home")):
        subprocess.run(["git", *args], cwd=str(path), check=True, capture_output=True)
    return path


@needs_git
@pytest.mark.parametrize("enclosed", [False, True], ids=["tmp-outside-git", "tmp-inside-another-repository"])
def test_a_recorded_snapshot_enforces_its_gate_rules_wherever_the_temp_dir_is(tmp_path, monkeypatch, enclosed):
    """Given main with a no-eval gate and a work tree calling eval, When ``check --record`` exports
    the snapshot into a temp dir that sits inside an unrelated repository (a $HOME repository), Then
    the row still fails: that repository's HEAD holds no rules, so it cannot unbind the gate."""
    import tempfile

    repo = hv.make_project(tmp_path)
    repo.git("checkout", "-q", "main")
    repo.write(".aegis/rules/invariants/no-eval.md", NO_EVAL_GATE)
    repo.commit("gate")
    repo.git("checkout", "-q", "-B", "work", "main")
    repo.write("src/app.py", "x = eval(input())\n")
    scratch = (_unrelated_repository(tmp_path / "home-repo") if enclosed else tmp_path) / "tmp"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    out = checkrun.record(repo.root, base="main")
    assert out.status == "recorded"
    assert out.row["layer1"]["findings"] >= 1 and out.row["passed"] is False and out.row["exit"] == 1


# ── CI selection ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("override", [
    {"event": "pull_request"}, {"same_repo": False}, {"workflow": "other.yml"}, {"conclusion": "cancelled"},
])
def test_runs_that_cannot_speak_for_a_commit_are_ignored(override):
    assert credit.select_ci_run([hv.ci_run(SHA, **override)], SHA, hv.CI_WORKFLOW) is None


def test_a_run_for_another_sha_is_ignored():
    assert credit.select_ci_run([hv.ci_run("b" * 40)], SHA, hv.CI_WORKFLOW) is None


def test_the_newest_attempt_wins_and_a_cancelled_one_does_not_replace_it():
    runs = [hv.ci_run(SHA, "failure", attempt=1, run_id=1), hv.ci_run(SHA, "success", attempt=2, run_id=1),
            hv.ci_run(SHA, "cancelled", attempt=3, run_id=1)]
    chosen = credit.select_ci_run(runs, SHA, hv.CI_WORKFLOW)
    assert chosen["run_attempt"] == 2 and credit.ci_conclusion(chosen) == "success"


@pytest.mark.parametrize("status,conclusion,expected", [
    ("in_progress", None, "pending"), ("completed", "neutral", "pending"), ("completed", "failure", "failure"),
    ("completed", "success", "success"),
])
def test_ci_conclusion_names_only_decisive_states(status, conclusion, expected):
    assert credit.ci_conclusion(hv.ci_run(SHA, conclusion, status=status)) == expected
    assert credit.ci_conclusion(None) == "none"


@needs_git
def test_confirm_stores_the_conclusion_per_head_sha_and_does_not_ask_twice(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    hv.mcp_call("aegis_scan", repo.root, files=["src/app.py"])
    checkrun.record(repo.root, tests=True, base="main")
    hv.mcp_call("aegis_report_outcome", repo.root, outcome="success", rules_used=["trap-sample"], idempotency_key="k")
    commit = repo.commit("work")
    repo.git("branch", "-f", "main", commit)
    ci = hv.FakeCI([hv.ci_run(commit)])
    landed = credit.landed_lookup(repo.root)
    first = credit.confirm(repo.root, client=ci, workflow=hv.CI_WORKFLOW, landed=landed)
    again = credit.confirm(repo.root, client=ci, workflow=hv.CI_WORKFLOW, landed=landed)
    assert first["confirmed"] == 1 and again["confirmed"] == 1 and ci.asked == [commit, commit]
    row, = hv.rows_of(repo.root, "ci")
    assert row["commit"] == commit and row["ci_conclusion"] == "success" and row["ci_run_attempt"] == 1


@needs_git
def test_an_unreachable_ci_leaves_credit_where_it_is(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    hv.mcp_call("aegis_scan", repo.root, files=["src/app.py"])
    checkrun.record(repo.root, tests=True, base="main")
    hv.mcp_call("aegis_report_outcome", repo.root, outcome="success", rules_used=["trap-sample"], idempotency_key="k")
    commit = repo.commit("work")
    repo.git("branch", "-f", "main", commit)
    summary = credit.confirm(repo.root, client=hv.FakeCI(error="gh is not installed"), workflow=hv.CI_WORKFLOW,
                             landed=credit.landed_lookup(repo.root))
    assert summary["errors"] == ["gh is not installed"] and hv.rows_of(repo.root, "ci") == []


def _runner(returncode=0, stdout=""):
    class Result:
        pass

    def run(argv, cwd=None):
        result = Result()
        result.returncode, result.stdout = returncode, stdout
        run.argv = argv
        return result

    return run


@pytest.mark.parametrize("runner,needle", [
    (None, "gh is not installed"), (_runner(1), "exit 1"), (_runner(0, "nope"), "not JSON"),
    (_runner(0, "[]"), "no workflow_runs"),
])
def test_the_gh_client_fails_closed(runner, needle):
    client = credit.GhRestClient("octo/proj", runner=runner or (lambda argv, cwd=None: None))
    with pytest.raises(credit.CIUnavailable, match=needle):
        client.runs_for(SHA)


def test_the_gh_client_asks_for_exactly_one_commit_and_refuses_a_short_id():
    runner = _runner(0, json.dumps({"workflow_runs": [hv.ci_run(SHA)]}))
    assert credit.GhRestClient("octo/proj", runner=runner).runs_for(SHA)[0]["head_sha"] == SHA
    assert runner.argv == ["api", f"repos/octo/proj/actions/runs?head_sha={SHA}&per_page=100"]
    with pytest.raises(credit.CIUnavailable, match="full commit id"):
        credit.GhRestClient("octo/proj", runner=runner).runs_for("abc")


def test_the_gh_client_reads_the_default_branch_from_the_repository():
    runner = _runner(0, json.dumps({"full_name": "octo/proj", "default_branch": "trunk"}))
    assert credit.GhRestClient("octo/proj", runner=runner).default_branch() == "trunk"
    assert runner.argv == ["api", "repos/octo/proj"]
    assert credit.GhRestClient(runner=runner).default_branch() == "trunk"
    assert runner.argv == ["api", "repos/{owner}/{repo}"]  # gh expands it from the clone's origin


@pytest.mark.parametrize("runner,needle", [
    (None, "gh is not installed"), (_runner(1), "exit 1"), (_runner(0, "nope"), "not JSON"),
    (_runner(0, "[]"), "no usable default_branch"), (_runner(0, "{}"), "no usable default_branch"),
    (_runner(0, '{"default_branch": ""}'), "no usable default_branch"),
    (_runner(0, '{"default_branch": 7}'), "no usable default_branch"),
    (_runner(0, '{"default_branch": "main\\nevil"}'), "no usable default_branch"),
    (_runner(0, '{"default_branch": "ma in"}'), "no usable default_branch"),
], ids=["missing", "exit", "not-json", "list", "empty", "blank", "int", "newline", "space"])
def test_the_default_branch_fails_closed(runner, needle):
    client = credit.GhRestClient("octo/proj", runner=runner or (lambda argv, cwd=None: None))
    with pytest.raises(credit.CIUnavailable, match=needle):
        client.default_branch()


# ── trailer and CI falsification ─────────────────────────────────────────────

def test_the_trailer_round_trips_and_rejects_anything_else():
    line = credit.format_trailer(SHA, 0)
    assert credit.parse_trailer(line) == {"tree": SHA, "exit": 0}
    for bad in ("Aegis-Check: tree=zz exit=0", "Aegis-Check: tree=" + SHA, "aegis-check: tree=" + SHA + " exit=0", "",
                "Aegis-Check: tree=" + SHA + " exit=0 extra"):
        assert credit.parse_trailer(bad) is None


@pytest.mark.parametrize("trailer,rerun,second,result,failed", [
    ({"tree": SHA, "exit": 0}, {"tree": SHA, "exit": 0}, None, "agree", False),
    ({"tree": SHA, "exit": 0}, {"tree": "b" * 40, "exit": 1}, None, "unbound", False),
    (None, {"tree": SHA, "exit": 1}, None, "unbound", False),
    ("garbage", {"tree": SHA, "exit": 1}, None, "unbound", False),
    ({"tree": SHA, "exit": 0}, {"tree": SHA, "exit": 1}, None, "rerun", False),
    ({"tree": SHA, "exit": 0}, {"tree": SHA, "exit": 1}, {"tree": SHA, "exit": 0}, "agree", False),
    ({"tree": SHA, "exit": 0}, {"tree": SHA, "exit": 1}, {"tree": SHA, "exit": 1}, "void", True),
    ({"tree": SHA, "exit": 1}, {"tree": SHA, "exit": 0}, {"tree": SHA, "exit": 0}, "void", True),
])
def test_ci_divergence_is_decided_by_equal_trees_only(trailer, rerun, second, result, failed):
    verdict = credit.check_ci_divergence(trailer, rerun, second)
    assert (verdict["result"], verdict["failed"]) == (result, failed)


def test_a_raw_trailer_line_is_not_a_parsed_trailer():
    verdict = credit.check_ci_divergence(credit.format_trailer(SHA, 0), {"tree": SHA, "exit": 0})
    assert verdict["result"] == "unbound" and verdict["failed"] is False


def test_an_inconclusive_rerun_is_unbound_never_a_failure():
    verdict = credit.check_ci_divergence({"tree": SHA, "exit": 0},
                                         {"tree": SHA, "inconclusive": True, "reason": "timed out"})
    assert verdict == {"result": "unbound", "failed": False, "reason": "CI rerun timed out"}


def _trailer_head(repo, value: int = 2, exit_code: int = 0) -> str:
    repo.write("src/app.py", f"def app():\n    return {value}\n")
    tree = hv.tree_now(repo.root)
    repo.commit(f"change {value}\n\n{credit.format_trailer(tree, exit_code)}")
    return tree


def _check_row(repo, tree: str, check_id: str) -> None:
    from aegis_core.telemetry_engine import ledger

    ledger.append_rows(repo.root, [{"v": ledger.LEDGER_VERSION, "ts": "2026-10-20T00:00:00Z", "event": "check",
                                    "id": check_id, "tree": tree, "witness": "aegis", "passed": True}])


@needs_git
def test_a_divergence_that_repeats_voids_the_checks_of_that_tree(tmp_path):
    repo = hv.make_project(tmp_path)
    tree = _trailer_head(repo)
    _check_row(repo, tree, "c-diverged")
    out = credit.verify_commit_trailers(repo.root, "main", "HEAD", rerun_fn=lambda _c, t: {"tree": t, "exit": 1})
    assert [(e["result"], e["failed"]) for e in out] == [("void", True)]
    assert [(r["check"], r["reason"]) for r in hv.rows_of(repo.root, "void")] == [("c-diverged", "ci_divergence")]


@needs_git
def test_a_divergence_the_second_rerun_contradicts_agrees_and_voids_nothing(tmp_path):
    repo = hv.make_project(tmp_path)
    tree = _trailer_head(repo)
    _check_row(repo, tree, "c-flaky")
    answers = iter([1, 0])
    out = credit.verify_commit_trailers(repo.root, "main", "HEAD",
                                        rerun_fn=lambda _c, t: {"tree": t, "exit": next(answers)})
    assert [e["result"] for e in out] == ["agree"] and hv.rows_of(repo.root, "void") == []


@needs_git
@posix_only
def test_a_rerun_that_times_out_is_unbound_and_check_ci_passes(tmp_path, monkeypatch, capsys):
    from aegis_cli.cli import main

    repo = hv.make_project(tmp_path, runner="import time\ntime.sleep(30)\n")
    hv.use_stub_runner(repo.home.path)
    _trailer_head(repo)
    out = checkrun.verify_commit_trailers(repo.root, "main", "HEAD", timeout=1)
    assert [(e["result"], e["failed"]) for e in out] == [("unbound", False)] and "timed out" in out[0]["reason"]
    monkeypatch.setattr(checkrun, "DEFAULT_TIMEOUT_S", 1.0)
    monkeypatch.chdir(repo.root)
    capsys.readouterr()
    assert main(["check", "--ci", "--base", "main", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["trailer_checks"][0]["result"] == "unbound"


@needs_git
def test_the_rerun_uses_the_record_recipe_and_snapshot_bytes(tmp_path, monkeypatch):
    repo = hv.make_project(tmp_path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    repo.commit("committed LF")
    repo.home.config("core.autocrlf", "true")
    seen = []

    def recorder(argv, cwd, env, timeout, junit, output):
        seen.append(([a.replace(str(junit), "JUNIT") for a in argv], sorted(env), timeout,
                     (Path(cwd) / "src" / "app.py").read_bytes()))
        return checkrun.TestsRun(exit=0, collected=1, passed=1)

    monkeypatch.setattr(checkrun, "run_tests", recorder)
    recorded = checkrun.record(repo.root, tests=True, base="main")
    rerun = checkrun.rerun_commit_snapshot(repo.root, "HEAD", "main")
    assert recorded.status == "recorded" and rerun["tree"] == recorded.row["tree"] and rerun["exit"] == 0
    assert len(seen) == 2 and seen[0] == seen[1]
    assert seen[0][2] == checkrun.DEFAULT_TIMEOUT_S and seen[0][3] == b"def app():\n    return 2\n"


@needs_git
def test_a_rerun_without_a_merge_base_or_commit_is_unbound_with_a_reason(tmp_path):
    repo = hv.make_project(tmp_path)
    repo.git("checkout", "-q", "--orphan", "island")
    repo.commit("unrelated history")
    repo.git("checkout", "-q", "work")
    tree = hv.tree_now(repo.root)
    for commit, base in (("HEAD", "island"), ("0" * 40, "main")):
        rerun = checkrun.rerun_commit_snapshot(repo.root, commit, base)
        verdict = credit.check_ci_divergence({"tree": tree, "exit": 0}, rerun)
        assert verdict["result"] == "unbound" and verdict["failed"] is False and verdict["reason"], commit


# ── the approval anchor comes from git, never from a ledger row ─────────────

needs_signing = pytest.mark.skipif(not hg.signing_ok(), reason="needs git 2.34+ and ssh-keygen")


class _Approvals:
    """``main`` lists the human key in allowed_signers; ``work`` holds one protected change, recorded."""

    def __init__(self, tmp_path, *, delete_test: bool = False):
        from aegis_core import human_gate

        self.gate = human_gate
        self.repo = repo = hv.make_project(tmp_path)
        self.human, human_pub = hg.keygen(tmp_path / "keys", "human")
        self.agent, self.agent_pub = hg.keygen(tmp_path / "keys", "agent")
        repo.git("checkout", "-q", "main")
        repo.write("allowed_signers", hg.allowed_signers_text(human_pub))
        repo.write("tests/test_old.py", "def test_old():\n    assert True\n")
        self.fork = repo.commit("signers")
        repo.git("checkout", "-q", "-B", "work", "main")
        if delete_test:
            repo.git("rm", "-q", "tests/test_old.py")
        repo.write("conftest.py", "# protected change\n")
        self.row = checkrun.record(repo.root, base="main").row
        assert self.row["protected_changed"] is True and self.row["base"] == self.fork
        self.change = repo.commit("protected change")

    def approve(self, key, base: str) -> str:
        digest = self.gate.governance_tree_hash(self.repo.root, self.change, base=base)
        return self.repo.commit(self.gate.approval_message(digest), sign_key=key, allow_empty=True)

    def land(self, squash: bool = False) -> str:
        repo = self.repo
        repo.git("checkout", "-q", "main")
        if squash:
            repo.git("merge", "-q", "--squash", "work")
            repo.git("commit", "-q", "-m", "squashed")
        else:
            repo.git("merge", "-q", "--no-ff", "--no-edit", "work")
        landed = repo.head()
        repo.git("checkout", "-q", "work")
        return landed

    def forge(self, check_id: str, **fields) -> str:
        from aegis_core.telemetry_engine import ledger

        row = {k: v for k, v in self.row.items() if k != "seq"}
        row.update(id=check_id, **fields)
        for key in [k for k, v in fields.items() if v is None]:
            row.pop(key)
        ledger.append_rows(self.repo.root, [row])
        return check_id

    def lookup(self, check_id: str, **kw) -> bool:
        return credit.approval_lookup(self.repo.root, credit.read_rows(self.repo.root), **kw)(check_id)


@needs_signing
def test_a_ledger_base_off_the_protected_branch_cannot_choose_the_signers(tmp_path):
    from aegis_core.telemetry_engine import ledger

    case = _Approvals(tmp_path)
    repo = case.repo
    repo.git("checkout", "-q", "-b", "evil", case.fork)
    repo.write("allowed_signers", hg.allowed_signers_text(case.agent_pub))
    evil = repo.commit("agent key")
    repo.git("checkout", "-q", "work")
    case.approve(case.agent, base=evil)
    landed = case.land()
    forged = case.forge("forged", base=evil, tests={"exit": 0, "passed": 3, "failed": 0})
    assert case.lookup(forged) is False
    stamp = "2026-10-20T00:00:00Z"
    ledger.append_rows(repo.root, [
        {"v": ledger.LEDGER_VERSION, "ts": stamp, "event": "report", "check": forged, "rule": "trap-sample", "result": "tp"},
        {"v": ledger.LEDGER_VERSION, "ts": stamp, "event": "ci", "commit": landed, "ci_conclusion": "success"},
    ])
    rows = credit.read_rows(repo.root)
    derived, = credit.derive(rows, landed=credit.landed_lookup(repo.root),
                             approved=credit.approval_lookup(repo.root, rows), verified_ci={landed: "success"})
    assert (derived.state, derived.counts, derived.reason) == ("confirmed", False, "protected_changed")


@needs_signing
@pytest.mark.parametrize("squash", [False, True], ids=["merge", "squash"])
def test_a_genuine_approval_at_the_recorded_fork_point_verifies_after_landing(tmp_path, squash):
    case = _Approvals(tmp_path)
    case.approve(case.human, base=case.fork)
    case.land(squash=squash)
    assert case.lookup(case.row["id"]) is True


@needs_signing
def test_an_approved_test_deletion_still_verifies_after_landing(tmp_path):
    case = _Approvals(tmp_path, delete_test=True)
    case.approve(case.human, base=case.fork)
    case.land()
    assert case.lookup(case.row["id"]) is True


@needs_signing
def test_an_unusable_base_or_branch_is_never_approved_and_never_falls_back(tmp_path, monkeypatch):
    case = _Approvals(tmp_path)
    case.approve(case.human, base=case.fork)
    case.land()
    for i, base in enumerate(("zz", "", case.fork[:12], case.fork.upper(), None)):
        assert case.lookup(case.forge(f"bad-{i}", base=base)) is False, base
    assert case.lookup(case.row["id"], branch="no-such-branch") is False
    case.repo.git("branch", "-m", "main", "trunk")
    assert case.lookup(case.row["id"]) is False


def _revoked_agent_key(tmp_path, *, later_commit: bool = False):
    """``main`` first listed the agent key in allowed_signers, then replaced it with the human key
    (optionally followed by an unrelated commit); ``work`` holds one recorded protected change."""
    from aegis_core import human_gate

    repo = hv.make_project(tmp_path)
    human, human_pub = hg.keygen(tmp_path / "keys", "human")
    agent, agent_pub = hg.keygen(tmp_path / "keys", "agent")
    repo.git("checkout", "-q", "main")
    repo.write("allowed_signers", hg.allowed_signers_text(agent_pub))
    old = repo.commit("signers: agent key (mistake)")
    repo.write("allowed_signers", hg.allowed_signers_text(human_pub))
    fork = repo.commit("signers: revoke the agent key")
    if later_commit:
        repo.write("NOTES.md", "after the signer change\n")
        fork = repo.commit("unrelated")
    repo.git("checkout", "-q", "-B", "work", "main")
    repo.write("conftest.py", "# protected change\n")
    row = checkrun.record(repo.root, base="main").row
    assert row["protected_changed"] is True and row["base"] == fork
    change = repo.commit("protected change")

    def approve(key, base):
        digest = human_gate.governance_tree_hash(repo.root, change, base=base)
        repo.commit(human_gate.approval_message(digest), sign_key=key, allow_empty=True)

    def land():
        repo.git("checkout", "-q", "main")
        repo.git("merge", "-q", "--no-ff", "--no-edit", "work")
        repo.git("checkout", "-q", "work")

    return repo, row, old, fork, (human, agent), approve, land


def _lookup(repo, check_id: str) -> bool:
    return credit.approval_lookup(repo.root, credit.read_rows(repo.root))(check_id)


@needs_signing
def test_a_ledger_base_older_than_the_last_signer_change_cannot_revive_a_revoked_key(tmp_path):
    """Given main replaced the agent key by the human key, When a forged row names the older
    ancestor that still listed the agent key and the agent signed for it, Then credit sees no approval."""
    from aegis_core.telemetry_engine import ledger

    repo, row, old, _fork, (_human, agent), approve, land = _revoked_agent_key(tmp_path)
    approve(agent, old)
    land()
    assert _lookup(repo, row["id"]) is False
    forged = {k: v for k, v in row.items() if k != "seq"}
    forged.update(id="forged", base=old)
    ledger.append_rows(repo.root, [forged])
    assert _lookup(repo, "forged") is False


@needs_signing
@pytest.mark.parametrize("later_commit", [False, True], ids=["base-is-the-signer-change", "base-after-it"])
def test_a_human_approval_at_or_after_the_last_signer_change_still_verifies(tmp_path, later_commit):
    repo, row, _old, fork, (human, _agent), approve, land = _revoked_agent_key(tmp_path, later_commit=later_commit)
    approve(human, fork)
    land()
    assert _lookup(repo, row["id"]) is True


@needs_signing
def test_a_signer_history_git_cannot_read_fails_closed(tmp_path, monkeypatch):
    from aegis_core import gitsafe

    repo, row, _old, fork, (human, _agent), approve, land = _revoked_agent_key(tmp_path)
    approve(human, fork)
    land()
    real = gitsafe.run

    def no_log(args, *a, **k):
        if args and args[0] == "log":
            return subprocess.CompletedProcess(args, 128, b"", b"fatal: bad object")
        return real(args, *a, **k)

    monkeypatch.setattr(gitsafe, "run", no_log)
    assert _lookup(repo, row["id"]) is False
    monkeypatch.setattr(gitsafe, "run", real)
    assert _lookup(repo, row["id"]) is True  # a failure is not remembered


@needs_signing
def test_git_trouble_fails_closed_and_a_programming_error_propagates(tmp_path, monkeypatch):
    from aegis_core import gitsafe, human_gate

    case = _Approvals(tmp_path)
    case.approve(case.human, base=case.fork)
    case.land()

    def git_trouble(*_a, **_k):
        raise gitsafe.GitError("git timed out")

    monkeypatch.setattr(human_gate, "find_approval", git_trouble)
    assert case.lookup(case.row["id"]) is False

    def bug(*_a, **_k):
        raise ValueError("a bug")

    monkeypatch.setattr(human_gate, "find_approval", bug)
    with pytest.raises(ValueError):
        case.lookup(case.row["id"])


# ── a passing check needs a tests run ────────────────────────────────────────

def _staged_tree(repo) -> str:
    repo.git("add", "-A")
    return repo.git("write-tree")


def _row(tree: str, check_id: str, *, passed: bool, tests, exit_code: int = 0):
    from aegis_core.telemetry_engine import ledger

    return {"v": ledger.LEDGER_VERSION, "ts": "2026-10-20T00:00:00Z", "event": "check", "id": check_id, "tree": tree,
            "witness": "aegis", "passed": passed, "tests": tests, "exit": exit_code}


def _append(repo, *rows) -> None:
    from aegis_core.telemetry_engine import ledger

    ledger.append_rows(repo.root, list(rows))


def _report(repo, tree: str):
    return credit.submit_report(repo.root, tree=tree, session="s", host="h", key="k", outcome="success",
                                rules_for=lambda _check: ["trap-sample"])


@needs_git
def test_a_layer_one_only_row_cannot_launder_a_failed_tests_run(tmp_path):
    from aegis_cli.hooks import commitmsg

    repo = hv.make_project(tmp_path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    tree = _staged_tree(repo)
    _append(repo, _row(tree, "c-tests", passed=False, tests={"exit": 1, "passed": 2, "failed": 1}, exit_code=1),
            _row(tree, "c-layer1", passed=True, tests=None))
    assert credit.passing_check(credit.read_rows(repo.root), tree) is None
    assert commitmsg.trailer_for_staged(repo.root) is None
    out = _report(repo, tree)
    assert out["status"] == "claimed" and out["witness"] == "self"


@needs_git
def test_a_passing_tests_row_still_counts_after_a_later_layer_one_only_row(tmp_path):
    from aegis_cli.hooks import commitmsg

    repo = hv.make_project(tmp_path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    tree = _staged_tree(repo)
    _append(repo, _row(tree, "c-tests", passed=True, tests={"exit": 0, "passed": 3, "failed": 0}),
            _row(tree, "c-layer1", passed=True, tests=None))
    assert credit.passing_check(credit.read_rows(repo.root), tree)["id"] == "c-tests"
    assert commitmsg.trailer_for_staged(repo.root) == credit.format_trailer(tree, 0)
    assert _report(repo, tree)["witness"] == "aegis"


def test_a_run_that_collected_no_tests_is_never_a_passing_check():
    rows = [_row(SHA, "c-empty", passed=False, tests={"exit": 5, "passed": 0, "collected": 0}, exit_code=5)]
    assert credit.passing_check(rows, SHA) is None


@pytest.mark.parametrize("tests_field", [
    None, {}, "passed", {"exit": 1, "passed": 2, "failed": 1}, {"exit": 0, "passed": 0}, {"exit": 0, "passed": 3,
                                                                                          "timed_out": True},
], ids=["layer1-only", "empty", "not-a-mapping", "failing", "nothing-passed", "timed-out"])
def test_a_check_row_without_a_passing_tests_run_earns_no_credit(tests_field):
    """Given a 4.3.x Layer-1-only (or untested) check row, a report naming it and a verified CI
    success, When credit is derived, Then nothing counts: such rows no longer credit (W4.5.1)."""
    check = {"event": "check", "id": "c1", "tree": SHA, "witness": "aegis", "passed": True, "tests": tests_field}
    if tests_field is None:
        del check["tests"]
    rows = [check, {"event": "report", "check": "c1", "for_rule": "r", "result": "tp", "ts": "t"},
            {"event": "ci", "commit": "c" * 40, "ci_conclusion": "success"}]
    credits = credit.derive(rows, landed=lambda tree: "c" * 40, verified_ci={"c" * 40: "success"})
    assert [(c.counts, c.reason) for c in credits] == [(False, "no_tests")]
    assert credit.confirmed_outcome_rows(credits) == []


def test_a_check_row_with_a_passing_tests_run_still_confirms():
    check = {"event": "check", "id": "c1", "tree": SHA, "witness": "aegis", "passed": True,
             "tests": {"exit": 0, "passed": 3, "failed": 0}}
    rows = [check, {"event": "report", "check": "c1", "for_rule": "r", "result": "tp", "ts": "t"},
            {"event": "ci", "commit": "c" * 40, "ci_conclusion": "success"}]
    credits = credit.derive(rows, landed=lambda tree: "c" * 40, verified_ci={"c" * 40: "success"})
    assert [(c.state, c.counts, c.result) for c in credits] == [("confirmed", True, "tp")]


# ── derivation edges ─────────────────────────────────────────────────────────

TESTED = {"exit": 0, "passed": 3, "failed": 0}

def test_derive_is_pure_and_needs_a_report_to_name_a_rule():
    check = {"event": "check", "id": "c1", "tree": SHA, "witness": "aegis", "passed": True, "cmd_digest": "d",
             "env_class": "e", "tests": TESTED}
    report = {"event": "report", "check": "c1", "for_rule": "r", "result": "tp", "ts": "t"}
    ci = {"event": "ci", "commit": "c" * 40, "ci_conclusion": "success"}
    rows = [check, report, report, ci]
    snapshot = json.dumps(rows, sort_keys=True)
    unverified = credit.derive(rows, landed=lambda tree: "c" * 40)
    assert [(c.state, c.reason, c.counts) for c in unverified] == [("landed", "unverified_ci", False)]
    credits = credit.derive(rows, landed=lambda tree: "c" * 40, verified_ci={"c" * 40: "success"})
    assert [(c.state, c.counts) for c in credits] == [("confirmed", True)]  # a duplicate report is one credit
    assert json.dumps(rows, sort_keys=True) == snapshot
    assert credit.derive([check], landed=lambda tree: None) == []
    assert credit.confirmed_outcome_rows(credits)[0]["rule"] == "r"


def test_a_type_error_inside_a_landed_lookup_propagates_and_is_not_retried():
    """Given a check row with a head and a landed lookup that raises TypeError internally, When
    credit is derived, Then the TypeError surfaces after one call (no retry as landed(tree))."""
    calls = []

    def landed(tree, head=None):
        calls.append((tree, head))
        raise TypeError("boom")

    check = {"event": "check", "id": "c1", "tree": SHA, "head": "d" * 40, "passed": True, "tests": TESTED}
    report = {"event": "report", "check": "c1", "for_rule": "r", "result": "tp", "ts": "t"}
    with pytest.raises(TypeError, match="boom"):
        credit.derive([check, report], landed=landed)
    assert calls == [(SHA, "d" * 40)]


def test_a_landed_lookup_gets_the_head_once_and_a_row_without_a_head_gets_the_tree_alone():
    calls = []

    def landed(*args):
        calls.append(args)
        return "c" * 40

    rows = [{"event": "check", "id": "c1", "tree": SHA, "head": "d" * 40, "passed": True, "tests": TESTED},
            {"event": "check", "id": "c2", "tree": "2" * 40, "head": "", "passed": True, "tests": TESTED},
            {"event": "report", "check": "c1", "for_rule": "r", "result": "tp", "ts": "t"},
            {"event": "report", "check": "c2", "for_rule": "r", "result": "tp", "ts": "t"}]
    assert [c.commit for c in credit.derive(rows, landed=landed)] == ["c" * 40] * 2
    assert calls == [(SHA, "d" * 40), ("2" * 40,)]


@pytest.mark.parametrize("claimed,fields,expected", [
    ("tp", {"passed": True}, "tp"),
    ("trigger", {"passed": True}, "trigger"),
    ("fp", {"passed": True}, "trigger"),  # a stored fp row is neutralised on read, no rewrite
    (None, {"passed": True}, "trigger"),
    ("tp", {"passed": False}, "trigger"),
    ("tp", {"passed": 1}, "trigger"),
    ("tp", {}, "trigger"),
    ("tp", {"passed": True, "partial": True}, "trigger"),
])
def test_the_credit_sign_is_tp_only_for_a_tp_claim_on_a_passed_check(claimed, fields, expected):
    """Given a confirmed landing, When the report claims ``claimed`` for a check with ``fields``,
    Then the credit is ``tp`` only for a tp claim on a passed, complete check, else a trigger."""
    check = {"event": "check", "id": "c1", "tree": SHA, "witness": "aegis", "tests": TESTED, **fields}
    report = {"event": "report", "check": "c1", "for_rule": "r", "ts": "t"}
    if claimed is not None:
        report["result"] = claimed
    rows = [check, report, {"event": "ci", "commit": "c" * 40, "ci_conclusion": "success"}]
    credits = credit.derive(rows, landed=lambda tree: "c" * 40, verified_ci={"c" * 40: "success"})
    assert [(c.state, c.counts, c.result) for c in credits] == [("confirmed", True, expected)]
    assert [r["outcome"] for r in credit.confirmed_outcome_rows(credits)] == [expected]


def test_a_failed_ci_run_voids_and_a_revert_style_void_row_is_terminal():
    check = {"event": "check", "id": "c1", "tree": SHA, "passed": True}
    report = {"event": "report", "check": "c1", "for_rule": "r", "result": "tp"}
    failed = credit.derive([check, report, {"event": "ci", "commit": "c" * 40, "ci_conclusion": "failure"}],
                           landed=lambda tree: "c" * 40)
    assert failed[0].state == "voided" and failed[0].reason == "ci_failed" and not failed[0].counts


def test_report_idempotency_is_refused_for_a_different_outcome(tmp_path):
    tree = "1" * 40
    credit.submit_report(tmp_path, tree=tree, session="s", host="h", key="k", outcome="success", rules_for=lambda c: [])
    with pytest.raises(credit.ReportConflict):
        credit.submit_report(tmp_path, tree=tree, session="s", host="h", key="k", outcome="failure",
                             rules_for=lambda c: [])
    assert credit.submit_report(tmp_path, tree=tree, session="s", host="h", key="k", outcome="success",
                                rules_for=lambda c: [])["status"] == "claimed"


def test_a_report_with_no_tree_is_a_claim_and_the_cap_is_honoured(tmp_path):
    first = credit.submit_report(tmp_path, tree=None, session="s", host="h", key="a", outcome="success",
                                 rules_for=lambda c: [], cap=1)
    second = credit.submit_report(tmp_path, tree="2" * 40, session="s", host="h", key="b", outcome="success",
                                  rules_for=lambda c: [], cap=1)
    assert first["status"] == "claimed" and second["status"] == "rate_limited"
    assert len(hv.rows_of(tmp_path, "claimed")) == 1


# ── evidence ignores the caller's GIT_DIR (R-trust-19) ─────────────────────────

_LOCAL_GIT_ENV = ("GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
                  "GIT_OBJECT_DIRECTORY", "GIT_DIR", "GIT_WORK_TREE", "GIT_IMPLICIT_WORK_TREE", "GIT_GRAFT_FILE",
                  "GIT_INDEX_FILE", "GIT_REPLACE_REF_BASE", "GIT_PREFIX", "GIT_SHALLOW_FILE", "GIT_COMMON_DIR")


@pytest.fixture
def two_repos(tmp_path):
    """A (work branch: only_in_a.txt and a sharpened rule) and B (work branch: only_in_b.txt)."""
    a = hv.make_project(tmp_path, name="a")
    a.write("only_in_a.txt", "a\n")
    a.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("hypothesis: sample", "hypothesis: sharper"))
    a.commit("a")
    b = hv.make_project(tmp_path, name="b")
    b.write("only_in_b.txt", "b\n")
    b.commit("b")
    hv.use_stub_runner(a.home.path)
    return a, b


def _ambient(monkeypatch, b) -> None:
    monkeypatch.setenv("GIT_DIR", str(b.root / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(b.root))


def _git_children(monkeypatch):
    """The environment of every git child, whichever runner starts it."""
    seen = []
    real = subprocess.run

    def spy(argv, *args, **kwargs):
        if os.path.basename(str(argv[0])).lower() in ("git", "git.exe"):
            seen.append(dict(kwargs.get("env") or os.environ))
        return real(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    return seen


def _evidence_calls(a):
    from aegis_core import human_gate, regression, release_verify, rule_integrity, sync

    head = a.head()
    no_rerun = lambda commit, tree: {"tree": tree, "exit": 0}  # noqa: E731

    def gh(argv, timeout=0):
        return (0, "gh version 2.93.0 (2026-01-01)\n", "") if argv[:1] == ["--version"] else (1, "", "no")

    return {
        "treeid.tree_files": lambda: treeid.tree_files(a.root),
        "treeid.tree_of": lambda: treeid.tree_of(a.root),
        "checkrun.record": lambda: checkrun.record(a.root),
        "checkrun.rerun_commit_snapshot": lambda: checkrun.rerun_commit_snapshot(a.root, head, "main", timeout=60),
        "checkrun.verify_commit_trailers": lambda: checkrun.verify_commit_trailers(a.root, "main", rerun_fn=no_rerun),
        "credit.verify_commit_trailers": lambda: credit.verify_commit_trailers(a.root, "main", rerun_fn=no_rerun),
        "rule_integrity.check_ci": lambda: rule_integrity.check_ci(a.root, "main", "HEAD"),
        "human_gate.find_approval": lambda: human_gate.find_approval(a.root, "HEAD", "main"),
        "human_gate.find_test_exemption": lambda: human_gate.find_test_exemption(a.root, "HEAD", "main", head),
        "human_gate.verify_approval": lambda: human_gate.verify_approval(a.root, head, "0" * 64, "main"),
        "human_gate.verify_insight_approval": lambda: human_gate.verify_insight_approval(a.root, head, "x", "main"),
        "human_gate.verify_test_exemption": lambda: human_gate.verify_test_exemption(a.root, head, head, "main"),
        "release_verify.verify_release": lambda: release_verify.verify_release(a.root, head, run=gh,
                                                                               tier_runner=lambda *x, **k: None),
        "regression.check_ci_regressions": lambda: regression.check_ci_regressions(a.root, "main", "HEAD"),
        "sync.base_fetch": lambda: sync.base_fetch(a.root),
        "sync.sync": lambda: sync.sync(a.root),
    }


_EVIDENCE = [
    "treeid.tree_files", "treeid.tree_of", "checkrun.record", "checkrun.rerun_commit_snapshot",
    "checkrun.verify_commit_trailers", "credit.verify_commit_trailers", "rule_integrity.check_ci",
    "human_gate.find_approval", "human_gate.find_test_exemption", "human_gate.verify_approval",
    "human_gate.verify_insight_approval", "human_gate.verify_test_exemption", "release_verify.verify_release",
    "regression.check_ci_regressions", "sync.base_fetch", "sync.sync",
]


@needs_git
@pytest.mark.parametrize("name", _EVIDENCE)
def test_no_evidence_git_call_follows_an_exported_git_dir(two_repos, monkeypatch, name):
    """Given GIT_DIR/GIT_WORK_TREE exported for repository B, when an evidence function runs against A,
    then no git child it starts is pointed at B (the leak matrix of R-trust-19)."""
    a, b = two_repos
    call = _evidence_calls(a)[name]
    _ambient(monkeypatch, b)
    seen = _git_children(monkeypatch)
    try:
        call()
    except Exception:  # noqa: BLE001 - the verdict does not matter here, only where git looked
        pass
    assert seen, "the function started no git at all"
    marks = {os.path.normcase(str(b.root)), os.path.normcase(os.path.realpath(b.root))}
    leaked = sorted({k for env in seen for k, v in env.items()
                     if k.upper() in _LOCAL_GIT_ENV and any(m in os.path.normcase(v) for m in marks)})
    assert leaked == []


@needs_git
def test_the_tree_head_base_and_rules_are_the_repository_asked_about(two_repos, monkeypatch):
    """Given GIT_DIR/GIT_WORK_TREE exported for B, then every tree, head, base and rule read is A's."""
    from aegis_core import rule_integrity

    a, b = two_repos
    clean_tree, head, base = treeid.tree_of(a.root).tree, a.head(), a.git("merge-base", "main", "HEAD")
    assert clean_tree == hv.tree_now(a.root)
    _ambient(monkeypatch, b)  # from here the helpers' own git would follow it too
    files = treeid.tree_files(a.root)
    assert "only_in_a.txt" in files and "only_in_b.txt" not in files
    assert treeid.tree_of(a.root).tree == clean_tree
    outcome = checkrun.record(a.root)
    assert outcome.status == "recorded", outcome.reason
    assert outcome.row["head"] == head and outcome.row["tree"] == clean_tree and outcome.row["base"] == base
    report = rule_integrity.check_ci(a.root, "main", "HEAD")
    assert report.head == head and report.merge_base == base


@needs_git
def test_approve_reads_the_key_from_the_user_config_and_signs_in_the_repository_asked_about(two_repos, monkeypatch):
    """Given the signing key only in GIT_CONFIG_GLOBAL and GIT_DIR exported for B, when aegis approve
    runs in A, then the key comes from that file and the signed commit is made in A (spy, no ssh-keygen)."""
    import argparse
    import builtins

    from aegis_cli import approve
    from aegis_core import gitsafe, human_gate

    a, b = two_repos
    head = a.head()
    config = a.home.path / "global.gitconfig"
    config.write_bytes(b"[gpg]\n\tformat = ssh\n[user]\n\tsigningkey = key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    _ambient(monkeypatch, b)
    with gitsafe.scrubbed():
        assert human_gate.signing_config(a.root) == {"format": "ssh", "key": "key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"}
    signed = []

    def custody(top):
        signed.append(("custody", Path(top), human_gate.signing_config(top)["key"]))
        return human_gate.KeyCustody("agent", "an agent holds the key", False)

    monkeypatch.setattr(human_gate, "check_key_custody", custody)
    monkeypatch.setattr(human_gate, "signed_empty_commit",
                        lambda top, message, interactive=False: signed.append(("sign", Path(top), message)) or head)
    monkeypatch.setattr(approve, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr(builtins, "input", lambda prompt="": "y")
    code = approve.run_approve(argparse.Namespace(workspace=str(a.root), json=False, base="main", exempt_test=None,
                                                  reason=None))
    assert code == 0
    assert [(kind, os.path.samefile(top, a.root)) for kind, top, _ in signed] == [("custody", True), ("sign", True)]
    assert signed[0][2] == "key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"


# ── the JUnit reader and one name per function (R-trust-50) ───────────────────

_JUNIT = b"""<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" tests="5"><error message="suite setup">boom</error>
<testcase classname="tests.test_a" name="test_one"/>
<testcase classname="tests.test_a" name="test_two"/>
<testcase classname="tests.test_a" name="test_three"/>
<testcase classname="tests.test_a" name="test_bad"><failure message="no">x</failure></testcase>
<testcase classname="tests.test_a" name="test_skip"><skipped message="later"/></testcase>
</testsuite></testsuites>
"""
_SUMMARY = "import sys; print('2 passed, 1 failed in 0.01s'); sys.exit(1)"


def test_a_junit_file_is_counted_case_by_case(tmp_path):
    import hashlib

    junit = tmp_path / "junit.xml"
    junit.write_bytes(_JUNIT)
    run = checkrun.run_tests([sys.executable, "-c", _SUMMARY], tmp_path, checkrun.hermetic_env(tmp_path), 60.0, junit,
                             tmp_path / "out.txt")
    ids = sorted(f"tests.test_a::{n}" for n in ("test_one", "test_two", "test_three", "test_bad", "test_skip"))
    assert (run.collected, run.passed, run.failed, run.skipped) == (5, 3, 1, 1)
    assert run.nodeid_digest == hashlib.sha256("\n".join(ids).encode("utf-8")).hexdigest()
    passed, failed, errors = checkrun.parse_junit_cases(junit)
    assert passed == {"tests.test_a::test_one", "tests.test_a::test_two", "tests.test_a::test_three"}
    assert failed == {"tests.test_a::test_bad"} and errors == ["<suite:pytest>"]


@pytest.mark.parametrize("junit_bytes", [b"<testsuite><testcase", None], ids=["malformed", "oversized"])
def test_an_unreadable_junit_file_falls_back_to_the_summary_line(tmp_path, monkeypatch, junit_bytes):
    junit = tmp_path / "junit.xml"
    if junit_bytes is None:
        monkeypatch.setattr(checkrun, "_MAX_JUNIT_BYTES", 64)
        junit_bytes = _JUNIT
    junit.write_bytes(junit_bytes)
    run = checkrun.run_tests([sys.executable, "-c", _SUMMARY], tmp_path, checkrun.hermetic_env(tmp_path), 60.0, junit,
                             tmp_path / "out.txt")
    assert (run.collected, run.passed, run.failed, run.nodeid_digest) == (3, 2, 1, None)
    assert checkrun.parse_junit_cases(junit) == (set(), set(), [])


def test_each_function_has_one_name_and_no_public_name_is_unreferenced():
    for gone in ("parse_junit", "_junit", "_hermetic_env", "_kill_group"):
        assert not hasattr(checkrun, gone), gone
    assert "parse_junit" not in checkrun.__all__
    assert all(hasattr(checkrun, name) for name in checkrun.__all__)
    assert treeid.named_paths(["a", "b"]) == "a, b" and "named_paths" in treeid.__all__
    assert treeid.named_paths([str(i) for i in range(7)]) == "0, 1, 2, 3, 4 and 2 more"


def test_the_process_group_killer_a_caller_patches_is_the_one_a_run_uses(tmp_path, monkeypatch):
    killed = []
    monkeypatch.setattr(checkrun, "kill_group", lambda proc: killed.append(proc.pid))
    checkrun.run_tests([sys.executable, "-c", "pass"], tmp_path, checkrun.hermetic_env(tmp_path), 60.0,
                       tmp_path / "junit.xml", tmp_path / "out.txt")
    assert len(killed) == 1


@needs_git
@pytest.mark.skipif(sys.platform == "win32", reason="time.tzset is POSIX")
def test_a_check_row_stamps_a_naive_now_as_utc(tmp_path):
    """A naive datetime is UTC by rule (R-structure-20); it was read as local time here."""
    from datetime import datetime

    repo = hv.make_project(tmp_path)
    old = os.environ.get("TZ")
    os.environ["TZ"] = "America/New_York"
    time.tzset()
    try:
        outcome = checkrun.record(repo.root, now=datetime(2026, 10, 19, 12, 0))
    finally:
        if old is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old
        time.tzset()
    assert outcome.status == "recorded", outcome.reason
    assert outcome.row["ts"] == outcome.row["checked_at"] == "2026-10-19T12:00:00Z"
