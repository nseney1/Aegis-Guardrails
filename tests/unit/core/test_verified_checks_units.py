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


def test_a_trailer_line_is_accepted_as_well_as_a_parsed_one():
    assert credit.check_ci_divergence(credit.format_trailer(SHA, 0), {"tree": SHA, "exit": 0})["result"] == "agree"


# ── derivation edges ─────────────────────────────────────────────────────────

def test_derive_is_pure_and_needs_a_report_to_name_a_rule():
    check = {"event": "check", "id": "c1", "tree": SHA, "witness": "aegis", "passed": True, "cmd_digest": "d",
             "env_class": "e"}
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
    check = {"event": "check", "id": "c1", "tree": SHA, "witness": "aegis", **fields}
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
