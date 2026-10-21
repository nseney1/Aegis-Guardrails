"""`aegis check`: the v4 verification gate, driven through the real CLI entry point.

Interface: aegis check [FILES...] [--hook] [--strict] [--full]
           [--plan TEXT | --plan-file PATH] [--llm-cmd CMD] [--dry-run] [--format text|json]

Layer 1 (default) = the workspace checkpoint checks plus call_graph, import_guard
and forbid_ast on the target files. Layer 2 (--full, or a plan) adds the adversarial
review, run by one external command (--llm-cmd / AEGIS_LLM_CMD).
"""
from __future__ import annotations

import json
import shlex
import subprocess
import sys
import textwrap
import unicodedata
from pathlib import Path

import pytest

from aegis_cli.cli import main

CLEAN = "def compute(a: int, b: int) -> int:\n    return a + b\n\n\ndef main():\n    return compute(1, 2)\n"
UNGUARDED_IMPORT = "import unapproved_third_party_pkg_xyz\n\n\ndef main():\n    return 1\n"

FAKE_LLM = textwrap.dedent(
    """\
    import json, sys
    mode = sys.argv[1]
    prompt = sys.stdin.read()
    spec = "Spec Agent" in prompt
    if mode == "fail":
        sys.stderr.write("quota exceeded\\n")
        sys.exit(7)
    if mode == "hostile-fail":
        sys.stderr.write("quota\\x1b]0;pwned\\x07 exceeded\\x1b[2K\\x9b31m\\x7f\\n")
        sys.exit(7)
    if mode == "dump":
        with open(sys.argv[2], "a", encoding="utf-8") as out:
            out.write(prompt)
    if mode == "garbage":
        print("Internal Server Error: 500 API Gateway Timeout")
    if mode == "code-fail" and not spec:
        sys.stderr.write("quota exceeded\\n")
        sys.exit(7)
    elif mode in ("block", "revise", "ship", "code-fail") and spec:
        print(json.dumps([{
            "category": "code_injection", "severity": {"block": "critical", "revise": "high"}.get(mode, "low"),
            "risk": "eval of untrusted input", "mechanism": "code execution",
            "affected_function": "compute",
        }]))
    elif mode == "unknown" and spec:
        print(json.dumps([{"category": "not_a_category", "severity": "high", "risk": "r",
                           "mechanism": "m", "affected_function": "compute"}]))
    elif mode == "spec-file" and spec:
        with open(sys.argv[2], encoding="utf-8") as reply:
            print(reply.read())
    else:
        print("[]")
    """
)


def _exit_code(argv: list[str]) -> int:
    try:
        return main(argv)
    except SystemExit as exc:
        return exc.code


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    return root


@pytest.fixture
def llm(tmp_path: Path):
    script = tmp_path / "fake_llm.py"
    script.write_text(FAKE_LLM, encoding="utf-8")
    return lambda mode, *extra: shlex.join([sys.executable, str(script), mode, *extra])


@pytest.fixture(autouse=True)
def _no_ambient_backend(monkeypatch):
    monkeypatch.delenv("AEGIS_LLM_CMD", raising=False)
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _git_repo(root: Path) -> Path:
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "T")
    (root / "README.md").write_text("# p\n", encoding="utf-8")
    _git(root, "add", "README.md")
    _git(root, "commit", "-q", "-m", "init")
    return root


def _shallow_clone_of_a_branch_without_main(origin: Path, tmp_path: Path) -> Path:
    """A depth-1 CI-style checkout: no HEAD~1, no main/develop, so no base to diff against."""
    _git_repo(origin)
    _git(origin, "checkout", "-q", "-b", "feature")
    (origin / "CHANGELOG.md").write_text("- x\n", encoding="utf-8")
    _git(origin, "add", "CHANGELOG.md")
    _git(origin, "commit", "-q", "-m", "feature")
    clone = tmp_path / "ci-checkout"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", "--branch", "feature", "--single-branch", origin.as_uri(), str(clone)],
        check=True, capture_output=True,
    )
    return clone


# ── Flag diet ───────────────────────────────────────────────────────────────

class TestInterface:
    @pytest.mark.parametrize(
        "flag",
        [
            ["--no-layer2"], ["--all"], ["--files", "a.py"], ["--pre-commit"], ["--checkpoint-only"],
            ["--layer1-only"], ["--deep"], ["--release"], ["--release-gate"], ["--require-arbitration"],
            ["--in-band"], ["--provider", "gemini"], ["--format", "sarif"],
        ],
        ids=lambda f: f[0] if len(f) == 1 else " ".join(f),
    )
    def test_removed_flags_are_usage_errors(self, ws, capsys, flag):
        assert _exit_code(["check", "--workspace", str(ws), *flag]) == 2
        err = capsys.readouterr().err
        assert "unrecognized arguments" in err or "invalid choice" in err

    @pytest.mark.parametrize("name", ["verify", "checkpoint"])
    def test_verify_and_checkpoint_are_no_longer_check_aliases(self, ws, name):
        assert _exit_code([name, "--workspace", str(ws)]) == 2

    def test_plan_and_plan_file_are_mutually_exclusive(self, ws, capsys):
        assert _exit_code(["check", "--workspace", str(ws), "--plan", "x", "--plan-file", "p.md"]) == 2
        assert "not allowed with argument" in capsys.readouterr().err


# ── Layer 1 (default) ───────────────────────────────────────────────────────

class TestLayer1:
    def test_clean_file_passes(self, ws, capsys):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "clean.py"]) == 0
        out = capsys.readouterr().out
        assert "Layer 1:" in out and "PASSED" in out
        assert "Layer 2" not in out

    def test_unguarded_third_party_import_fails(self, ws, capsys):
        (ws / "bad.py").write_text(UNGUARDED_IMPORT, encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "bad.py"]) == 1
        assert "import_guard" in capsys.readouterr().out

    def test_only_the_named_files_are_checked(self, ws):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        (ws / "bad.py").write_text(UNGUARDED_IMPORT, encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "clean.py"]) == 0
        assert _exit_code(["check", "--workspace", str(ws), "clean.py", "bad.py"]) == 1

    def test_missing_file_is_an_error(self, ws, capsys):
        assert _exit_code(["check", "--workspace", str(ws), "nope.py"]) == 1
        assert "file not found: nope.py" in capsys.readouterr().err

    def test_out_of_tree_files_are_refused(self, ws, capsys):
        assert _exit_code(["check", "--workspace", str(ws), "../../etc/passwd"]) == 1
        assert "outside the repository" in capsys.readouterr().err

    def test_no_changed_files_is_a_clean_pass(self, ws, capsys):
        assert _exit_code(["check", "--workspace", str(ws)]) == 0
        assert "0 files changed" in capsys.readouterr().out

    def test_an_unreadable_gate_rule_fails_the_check(self, ws, capsys):
        invariants = ws / ".aegis" / "rules" / "invariants"
        invariants.mkdir(parents=True)
        (invariants / "no-subprocess.md").write_bytes(
            b"---\nid: no-subprocess\ntype: invariant\nenforcement: gate\n"
            b"forbid_ast:\n  calls: [subprocess.run]\n---\nNo shelling out \xff here.\n"
        )
        (ws / "bad.py").write_text(
            "import subprocess\n\n\ndef main():\n    return subprocess.run(['true'])\n", encoding="utf-8"
        )
        assert _exit_code(["check", "--workspace", str(ws), "bad.py"]) == 1
        out = capsys.readouterr().out
        assert "forbid_ast: .aegis/rules/invariants/no-subprocess.md" in out
        assert "PASSED" not in out

    def test_a_malformed_forbid_ast_rule_fails_the_check(self, ws, capsys):
        invariants = ws / ".aegis" / "rules" / "invariants"
        invariants.mkdir(parents=True)
        (invariants / "r1.md").write_text(
            "---\nid: r1\ntype: invariant\nenforcement: gate\nforbid_ast:\n  - calls: [eval]\n---\n", encoding="utf-8"
        )
        (ws / "bad.py").write_text("def main(x):\n    return eval(x)\n", encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "--hook", "bad.py"]) == 1
        out = capsys.readouterr().out
        assert "forbid_ast: .aegis/rules/invariants/r1.md" in out
        assert "PASSED" not in out

    def test_a_directory_target_checks_the_files_under_it(self, ws, capsys):
        _git_repo(ws)
        (ws / "src").mkdir()
        (ws / "src" / "m.py").write_text(UNGUARDED_IMPORT, encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "--format", "json", "src"]) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["files"] == ["src/m.py"]
        assert [r["tool"] for r in payload["layer1"] if not r["verdict"]] == ["import_guard"]

    def test_a_directory_target_skips_git_ignored_files(self, ws, capsys):
        _git_repo(ws)
        (ws / ".gitignore").write_text("build/\n", encoding="utf-8")
        (ws / "src" / "build").mkdir(parents=True)
        (ws / "src" / "build" / "gen.py").write_text(UNGUARDED_IMPORT, encoding="utf-8")
        (ws / "src" / "ok.py").write_text(CLEAN, encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "--format", "json", "src"]) == 0
        assert json.loads(capsys.readouterr().out)["files"] == ["src/ok.py"]

    def test_a_directory_target_outside_a_git_work_tree_is_an_error(self, ws, capsys):
        (ws / "src").mkdir()
        (ws / "src" / "m.py").write_text(UNGUARDED_IMPORT, encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "src"]) == 1
        captured = capsys.readouterr()
        assert "cannot list the files under src" in captured.err
        assert "PASSED" not in captured.out

    def test_a_named_file_no_check_applies_to_is_not_reported_as_no_changes(self, ws, capsys):
        (ws / "notes.txt").write_text("remember the milk\n", encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "notes.txt"]) == 0
        out = capsys.readouterr().out
        assert "Layer 1: no check applies to the 1 target file (0 checks run, PASSED)" in out
        assert "No changed files" not in out

    def test_no_base_commit_is_said_not_called_a_clean_repository(self, ws, tmp_path, capsys):
        clone = _shallow_clone_of_a_branch_without_main(ws, tmp_path)
        assert _exit_code(["check", "--workspace", str(clone)]) == 0
        out = capsys.readouterr().out
        assert "Layer 1: 0 files changed (no base commit found to diff against" in out
        assert "clean repository" not in out

    @pytest.mark.parametrize(
        "extra, fast",
        [([], True), (["--hook"], True), (["--full", "--plan", "p"], False), (["--plan", "p"], False)],
        ids=["default", "hook", "full", "plan"],
    )
    def test_mutation_testing_runs_only_behind_layer2(self, ws, monkeypatch, llm, extra, fast):
        from aegis_core.verification import runner

        seen = []

        def spy(**kwargs):
            seen.append(kwargs["fast_mode"])
            return []

        monkeypatch.setattr(runner, "run_layer1", spy)
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        backend = ["--llm-cmd", llm("ship")] if "--hook" not in extra else []
        _exit_code(["check", "--workspace", str(ws), *backend, *extra, "clean.py"])
        assert seen == [fast]

    def test_changed_files_come_from_git_when_none_are_named(self, ws, capsys):
        _git_repo(ws)
        (ws / "bad.py").write_text(UNGUARDED_IMPORT, encoding="utf-8")
        _git(ws, "add", "bad.py")
        assert _exit_code(["check", "--workspace", str(ws)]) == 1
        assert "bad.py" in capsys.readouterr().out

    def test_dry_run_lists_files_and_runs_nothing(self, ws, capsys):
        (ws / "bad.py").write_text(UNGUARDED_IMPORT, encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "--dry-run", "bad.py"]) == 0
        out = capsys.readouterr().out
        assert "Dry run" in out and "bad.py" in out and "Layer 1" in out
        assert "import_guard" not in out

    def test_json_is_one_document_with_layer1_and_checkpoint(self, ws, capsys):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "--format", "json", "clean.py"]) == 0
        raw = capsys.readouterr().out
        assert "\x1b[" not in raw
        payload = json.loads(raw)
        assert payload["passed"] is True
        assert payload["files"] == ["clean.py"]
        assert {r["tool"] for r in payload["layer1"]} >= {"call_graph", "import_guard"}
        assert isinstance(payload["checkpoint_issues"], list)
        assert "layer2" not in payload

    def test_global_json_flag_matches_format_json(self, ws, capsys):
        (ws / "bad.py").write_text(UNGUARDED_IMPORT, encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "--json", "bad.py"]) == 1
        assert json.loads(capsys.readouterr().out)["passed"] is False


# ── --strict and the workspace checkpoint ───────────────────────────────────

class TestStrict:
    def _missing_test_and_hardcoded_path(self, ws: Path) -> None:
        (ws / "src").mkdir()
        (ws / "src" / "svc.py").write_text('CACHE = "/home/alice/cache"\n', encoding="utf-8")

    def test_checkpoint_issues_warn_by_default(self, ws, capsys):
        self._missing_test_and_hardcoded_path(ws)
        assert _exit_code(["check", "--workspace", str(ws)]) == 0
        out = capsys.readouterr().out
        assert "[WARN] Missing test file for svc.py" in out
        assert "[WARN] Hardcoded absolute path found in svc.py:1" in out

    def test_strict_fails_on_checkpoint_issues(self, ws, capsys):
        # #12: `check --strict` must not be a passing no-op on a failing workspace.
        self._missing_test_and_hardcoded_path(ws)
        assert _exit_code(["check", "--workspace", str(ws), "--strict"]) == 1
        out = capsys.readouterr().out
        assert "[FAIL] Missing test file for svc.py" in out
        assert "[FAIL] Hardcoded absolute path found in svc.py:1" in out

    def test_strict_passes_a_clean_workspace(self, ws):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        (ws / "tests").mkdir()
        (ws / "tests" / "test_clean.py").write_text(
            "from clean import compute\n\n\ndef test_compute():\n    assert compute(1, 2) == 3\n", encoding="utf-8"
        )
        assert _exit_code(["check", "--workspace", str(ws), "--strict", "clean.py"]) == 0

    def test_json_reports_checkpoint_issues(self, ws, capsys):
        self._missing_test_and_hardcoded_path(ws)
        assert _exit_code(["check", "--workspace", str(ws), "--strict", "--format", "json"]) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["passed"] is False
        assert {i["check"] for i in payload["checkpoint_issues"]} == {"test_coverage", "hardcoded_paths"}


# ── --hook (git pre-commit) ─────────────────────────────────────────────────

class TestHook:
    def test_staged_clean_file_passes(self, ws):
        _git_repo(ws)
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        _git(ws, "add", "clean.py")
        assert _exit_code(["check", "--workspace", str(ws), "--hook"]) == 0

    def test_staged_unguarded_import_blocks(self, ws, capsys):
        _git_repo(ws)
        (ws / "bad.py").write_text(UNGUARDED_IMPORT, encoding="utf-8")
        _git(ws, "add", "bad.py")
        assert _exit_code(["check", "--workspace", str(ws), "--hook"]) == 1
        assert "import_guard: bad.py" in capsys.readouterr().out

    @pytest.mark.parametrize(
        "extra", [["--full"], ["--plan", "x"], ["--plan-file", "plan.md"], ["--plan", ""], ["--plan-file", ""]]
    )
    def test_hook_never_runs_layer2(self, ws, capsys, llm, extra):
        assert _exit_code(["check", "--workspace", str(ws), "--hook", "--llm-cmd", llm("ship"), *extra]) == 2
        assert "--hook runs Layer 1 only" in capsys.readouterr().err

    @pytest.mark.parametrize("strict", [[], ["--strict"]])
    def test_hook_fails_when_layer1_cannot_run(self, ws, monkeypatch, capsys, strict):
        from aegis_core.verification import runner

        def boom(**_kwargs):
            raise RuntimeError("driver registry exploded")

        monkeypatch.setattr(runner, "run_layer1", boom)
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "--hook", *strict, "clean.py"]) == 1
        assert "Layer 1 could not run: driver registry exploded" in capsys.readouterr().err

    @pytest.mark.parametrize("strict", [[], ["--strict"]])
    def test_hook_fails_when_a_layer1_tool_raises(self, ws, monkeypatch, capsys, strict):
        from aegis_core.verification import call_graph

        def boom(*_args, **_kwargs):
            raise RecursionError("maximum recursion depth exceeded")

        monkeypatch.setattr(call_graph, "check", boom)
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "--hook", *strict, "clean.py"]) == 1
        out = capsys.readouterr().out
        assert "call_graph: clean.py" in out
        assert "RecursionError: maximum recursion depth exceeded" in out


# ── Layer 2 (--full / --plan) ───────────────────────────────────────────────

class TestLayer2:
    @pytest.mark.parametrize(
        "extra", [["--full", "--plan", "p"], ["--plan", "p"], ["--plan-file", "plan.md"], ["--full"]],
        ids=["full+plan", "plan", "plan-file", "full"],
    )
    def test_without_a_backend_exits_2_before_running_anything(self, ws, capsys, extra):
        (ws / "plan.md").write_text("Add compute\n", encoding="utf-8")
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), *extra, "clean.py"]) == 2
        captured = capsys.readouterr()
        assert "Layer 2 needs --llm-cmd or AEGIS_LLM_CMD" in captured.err
        assert "skipped" not in (captured.out + captured.err).lower()
        assert "Layer 1:" not in captured.out

    @pytest.mark.parametrize(
        "extra",
        [["--plan", ""], ["--plan", "  \n"], ["--plan-file", ""], ["--full", "--plan-file", " "],
         ["--plan-file", "blank.md"]],
        ids=["plan-empty", "plan-blank", "plan-file-empty", "full+plan-file-blank", "plan-file-blank-content"],
    )
    @pytest.mark.parametrize("backend", [False, True], ids=["no-backend", "backend"])
    def test_an_empty_plan_is_a_usage_error_never_a_layer1_pass(self, ws, capsys, llm, extra, backend):
        # `--plan "$PLAN"` with PLAN unset asked for Layer 2: it must never read as a Layer 1 pass (b1-verify F1).
        (ws / "blank.md").write_text("  \n", encoding="utf-8")
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        cmd = ["--llm-cmd", llm("ship")] if backend else []
        assert _exit_code(["check", "--workspace", str(ws), *cmd, *extra, "clean.py"]) == 2
        captured = capsys.readouterr()
        # Without a backend, a plan file that is read and found empty may report the missing backend first.
        needs_plan = backend or "blank.md" not in extra
        assert ("Layer 2 needs a task plan" if needs_plan else "Layer 2 needs") in captured.err
        assert "Layer 1:" not in captured.out

    def test_full_with_no_changes_and_no_base_commit_exits_2(self, ws, tmp_path, capsys, llm):
        clone = _shallow_clone_of_a_branch_without_main(ws, tmp_path)
        argv = ["check", "--workspace", str(clone), "--full", "--plan", "x", "--llm-cmd", llm("ship")]
        assert _exit_code(argv) == 2
        captured = capsys.readouterr()
        assert "no base commit found to diff against (a shallow clone?)" in captured.err
        assert "pass the files to review" in captured.err
        assert "Layer 1:" not in captured.out

    def test_env_backend_ship_passes(self, ws, monkeypatch, capsys, llm):
        monkeypatch.setenv("AEGIS_LLM_CMD", llm("ship"))
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "--full", "--plan", "Add compute", "clean.py"]) == 0
        out = capsys.readouterr().out
        assert "Layer 2: ✅ SHIP" in out

    def test_plan_alone_implies_full(self, ws, capsys, llm):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "--llm-cmd", llm("ship"), "--plan", "Add compute", "clean.py"]) == 0
        assert "Layer 2: ✅ SHIP" in capsys.readouterr().out

    def test_flag_beats_env(self, ws, monkeypatch, llm):
        monkeypatch.setenv("AEGIS_LLM_CMD", llm("fail"))
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        argv = ["check", "--workspace", str(ws), "--llm-cmd", llm("ship"), "--plan", "Add compute", "clean.py"]
        assert _exit_code(argv) == 0

    def test_a_layer2_block_is_advisory_when_layer1_passes(self, ws, capsys, llm):
        # T6 is log-only: the exit status is Layer 1's (R-checks-43).
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        argv = ["check", "--workspace", str(ws), "--llm-cmd", llm("block"), "--plan", "Add compute", "clean.py"]
        assert _exit_code(argv) == 0
        out = capsys.readouterr().out
        assert "Layer 2: 🔴 BLOCK" in out
        assert "advisory" in out

    def test_a_layer2_revise_is_advisory_when_layer1_passes(self, ws, capsys, llm):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        argv = ["check", "--workspace", str(ws), "--llm-cmd", llm("revise"), "--plan", "Add compute", "clean.py"]
        assert _exit_code(argv) == 0
        out = capsys.readouterr().out
        assert "REVISE" in out
        assert "advisory" in out

    def test_an_unreadable_spec_reply_is_unverified_never_ship_or_block(self, ws, capsys, llm):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        argv = ["check", "--workspace", str(ws), "--llm-cmd", llm("garbage"), "--plan", "Add compute", "clean.py"]
        assert _exit_code(argv) == 0
        out = capsys.readouterr().out
        assert "Layer 2: ⚠️ UNVERIFIED" in out
        assert "infra_status: unverified (spec_agent_unparseable, code_agent_unparseable, no_predictions)" in out
        assert "SHIP" not in out
        assert "BLOCK" not in out

    def test_an_empty_review_is_unverified_never_ship(self, ws, capsys, llm):
        """R-checks-44: a valid `[]` from the Spec Agent is a review that predicted nothing, not a SHIP."""
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        argv = ["check", "--workspace", str(ws), "--llm-cmd", llm("empty"), "--plan", "Add compute", "clean.py"]
        assert _exit_code(argv) == 0
        out = capsys.readouterr().out
        assert "Layer 2: ⚠️ UNVERIFIED" in out
        assert "infra_status: unverified (no_predictions)" in out
        assert "SHIP" not in out

    def test_dropped_unknown_categories_are_counted_in_text_and_json(self, ws, capsys, llm):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        argv = ["check", "--workspace", str(ws), "--llm-cmd", llm("unknown"), "--plan", "p", "clean.py"]
        assert _exit_code(argv) == 0
        assert "infra_status: unverified (no_predictions, unknown_category:1)" in capsys.readouterr().out
        assert _exit_code([*argv[:1], "--format", "json", *argv[1:]]) == 0
        layer2 = json.loads(capsys.readouterr().out)["layer2"]
        assert layer2["verdict"] is None
        assert layer2["unverified_reasons"] == ["no_predictions", "unknown_category:1"]

    @pytest.mark.parametrize("mode,expected", [("garbage", "UNVERIFIED"), ("block", "BLOCK"), ("ship", "SHIP")],
                             ids=["unreadable", "block", "ship"])
    def test_the_ledger_records_unverified_for_a_review_that_did_not_complete(self, ws, llm, mode, expected):
        """Given a trap matching the change and a passing Layer 1, When ``aegis check --full`` runs and the
        Spec Agent's reply cannot be parsed, Then the telemetry row says UNVERIFIED (never SHIP) and the
        exit status is Layer 1's; a review that completed records its own verdict."""
        from aegis_core.telemetry_engine import ledger
        from aegis_core.verification import Verdict

        traps = ws / ".aegis" / "rules" / "traps"
        traps.mkdir(parents=True)
        (traps / "trap-py.md").write_text(
            "---\nid: trap-py\ntype: trap\ndomain: correctness\nenforcement: advisory\nhypothesis: py\n"
            "target_paths:\n  - '*.py'\n---\n# Py\n\nBody long enough to be a rule body.\n", encoding="utf-8")
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        argv = ["check", "--workspace", str(ws), "--full", "--plan", "Add compute", "--llm-cmd", llm(mode), "clean.py"]
        assert _exit_code(argv) == 0
        rows = [r for r in ledger.read(ws).rows if r.get("rule") == "trap-py"]
        want = "UNVERIFIED" if expected == "UNVERIFIED" else str(Verdict[expected])
        assert [(r.get("outcome"), (r.get("meta") or {}).get("verdict")) for r in rows] == [("trigger", want)]

    @staticmethod
    def _spec_reply(tmp_path: Path, severity: str, risk) -> str:
        reply = tmp_path / "spec_reply.json"
        reply.write_text(json.dumps([{"category": "code_injection", "severity": severity, "risk": risk,
                                      "mechanism": "m", "affected_function": "compute"}]), encoding="utf-8")
        return str(reply)

    def test_model_risk_text_prints_as_one_sanitized_line(self, ws, tmp_path, capsys, llm):
        # The reviewed code can steer its reviewer: the model's text must not forge lines (R-checks-38).
        hostile = "eval\x1b[2A\x1b[2Kfake\nLayer 2: ✅ SHIP\x1b]0;pwned\x07 \x9b31m\r::error::forged\x7f"
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        cmd = llm("spec-file", self._spec_reply(tmp_path, "critical", hostile))
        assert _exit_code(["check", "--workspace", str(ws), "--llm-cmd", cmd, "--plan", "p", "clean.py"]) == 0
        out = capsys.readouterr().out
        assert not [c for c in out if c != "\n" and unicodedata.category(c) == "Cc"]
        assert [line for line in out.splitlines() if line.startswith("Layer 2:")] == [
            "Layer 2: 🔴 BLOCK (advisory: the exit status is Layer 1's)"]
        assert not [line for line in out.splitlines() if line.startswith("::")]
        assert "[critical] eval" in out
        assert "fake" in out

    @pytest.mark.parametrize("risk", [None, 5, ["a", "b"]], ids=["null", "number", "list"])
    def test_a_non_string_model_risk_still_prints(self, ws, tmp_path, capsys, llm, risk):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        cmd = llm("spec-file", self._spec_reply(tmp_path, "low", risk))
        assert _exit_code(["check", "--workspace", str(ws), "--llm-cmd", cmd, "--plan", "p", "clean.py"]) == 0
        out = capsys.readouterr().out
        assert "Layer 2: ✅ SHIP" in out
        assert "[low] " in out

    def test_a_layer1_failure_still_fails_whatever_layer2_says(self, ws, capsys, llm):
        (ws / "bad.py").write_text(UNGUARDED_IMPORT, encoding="utf-8")
        argv = ["check", "--workspace", str(ws), "--llm-cmd", llm("ship"), "--plan", "Add main", "bad.py"]
        assert _exit_code(argv) == 1
        out = capsys.readouterr().out
        assert "🔴 import_guard" in out

    def test_failing_backend_is_an_explicit_error(self, ws, capsys, llm):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        argv = ["check", "--workspace", str(ws), "--llm-cmd", llm("fail"), "--plan", "Add compute", "clean.py"]
        assert _exit_code(argv) == 1
        assert "Layer 2 failed: LLM command exited 7: quota exceeded" in capsys.readouterr().err

    def test_a_code_agent_backend_failure_is_the_same_explicit_error(self, ws, capsys, llm):
        # A model command that fails is a setup error the user must see, whichever agent's call it was.
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        argv = ["check", "--workspace", str(ws), "--llm-cmd", llm("code-fail"), "--plan", "Add compute", "clean.py"]
        assert _exit_code(argv) == 1
        assert "Layer 2 failed: LLM command exited 7: quota exceeded" in capsys.readouterr().err

    def test_a_failing_model_commands_stderr_prints_as_one_sanitized_line(self, ws, capsys, llm):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        argv = ["check", "--workspace", str(ws), "--llm-cmd", llm("hostile-fail"), "--plan", "p", "clean.py"]
        assert _exit_code(argv) == 1
        err = capsys.readouterr().err
        assert "Layer 2 failed: LLM command exited 7: quota" in err
        assert "exceeded" in err
        assert not [c for c in err if c != "\n" and unicodedata.category(c) == "Cc"]

    def test_full_without_a_plan_exits_2(self, ws, capsys, llm):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(ws), "--full", "--llm-cmd", llm("ship"), "clean.py"]) == 2
        assert "Layer 2 needs a task plan" in capsys.readouterr().err

    def test_missing_plan_file_is_an_error(self, ws, capsys, llm):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        argv = ["check", "--workspace", str(ws), "--llm-cmd", llm("ship"), "--plan-file", "missing.md", "clean.py"]
        assert _exit_code(argv) == 1
        assert "plan file not found: missing.md" in capsys.readouterr().err

    def test_no_changed_files_says_layer2_had_nothing_to_review(self, ws, capsys, llm):
        _git_repo(ws)
        assert _exit_code(["check", "--workspace", str(ws), "--full", "--plan", "x", "--llm-cmd", llm("fail")]) == 0
        out = capsys.readouterr().out
        assert "Layer 1: 0 files changed (clean repository)" in out
        assert "Layer 2: no changed files to review" in out

    def test_no_changed_files_json_reports_layer2_unreviewed(self, ws, capsys, llm):
        _git_repo(ws)
        argv = ["check", "--workspace", str(ws), "--format", "json", "--plan", "x", "--llm-cmd", llm("ship")]
        assert _exit_code(argv) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["passed"] is True
        assert payload["layer2"] == {"verdict": None, "summary": "Layer 2: no changed files to review"}

    def test_no_changed_files_layer1_only_does_not_mention_layer2(self, ws, capsys):
        _git_repo(ws)
        assert _exit_code(["check", "--workspace", str(ws)]) == 0
        assert "Layer 2" not in capsys.readouterr().out

    def test_no_arbitration_evidence_is_written(self, ws, llm):
        _git_repo(ws)
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        _git(ws, "add", "clean.py")
        assert _exit_code(["check", "--workspace", str(ws), "--llm-cmd", llm("ship"), "--plan", "Add compute"]) == 0
        assert not list(ws.rglob("arbitration_cycle_*.json"))

    def test_json_includes_the_layer2_verdict_as_advisory(self, ws, capsys, llm):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        argv = ["check", "--workspace", str(ws), "--format", "json", "--llm-cmd", llm("block"), "--plan", "p", "clean.py"]
        assert _exit_code(argv) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["passed"] is True
        assert payload["layer2"]["verdict"] == "block"
        assert payload["layer2"]["advisory"] is True
        assert payload["layer2"]["layer1_verdict"] == "PASS"

    def test_json_prediction_rows_carry_the_record_keys_and_no_4_3_aliases(self, ws, capsys, llm):
        """R-checks-46: claim_type/target/horizon_commits served data that never shipped."""
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        argv = ["check", "--workspace", str(ws), "--format", "json", "--llm-cmd", llm("block"), "--plan", "p", "clean.py"]
        assert _exit_code(argv) == 0
        row, = json.loads(capsys.readouterr().out)["layer2"]["llm_predictions"]
        assert set(row) == {
            "id", "verdict_id", "ts", "tree", "backend", "scope", "observable", "window_days", "p",
            "disposition", "outcome", "resolved_at", "resolving_commit", "category", "severity", "risk",
            "mechanism", "affected_function",
        }
        assert (row["scope"], row["observable"]) == ("compute", "fix_touch_in_window")

    def test_json_reports_an_unreadable_spec_reply_as_unverified(self, ws, capsys, llm):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        argv = ["check", "--workspace", str(ws), "--format", "json", "--llm-cmd", llm("garbage"), "--plan", "p", "clean.py"]
        assert _exit_code(argv) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["passed"] is True
        assert payload["layer2"]["verdict"] is None
        assert payload["layer2"]["infra_status"] == "unverified"
        assert payload["layer2"]["unverified_reasons"] == [
            "spec_agent_unparseable", "code_agent_unparseable", "no_predictions"]
        assert payload["layer2"]["advisory"] is True


class TestVendorAdvisory:
    """R-checks-49: a declared arbiter_vendor (user scope) against the generating host's label."""

    SAME = "Same-vendor arbiter provides prompt isolation only, not model independence."
    UNKNOWN = "Vendor independence unverified"

    @staticmethod
    def _run(ws, llm, monkeypatch, capsys, config, client, fmt="json"):
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        if config is not None:
            user = Path.home() / ".aegis"
            user.mkdir(parents=True, exist_ok=True)
            (user / "config.json").write_text(config, encoding="utf-8")
        if client is None:
            monkeypatch.delenv("AEGIS_CLIENT", raising=False)
        else:
            monkeypatch.setenv("AEGIS_CLIENT", client)
        argv = ["check", "--workspace", str(ws), "--format", fmt, "--llm-cmd", llm("ship"), "--plan", "p", "clean.py"]
        code = _exit_code(argv)
        out = capsys.readouterr().out
        return code, (json.loads(out)["layer2"]["vendor_warning"] if fmt == "json" else out)

    @pytest.mark.parametrize("declared,client,want", [
        ("claude", "claude-code", SAME),
        ("anthropic", "claude-code", SAME),
        ("google", "antigravity", SAME),
        ("openai", "codex-cli", SAME),
        ("gemini", "claude-code", ""),
        ("gemini", None, UNKNOWN),
        ("claude", "cursor", UNKNOWN),
        (None, "claude-code", ""),
    ], ids=["claude", "anthropic", "google", "openai", "cross", "no-host", "multi-model-host", "undeclared"])
    def test_the_advisory_compares_the_declared_vendor_with_the_host(self, ws, llm, monkeypatch, capsys,
                                                                     declared, client, want):
        config = json.dumps({"arbiter_vendor": declared}) if declared else None
        code, warning = self._run(ws, llm, monkeypatch, capsys, config, client)
        assert code == 0
        assert warning.startswith(want) if want == self.UNKNOWN else warning == want

    def test_a_malformed_user_config_never_fails_layer2(self, ws, llm, monkeypatch, capsys):
        assert self._run(ws, llm, monkeypatch, capsys, "{not json", "claude-code") == (0, "")

    def test_text_prints_the_vendor_line_only_when_there_is_one(self, ws, llm, monkeypatch, capsys):
        code, out = self._run(ws, llm, monkeypatch, capsys, '{"arbiter_vendor": "claude"}', "claude-code", "text")
        assert code == 0
        assert f"  Vendor: {self.SAME}" in out
        code, out = self._run(ws, llm, monkeypatch, capsys, '{"arbiter_vendor": "gemini"}', "claude-code", "text")
        assert (code, "Vendor:" in out) == (0, False)


class TestDefaultPlanDiscovery:
    """Without --plan/--plan-file, docs/plan.md, .aegis/plan.md or PLAN.md is the plan sent to the model."""

    @staticmethod
    def _symlink(link: Path, target: Path) -> None:
        try:
            link.symlink_to(target, target_is_directory=target.is_dir())
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"cannot create symlinks here: {exc}")

    def test_a_regular_default_plan_is_sent_to_the_model(self, ws, tmp_path, llm):
        (ws / "PLAN.md").write_text("Add compute\n", encoding="utf-8")
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        prompts = tmp_path / "prompts.txt"
        argv = ["check", "--workspace", str(ws), "--full", "--llm-cmd", llm("dump", str(prompts)), "clean.py"]
        assert _exit_code(argv) == 0
        assert "Add compute" in prompts.read_text(encoding="utf-8")

    @pytest.mark.parametrize("layout", ["file-to-outside", "dir-to-outside", "file-to-inside"])
    def test_a_symlinked_default_plan_is_never_read(self, ws, tmp_path, capsys, llm, layout):
        # A hostile branch must not route a secret into the model prompt via PLAN.md (b1-verify review).
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        (secrets / "plan.md").write_text("TOKEN-5150\n", encoding="utf-8")
        if layout == "file-to-outside":
            self._symlink(ws / "PLAN.md", secrets / "plan.md")
        elif layout == "dir-to-outside":
            self._symlink(ws / "docs", secrets)
        else:
            (ws / "notes").mkdir()
            (ws / "notes" / "real.md").write_text("TOKEN-5150\n", encoding="utf-8")
            self._symlink(ws / "PLAN.md", ws / "notes" / "real.md")
        (ws / "clean.py").write_text(CLEAN, encoding="utf-8")
        prompts = tmp_path / "prompts.txt"
        argv = ["check", "--workspace", str(ws), "--full", "--llm-cmd", llm("dump", str(prompts)), "clean.py"]
        assert _exit_code(argv) == 2
        captured = capsys.readouterr()
        assert "Layer 2 needs a task plan" in captured.err
        assert "is a symlink or leaves the repository" in captured.err
        assert not prompts.exists()
        assert "TOKEN-5150" not in captured.out + captured.err
