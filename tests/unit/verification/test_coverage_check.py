"""Behavioral tests for T9 (PR-Native Output & Opt-in Diff Coverage) and T10 (status blocked_commands)."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
import sys

import pytest

from aegis_cli.formatters.report import (
    ci_findings,
    format_github_step_summary,
    format_sarif_report,
    github_annotation_lines,
    layer1_findings,
)
from aegis_core import events, testexec
from aegis_core.verification import coverage_check
from aegis_core.verification.coverage_check import parse_changed_lines, run_diff_coverage
from tests import helpers_humangate as hg


def hdr(path: str) -> str:
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"


class TestDiffCoverage:
    """Diff parsing, coverage evaluation, and isolated .aegis/state coverage execution."""

    def test_parse_changed_lines_from_unified_diff(self):
        diff_text = (
            "diff --git a/aegis_core/foo.py b/aegis_core/foo.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/aegis_core/foo.py\n"
            "+++ b/aegis_core/foo.py\n"
            "@@ -10,0 +11,3 @@ def alpha():\n"
            "+    x = 1\n"
            "+    y = 2\n"
            "+    return x + y\n"
            "@@ -25,2 +28,1 @@ def beta():\n"
            "-    old_a()\n"
            "-    old_b()\n"
            "+    new_call()\n"
            "diff --git a/aegis_core/deleted.py b/aegis_core/deleted.py\n"
            "--- a/aegis_core/deleted.py\n"
            "+++ /dev/null\n"
            "@@ -1,5 +0,0 @@\n"
        )
        changed = parse_changed_lines(diff_text)
        assert changed == {"aegis_core/foo.py": {11, 12, 13, 28}}

    # R-checks-32: every body line inside a hunk is content, whatever it starts with.

    def test_an_added_line_starting_with_plus_plus_stays_in_its_file(self):
        diff = hdr("a.py") + "@@ -0,0 +5,3 @@\n+a = 1\n+++ x\n+c = 3\n@@ -20,0 +22,1 @@\n+z = 9\n"
        assert parse_changed_lines(diff) == {"a.py": {5, 6, 7, 22}}

    def test_added_lines_that_look_like_headers_are_counted(self):
        diff = hdr("a.py") + "@@ -0,0 +5,4 @@\n+a = 1\n+++x\n++++ b/x\n+d = 4"
        assert parse_changed_lines(diff) == {"a.py": {5, 6, 7, 8}}

    def test_a_removed_line_starting_with_dash_dash_does_not_reset_the_hunk(self):
        diff = hdr("a.py") + "@@ -5,1 +5,2 @@\n--- old\n+new1 = 1\n+new2 = 2"
        assert parse_changed_lines(diff) == {"a.py": {5, 6}}

    @pytest.mark.parametrize("separator", ["diff --git a/b.py b/b.py\n", ""], ids=["git-header", "bare"])
    def test_a_lookalike_hunk_does_not_hide_the_next_files_headers(self, separator):
        diff = (hdr("a.py") + "@@ -1,1 +1,2 @@\n-+++ b/evil.py\n++++ b/evil.py\n+--- a/z\n"
                + separator + "--- a/b.py\n+++ b/b.py\n@@ -0,0 +1,1 @@\n+x = 1\n")
        assert parse_changed_lines(diff) == {"a.py": {1, 2}, "b.py": {1}}

    def test_countless_headers_deletions_and_no_newline_markers_keep_the_numbering(self):
        diff = (hdr("a.py") + "@@ -3 +3 @@\n-a\n+b\n"
                "@@ -5,2 +4,0 @@\n-gone1\n--- gone2\n"
                "@@ -8,1 +7,1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n"
                "@@ -10,0 +9,3 @@\n+a\x0cb\n+c\x1cd\n+e\n")
        assert parse_changed_lines(diff) == {"a.py": {3, 7, 9, 10, 11}}



# ── R-checks-33: coverage is a report, never a verdict ───────────────────────

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")


@pytest.fixture
def cov_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GITHUB_EVENT_PATH", "GITHUB_EVENT_NAME", "GITHUB_BASE_REF", "GITHUB_STEP_SUMMARY",
                 "GIT_CONFIG_GLOBAL", "CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    before = os.getcwd()
    yield home
    os.chdir(before)


def cov_repo(tmp_path: Path) -> hg.Repo:
    """``main``: pkg/a.py and pkg/b.py; ``work`` checked out, adding lines 3-7 to pkg/a.py (7 a comment)."""
    repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    repo.write("pkg/__init__.py", "")
    repo.write("pkg/a.py", "x = 1\ny = 2\n")
    repo.write("pkg/b.py", "z = 1\n")
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE)
    repo.commit("base")
    repo.branch("work")
    repo.write("pkg/a.py", "x = 1\ny = 2\nif x:\n    y = 3\nz = 4\nw = 5\n# a comment\n")
    repo.commit("feat: more lines")
    return repo


A_REPORT = {"pkg/a.py": {"executed_lines": [1, 2, 3, 4], "missing_lines": [5, 6]}}


def fake_coverage(monkeypatch: pytest.MonkeyPatch, files=None, *, run=None, json_text=None) -> list:
    """Stand in for ``python -m coverage`` at the process boundary: ``json -o PATH`` writes the report
    (``files``, or ``json_text`` verbatim, or nothing when both are None); ``run`` is the run's result."""
    calls: list = []

    def fake(argv, cwd=None, env=None, timeout=60):
        calls.append({"argv": list(argv), "env": dict(env or {}), "cwd": str(cwd), "timeout": timeout})
        if "json" in argv[3:4]:
            target = Path(argv[argv.index("-o") + 1])
            if json_text is not None:
                target.write_bytes(json_text.encode("utf-8"))
            elif files is not None:
                target.write_bytes(json.dumps({"files": files}).encode("utf-8"))
            return {"returncode": 0 if files is not None or json_text is not None else 1, "stdout": "",
                    "stderr": "", "timed_out": False}
        return run or {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}

    monkeypatch.setattr(coverage_check, "run_external_cmd", fake)
    return calls


def user_command(home: Path, command) -> None:
    (home / ".aegis").mkdir(parents=True, exist_ok=True)
    (home / ".aegis" / "config.json").write_text(json.dumps({"v": 1, "tests": {"command": command}}), encoding="utf-8")


@needs_git
class TestReportOnlyCoverage:
    def test_a_measured_run_reports_exact_counts_and_ranges_and_no_verdict(self, tmp_path, cov_env, monkeypatch):
        repo = cov_repo(tmp_path)
        calls = fake_coverage(monkeypatch, A_REPORT)
        res = run_diff_coverage(repo.root, "main", "HEAD")
        assert res == {"status": "reported", "reason": "", "covered_lines": 2, "executable_lines": 4, "ratio": 0.5,
                       "uncovered_ranges": {"pkg/a.py": [[5, 6]]}, "unmeasured": []}
        run, dump = (c["argv"] for c in calls)
        assert run[:4] == [sys.executable, "-m", "coverage", "run"] and run[5:] == [
            "-m", "pytest", "-p", "no:cacheprovider", "-o", "addopts="]
        rcfile = run[4].partition("=")[2]
        assert run[4].startswith("--rcfile=") and dump[4] == run[4]
        state = (repo.root / ".aegis" / "state").resolve()
        assert Path(rcfile).resolve().parent.parent == state
        assert Path(calls[0]["env"]["COVERAGE_FILE"]).resolve().parent.parent == state
        assert calls[0]["timeout"] == testexec.DEFAULT_TIMEOUT_S
        assert [p.name for p in state.iterdir()] == [".gitignore"], "the scratch directory is removed"

    def test_a_missing_coverage_module_is_unverified_not_zero_percent(self, tmp_path, cov_env, monkeypatch):
        repo = cov_repo(tmp_path)
        err = "Traceback (most recent call last):\n  ...\n/usr/bin/python3: No module named coverage\n"
        fake_coverage(monkeypatch, None, run={"returncode": 1, "stdout": "", "stderr": err, "timed_out": False})
        res = run_diff_coverage(repo.root, "main", "HEAD")
        assert res["status"] == "unverified" and res["ratio"] is None
        assert "No module named coverage" in res["reason"] and len(res["reason"]) <= 200

    def test_a_timed_out_run_is_unverified(self, tmp_path, cov_env, monkeypatch):
        repo = cov_repo(tmp_path)
        fake_coverage(monkeypatch, A_REPORT, run={"returncode": 124, "stdout": "", "stderr": "", "timed_out": True})
        res = run_diff_coverage(repo.root, "main", "HEAD")
        assert (res["status"], res["ratio"]) == ("unverified", None) and "timed out" in res["reason"]

    def test_a_truncated_report_is_unverified_without_raising(self, tmp_path, cov_env, monkeypatch):
        repo = cov_repo(tmp_path)
        fake_coverage(monkeypatch, json_text='{"files": {"pkg/a.py": {"executed_')
        res = run_diff_coverage(repo.root, "main", "HEAD")
        assert (res["status"], res["ratio"]) == ("unverified", None)

    @pytest.mark.parametrize("base", ["no-such-ref", "--foo", "--output=x", "orphan"])
    def test_a_base_git_cannot_diff_is_unverified_and_runs_nothing(self, tmp_path, cov_env, monkeypatch, base):
        repo = cov_repo(tmp_path)
        repo.git("checkout", "-q", "--orphan", "orphan")
        repo.git("rm", "-rfq", ".")
        repo.write("other.py", "o = 1\n")
        repo.commit("unrelated")
        repo.git("checkout", "-q", "work")
        calls = fake_coverage(monkeypatch, A_REPORT)
        res = run_diff_coverage(repo.root, base, "HEAD")
        assert res["status"] == "unverified" and res["reason"] == f"cannot diff {base}..HEAD"
        assert calls == [] and not (repo.root / "x").exists()

    def test_a_test_command_that_is_not_pytest_is_unverified(self, tmp_path, cov_env, monkeypatch):
        repo = cov_repo(tmp_path)
        user_command(cov_env, "make test")
        calls = fake_coverage(monkeypatch, A_REPORT)
        res = run_diff_coverage(repo.root, "main", "HEAD")
        assert (res["status"], res["reason"], calls) == ("unverified", "tests.command is not pytest-based", [])

    @pytest.mark.parametrize("command", ["pytest -x tests/unit", "python -m pytest -x tests/unit",
                                         ["/opt/venv/bin/python3", "-m", "pytest", "-x", "tests/unit"]])
    def test_the_user_scope_test_command_gives_the_pytest_arguments(self, tmp_path, cov_env, monkeypatch, command):
        repo = cov_repo(tmp_path)
        user_command(cov_env, command)
        calls = fake_coverage(monkeypatch, A_REPORT)
        assert run_diff_coverage(repo.root, "main", "HEAD")["status"] == "reported"
        assert calls[0]["argv"][5:] == ["-m", "pytest", "-x", "tests/unit", "-p", "no:cacheprovider", "-o", "addopts="]

    @pytest.mark.parametrize("kind", ["absolute-python", "relative-python", "absolute-pytest", "bare-pytest"])
    def test_both_coverage_commands_keep_the_interpreter_contract(self, tmp_path, cov_env, monkeypatch, kind):
        repo = cov_repo(tmp_path)
        python = tmp_path / "environment" / ("python3.exe" if os.name == "nt" else "python3")
        command = {
            "absolute-python": [str(python), "-m", "pytest"],
            "relative-python": ["python3", "-m", "pytest"],
            "absolute-pytest": [str(python.with_name("pytest"))],
            "bare-pytest": ["pytest"],
        }[kind]
        user_command(cov_env, [*command, "-x", "tests/unit"])
        monkeypatch.delenv("COVERAGE_CORE", raising=False)
        calls = fake_coverage(monkeypatch, A_REPORT)
        assert run_diff_coverage(repo.root, "main", "HEAD")["status"] == "reported"
        selected = str(python) if kind == "absolute-python" else sys.executable
        assert [call["argv"][0] for call in calls] == [selected, selected]
        if kind == "absolute-python":
            assert all("COVERAGE_CORE" not in call["env"] for call in calls)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX executable wrapper")
    @pytest.mark.parametrize("mode", ["report", "missing-coverage", "failed-interpreter"])
    def test_a_configured_python_process_controls_coverage(self, tmp_path, cov_env, monkeypatch, mode):
        repo = cov_repo(tmp_path)
        marker, python = tmp_path / "interpreter.jsonl", tmp_path / "environment" / "python3"
        python.parent.mkdir()
        python.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\nfrom pathlib import Path\n"
            f"marker = Path({str(marker)!r})\n"
            "with marker.open('a') as output:\n"
            "    output.write(json.dumps({'argv': sys.argv[1:], 'core': os.environ.get('COVERAGE_CORE')}) + '\\n')\n"
            "if os.environ.get('COVERAGE_CORE') == 'sysmon':\n"
            "    sys.stderr.write('selected interpreter does not support sys.monitoring\\n')\n"
            "    sys.exit(1)\n"
            f"if {mode!r} != 'report':\n"
            f"    sys.stderr.write({'No module named coverage' if mode == 'missing-coverage' else 'configured Python cannot load its project environment'!r} + '\\n')\n"
            "    sys.exit(7)\n"
            "if sys.argv[1:4] == ['-m', 'coverage', 'json']:\n"
            f"    Path(sys.argv[sys.argv.index('-o') + 1]).write_text(json.dumps({{'files': {A_REPORT!r}}}))\n",
            encoding="utf-8",
        )
        python.chmod(0o700)
        user_command(cov_env, [str(python), "-m", "pytest"])
        monkeypatch.delenv("COVERAGE_CORE", raising=False)
        result = run_diff_coverage(repo.root, "main", "HEAD")
        if mode == "report":
            assert (result["status"], result["ratio"], result["reason"]) == ("reported", 0.5, "")
        else:
            expected = ("No module named coverage" if mode == "missing-coverage"
                        else "configured Python cannot load its project environment")
            assert (result["status"], result["ratio"], result["reason"]) == ("unverified", None, expected)
        calls = [json.loads(line) for line in marker.read_text().splitlines()]
        assert [call["argv"][2] for call in calls] == ["run", "json"]
        assert all(call["core"] is None for call in calls)

    def test_the_repositorys_coverage_json_and_coveragerc_are_never_read(self, tmp_path, cov_env, monkeypatch):
        repo = cov_repo(tmp_path)
        repo.write("coverage.json", json.dumps({"files": {"pkg/a.py": {"executed_lines": [3, 4, 5, 6], "missing_lines": []}}}))
        repo.write(".coveragerc", "[report]\nexclude_lines =\n    .*\n")
        calls = fake_coverage(monkeypatch, A_REPORT)
        res = run_diff_coverage(repo.root, "main", "HEAD")
        assert (res["ratio"], res["covered_lines"]) == (0.5, 2)
        rcfile = Path(calls[0]["argv"][4].partition("=")[2])
        assert rcfile.name != ".coveragerc" and rcfile.parent.parent.name == "state"

    def test_a_linked_state_directory_writes_nothing_outside_and_is_unverified(self, tmp_path, cov_env, monkeypatch):
        from conftest import symlink_or_skip

        repo = cov_repo(tmp_path)
        outside = tmp_path / "outside"
        outside.mkdir()
        symlink_or_skip(outside, repo.root / ".aegis" / "state", target_is_directory=True)
        calls = fake_coverage(monkeypatch, A_REPORT)
        res = run_diff_coverage(repo.root, "main", "HEAD")
        assert res["status"] == "unverified" and calls == []
        assert list(outside.iterdir()) == []

    def test_a_module_the_tests_never_import_is_unmeasured_and_not_counted(self, tmp_path, cov_env, monkeypatch):
        repo = cov_repo(tmp_path)
        repo.write("pkg/new.py", "n = 1\nm = 2\n")
        repo.commit("feat: a module nobody imports")
        fake_coverage(monkeypatch, A_REPORT)
        res = run_diff_coverage(repo.root, "main", "HEAD")
        assert (res["unmeasured"], res["executable_lines"], res["ratio"]) == (["pkg/new.py"], 4, 0.5)

    def test_no_changed_python_line_is_reported_with_no_ratio_and_runs_nothing(self, tmp_path, cov_env, monkeypatch):
        repo = cov_repo(tmp_path)
        calls = fake_coverage(monkeypatch, A_REPORT)
        res = run_diff_coverage(repo.root, "HEAD", "HEAD")
        assert (res["status"], res["ratio"], res["executable_lines"], calls) == ("reported", None, 0, [])

    def test_only_the_branchs_own_changes_are_demanded(self, tmp_path, cov_env, monkeypatch):
        """Forked history: main also changed pkg/b.py after the fork; the merge-base diff leaves it out."""
        repo = cov_repo(tmp_path)
        repo.git("checkout", "-q", "main")
        repo.write("pkg/b.py", "z = 1\nq = 2\n")
        repo.commit("main moves on")
        repo.git("checkout", "-q", "work")
        fake_coverage(monkeypatch, {**A_REPORT, "pkg/b.py": {"executed_lines": [], "missing_lines": [1, 2]}})
        res = run_diff_coverage(repo.root, "main", "HEAD")
        assert (res["executable_lines"], list(res["uncovered_ranges"])) == (4, ["pkg/a.py"])

    def test_a_removed_dash_dash_line_does_not_drop_the_lines_added_after_it(self, tmp_path, cov_env, monkeypatch):
        """R-checks-32 at report level: the hunk is "--- old" plus five added lines; one of five ran."""
        repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
        repo.write("pkg/foo.py", "a\nb\nc\nd\n-- old\n")
        repo.commit("base")
        repo.branch("work")
        repo.write("pkg/foo.py", "a\nb\nc\nd\nv = 1\nw = 2\nx = 3\ny = 4\nz = 5\n")
        repo.commit("feat: replace the old line")
        fake_coverage(monkeypatch, {"pkg/foo.py": {"executed_lines": [5], "missing_lines": [6, 7, 8, 9]}})
        res = run_diff_coverage(repo.root, "main", "HEAD")
        assert (res["ratio"], res["uncovered_ranges"]) == (pytest.approx(0.20), {"pkg/foo.py": [[6, 9]]})

    # Review F4: the changed lines come from git objects, but coverage measures the work tree.

    def test_a_checkout_that_is_not_the_head_is_unverified_and_runs_nothing(self, tmp_path, cov_env, monkeypatch):
        """Given GitHub's default pull request checkout (a merge of the head into the base), When the head's
        changed lines are measured, Then the result is unverified, names the head, and nothing runs."""
        repo = cov_repo(tmp_path)
        head = repo.head()
        repo.git("checkout", "-q", "--detach", "main")
        repo.git("merge", "-q", "--no-ff", "-m", "Merge work into main", "work")
        calls = fake_coverage(monkeypatch, A_REPORT)
        res = run_diff_coverage(repo.root, "main", head)
        assert (res["status"], res["ratio"], calls) == ("unverified", None, [])
        assert res["reason"] == f"the checkout is not {head[:12]}; check out the pull request head"

    @pytest.mark.parametrize("change", ["modified", "staged", "deleted"])
    def test_a_work_tree_with_tracked_changes_is_unverified_and_runs_nothing(
        self, tmp_path, cov_env, monkeypatch, change
    ):
        repo = cov_repo(tmp_path)
        if change == "deleted":
            (repo.root / "pkg" / "b.py").unlink()
        else:
            repo.write("pkg/b.py", "z = 1\nforged = 2\n")
            if change == "staged":
                repo.git("add", "pkg/b.py")
        calls = fake_coverage(monkeypatch, A_REPORT)
        res = run_diff_coverage(repo.root, "main", "HEAD")
        assert (res["status"], res["ratio"], calls) == ("unverified", None, [])
        assert res["reason"] == "the work tree has uncommitted changes to tracked files: pkg/b.py"

    def test_an_untracked_file_does_not_make_the_run_unverified(self, tmp_path, cov_env, monkeypatch):
        repo = cov_repo(tmp_path)
        repo.write("scratch.py", "s = 1\n")
        fake_coverage(monkeypatch, A_REPORT)
        res = run_diff_coverage(repo.root, "main", "HEAD")
        assert (res["status"], res["ratio"]) == ("reported", 0.5)

    def test_testexec_pytest_args(self):
        assert testexec.pytest_args(["pytest", "-x"]) == ["-x"]
        assert testexec.pytest_args(["py.test"]) == []
        assert testexec.pytest_args(["python3", "-m", "pytest", "-q"]) == ["-q"]
        assert testexec.pytest_args(["make", "test"]) is None
        assert testexec.pytest_args(["python", "-m", "unittest"]) is None
        assert testexec.pytest_args([]) is None


class TestSarifAndGitHubFormatters:
    """SARIF 2.1.0 and GitHub annotations / step-summary formatting."""

    @staticmethod
    def _layer1_doc(path: str, line: int = 14) -> dict:
        """A Layer 1 report document: one failed forbid_ast row and one checkpoint issue (no line)."""
        return {"passed": False,
                "layer1": [{"tool": "forbid_ast:no-eval", "target": path, "verdict": False,
                            "detail": "Forbidden eval() call", "lines": [line, line + 3]}],
                "findings": [{"rule": "repo-gate", "message": "Unanchored repository-level gate failure", "level": "error"}]}

    def test_sarif_report_valid_schema_and_routes_lineless_to_step_summary(self, tmp_path: Path):
        report_dict = self._layer1_doc(str(tmp_path / "aegis_core/bad.py"))

        sarif_raw = format_sarif_report(report_dict, workspace_root=tmp_path)
        sarif = json.loads(sarif_raw)
        assert sarif["version"] == "2.1.0"
        assert "sarif-2.1.0" in sarif["$schema"]
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        loc = results[0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "aegis_core/bad.py"
        assert loc["region"]["startLine"] == 14
        assert loc["region"]["startColumn"] == 1
        assert "primaryLocationLineHash" in results[0]["partialFingerprints"]

        # Line-less finding must be routed to the step summary, never emitted with startLine: 0
        assert all(
            r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
            for r in results
        )
        assert "Unanchored repository-level gate failure" in format_github_step_summary(report_dict, tmp_path)

    def test_github_step_summary_lists_anchored_findings(self):
        summary_md = format_github_step_summary(self._layer1_doc("aegis_core/bad.py"))
        assert "aegis_core/bad.py" in summary_md
        assert "no-eval" in summary_md

    def test_ci_findings_read_the_fixed_keys_and_name_no_invented_line(self):
        doc = {"weakenings": [{"code": "rule-deleted", "rule": "inv-a", "path": ".aegis/rules/invariants/inv-a.md",
                               "message": "deleted"}],
               "regression": {"tier": "warning", "findings": [{"code": "no_test_changes", "commit": "c" * 40,
                                                                "path": "src/a.py", "message": "no test"}]},
               "trailer_checks": [{"commit": "d" * 40, "failed": True, "reason": "diverged"}]}
        found = ci_findings(doc)
        assert [(f["rule_id"], f["uri"], f["line"], f["level"]) for f in found] == [
            ("inv-a", ".aegis/rules/invariants/inv-a.md", 0, "error"), ("no_test_changes", "src/a.py", 0, "warning"),
            ("trailer-divergence", "", 0, "error")]
        assert all(set(f) == {"rule_id", "uri", "line", "col", "message", "level"} for f in found)
        approved = ci_findings({**doc, "approval": {"valid": True}})
        assert approved[0]["level"] == "note"

    def test_layer1_findings_anchor_at_the_first_line_relative_to_the_workspace(self, tmp_path):
        from aegis_core.verification import ToolEvidence

        e = ToolEvidence(tool="import_guard", target=str(tmp_path / "src" / "a" / "x.py"), verdict=False,
                         detail="unapproved import", lines=[3])
        doc = {"layer1": [{"tool": e.tool, "target": e.target, "verdict": e.verdict, "detail": e.detail, "lines": e.lines}]}
        (found,) = layer1_findings(doc, workspace_root=tmp_path)
        assert (found["uri"], found["line"], found["rule_id"]) == ("src/a/x.py", 3, "import_guard")

    def test_every_exported_formatter_name_resolves(self):
        import aegis_cli.formatters.report as report

        assert all(hasattr(report, name) for name in report.__all__)
        namespace: dict = {}
        exec("from aegis_cli.formatters.report import *", namespace)
        assert set(report.__all__) <= set(namespace)

    def test_the_formatter_modules_have_no_orphan_function(self):
        from aegis_core.verification import call_graph

        repo = Path(__file__).resolve().parents[3]
        for rel in ("aegis_cli/formatters/report.py", "aegis_core/verification/perf_check.py"):
            result = call_graph.check(str(repo / rel), str(repo), exclude_names={"main"})
            assert result.verdict, (rel, result.detail)

    def test_hostile_text_makes_exactly_one_workflow_command_each(self):
        nasty = "a%b\rc\nd:e,f"
        doc = {"weakenings": [{"code": "rule-deleted", "rule": nasty, "path": f"rules/{nasty}.md", "message": nasty}],
               "trailer_checks": [{"commit": "d" * 40, "failed": True, "reason": nasty}]}
        lines = github_annotation_lines(doc)
        assert len(lines) == 2 and all(line.startswith("::error ") for line in lines)
        assert "file=rules/a%25b%0Dc%0Ad%3Ae%2Cf.md," in lines[0]
        assert lines[0].endswith("::rule-deleted: a%25b%0Dc%0Ad:e,f: a%25b%0Dc%0Ad:e,f")


class TestSarifIsSchemaValidAndHonest:
    """R-checks-36: the SARIF log holds only schema keys, anchored findings only, stable fingerprints."""

    DOC = {"passed": False,
           "layer1": [{"tool": "no-eval", "target": "pkg/bad.py", "verdict": False, "detail": "Forbidden eval() call",
                       "lines": [14]}],
           "findings": [{"rule": "repo-gate", "message": "Unanchored repository-level gate failure", "level": "error"}]}

    @staticmethod
    def _report(approved: bool = False):
        from aegis_core import human_gate, rule_integrity

        head = "b" * 40
        return rule_integrity.CiReport("main", head, "a" * 40, 1,
                                       (rule_integrity.Weakening("rule-deleted", "inv-a", "rules/inv-a.md", "deleted"),),
                                       human_gate.Approval(True, "ok", "", head, "Human") if approved else None)

    def test_the_log_has_only_schema_keys_and_line_less_findings_go_to_the_summary(self, tmp_path):
        text = format_sarif_report(self.DOC)
        assert type(text) is str
        log = json.loads(text)
        assert set(log) == {"$schema", "version", "runs"}
        (result,) = log["runs"][0]["results"]
        assert (result["ruleId"], result["locations"][0]["physicalLocation"]["region"]["startLine"]) == ("no-eval", 14)
        assert "Unanchored repository-level gate failure" not in text
        assert "Unanchored repository-level gate failure" in format_github_step_summary(self.DOC)

    def test_a_weakening_without_a_line_is_no_result_and_an_approved_one_is_no_failure(self, tmp_path, capsys, monkeypatch):
        from aegis_cli import check

        summary = tmp_path / "summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
        check._print_ci(self._report(), "sarif", str(tmp_path))
        assert json.loads(capsys.readouterr().out)["runs"][0]["results"] == []
        assert "rules/inv-a.md" in summary.read_text(encoding="utf-8")
        summary.unlink()
        check._print_ci(self._report(approved=True), "sarif", str(tmp_path))
        assert json.loads(capsys.readouterr().out)["runs"][0]["results"] == []
        text = summary.read_text(encoding="utf-8")
        assert "PASSED" in text and "rules/inv-a.md" not in text
        check._print_ci(self._report(approved=True), "github", str(tmp_path))
        assert [line for line in capsys.readouterr().out.splitlines() if line.startswith("::")] == [
            "::notice file=rules/inv-a.md,title=weakening approved::rule-deleted: inv-a: deleted"]

    @staticmethod
    def _prints(*rows) -> list:
        doc = {"layer1": [{"tool": rule, "target": path, "verdict": False, "detail": message, "lines": [line]}
                          for rule, path, line, message in rows]}
        return [r["partialFingerprints"]["primaryLocationLineHash"] for r in json.loads(format_sarif_report(doc))["runs"][0]["results"]]

    def test_fingerprints_survive_line_moves_and_tell_duplicates_apart(self):
        one = ("no-eval", "pkg/bad.py", 14, "m")
        assert self._prints(one) == self._prints(("no-eval", "pkg/bad.py", 20, "m"))
        a, b = self._prints(one, ("no-eval", "pkg/bad.py", 40, "m"))
        assert a != b
        assert self._prints(("no-eval", "pkg/bad.py", 21, "m"), ("no-eval", "pkg/bad.py", 47, "m")) == [a, b]
        assert sorted(self._prints(("no-eval", "pkg/bad.py", 40, "m"), one)) == sorted([a, b])
        for other in (("other", "pkg/bad.py", 14, "m"), ("no-eval", "pkg/good.py", 14, "m"), ("no-eval", "pkg/bad.py", 14, "n")):
            assert self._prints(other) != self._prints(one)
        assert self._prints(("no-eval", "pkg\\bad.py", 14, "m")) == self._prints(one)
        assert re.fullmatch(r"[0-9a-f]{16}", a)

    @needs_git
    def test_an_error_path_still_prints_a_valid_empty_log(self, tmp_path, capsys, monkeypatch):
        from aegis_cli.cli import main

        repo = cov_repo(tmp_path)
        monkeypatch.chdir(repo.root)
        rc = main(["check", "--ci", "--base", "no-such-ref", "--format", "sarif"])
        out, err = capsys.readouterr()
        assert rc == 1 and err.startswith("Error:")
        log = json.loads(out)
        assert set(log) == {"$schema", "version", "runs"} and log["runs"][0]["results"] == []
        assert log["runs"][0]["invocations"][0]["executionSuccessful"] is False


class TestStatusBlockedCommands:
    """T10: aegis status reports hook-observed blocked_commands per host."""

    def test_status_counts_blocked_guard_match_events_per_host(self, tmp_path: Path, capsys):
        import argparse
        from aegis_cli.status import run_status

        ws = tmp_path / "ws"
        (ws / ".aegis" / "rules").mkdir(parents=True)
        events.append(
            ws,
            "guard_match",
            "block",
            {"rule": "git-safety", "tier": "block", "action": "block"},
            host="claude-code",
        )
        events.append(
            ws,
            "guard_match",
            "block",
            {"rule": "git-safety", "tier": "block", "action": "block"},
            host="claude-code",
        )
        events.append(
            ws,
            "guard_match",
            "record",
            {"rule": "git-safety", "tier": "record", "action": "record"},
            host="claude-code",
        )
        events.append(
            ws,
            "guard_match",
            "block",
            {"rule": "git-safety", "tier": "block", "action": "block"},
            host="cursor",
        )

        rc = run_status(argparse.Namespace(_root=ws, json=True))
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["blocked_commands"] == {
            "total": 3,
            "by_host": {"claude-code": 2, "cursor": 1},
            "source": "hook-observed",
            "label": "hook-observed",
        }

    def test_status_without_guard_events_reports_zero_blocked_commands(self, tmp_path: Path, capsys):
        import argparse
        from aegis_cli.status import run_status

        ws = tmp_path / "ws"
        (ws / ".aegis" / "rules").mkdir(parents=True)
        assert run_status(argparse.Namespace(_root=ws, json=True)) == 0
        assert json.loads(capsys.readouterr().out)["blocked_commands"] == {
            "total": 0, "by_host": {}, "source": "hook-observed", "label": "hook-observed"}

    def test_status_has_one_reader_of_blocked_commands(self):
        """run_status is the only status surface; the unreached first-draft collector is gone (R-cli-43)."""
        import aegis_cli.status as status

        assert [name for name in vars(status) if name.startswith("collect")] == []


class TestCheckCliIntegration:
    """CLI integration tests for --format sarif, --coverage, and GITHUB_STEP_SUMMARY."""

    def test_format_sarif_without_ci_errors(self, tmp_path: Path, capsys):
        import argparse
        from aegis_cli.check import CheckCommand

        parser = argparse.ArgumentParser()
        cmd = CheckCommand()
        cmd.configure_parser(parser)
        args = parser.parse_args(["--card", "--format", "sarif"])
        args._root = tmp_path

        rc = cmd.execute(args)
        assert rc == 2
        err = capsys.readouterr().err
        assert "--format sarif" in err and "--ci" in err

    @needs_git
    def test_ci_coverage_is_reported_and_never_changes_the_exit_code(self, tmp_path, cov_env, capsys, monkeypatch):
        """Given a failing ratio, then an unmeasurable run, When check --ci --coverage runs, Then both exit 0;
        the first prints the figure and the second UNVERIFIED, in the text and in the step summary."""
        from aegis_cli.cli import main

        repo = cov_repo(tmp_path)
        summary = tmp_path / "summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
        monkeypatch.chdir(repo.root)
        fake_coverage(monkeypatch, A_REPORT)
        rc = main(["check", "--ci", "--coverage", "--base", "main"])
        out = capsys.readouterr().out
        assert rc == 0, out
        assert "  coverage (report only): 50.0% of 4 changed executable lines (0 file(s) not measured)" in out
        text = summary.read_text(encoding="utf-8")
        assert "### Diff Coverage (report only): 50.0% of 4 changed executable lines" in text and "PASS (" not in text
        summary.unlink()

        missing = {"returncode": 1, "stdout": "", "stderr": "python3: No module named coverage\n", "timed_out": False}
        fake_coverage(monkeypatch, None, run=missing)
        rc = main(["check", "--ci", "--coverage", "--base", "main"])
        out = capsys.readouterr().out
        assert rc == 0 and "  coverage: UNVERIFIED (python3: No module named coverage)" in out
        assert "### Diff Coverage: UNVERIFIED (`python3: No module named coverage`)" in summary.read_text(encoding="utf-8")
        rc = main(["check", "--ci", "--coverage", "--base", "main", "--format", "json"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == 0 and payload["status"] == "pass"
        assert payload["coverage"]["status"] == "unverified" and "passed" not in payload["coverage"]

    @needs_git
    def test_ci_coverage_on_a_checkout_that_is_not_the_head_says_unverified_and_exits_0(
        self, tmp_path, cov_env, capsys, monkeypatch
    ):
        """Review F4: Given a dirty tracked file, then a checkout at another commit than --head, When check
        --ci --coverage runs, Then it prints UNVERIFIED with the mismatch and exits 0 both times."""
        from aegis_cli.cli import main

        repo = cov_repo(tmp_path)
        head = repo.head()
        monkeypatch.chdir(repo.root)
        calls = fake_coverage(monkeypatch, A_REPORT)
        repo.write("pkg/b.py", "z = 2\n")
        rc = main(["check", "--ci", "--coverage", "--base", "main"])
        out = capsys.readouterr().out
        assert rc == 0, out
        assert "  coverage: UNVERIFIED (the work tree has uncommitted changes to tracked files: pkg/b.py)" in out
        repo.git("checkout", "-q", "--", "pkg/b.py")
        repo.git("checkout", "-q", "--detach", "main")
        rc = main(["check", "--ci", "--coverage", "--base", "main", "--head", head])
        out = capsys.readouterr().out
        assert rc == 0, out
        assert f"  coverage: UNVERIFIED (the checkout is not {head[:12]}; check out the pull request head)" in out
        assert calls == []

    def test_ci_format_sarif_and_github_step_summary(self, tmp_path: Path, capsys, monkeypatch):
        import argparse
        import subprocess
        from aegis_cli.check import CheckCommand

        ws = tmp_path / "ws"
        (ws / ".aegis" / "rules").mkdir(parents=True)
        subprocess.run(["git", "init"], cwd=ws, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=ws, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=ws, check=True)
        (ws / "README.md").write_text("hi\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=ws, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=ws, check=True, capture_output=True)

        summary_file = tmp_path / "step_summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

        parser = argparse.ArgumentParser()
        cmd = CheckCommand()
        cmd.configure_parser(parser)
        args = parser.parse_args(["--ci", "--base", "HEAD", "--format", "sarif"])
        args._root = ws

        rc = cmd.execute(args)
        assert rc == 0
        out = capsys.readouterr().out
        sarif = json.loads(out)
        assert sarif["version"] == "2.1.0"
        assert summary_file.is_file()
        assert "Aegis Check Summary" in summary_file.read_text(encoding="utf-8")


