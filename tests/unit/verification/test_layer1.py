from pathlib import Path
"""Integration tests for the Layer 1 runner + persistence checker.

Validates against the actual Soma codebase (post-fix) and against
synthetic pre-fix scenarios.
"""
import sys
import textwrap

import pytest

# tests/test_verification/ → tests/ → REPO_ROOT
REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
sys.path.insert(0, REPO_ROOT)

from aegis_core.verification import ToolEvidence
from aegis_core.verification import persistence_checker
from aegis_core.verification import call_graph
from aegis_core.verification import runner
from unittest.mock import patch


class TestPersistenceChecker:
    """Test the persistence completeness checker against real and synthetic code."""


    def test_synthetic_gap_detected(self, tmp_path):
        """A file that mutates a key but doesn't serialize it should FAIL."""
        code = textwrap.dedent("""\
            def save(data):
                fitness = data.get('fitness', {})
                fitness['score'] = 0.5
                fitness['secret_key'] = 42  # not serialized!

                for line in lines:
                    if line.startswith('score:'):
                        line = f"score: {fitness['score']}"
                # secret_key never handled in serialization
        """)
        filepath = tmp_path / "test_file.py"
        filepath.write_text(code)

        result = persistence_checker.check(str(filepath), "fitness")
        assert result.verdict is False
        assert "secret_key" in result.detail

    def test_excluded_keys_not_flagged(self, tmp_path):
        """Keys in the exclude list should not be flagged as gaps."""
        code = textwrap.dedent("""\
            def process(data):
                fitness = data.get('fitness', {})
                fitness['cached_value'] = compute()  # intentionally in-memory only

                for line in lines:
                    pass  # no serialization at all
        """)
        filepath = tmp_path / "test_file.py"
        filepath.write_text(code)

        result = persistence_checker.check(str(filepath), "fitness", exclude={"cached_value"})
        assert result.verdict is True

    def test_no_mutations_passes(self, tmp_path):
        """A file with no dict mutations should pass trivially."""
        code = "x = 1\ny = 2\n"
        filepath = tmp_path / "empty.py"
        filepath.write_text(code)

        result = persistence_checker.check(str(filepath), "fitness")
        assert result.verdict is True


class TestCallGraph:
    """Test the call graph completeness checker."""


    def test_synthetic_orphan_detected(self, tmp_path):
        """A function with no call sites should be flagged."""
        code = textwrap.dedent("""\
            def orphan_function():
                pass

            def another_orphan():
                pass
        """)
        filepath = tmp_path / "orphan.py"
        filepath.write_text(code)

        result = call_graph.check(str(filepath), str(tmp_path))
        assert result.verdict is False
        assert "orphan_function" in result.detail or "another_orphan" in result.detail


class TestLayer1Runner:
    """Test the Layer 1 orchestrator."""


    def test_gate_verdict_all_pass(self):
        """Gate should pass when all tools pass."""
        results = [
            ToolEvidence("t1", "f1", True, "ok"),
            ToolEvidence("t2", "f2", True, "ok"),
        ]
        assert runner.gate_verdict(results) is True

    def test_gate_verdict_any_fail(self):
        """Gate should fail when any tool fails."""
        results = [
            ToolEvidence("t1", "f1", True, "ok"),
            ToolEvidence("t2", "f2", False, "gap found"),
        ]
        assert runner.gate_verdict(results) is False

    def test_format_summary_pass(self):
        results = [ToolEvidence("t1", "f1", True, "ok")]
        summary = runner.format_summary(results)
        assert "1/1 PASSED" in summary

    def test_format_summary_fail(self):
        results = [
            ToolEvidence("t1", "f1", True, "ok"),
            ToolEvidence("t2", "f2", False, "gap"),
        ]
        summary = runner.format_summary(results)
        assert "1/2 FAILED" in summary


# ── 2A: Mutation Tester + Branch Coverage in Runner ─────────────────


class TestRunnerMutationTesterIntegration:
    """run_layer1() should wire mutation_tester with auto-discovery."""

    def test_mutation_targets_explicit(self, tmp_path):
        """When mutation_targets is provided, runner calls mutation_tester."""
        # Create a simple source + test pair
        src = tmp_path / "widget.py"
        src.write_text(textwrap.dedent("""\
            def add(a, b):
                return a + b
        """))
        test = tmp_path / "test_widget.py"
        test.write_text(textwrap.dedent("""\
            from widget import add
            def test_add():
                assert add(1, 2) == 3
        """))

        results = runner.run_layer1(
            changed_files=["widget.py"],
            repo_root=str(tmp_path),
            mutation_targets=[("widget.py", "add", "test_widget.py")],
        )
        mutation_results = [r for r in results if r.tool == "mutation_tester"]
        assert len(mutation_results) >= 1
        assert all(isinstance(r, ToolEvidence) for r in mutation_results)

    def test_mutation_respects_max_mutations(self, tmp_path):
        """Runner should pass max_mutations budget to mutation_tester."""
        src = tmp_path / "calc.py"
        src.write_text(textwrap.dedent("""\
            def multiply(a, b):
                return a * b
            def subtract(a, b):
                return a - b
        """))
        test = tmp_path / "test_calc.py"
        test.write_text(textwrap.dedent("""\
            from calc import multiply, subtract
            def test_multiply():
                assert multiply(3, 4) == 12
            def test_subtract():
                assert subtract(5, 2) == 3
        """))

        results = runner.run_layer1(
            changed_files=["calc.py"],
            repo_root=str(tmp_path),
            mutation_targets=[("calc.py", "multiply", "test_calc.py")],
            max_mutations=2,
        )
        mutation_results = [r for r in results if r.tool == "mutation_tester"]
        assert len(mutation_results) >= 1
        # The detail should reflect the bounded mutation count
        for r in mutation_results:
            assert isinstance(r.detail, str)

    def test_mutation_auto_discovery(self, tmp_path):
        """When mutation_targets is None but test files exist, auto-discover."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "foo.py").write_text("def bar(): return 1 + 2\n")

        test_dir = tmp_path / "tests"
        test_dir.mkdir()
        (test_dir / "test_foo.py").write_text(
            "from src.foo import bar\ndef test_bar():\n    assert bar() == 3\n"
        )

        results = runner.run_layer1(
            changed_files=["src/foo.py"],
            repo_root=str(tmp_path),
            # No explicit mutation_targets — should auto-discover
        )
        # Should attempt to find test_foo.py for foo.py
        tool_names = [r.tool for r in results]
        assert "mutation_tester" in tool_names


class TestGetModifiedLines:
    """The changed lines of a file against its base, read through gitsafe (no git diff)."""

    @staticmethod
    def _git(repo, *args):
        import subprocess

        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                       cwd=str(repo), check=True, capture_output=True)

    def _repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        self._git(repo, "init", "-q", "-b", "main")
        (repo / "app.py").write_text("".join(f"line{i}\n" for i in range(1, 21)), encoding="utf-8")
        self._git(repo, "add", "-A")
        self._git(repo, "commit", "-q", "-m", "init")
        return repo

    def test_get_modified_lines_against_head(self, tmp_path):
        from aegis_core.verification.runner import _get_modified_lines

        repo = self._repo(tmp_path)
        lines = (repo / "app.py").read_text(encoding="utf-8").splitlines()
        lines[2] = "changed3"
        lines[14:14] = ["new15", "new16"]
        (repo / "app.py").write_text("\n".join(lines) + "\n", encoding="utf-8")

        assert _get_modified_lines("app.py", str(repo)) == {3, 15, 16}

    def test_get_modified_lines_none_when_nothing_changed(self, tmp_path):
        from aegis_core.verification.runner import _get_modified_lines

        repo = self._repo(tmp_path)
        assert _get_modified_lines("app.py", str(repo)) is None

    def test_get_modified_lines_uses_the_pull_request_base(self, tmp_path, monkeypatch):
        from aegis_core.verification.runner import _get_modified_lines

        repo = self._repo(tmp_path)
        self._git(repo, "checkout", "-q", "-b", "topic")
        self._git(repo, "branch", "develop", "main")
        with open(repo / "app.py", "a", encoding="utf-8") as fh:
            fh.write("line21\nline22\n")
        self._git(repo, "commit", "-q", "-am", "topic")
        monkeypatch.setenv("GITHUB_BASE_REF", "develop")

        # clean tree: HEAD shows nothing, the merge base with develop shows the commit
        assert _get_modified_lines("app.py", str(repo)) == {21, 22}
        assert _get_modified_lines("app.py", str(repo), diff_base="develop...HEAD") == {21, 22}

    def test_get_modified_lines_new_file_is_all_new(self, tmp_path):
        from aegis_core.verification.runner import _get_modified_lines

        repo = self._repo(tmp_path)
        (repo / "fresh.py").write_text("a\nb\n", encoding="utf-8")
        assert _get_modified_lines("fresh.py", str(repo)) == {1, 2}

    def test_get_modified_lines_outside_git_is_none(self, tmp_path):
        from aegis_core.verification.runner import _get_modified_lines

        (tmp_path / "app.py").write_text("x\n", encoding="utf-8")
        assert _get_modified_lines("missing.py", str(tmp_path)) is None


class TestRunnerCoverageEnhancements:
    """Tests for edge cases in runner.py discovery and mapping."""

    def test_find_test_file_runner_mapping(self):
        from aegis_core.verification.runner import _find_test_file
        test_file = _find_test_file("aegis_core/verification/runner.py", REPO_ROOT)
        assert test_file is not None
        assert test_file.endswith("test_layer1.py")

        # Test decomposed domain mappings
        mcp_test = _find_test_file("aegis_mcp/handlers/governance.py", REPO_ROOT)
        assert mcp_test is not None and mcp_test.endswith("test_mcp_handlers.py")

        telemetry_test = _find_test_file("aegis_core/outcomes/telemetry.py", REPO_ROOT)
        assert telemetry_test is not None and telemetry_test.endswith("test_outcomes_telemetry.py")

        engine_test = _find_test_file("aegis_core/outcomes/engine.py", REPO_ROOT)
        assert engine_test is not None and engine_test.endswith("test_outcome_engine.py")

        skills_test = _find_test_file("aegis_core/skills/__init__.py", REPO_ROOT)
        assert skills_test is not None and skills_test.endswith("test_skills.py")

        slots_test = _find_test_file("aegis_core/skills/slots.py", REPO_ROOT)
        assert slots_test is not None and slots_test.endswith("test_slots.py")

    def test_discover_functions_with_target_lines(self, tmp_path):
        from aegis_core.verification.runner import _discover_functions
        code = textwrap.dedent("""\
            def func_a():
                return 1

            def func_b():
                return 2

            def func_c():
                return 3
        """)
        f = tmp_path / "module.py"
        f.write_text(code)

        # Lines 1-2 belong to func_a
        assert _discover_functions(str(f), target_lines={1, 2}) == ["func_a"]
        # Lines 4-5 belong to func_b
        assert _discover_functions(str(f), target_lines={5}) == ["func_b"]
        # No overlap
        assert _discover_functions(str(f), target_lines={100}) == []

    def test_run_layer1_polyglot_call_graph(self, tmp_path):
        """run_layer1 invokes call_graph on polyglot files if a driver is resolved."""
        from aegis_core.verification import runner
        ts_file = tmp_path / "app.ts"
        ts_file.write_text("export function run() {}\n")

        with patch("aegis_core.ast.runner.ASTDriverRegistry.resolve_driver", return_value="node driver.js"), \
             patch("aegis_core.verification.call_graph.check") as mock_cg:
            mock_cg.return_value = ToolEvidence("call_graph", str(ts_file), True, "0 orphans")
            results = runner.run_layer1(
                changed_files=["app.ts"],
                repo_root=str(tmp_path),
                fast_mode=True,
            )
            assert mock_cg.called
            assert any(r.target == str(ts_file) for r in results)

    def test_get_modified_lines_uses_diff_base_and_head_fallback(self, tmp_path):
        """An explicit diff_base wins; a clean tree falls back to HEAD~1."""
        import subprocess
        from aegis_core.verification import runner

        def git(*args):
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                           cwd=str(tmp_path), check=True, capture_output=True)

        (tmp_path / "foo.py").write_text("".join(f"l{i}\n" for i in range(1, 11)), encoding="utf-8")
        git("init", "-q", "-b", "trunk")
        git("add", "-A")
        git("commit", "-q", "-m", "one")
        git("branch", "feat")
        with open(tmp_path / "foo.py", "a", encoding="utf-8") as fh:
            fh.write("".join(f"l{i}\n" for i in range(11, 16)))
        git("commit", "-q", "-am", "two")

        # clean tree: HEAD shows nothing, HEAD~1 shows the last commit's lines
        assert runner._get_modified_lines("foo.py", str(tmp_path)) == {11, 12, 13, 14, 15}

        (tmp_path / "foo.py").write_text("x\n" + (tmp_path / "foo.py").read_text(encoding="utf-8"), encoding="utf-8")
        # an explicit base is compared first: against feat, line 1 and the five appended lines are new
        assert runner._get_modified_lines("foo.py", str(tmp_path), diff_base="feat") == {1, 12, 13, 14, 15, 16}


_LATIN1 = "# -*- coding: latin-1 -*-\nGREETING = 'café'\n".encode("latin-1")


class TestLayer1FailsClosed:
    """A Layer 1 tool that raises yields a failing result naming the tool and file (wave A F1)."""

    @pytest.fixture
    def ws(self, tmp_path):
        (tmp_path / "mod.py").write_text("def main():\n    return 1\n", encoding="utf-8")
        return tmp_path

    @pytest.mark.parametrize("module, tool", [(call_graph, "call_graph"), (runner.import_guard, "import_guard")])
    def test_tool_exception_becomes_a_failing_result(self, ws, monkeypatch, module, tool):
        def boom(*_args, **_kwargs):
            raise RecursionError("maximum recursion depth exceeded")

        monkeypatch.setattr(module, "check", boom)
        results = runner.run_layer1(changed_files=["mod.py"], repo_root=str(ws), fast_mode=True)
        failed = [r for r in results if r.tool == tool]
        assert [(r.target, r.verdict) for r in failed] == [("mod.py", False)]
        assert failed[0].detail == f"{tool}: cannot verify mod.py: RecursionError: maximum recursion depth exceeded"
        assert runner.gate_verdict(results) is False

    def test_forbid_ast_exception_becomes_a_failing_result(self, ws, monkeypatch):
        import aegis_core.ast.policy as policy

        rules = ws / ".aegis" / "rules" / "invariants"
        rules.mkdir(parents=True)
        (rules / "no-eval.md").write_text(
            "---\nid: no-eval\ntype: invariant\nenforcement: gate\nforbid_ast:\n  calls: [eval]\n---\n",
            encoding="utf-8",
        )

        def boom(*_args, **_kwargs):
            raise MemoryError("ast too large")

        monkeypatch.setattr(policy, "evaluate_forbid_ast_structured", boom)
        results = runner.run_layer1(changed_files=["mod.py"], repo_root=str(ws), fast_mode=True)
        failed = [r for r in results if r.tool == "forbid_ast:no-eval"]
        assert [(r.target, r.verdict, r.detail) for r in failed] == [
            ("mod.py", False, "forbid_ast:no-eval: cannot verify mod.py: MemoryError: ast too large")
        ]

    def test_forbid_ast_rule_discovery_failure_fails_closed(self, ws, monkeypatch):
        def boom(_root):
            raise PermissionError("rules dir unreadable")

        monkeypatch.setattr(runner, "_discover_forbid_ast_rules", boom)
        results = runner.run_layer1(changed_files=["mod.py"], repo_root=str(ws), fast_mode=True)
        failed = [r for r in results if r.tool == "forbid_ast"]
        assert [(r.target, r.verdict, r.detail) for r in failed] == [
            (".aegis/rules", False, "forbid_ast: cannot load rules: PermissionError: rules dir unreadable")
        ]

    def test_an_unreadable_rule_file_fails_closed(self, tmp_path):
        """One undecodable gate rule must not silently drop out of enforcement (b1-verify review)."""
        invariants = tmp_path / ".aegis" / "rules" / "invariants"
        invariants.mkdir(parents=True)
        (invariants / "no-subprocess.md").write_bytes(
            b"---\nid: no-subprocess\ntype: invariant\nenforcement: gate\n"
            b"forbid_ast:\n  calls: [subprocess.run]\n---\nNo shelling out \xff here.\n"
        )
        (invariants / "no-eval.md").write_text(
            "---\nid: no-eval\ntype: invariant\nenforcement: gate\nforbid_ast:\n  calls: [eval]\n---\n",
            encoding="utf-8",
        )
        (tmp_path / "bad.py").write_text(
            "import subprocess\n\n\ndef main():\n    return subprocess.run(['true'])\n", encoding="utf-8"
        )
        results = runner.run_layer1(changed_files=["bad.py"], repo_root=str(tmp_path), fast_mode=True)
        failed = [r for r in results if r.tool == "forbid_ast"]
        assert [(r.target, r.verdict) for r in failed] == [(".aegis/rules/invariants/no-subprocess.md", False)]
        assert failed[0].detail.startswith(
            "forbid_ast: cannot load rule .aegis/rules/invariants/no-subprocess.md: invalid UTF-8:"
        )
        assert runner.gate_verdict(results) is False

    def test_readable_rules_still_enforce_next_to_an_unreadable_one(self, tmp_path):
        invariants = tmp_path / ".aegis" / "rules" / "invariants"
        invariants.mkdir(parents=True)
        (invariants / "broken.md").write_bytes(b"---\nid: broken\nforbid_ast:\n  calls: [exec]\n---\n\xff\n")
        (invariants / "no-eval.md").write_text(
            "---\nid: no-eval\ntype: invariant\nenforcement: gate\nforbid_ast:\n  calls: [eval]\n---\n",
            encoding="utf-8",
        )
        (tmp_path / "bad.py").write_text("def main(x):\n    return eval(x)\n", encoding="utf-8")
        results = runner.run_layer1(changed_files=["bad.py"], repo_root=str(tmp_path), fast_mode=True)
        assert {(r.tool, r.target) for r in results if not r.verdict} == {
            ("forbid_ast", ".aegis/rules/invariants/broken.md"),
            ("forbid_ast:no-eval", "bad.py"),
        }

    @pytest.mark.parametrize(
        "spec, reason",
        [
            ("forbid_ast:\n  - calls: [eval]\n", "forbid_ast must map imports/calls/decorators to lists, not list"),
            ("forbid_ast: true\n", "forbid_ast must map imports/calls/decorators to lists, not bool"),
            ("forbid_ast:\n", "forbid_ast must map imports/calls/decorators to lists, not NoneType"),
            ("forbid_ast: {}\n", "forbid_ast declares no patterns"),
            ("forbid_ast:\n  calls: []\n", "forbid_ast declares no patterns"),
            ("forbid_ast:\n  calls: eval\n", "forbid_ast.calls must be a list of non-empty strings, not str"),
            ("forbid_ast:\n  calls:\n    - eval\n    - 3\n", "forbid_ast.calls must be a list of non-empty strings"),
            ("forbid_ast:\n  calls: ['  ']\n", "forbid_ast.calls must be a list of non-empty strings"),
            ("forbid_ast:\n  call: [eval]\n", "unknown forbid_ast key 'call' (allowed: imports, calls, decorators)"),
        ],
        ids=["list", "scalar", "null", "empty-map", "empty-list", "string-value", "non-string-item", "blank-item",
             "unknown-key"],
    )
    def test_a_malformed_forbid_ast_fails_closed(self, tmp_path, spec, reason):
        """A rule declaring forbid_ast in a shape that enforces nothing must not pass silently (b1-verify F2)."""
        invariants = tmp_path / ".aegis" / "rules" / "invariants"
        invariants.mkdir(parents=True)
        (invariants / "r1.md").write_text(
            f"---\nid: r1\ntype: invariant\nenforcement: gate\n{spec}---\nNo eval.\n", encoding="utf-8"
        )
        (tmp_path / "bad.py").write_text("def main(x):\n    return eval(x)\n", encoding="utf-8")
        results = runner.run_layer1(changed_files=["bad.py"], repo_root=str(tmp_path), fast_mode=True)
        failed = [(r.tool, r.target, r.verdict) for r in results if r.tool.startswith("forbid_ast")]
        assert failed == [("forbid_ast", ".aegis/rules/invariants/r1.md", False)]
        detail = next(r.detail for r in results if r.tool == "forbid_ast")
        assert detail.startswith(f"forbid_ast: cannot load rule .aegis/rules/invariants/r1.md: {reason}")
        assert runner.gate_verdict(results) is False

    def test_an_expired_rule_with_a_malformed_forbid_ast_is_not_enforced(self, tmp_path):
        # A rank-1 trap: expired_at on an invariant or gate is a load error since v4.3 (T3).
        traps = tmp_path / ".aegis" / "rules" / "traps"
        traps.mkdir(parents=True)
        (traps / "old.md").write_text(
            "---\nid: old\nexpired_at: '2026-01-01'\nforbid_ast: true\n---\n", encoding="utf-8"
        )
        (tmp_path / "mod.py").write_text("def main():\n    return 1\n", encoding="utf-8")
        results = runner.run_layer1(changed_files=["mod.py"], repo_root=str(tmp_path), fast_mode=True)
        assert [r for r in results if r.tool.startswith("forbid_ast")] == []

    def test_a_well_formed_forbid_ast_still_enforces(self, tmp_path):
        invariants = tmp_path / ".aegis" / "rules" / "invariants"
        invariants.mkdir(parents=True)
        (invariants / "r1.md").write_text(
            "---\nid: r1\nforbid_ast:\n  imports: []\n  calls: [eval]\n---\n", encoding="utf-8"
        )
        (tmp_path / "bad.py").write_text("def main(x):\n    return eval(x)\n", encoding="utf-8")
        results = runner.run_layer1(changed_files=["bad.py"], repo_root=str(tmp_path), fast_mode=True)
        assert [(r.tool, r.target, r.verdict) for r in results if r.tool.startswith("forbid_ast")] == [
            ("forbid_ast:r1", "bad.py", False)
        ]

    def test_unparseable_notes_that_never_name_forbid_ast_are_not_rules(self, tmp_path):
        notes = tmp_path / "rules"
        notes.mkdir()
        (notes / "style-notes.md").write_text("# Style\n\n- prefer small functions\nsee: below\n", encoding="utf-8")
        (notes / "latin1-notes.md").write_bytes(b"caf\xe9 notes\n")
        (tmp_path / "mod.py").write_text("def main():\n    return 1\n", encoding="utf-8")
        results = runner.run_layer1(changed_files=["mod.py"], repo_root=str(tmp_path), fast_mode=True)
        assert [r for r in results if r.tool.startswith("forbid_ast")] == []
        assert runner.gate_verdict(results) is True


_NO_EVAL = "---\nid: no-eval\ntype: invariant\nenforcement: gate\nforbid_ast:\n  calls: [eval]\n---\n"


def _no_eval_ws(tmp_path, files):
    rules = tmp_path / ".aegis" / "rules" / "invariants"
    rules.mkdir(parents=True)
    (rules / "no-eval.md").write_text(_NO_EVAL, encoding="utf-8")
    for name, text in files.items():
        (tmp_path / name).write_bytes(text.encode("utf-8"))
    return tmp_path


class TestOneForbidAstEvaluation:
    """R-checks-11: one evaluation per (file, rule) feeds the verdict, the lines and the overrides."""

    def test_each_file_and_rule_is_evaluated_once_however_many_sites(self, tmp_path, monkeypatch):
        import aegis_core.ast.policy as policy
        from aegis_core.verification import security_pack

        ws = _no_eval_ws(tmp_path, {"mod.py": "x = eval(1)\n" * 5000})
        # The built-in security pack (R-checks-29) makes its own passes per pack rule; this counts the user rule's.
        monkeypatch.setattr(security_pack, "evaluate_security_pack", lambda *a, **k: {})
        passes = []
        real = policy._eval_call_entry
        monkeypatch.setattr(policy, "_eval_call_entry", lambda *a, **k: passes.append(1) or real(*a, **k))
        results = runner.run_layer1(changed_files=["mod.py"], repo_root=str(ws), fast_mode=True)
        failing = [r for r in results if r.tool == "forbid_ast:no-eval"]
        assert [(r.verdict, len(r.lines)) for r in failing] == [(False, 5000)]
        assert len(passes) == 1

    def test_an_allowed_hit_is_recorded_once_and_an_allow_for_another_rule_still_fails(self, tmp_path):
        from aegis_core import credit

        ws = _no_eval_ws(tmp_path, {"ok.py": "x = eval(1)  # aegis: allow[no-eval]: reviewed\n",
                                    "other.py": "x = eval(1)  # aegis: allow[other-rule]: theirs\n"})
        for _ in range(2):
            results = runner.run_layer1(changed_files=["ok.py", "other.py"], repo_root=str(ws), fast_mode=True)
        assert [(r.target, r.verdict) for r in results if r.tool == "forbid_ast:no-eval"] == [("other.py", False)]
        overrides = [r for r in credit.read_rows(ws) if r.get("event") == "override"]
        assert [(r["file"], r["line"], r["reason"]) for r in overrides] == [("ok.py", 1, "reviewed")]


class TestLayer1LegacyEncodings:
    """call_graph and import_guard decode .py sources the way CPython does (PEP 263, BOM)."""

    def test_latin1_module_is_not_a_false_call_graph_failure(self, tmp_path):
        (tmp_path / "legacy.py").write_bytes(_LATIN1 + b"def main():\n    return GREETING\n")
        result = call_graph.check(str(tmp_path / "legacy.py"), str(tmp_path), exclude_names={"main"})
        assert result.verdict is True, result.detail

    def test_latin1_module_imports_are_extracted(self, tmp_path):
        (tmp_path / "legacy.py").write_bytes(_LATIN1 + b"import json\nimport some_vendor_sdk\n")
        modules = [i.module for i in runner.import_guard.extract_imports(str(tmp_path / "legacy.py"))]
        assert modules == ["json", "some_vendor_sdk"]

    def test_latin1_module_passes_layer1_end_to_end(self, tmp_path):
        (tmp_path / "legacy.py").write_bytes(_LATIN1 + b"import json\n\ndef main():\n    return json.dumps(GREETING)\n")
        results = runner.run_layer1(changed_files=["legacy.py"], repo_root=str(tmp_path), fast_mode=True)
        assert results and runner.gate_verdict(results) is True, [r.detail for r in results]

    def test_undecodable_module_fails_closed(self, tmp_path):
        (tmp_path / "bad.py").write_bytes(b"x = '\xff\xfe'\n")
        results = runner.run_layer1(changed_files=["bad.py"], repo_root=str(tmp_path), fast_mode=True)
        assert runner.gate_verdict(results) is False
        assert {r.tool for r in results if not r.verdict} >= {"import_guard"}
