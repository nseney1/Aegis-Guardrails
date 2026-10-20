from pathlib import Path
"""TDD tests for mutation_tester.py — AUDITED ground truth.

Audit findings applied:
- test_returns_tool_evidence: strengthened with verdict + target assertions
- test_reports_survival_count: regex for numeric survived/total
- test_respects_max_mutations: was TAUTOLOGICAL, now asserts budget cap
"""
import os
import re
import sys
import textwrap

import pytest

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
sys.path.insert(0, REPO_ROOT)

from aegis_core.verification import ToolEvidence
from tests.helpers_popen import install_fake_popen
from unittest.mock import patch, MagicMock


class TestMutationTesterContract:
    """Behavioral contract for mutation_tester.check()."""

    def test_returns_tool_evidence(self, tmp_path):
        """check() must return a passing ToolEvidence for a well-tested function."""
        from aegis_core.verification import mutation_tester

        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent("""\
            def add(a, b):
                return a + b
        """))

        test = tmp_path / "test_target.py"
        test.write_text(textwrap.dedent(f"""\
            import sys
            sys.path.insert(0, {str(tmp_path)!r})
            from target import add
            def test_add():
                assert add(2, 3) == 5
        """))

        result = mutation_tester.check(
            target_file=str(src),
            target_function="add",
            test_file=str(test),
        )
        assert isinstance(result, ToolEvidence)
        assert result.tool == "mutation_tester"
        assert "add" in result.target
        assert result.verdict is True
        assert result.lines == []  # No surviving mutations

    def test_catches_tautological_test(self, tmp_path):
        """A test that passes regardless of implementation should FAIL."""
        from aegis_core.verification import mutation_tester

        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent("""\
            def compute(x):
                return x * 2
        """))

        # Tautological: doesn't check the return value
        test = tmp_path / "test_target.py"
        test.write_text(textwrap.dedent(f"""\
            import sys
            sys.path.insert(0, {str(tmp_path)!r})
            from target import compute
            def test_compute():
                result = compute(5)
                assert isinstance(result, int)  # passes for ANY int return
        """))

        result = mutation_tester.check(
            target_file=str(src),
            target_function="compute",
            test_file=str(test),
        )
        assert result.verdict is False, \
            "Tautological test should be detected (mutations survive)"
        assert 2 in result.lines, \
            f"Surviving mutation should be on line 2 (return x * 2), got {result.lines}"

    def test_real_test_passes(self, tmp_path):
        """A test that validates behavior should PASS (no survivors)."""
        from aegis_core.verification import mutation_tester

        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent("""\
            def multiply(a, b):
                return a * b
        """))

        test = tmp_path / "test_target.py"
        test.write_text(textwrap.dedent(f"""\
            import sys
            sys.path.insert(0, {str(tmp_path)!r})
            from target import multiply
            def test_multiply_basic():
                assert multiply(3, 4) == 12
            def test_multiply_zero():
                assert multiply(0, 5) == 0
            def test_multiply_negative():
                assert multiply(-2, 3) == -6
        """))

        result = mutation_tester.check(
            target_file=str(src),
            target_function="multiply",
            test_file=str(test),
        )
        assert result.verdict is True, \
            f"Real tests should catch mutations, but got: {result.detail}"
        assert result.lines == [], \
            f"No mutations should survive, but got survivors at: {result.lines}"

    def test_reports_survival_count(self, tmp_path):
        """Result detail must include numeric survived vs total counts."""
        from aegis_core.verification import mutation_tester

        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent("""\
            def negate(x):
                return -x
        """))

        test = tmp_path / "test_target.py"
        test.write_text(textwrap.dedent(f"""\
            import sys
            sys.path.insert(0, {str(tmp_path)!r})
            from target import negate
            def test_negate():
                assert negate(5) == -5
        """))

        result = mutation_tester.check(
            target_file=str(src),
            target_function="negate",
            test_file=str(test),
        )
        # Detail must contain numeric counts like "0/3 survived" or "0 of 3"
        assert re.search(r"\d+\s*(?:/|\s+of\s+)\s*\d+", result.detail), \
            f"Detail must include survived/total counts, got: {result.detail}"

    def test_empty_function_passes(self, tmp_path):
        """A function with no mutable operations should pass trivially."""
        from aegis_core.verification import mutation_tester

        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent("""\
            def noop():
                pass
        """))

        test = tmp_path / "test_target.py"
        test.write_text(textwrap.dedent(f"""\
            import sys
            sys.path.insert(0, {str(tmp_path)!r})
            from target import noop
            def test_noop():
                assert noop() is None
        """))

        result = mutation_tester.check(
            target_file=str(src),
            target_function="noop",
            test_file=str(test),
        )
        assert result.verdict is True


class TestMutationTesterBudget:
    """Verify mutation budget controls."""

    def test_respects_max_mutations(self, tmp_path):
        """Must not generate more mutations than the budget allows."""
        from aegis_core.verification import mutation_tester

        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent("""\
            def big_function(a, b, c, d):
                x = a + b
                y = c - d
                z = x * y
                w = z / max(a, 1)
                return x + y + z + w
        """))

        test = tmp_path / "test_target.py"
        test.write_text(textwrap.dedent(f"""\
            import sys
            sys.path.insert(0, {str(tmp_path)!r})
            from target import big_function
            def test_basic():
                result = big_function(2, 3, 4, 1)
                assert isinstance(result, (int, float))
        """))

        result = mutation_tester.check(
            target_file=str(src),
            target_function="big_function",
            test_file=str(test),
            max_mutations=3,
        )
        assert isinstance(result, ToolEvidence)
        # Parse total mutations attempted from detail
        match = re.search(r"(\d+)\s*(?:/|\s+of\s+)\s*(\d+)", result.detail) or \
                re.search(r"(\d+)\s+mutation", result.detail)
        assert match, f"Could not parse mutation count from: {result.detail}"
        total = int(match.group(2)) if match.lastindex >= 2 else int(match.group(1))
        assert total <= 3, f"Expected <= 3 mutations attempted, got {total}"


class TestMutationTesterFailsClosed:
    """BUG-034: tests that cannot pass against the unmutated code used to
    count as killing every mutant, so check() reported verdict=True."""

    def _target(self, tmp_path):
        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent("""\
            def add(a, b):
                return a + b
        """))
        return src

    def test_unrunnable_test_file_fails_closed(self, tmp_path):
        from aegis_core.verification import mutation_tester

        src = self._target(tmp_path)
        test = tmp_path / "test_target.py"
        test.write_text(textwrap.dedent(f"""\
            import sys
            sys.path.insert(0, {str(tmp_path)!r})
            from target import add
            def test_add(:
                assert add(1, 2) == 3
        """))

        result = mutation_tester.check(str(src), "add", str(test))
        assert result.verdict is False
        assert "baseline" in result.detail.lower()
        assert result.lines == [-1]

    def test_baseline_assertion_failure_fails_closed(self, tmp_path):
        from aegis_core.verification import mutation_tester

        src = self._target(tmp_path)
        test = tmp_path / "test_target.py"
        test.write_text(textwrap.dedent(f"""\
            import sys
            sys.path.insert(0, {str(tmp_path)!r})
            from target import add
            def test_add():
                assert add(1, 2) == 4
        """))

        result = mutation_tester.check(str(src), "add", str(test))
        assert result.verdict is False
        assert "baseline" in result.detail.lower()


class TestMutationTesterAppliesEveryCollectedMutation:
    """BUG-039: comparison, boolean, statement-deletion and return-value
    mutations were counted but never applied, so a test that doesn't
    check them still reported verdict=True ("0/2 survived")."""

    def test_unchecked_comparison_survives(self, tmp_path):
        from aegis_core.verification import mutation_tester

        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent("""\
            def eq(a, b):
                return a == b
        """))
        test = tmp_path / "test_target.py"
        test.write_text(textwrap.dedent(f"""\
            import sys
            sys.path.insert(0, {str(tmp_path)!r})
            from target import eq
            def test_eq():
                eq(1, 2)
        """))

        result = mutation_tester.check(str(src), "eq", str(test))
        assert result.verdict is False, result.detail
        assert result.detail == "2/2 survived (1 test file ran)"

    def test_checked_boolean_logic_kills_mutants(self, tmp_path):
        from aegis_core.verification import mutation_tester

        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent("""\
            def both(a, b):
                return a and b
        """))
        test = tmp_path / "test_target.py"
        test.write_text(textwrap.dedent(f"""\
            import sys
            sys.path.insert(0, {str(tmp_path)!r})
            from target import both
            def test_both():
                assert both(True, False) is False
                assert both(True, True) is True
        """))

        result = mutation_tester.check(str(src), "both", str(test))
        assert result.verdict is True, result.detail
        assert result.detail == "0/2 survived (1 test file ran)"

    def test_docstring_and_return_none_are_not_mutated(self, tmp_path):
        """Deleting a docstring or turning `return None` into `return None`
        changes nothing, so no test could kill those mutants."""
        from aegis_core.verification import mutation_tester

        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent('''\
            def add(a, b):
                """Add two numbers."""
                return a + b

            def nothing(x):
                return None
        '''))
        test = tmp_path / "test_target.py"
        test.write_text(textwrap.dedent(f"""\
            import sys
            sys.path.insert(0, {str(tmp_path)!r})
            from target import add, nothing
            def test_add():
                assert add(1, 2) == 3
                assert add(2, 5) == 7
            def test_nothing():
                assert nothing(1) is None
        """))

        documented = mutation_tester.check(str(src), "add", str(test))
        assert documented.verdict is True, documented.detail
        assert documented.detail == "0/2 survived (1 test file ran)"
        returns_none = mutation_tester.check(str(src), "nothing", str(test))
        assert returns_none.verdict is True, returns_none.detail


class TestMutationTesterBoolAndTargetLines:
    """Tests for boolean constant mutation and target_lines scoping."""

    def test_bool_constant_mutated(self, tmp_path):
        from aegis_core.verification import mutation_tester

        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent("""\
            def is_ready():
                return True
        """))
        test = tmp_path / "test_target.py"
        test.write_text(textwrap.dedent(f"""\
            import sys
            sys.path.insert(0, {str(tmp_path)!r})
            from target import is_ready
            def test_ready():
                assert is_ready() is True
        """))

        result = mutation_tester.check(str(src), "is_ready", str(test))
        assert result.verdict is True
        assert "survived" in result.detail

    def test_target_lines_filtering(self, tmp_path):
        from aegis_core.verification import mutation_tester

        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent("""\
            def calc(x):
                a = x + 1
                b = a * 2
                return b
        """))
        test = tmp_path / "test_target.py"
        test.write_text(textwrap.dedent(f"""\
            import sys
            sys.path.insert(0, {str(tmp_path)!r})
            from target import calc
            def test_calc():
                assert calc(3) == 8
        """))

        # Restrict mutation testing only to line 2 (a = x + 1)
        res_line2 = mutation_tester.check(str(src), "calc", str(test), target_lines={2})
        assert res_line2.verdict is True

        # Restrict mutation testing to a line with no mutations (e.g. line 1 def calc)
        res_empty = mutation_tester.check(str(src), "calc", str(test), target_lines={1})
        assert res_empty.verdict is True
        assert res_empty.detail == "No mutations on modified lines"


class TestPolyglotMutationTesterCoverage:
    """Branch and line coverage for apply_mutation_point, collect_mutations_from_ast, and non-python check()."""

    def test_apply_mutation_point_coverage(self):
        from aegis_core.ast.schema import MutationPoint
        from aegis_core.verification.mutation_tester import apply_mutation_point

        # 1. No original op
        pt_empty = MutationPoint(line=1, col=0, original_op="", replacement_op="", mutation_type="cmpop")
        assert apply_mutation_point("code", pt_empty) is None

        # 2. original/mutated aliases
        source = "x == 1"
        pt_aliases = MutationPoint(line=1, col=2, original_op="==", replacement_op="!=", mutation_type="cmpop")
        object.__setattr__(pt_aliases, "original", "==")
        object.__setattr__(pt_aliases, "mutated", "!=")
        assert apply_mutation_point(source, pt_aliases) == "x != 1"

        # 3. byte_offset match
        pt_byte = MutationPoint(line=1, col=2, original_op="==", replacement_op="!=", mutation_type="cmpop")
        object.__setattr__(pt_byte, "byte_offset", 2)
        assert apply_mutation_point(source, pt_byte) == "x != 1"

        # 4. byte_offset mismatch falls through to line/col
        object.__setattr__(pt_byte, "byte_offset", 0)  # offset 0 is 'x ', not '=='
        assert apply_mutation_point(source, pt_byte) == "x != 1"

        # 5. Out of bounds line
        pt_oob = MutationPoint(line=999, col=0, original_op="==", replacement_op="!=", mutation_type="cmpop")
        assert apply_mutation_point(source, pt_oob) is None

        # 6. Column attribute variants (col vs column)
        pt_col = MutationPoint(line=1, col=0, original_op="==", replacement_op="!=", mutation_type="cmpop")
        object.__setattr__(pt_col, "col", None)
        object.__setattr__(pt_col, "column", 2)
        assert apply_mutation_point(source, pt_col) == "x != 1"

        # 7. Fallback search when col doesn't match
        pt_search = MutationPoint(line=1, col=0, original_op="==", replacement_op="!=", mutation_type="cmpop")
        assert apply_mutation_point(source, pt_search) == "x != 1"

        # 8. Target line does not contain orig
        pt_missing = MutationPoint(line=1, col=0, original_op="===", replacement_op="!==", mutation_type="cmpop")
        assert apply_mutation_point(source, pt_missing) is None

    def test_collect_mutations_from_ast_coverage(self):
        from aegis_core.ast.schema import MutationPoint, NormalizedAST
        from aegis_core.verification.mutation_tester import collect_mutations_from_ast

        # Empty points
        ast_empty = NormalizedAST(file_path="f.ts", language="typescript", mutation_points=())
        assert collect_mutations_from_ast(ast_empty) == []

        # target_function is None
        p1 = MutationPoint(line=1, col=0, original_op="+", replacement_op="-", mutation_type="binop")
        p2 = MutationPoint(line=2, col=0, original_op="*", replacement_op="/", mutation_type="binop")
        object.__setattr__(p1, "function_scope", "foo")
        ast_pts = NormalizedAST(file_path="f.ts", language="typescript", mutation_points=(p1, p2))
        assert collect_mutations_from_ast(ast_pts, target_function=None) == [p1, p2]

        # target_function filter
        assert collect_mutations_from_ast(ast_pts, target_function="foo") == [p1, p2]
        assert collect_mutations_from_ast(ast_pts, target_function="bar") == [p2]

    def test_check_non_python_runner_error(self, tmp_path):
        from aegis_core.verification import mutation_tester

        ts_file = tmp_path / "app.ts"
        ts_file.write_text("export function test() {}")
        test_file = tmp_path / "test.ts"
        test_file.write_text("test")

        mock_runner = MagicMock()
        mock_runner.parse_file.side_effect = RuntimeError("Driver failed")

        ev = mutation_tester.check(str(ts_file), "test", str(test_file), ast_runner=mock_runner)
        assert ev.verdict is False
        assert "Failed to parse NormalizedAST" in ev.detail

    def test_check_non_python_no_mutations_on_lines(self, tmp_path):
        from aegis_core.ast.schema import MutationPoint, NormalizedAST
        from aegis_core.verification import mutation_tester

        ts_file = tmp_path / "app.ts"
        ts_file.write_text("export function test() { return 1; }")
        test_file = tmp_path / "test.ts"
        test_file.write_text("test")

        p = MutationPoint(line=5, col=0, original_op="+", replacement_op="-", mutation_type="binop")
        mock_ast = NormalizedAST(file_path=str(ts_file), language="typescript", mutation_points=(p,))
        mock_runner = MagicMock()
        mock_runner.parse_file.return_value = mock_ast

        ev = mutation_tester.check(str(ts_file), "test", str(test_file), target_lines={1}, ast_runner=mock_runner)
        assert ev.verdict is True
        assert ev.detail == "No mutations on modified lines"

    def test_check_non_python_baseline_fail_and_survived_and_killed(self, tmp_path):
        from aegis_core.ast.schema import MutationPoint, NormalizedAST
        from aegis_core.verification import mutation_tester

        ts_file = tmp_path / "app.ts"
        ts_file.write_text("export function test() { return 1 + 2; }")
        test_file = tmp_path / "test.ts"
        test_file.write_text("test")

        p1 = MutationPoint(line=1, col=34, original_op="+", replacement_op="-", mutation_type="binop")
        p2 = MutationPoint(line=1, col=0, original_op="invalid", replacement_op="none", mutation_type="binop")
        mock_ast = NormalizedAST(file_path=str(ts_file), language="typescript", mutation_points=(p1, p2))
        mock_runner = MagicMock()
        mock_runner.parse_file.return_value = mock_ast

        passed = mutation_tester.TestRunResult(passed=True)
        failed = mutation_tester.TestRunResult(passed=False, status="fail", detail="exit code 1: E")

        # 1. Baseline tests fail
        with patch("aegis_core.verification.mutation_tester._check_tests", return_value=failed):
            ev = mutation_tester.check(str(ts_file), "test", str(test_file), ast_runner=mock_runner)
            assert ev.verdict is False
            assert "Baseline tests fail" in ev.detail
            assert ev.lines == [-1]

        # 2. Mutant survives (test passes against mutant)
        with patch("aegis_core.verification.mutation_tester._check_tests", return_value=passed):
            ev = mutation_tester.check(str(ts_file), "test", str(test_file), max_mutations=2, ast_runner=mock_runner)
            assert ev.verdict is False
            assert "1/2 survived" in ev.detail
            assert not list(tmp_path.glob("_mutant_*")), "a mutant was left beside the source"

        # 3. Mutant killed (baseline passes, mutant fails)
        run_results = [passed, failed]  # first baseline passes, then mutant fails
        with patch("aegis_core.verification.mutation_tester._check_tests", side_effect=run_results):
            ev = mutation_tester.check(str(ts_file), "test", str(test_file), max_mutations=1, ast_runner=mock_runner)
            assert ev.verdict is True
            assert "0/1 survived" in ev.detail

    def test_mutation_tester_reports_diagnostic_baseline_reasons(self, tmp_path, monkeypatch):
        """BUG-095: Mutation tester must report why baseline check failed."""
        from aegis_core.verification import mutation_tester
        import subprocess

        src = tmp_path / "target.py"
        src.write_text("def inc(x):\n    return x + 1\n")
        test = tmp_path / "test_target.py"
        test.write_text("def test_inc():\n    assert inc(1) == 2\n")

        # 1. Missing runner
        with patch("aegis_core.verification.test_runner.resolve_pytest_cmd", return_value=None):
            ev = mutation_tester.check(str(src), "inc", str(test))
            assert ev.verdict is False
            assert "pytest executable could not be resolved" in ev.detail

        # 2. Timeout
        install_fake_popen(monkeypatch, hang=True)
        with patch("aegis_core.verification.test_runner.resolve_pytest_cmd", return_value=["pytest"]):
            ev = mutation_tester.check(str(src), "inc", str(test))
            assert ev.verdict is False
            assert ev.detail.startswith("could not assess (timeout)")
            assert "within 30s" in ev.detail

        # 3. Failure exit code
        install_fake_popen(monkeypatch, returncode=1, stderr="AssertionError: expected 2 got 3")
        with patch("aegis_core.verification.test_runner.resolve_pytest_cmd", return_value=["pytest"]):
            ev = mutation_tester.check(str(src), "inc", str(test))
            assert ev.verdict is False
            assert "exit code 1" in ev.detail
            assert "AssertionError" in ev.detail

        # 4. Execution error (OSError)
        install_fake_popen(monkeypatch, spawn_error=OSError("disk read failure"))
        with patch("aegis_core.verification.test_runner.resolve_pytest_cmd", return_value=["pytest"]):
            ev = mutation_tester.check(str(src), "inc", str(test))
            assert ev.verdict is False
            assert "execution error: disk read failure" in ev.detail




class TestModuleSwapStaging:
    """What a mutant run is handed: the staged source, a fresh load marker and the plugin path."""

    def _swap(self, tmp_path):
        from aegis_core.verification import mutation_tester

        target = tmp_path / "pkg" / "mod.py"
        target.parent.mkdir()
        target.write_text("def f():\n    return 1\n", encoding="utf-8")
        workdir = tmp_path / "swap"
        workdir.mkdir()
        return mutation_tester._ModuleSwap(target, str(workdir))

    def test_staging_writes_the_source_the_plugin_will_serve(self, tmp_path):
        swap = self._swap(tmp_path)
        swap.stage("def f():\n    return 2\n")
        assert Path(swap.source_file).read_text(encoding="utf-8") == "def f():\n    return 2\n"

    def test_staging_clears_the_load_marker_of_the_previous_run(self, tmp_path):
        # A marker left by an earlier run would let a mutant that was never imported
        # count as killed when its test run fails for another reason.
        swap = self._swap(tmp_path)
        Path(swap.marker).write_text("pkg.mod", encoding="utf-8")
        assert swap.loaded()
        swap.stage("def f():\n    return 3\n")
        assert not swap.loaded()

    def test_the_plugin_dir_comes_first_and_an_inherited_pythonpath_is_kept(self, tmp_path, monkeypatch):
        swap = self._swap(tmp_path)
        monkeypatch.setenv("PYTHONPATH", "/opt/inherited")
        assert swap.stage("x = 1\n") == swap.workdir + os.pathsep + "/opt/inherited"
        monkeypatch.delenv("PYTHONPATH")
        assert swap.stage("x = 1\n") == swap.workdir

    def test_mutant_startup_timeout_retries_once_and_does_not_survive(self, tmp_path):
        """A mutant run that times out before loading the target module retries once
        and, if still timed out, is classified as timed-out/killed rather than survived."""
        from aegis_core.verification import mutation_tester

        src = tmp_path / "target.py"
        src.write_text("def inc(x):\n    return x + 1\n", encoding="utf-8")
        test = tmp_path / "test_target.py"
        test.write_text("def test_inc():\n    assert True\n", encoding="utf-8")

        baseline_ok = mutation_tester.TestRunResult(passed=True, status="pass", loaded=True)
        startup_timeout = mutation_tester.TestRunResult(
            passed=False, status="timeout", detail="timed out after 30s", loaded=False
        )

        with patch(
            "aegis_core.verification.mutation_tester._check_tests",
            side_effect=[baseline_ok, startup_timeout, startup_timeout],
        ) as mock_check:
            ev = mutation_tester.check(str(src), "inc", str(test), max_mutations=1)

        assert mock_check.call_count == 3  # 1 baseline + 1 mutant + 1 startup-timeout retry
        assert ev.verdict is True, ev.detail
        assert ev.detail == "0/1 survived (1 test file ran)"
        assert ev.lines == []

    def test_check_tests_kills_process_group_on_timeout(self, tmp_path):
        """A timed-out subprocess in _check_tests has its process group killed via checkrun.kill_group."""
        import subprocess
        from aegis_core.verification import mutation_tester

        test = tmp_path / "test_target.py"
        test.write_text("def test_inc():\n    assert True\n", encoding="utf-8")

        class _FakeProc:
            pid = 42424

            def communicate(self, timeout=None):
                raise subprocess.TimeoutExpired(cmd=["pytest"], timeout=timeout)

        fake_proc = _FakeProc()
        with patch("aegis_core.verification.test_runner.resolve_pytest_cmd", return_value=["pytest"]), patch(
            "subprocess.Popen", return_value=fake_proc
        ) as mock_popen, patch("aegis_core.checkrun.kill_group") as mock_kill_group:
            res = mutation_tester._check_tests([str(test)], timeout=5)

        assert res.passed is False
        assert res.status == "timeout"
        assert mock_popen.called
        assert mock_kill_group.called


class TestCheckTestsSpawn:
    """The spawn path does not depend on whether a test replaced subprocess.run (R-checks-52)."""

    def test_pytest_runs_through_popen_in_its_own_group_even_when_run_is_replaced(self, tmp_path, monkeypatch):
        import subprocess
        from aegis_core.verification import mutation_tester

        test = tmp_path / "test_trivial.py"
        test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        spawned = []
        real_popen = subprocess.Popen

        def spy(*args, **kwargs):
            spawned.append(kwargs)
            return real_popen(*args, **kwargs)

        def refuse(*args, **kwargs):
            raise AssertionError("pytest must not be started through subprocess.run")

        monkeypatch.setattr(subprocess, "run", refuse)
        monkeypatch.setattr(subprocess, "Popen", spy)
        res = mutation_tester._check_tests([str(test)], timeout=600)

        assert (res.status, res.detail) == ("pass", "")
        assert len(spawned) == 1
        if os.name == "nt":
            assert spawned[0]["creationflags"] & subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            assert spawned[0]["start_new_session"] is True

    def test_a_spawn_is_killed_as_a_group_after_it_ends(self, tmp_path, monkeypatch):
        from aegis_core.verification import mutation_tester

        test = tmp_path / "test_trivial.py"
        test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        spawns = install_fake_popen(monkeypatch, returncode=0)
        with patch("aegis_core.verification.test_runner.resolve_pytest_cmd", return_value=["pytest"]):
            res = mutation_tester._check_tests([str(test)], timeout=60)

        assert res.status == "pass"
        assert [(s["timeouts"], s["killed"] >= (0 if os.name == "nt" else 1)) for s in spawns] == [([60], True)]
