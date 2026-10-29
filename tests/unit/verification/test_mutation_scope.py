"""Which tests a mutant faces, and how long they may take (release blocker r3a).

A surviving mutant must mean that no relevant test detects the change. Layer 1 used to
run one conventionally named test file against a copy whose import lines were rewritten
to a sibling mutant module, so a function tested elsewhere, or reached through another
module, "survived" every mutation.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import textwrap
from typing import Optional
from unittest.mock import patch

import pytest

from aegis_core.verification import mutation_tester, runner
from aegis_core.verification.checkpoint_checks import check_test_coverage
from tests.helpers_popen import install_fake_popen

_STRONG = """\
    from pkg.mod import double

    def test_double():
        assert double(2) == 4
"""
_WEAK = """\
    from pkg.mod import double

    def test_double_runs():
        double(1)
"""


def _repo(tmp_path: Path, tests: dict, sources: Optional[dict] = None) -> Path:
    """A small project laid out like this repository: packages at the root, tests/ beside them."""
    root = tmp_path / "repo"
    files = {
        "pyproject.toml": '[tool.pytest.ini_options]\npythonpath = ["."]\n',
        "pkg/__init__.py": "",
        "pkg/mod.py": "def double(x):\n    return x + x\n",
        "pkg/helper.py": "from pkg.mod import double\n\n\ndef quad(x):\n    return double(double(x))\n",
        "pkg/model.py": "def double(x):\n    return 2 * x\n",
    }
    files.update(sources or {})
    files.update(tests)
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(body), encoding="utf-8")
    return root


def _mutation_evidence(results, func: str):
    found = [r for r in results if r.tool == "mutation_tester" and r.target.endswith(f"::{func}")]
    assert len(found) == 1, [(r.tool, r.target, r.detail) for r in results]
    return found[0]


def _snapshot(root: Path) -> set:
    return {p.relative_to(root).as_posix() for p in root.rglob("*")}


class TestTestFileResolution:
    """T1: the convention file plus every test file that imports the module and names the function."""

    def test_extracted_python_decoder_keeps_its_real_tests(self, tmp_path):
        repo = Path(__file__).resolve().parents[3]
        source = "aegis_core/ast/source.py"
        test = "tests/unit/core/test_ast_source.py"
        root = _repo(tmp_path, {}, sources={source: (repo / source).read_text(encoding="utf-8"),
                                           "aegis_core/__init__.py": "", "aegis_core/ast/__init__.py": ""})
        if (repo / test).is_file():
            (root / test).parent.mkdir(parents=True)
            shutil.copyfile(repo / test, root / test)

        ev = _mutation_evidence(runner.run_layer1([source], str(root), max_mutations=1), "read_python_source")

        assert ev.verdict is True, ev.detail
        assert ev.detail == "0/1 survived (1 test file ran)"
        assert not [issue for issue in check_test_coverage(root) if issue.get("file") == source]

    def test_tests_outside_the_convention_file_kill_mutants(self, tmp_path):
        root = _repo(tmp_path, {
            "tests/test_mod.py": _WEAK,  # the convention file checks nothing
            "tests/core/test_math.py": """\
                from pkg import mod

                def test_double_value():
                    assert mod.double(3) == 6
            """,
        })

        ev = _mutation_evidence(runner.run_layer1(["pkg/mod.py"], str(root)), "double")

        assert ev.verdict is True, ev.detail
        assert ev.detail == "0/2 survived (2 test files ran)"

    def test_every_import_form_counts_and_unrelated_files_do_not_run(self, tmp_path):
        must_not_run = '\n    def test_selected_by_mistake():\n        assert False, "not a relevant test"\n'
        root = _repo(tmp_path, {
            "tests/test_mod.py": _STRONG,
            "tests/test_dotted.py": """\
                import pkg.mod

                def test_dotted():
                    assert pkg.mod.double(3) == 6
            """,
            "tests/test_alias.py": """\
                from pkg.mod import double as dbl

                def test_alias():
                    assert dbl(4) == 8
            """,
            "tests/sub/test_multiline.py": """\
                from pkg import (
                    helper,
                    mod,
                )

                def test_multiline():
                    assert mod.double(5) == 10
                    assert helper.quad(1) == 4
            """,
            "tests/sub/test_inner.py": """\
                def test_inner():
                    from pkg.mod import double
                    assert double(6) == 12
            """,
            # imports the module but never names the function
            "tests/test_imports_only.py": "    from pkg import mod\n" + must_not_run,
            # names the function but never imports the module
            "tests/test_names_only.py": "    WORD = 'double'\n" + must_not_run,
            # imports a module whose name merely starts the same way
            "tests/test_other_module.py": "    import pkg.model\n    pkg.model.double\n" + must_not_run,
            # not a test file
            "tests/helpers.py": "from pkg.mod import double\n\nTWO = double(1)\n",
        })

        results = runner.run_layer1(["pkg/mod.py"], str(root), max_mutations=1)
        ev = _mutation_evidence(results, "double")

        assert ev.verdict is True, ev.detail
        assert ev.detail == "0/1 survived (5 test files ran)"

    def test_related_tests_run_without_a_convention_file(self, tmp_path):
        root = _repo(tmp_path, {"tests/test_math.py": _STRONG})

        ev = _mutation_evidence(runner.run_layer1(["pkg/mod.py"], str(root), max_mutations=1), "double")

        assert ev.verdict is True, ev.detail
        assert ev.detail == "0/1 survived (1 test file ran)"

    def test_convention_file_runs_first_and_the_cap_keeps_it(self, tmp_path):
        weak = {f"tests/test_a{i:02d}.py": _WEAK for i in range(16)}
        root = _repo(tmp_path, dict(weak, **{"tests/test_mod.py": _STRONG}))

        ev = _mutation_evidence(runner.run_layer1(["pkg/mod.py"], str(root), max_mutations=1), "double")

        assert ev.verdict is True, ev.detail
        assert ev.detail == "0/1 survived (15 test files ran; the 15-file cap left out 2)"

    def test_cap_leaves_out_the_files_that_sort_last(self, tmp_path):
        weak = {f"tests/test_a{i:02d}.py": _WEAK for i in range(14)}
        root = _repo(tmp_path, dict(weak, **{"tests/test_mod.py": _WEAK, "tests/test_zz.py": _STRONG}))

        ev = _mutation_evidence(runner.run_layer1(["pkg/mod.py"], str(root), max_mutations=1), "double")

        assert ev.verdict is False
        assert ev.detail == "1/1 survived (15 test files ran; the 15-file cap left out 1)"

    def test_convention_file_comes_from_the_source_package(self, tmp_path):
        """aegis_cli/scan.py is tested by tests/unit/cli/test_cli_scan.py, not by the
        test of aegis_core/scan.py that happens to share its stem."""
        for rel in ("tests/unit/core/test_scan.py", "tests/unit/cli/test_cli_scan.py"):
            (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / rel).write_text("", encoding="utf-8")

        cli = runner._find_test_file("aegis_cli/scan.py", str(tmp_path))
        core = runner._find_test_file("aegis_core/scan.py", str(tmp_path))

        assert Path(cli).relative_to(tmp_path).as_posix() == "tests/unit/cli/test_cli_scan.py"
        assert Path(core).relative_to(tmp_path).as_posix() == "tests/unit/core/test_scan.py"

    def test_modules_of_a_namespace_package_are_found_by_path(self, tmp_path):
        root = _repo(tmp_path, {"tests/test_ns.py": _STRONG.replace("pkg.mod", "nspkg.mod")},
                     sources={"nspkg/mod.py": "def double(x):\n    return x + x\n"})

        ev = _mutation_evidence(runner.run_layer1(["nspkg/mod.py"], str(root), max_mutations=1), "double")

        assert ev.verdict is True, ev.detail
        assert ev.detail == "0/1 survived (1 test file ran)"

    def test_modules_under_a_source_root_are_found_by_package(self, tmp_path):
        root = _repo(tmp_path, {"tests/test_src.py": _STRONG.replace("pkg.mod", "srcpkg.mod")}, sources={
            "pyproject.toml": '[tool.pytest.ini_options]\npythonpath = ["src"]\n',
            "src/srcpkg/__init__.py": "",
            "src/srcpkg/mod.py": "def double(x):\n    return x + x\n",
        })

        ev = _mutation_evidence(runner.run_layer1(["src/srcpkg/mod.py"], str(root), max_mutations=1), "double")

        assert ev.verdict is True, ev.detail
        assert ev.detail == "0/1 survived (1 test file ran)"

    def test_unparseable_test_modules_are_skipped(self, tmp_path):
        root = _repo(tmp_path, {
            "tests/test_mod.py": _STRONG,
            "tests/test_broken.py": "from pkg.mod import double\n\ndef test_broken(:\n    double(1)\n",
        })

        ev = _mutation_evidence(runner.run_layer1(["pkg/mod.py"], str(root), max_mutations=1), "double")

        assert ev.detail == "0/1 survived (1 test file ran)"

    def test_unreadable_test_modules_are_skipped(self, tmp_path):
        """A test module whose text cannot be read is not selected and stops nothing."""
        root = _repo(tmp_path, {"tests/test_mod.py": _STRONG})
        try:
            os.symlink(str(root / "tests" / "missing.py"), str(root / "tests" / "test_dangling.py"))
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"cannot create a symlink here: {exc}")

        ev = _mutation_evidence(runner.run_layer1(["pkg/mod.py"], str(root), max_mutations=1), "double")

        assert ev.detail == "0/1 survived (1 test file ran)"

    def test_baseline_runs_the_same_set(self, tmp_path):
        root = _repo(tmp_path, {
            "tests/test_mod.py": _STRONG,
            "tests/test_wrong.py": """\
                from pkg.mod import double

                def test_double_wrong():
                    assert double(2) == 5
            """,
        })

        ev = _mutation_evidence(runner.run_layer1(["pkg/mod.py"], str(root)), "double")

        assert ev.verdict is False
        assert ev.detail.startswith("Baseline tests fail against the unmutated code")
        assert "test_wrong.py::test_double_wrong" in ev.detail
        assert "2 test files ran" in ev.detail
        assert ev.lines == [-1]


class TestMutantReachesEveryImporter:
    """The mutant replaces the module for the whole test run, however the tests reach it."""

    def test_mutant_is_seen_through_another_module(self, tmp_path):
        root = _repo(tmp_path, {
            "tests/test_helper.py": """\
                from pkg import helper, mod  # mod.double is reached through helper.quad

                def test_quad():
                    assert helper.quad(3) == 12
            """,
        })

        ev = mutation_tester.check(str(root / "pkg/mod.py"), "double", str(root / "tests/test_helper.py"))

        assert ev.verdict is True, ev.detail
        assert ev.detail == "0/2 survived (1 test file ran)"

    def test_tests_that_never_import_the_module_are_named(self, tmp_path):
        root = _repo(tmp_path, {"tests/test_unrelated.py": "def test_nothing():\n    assert True\n"})

        ev = mutation_tester.check(str(root / "pkg/mod.py"), "double", str(root / "tests/test_unrelated.py"))

        assert ev.verdict is False
        assert ev.detail == "2/2 survived: no test that ran imported mod.py (1 test file ran)"
        assert ev.lines == [2]

    def test_check_leaves_the_tree_as_it_found_it(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PYTHONDONTWRITEBYTECODE", raising=False)
        root = _repo(tmp_path, {"tests/test_mod.py": _WEAK})
        before = _snapshot(root)

        ev = mutation_tester.check(str(root / "pkg/mod.py"), "double", str(root / "tests/test_mod.py"))

        assert ev.detail == "2/2 survived (1 test file ran)"
        assert _snapshot(root) == before

    def test_unknown_function_fails_closed(self, tmp_path):
        root = _repo(tmp_path, {"tests/test_mod.py": _STRONG})

        ev = mutation_tester.check(str(root / "pkg/mod.py"), "triple", str(root / "tests/test_mod.py"))

        assert ev.verdict is False
        assert ev.detail == "could not assess: no function named triple in mod.py"

    def test_no_test_files_fails_closed_without_running_pytest(self, tmp_path, monkeypatch):
        root = _repo(tmp_path, {})
        spawns = install_fake_popen(monkeypatch)

        ev = mutation_tester.check(str(root / "pkg/mod.py"), "double", [])

        assert ev.verdict is False
        assert ev.detail == "could not assess: no test file to run"
        assert spawns == []

    def test_source_that_cannot_be_regenerated_fails_closed(self, tmp_path, monkeypatch):
        root = _repo(tmp_path, {"tests/test_mod.py": _STRONG})

        def unparse(tree):
            raise RecursionError("too deep")

        monkeypatch.setattr(mutation_tester.ast, "unparse", unparse)
        ev = mutation_tester.check(str(root / "pkg/mod.py"), "double", str(root / "tests/test_mod.py"))

        assert ev.verdict is False
        assert ev.detail == "could not assess: cannot regenerate mod.py: RecursionError: too deep"
        assert ev.lines == [-1]


_CLASSES = """\
    class Base:
        def verify(self, x):
            return x


    class Doubler(Base):
        def verify(self, x):
            return x + x


    def outer(x):
        def inner(y):
            return y * 3
        return inner(x)
"""
_DOUBLER_TEST = """\
    from pkg.mod import Doubler

    def test_doubler_verify():
        assert Doubler().verify(2) == 4
"""


class TestQualifiedTargets:
    """A method is targeted as Class.method and a nested function as outer.inner, each once,
    so the mutants land in the definition that changed, not in the first one with its name."""

    def test_discovery_qualifies_methods_and_nested_functions(self, tmp_path):
        mod = tmp_path / "mod.py"
        mod.write_text(textwrap.dedent(_CLASSES), encoding="utf-8")

        found = runner._discover_functions(str(mod))

        assert sorted(found) == ["Base.verify", "Doubler.verify", "outer", "outer.inner"]

    def test_discovery_lists_a_redefined_function_once(self, tmp_path):
        mod = tmp_path / "mod.py"
        mod.write_text(textwrap.dedent("""\
            import sys

            if sys.platform == "win32":
                def tidy(text):
                    return text.strip()
            else:
                def tidy(text):
                    return text.rstrip()
        """), encoding="utf-8")

        assert runner._discover_functions(str(mod)) == ["tidy"]

    def test_discovery_selects_the_method_on_the_changed_lines(self, tmp_path):
        mod = tmp_path / "mod.py"
        mod.write_text(textwrap.dedent(_CLASSES), encoding="utf-8")

        assert runner._discover_functions(str(mod), target_lines={8}) == ["Doubler.verify"]

    def test_a_qualified_method_is_the_one_mutated(self, tmp_path):
        root = _repo(tmp_path, {"tests/test_mod.py": _DOUBLER_TEST}, sources={"pkg/mod.py": _CLASSES})
        args = (str(root / "pkg/mod.py"),)
        test = str(root / "tests/test_mod.py")

        doubler = mutation_tester.check(*args, "Doubler.verify", test)
        base = mutation_tester.check(*args, "Base.verify", test)

        assert (doubler.verdict, doubler.detail) == (True, "0/2 survived (1 test file ran)")
        assert (base.verdict, base.detail, base.lines) == (False, "1/1 survived (1 test file ran)", [3])

    def test_a_nested_function_is_mutated_through_its_outer_name(self, tmp_path):
        root = _repo(tmp_path, {"tests/test_mod.py": """\
            from pkg.mod import outer

            def test_outer():
                assert outer(2) == 6
        """}, sources={"pkg/mod.py": _CLASSES})

        ev = mutation_tester.check(str(root / "pkg/mod.py"), "outer.inner", str(root / "tests/test_mod.py"))

        assert (ev.verdict, ev.detail) == (True, "0/3 survived (1 test file ran)")

    def test_an_unknown_qualified_name_fails_closed(self, tmp_path):
        root = _repo(tmp_path, {"tests/test_mod.py": _DOUBLER_TEST}, sources={"pkg/mod.py": _CLASSES})

        ev = mutation_tester.check(str(root / "pkg/mod.py"), "Tripler.verify", str(root / "tests/test_mod.py"))

        assert ev.verdict is False
        assert ev.detail == "could not assess: no function named Tripler.verify in mod.py"

    def test_layer1_reports_each_method_under_its_class(self, tmp_path):
        root = _repo(tmp_path, {"tests/test_mod.py": _DOUBLER_TEST}, sources={"pkg/mod.py": _CLASSES})

        results = runner.run_layer1(["pkg/mod.py"], str(root))
        targets = sorted(r.target.rpartition("::")[2] for r in results if r.tool == "mutation_tester")

        assert targets == ["Base.verify", "Doubler.verify", "outer"]
        assert _mutation_evidence(results, "Doubler.verify").detail == "0/2 survived (1 test file ran)"


class TestRunTimeouts:
    """T2: the per-run timeout grows with the files that run; a baseline timeout names its cause."""

    @pytest.mark.parametrize("count, timeout, note", [
        (1, 30, "1 test file ran"),
        (3, 60, "3 test files ran"),
        (17, 240, "15 test files ran; the 15-file cap left out 2"),
    ])
    def test_baseline_timeout_is_reported_with_its_limit(self, tmp_path, monkeypatch, count, timeout, note):
        root = _repo(tmp_path, {f"tests/test_t{i:02d}.py": _STRONG for i in range(count)})
        files = [str(root / f"tests/test_t{i:02d}.py") for i in range(count)]
        spawns = install_fake_popen(monkeypatch, hang=True)
        with patch("aegis_core.verification.test_runner.resolve_pytest_cmd", return_value=["pytest"]):
            ev = mutation_tester.check(str(root / "pkg/mod.py"), "double", files)

        assert ev.verdict is False
        assert ev.detail == f"could not assess (timeout): the baseline run did not finish within {timeout}s ({note})"
        assert ev.lines == [-1]
        assert [s["timeouts"][0] for s in spawns] == [timeout]
