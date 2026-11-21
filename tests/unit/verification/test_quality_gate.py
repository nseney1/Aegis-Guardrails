from pathlib import Path
"""TDD Gate 1 tests for test quality gate (Phase 2H).

Verifies the deterministic AST and file-matching quality gate checks:
- check_assertion_density: ensures all test functions have assert statements
- check_no_bare_pass: detects placeholder/stub tests using bare pass or ellipsis
- both skip pytest fixtures named test_* (#1)
"""
import sys
import textwrap

import pytest

from aegis_core.verification import quality_gate

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
sys.path.insert(0, REPO_ROOT)

from aegis_core.verification import ToolEvidence

from aegis_core.verification.quality_gate import check_assertion_density, check_no_bare_pass


@pytest.mark.parametrize("source", [
    "def test_real():\n    assert True\n",
    "def test_missing():\n    value = 1\n",
    "def test_stub():\n    pass\n",
    'async def test_stub():\n    "docstring"\n    ...\n',
    "@pytest.fixture\ndef test_fixture():\n    pass\n",
    "if HAVE_ENV:\n    def test_env():\n        assert True\n"
    "else:\n    def test_env():\n        pytest.skip('unavailable')\n",
])
def test_paired_quality_evidence_matches_public_wrappers(tmp_path, source):
    path = tmp_path / "test_pair.py"
    path.write_text(source, encoding="utf-8")
    filename = str(path)
    assert quality_gate.check_test_quality(filename) == (
        check_assertion_density(filename), check_no_bare_pass(filename),
    )


@pytest.mark.parametrize("name", [
    "check_test_quality", "check_assertion_density", "check_no_bare_pass",
])
def test_quality_public_checks_preserve_input_errors(tmp_path, name):
    filename = str(tmp_path / "test_invalid.py")
    check = getattr(quality_gate, name)
    with pytest.raises(FileNotFoundError) as error:
        check(filename)
    assert error.value.filename == filename
    Path(filename).write_text("def test_broken(:\n", encoding="utf-8")
    with pytest.raises(SyntaxError) as error:
        check(filename)
    assert (error.value.filename, error.value.lineno) == (filename, 1)


class TestCheckAssertionDensity:
    """Test assertion density verification on test files."""

    def test_assertion_density_passes_when_all_tests_have_asserts(self, tmp_path):
        """Happy path: test file where every test function contains at least one assert."""
        test_file = tmp_path / "test_sample_good.py"
        test_file.write_text(textwrap.dedent("""\
            def test_addition():
                result = 1 + 1
                assert result == 2

            def test_multiplication():
                product = 3 * 4
                assert product == 12
                assert product > 0
        """))

        result = check_assertion_density(str(test_file))

        assert isinstance(result, ToolEvidence)
        assert result.tool == "assertion_density"
        assert result.verdict is True
        assert result.target == str(test_file)
        assert len(result.lines) == 0
        assert "pass" in result.detail.lower() or "density" in result.detail.lower() or "all" in result.detail.lower()

    def test_assertion_density_fails_when_test_lacks_assert(self, tmp_path):
        """Sad path: test file containing a test function without any assert statement."""
        test_file = tmp_path / "test_sample_missing_assert.py"
        test_file.write_text(textwrap.dedent("""\
            def test_valid():
                assert True

            def test_missing_assertion():
                x = 10
                y = 20
                total = x + y
        """))

        result = check_assertion_density(str(test_file))

        assert isinstance(result, ToolEvidence)
        assert result.tool == "assertion_density"
        assert result.verdict is False
        assert result.target == str(test_file)
        assert "test_missing_assertion" in result.detail
        assert len(result.lines) > 0

    def test_assertion_density_ignores_non_test_helper_functions(self, tmp_path):
        """Edge case: non-test helper functions without assert statements should not cause failure."""
        test_file = tmp_path / "test_with_helpers.py"
        test_file.write_text(textwrap.dedent("""\
            def build_fixture_data():
                return {"user": "alice", "active": True}

            def test_using_helper():
                data = build_fixture_data()
                assert data["user"] == "alice"
        """))

        result = check_assertion_density(str(test_file))

        assert isinstance(result, ToolEvidence)
        assert result.tool == "assertion_density"
        assert result.verdict is True

    def test_assertion_density_inspects_class_test_methods(self, tmp_path):
        """Edge case: test methods inside a test class should also be verified for assertions."""
        test_file = tmp_path / "test_class_suite.py"
        test_file.write_text(textwrap.dedent("""\
            class TestSuite:
                def test_valid_method(self):
                    assert 1 == 1

                def test_empty_method(self):
                    value = 42
        """))

        result = check_assertion_density(str(test_file))

        assert isinstance(result, ToolEvidence)
        assert result.tool == "assertion_density"
        assert result.verdict is False
        assert "test_empty_method" in result.detail

    def test_assertion_density_recognizes_nested_asserts(self, tmp_path):
        """Edge case: assert statement nested in context manager, try block, or conditional counts."""
        test_file = tmp_path / "test_nested_asserts.py"
        test_file.write_text(textwrap.dedent("""\
            def test_nested_in_with():
                with open("/dev/null") as f:
                    assert f is not None

            def test_nested_in_condition():
                x = 5
                if x > 0:
                    assert x == 5
        """))

        result = check_assertion_density(str(test_file))

        assert isinstance(result, ToolEvidence)
        assert result.tool == "assertion_density"
        assert result.verdict is True

    def test_assertion_density_recognizes_pytest_raises(self, tmp_path):
        """pytest.raises is an assertion-equivalent and should pass density check."""
        test_file = tmp_path / "test_raises.py"
        test_file.write_text(textwrap.dedent("""\
            import pytest

            def test_raises_value_error():
                with pytest.raises(ValueError):
                    int("not_a_number")

            def test_raises_with_match():
                with pytest.raises(TypeError, match="unsupported"):
                    1 + "string"
        """))

        result = check_assertion_density(str(test_file))

        assert isinstance(result, ToolEvidence)
        assert result.tool == "assertion_density"
        assert result.verdict is True

    def test_assertion_density_recognizes_the_call_form_of_pytest_raises(self, tmp_path):
        """pytest.raises(E, func, *args) and pytest.warns(W, func) assert without a `with` (b1-verify review)."""
        test_file = tmp_path / "test_raises_call.py"
        test_file.write_text(textwrap.dedent("""\
            import warnings
            import pytest

            def test_raises_call():
                pytest.raises(ValueError, int, "x")

            def test_warns_call():
                pytest.warns(UserWarning, warnings.warn, "w")

            def test_deprecated_call_form():
                pytest.deprecated_call(warnings.warn, "d", DeprecationWarning)
        """))
        result = check_assertion_density(str(test_file))
        assert result.verdict is True, result.detail

    def test_a_bare_pytest_raises_object_is_not_an_assertion(self, tmp_path):
        test_file = tmp_path / "test_raises_object.py"
        test_file.write_text(textwrap.dedent("""\
            import pytest

            def test_builds_but_never_enters():
                pytest.raises(ValueError)
        """))
        result = check_assertion_density(str(test_file))
        assert (result.verdict, result.detail) == (False, "Tests lacking assertions: test_builds_but_never_enters")

    def test_assertion_density_recognizes_pytest_fail(self, tmp_path):
        """pytest.fail is an assertion-equivalent and should pass density check."""
        test_file = tmp_path / "test_fail.py"
        test_file.write_text(textwrap.dedent("""\
            import pytest

            def test_conditional_fail():
                value = compute_something()
                if value < 0:
                    pytest.fail("Value must not be negative")

            def compute_something():
                return 1
        """))

        result = check_assertion_density(str(test_file))

        assert isinstance(result, ToolEvidence)
        assert result.tool == "assertion_density"
        assert result.verdict is True

    def test_assertion_density_recognizes_unittest_assertions(self, tmp_path):
        """self.assert* (unittest style) should pass density check."""
        test_file = tmp_path / "test_unittest_style.py"
        test_file.write_text(textwrap.dedent("""\
            import unittest

            class TestMath(unittest.TestCase):
                def test_addition(self):
                    self.assertEqual(1 + 1, 2)

                def test_truth(self):
                    self.assertTrue(True)
                    self.assertFalse(False)
        """))

        result = check_assertion_density(str(test_file))

        assert isinstance(result, ToolEvidence)
        assert result.tool == "assertion_density"
        assert result.verdict is True

class TestCheckNoBarePass:
    """Test detection of bare pass and ellipsis test stubs."""

    def test_no_bare_pass_passes_for_real_test_functions(self, tmp_path):
        """Happy path: real test functions with substantive implementation pass."""
        test_file = tmp_path / "test_real_code.py"
        test_file.write_text(textwrap.dedent("""\
            def test_real_behavior():
                items = [1, 2, 3]
                items.append(4)
                assert len(items) == 4
        """))

        result = check_no_bare_pass(str(test_file))

        assert isinstance(result, ToolEvidence)
        assert result.tool == "no_bare_pass"
        assert result.verdict is True
        assert result.target == str(test_file)
        assert len(result.lines) == 0

    def test_no_bare_pass_fails_for_pass_body(self, tmp_path):
        """Sad path: test function whose body is only 'pass' must fail."""
        test_file = tmp_path / "test_bare_pass.py"
        test_file.write_text(textwrap.dedent("""\
            def test_stub_pass():
                pass
        """))

        result = check_no_bare_pass(str(test_file))

        assert isinstance(result, ToolEvidence)
        assert result.tool == "no_bare_pass"
        assert result.verdict is False
        assert result.target == str(test_file)
        assert "test_stub_pass" in result.detail
        assert len(result.lines) > 0

    def test_no_bare_pass_fails_for_ellipsis_body(self, tmp_path):
        """Sad path: test function whose body is only '...' (Ellipsis) must fail."""
        test_file = tmp_path / "test_bare_ellipsis.py"
        test_file.write_text(textwrap.dedent("""\
            def test_stub_ellipsis():
                ...
        """))

        result = check_no_bare_pass(str(test_file))

        assert isinstance(result, ToolEvidence)
        assert result.tool == "no_bare_pass"
        assert result.verdict is False
        assert result.target == str(test_file)
        assert "test_stub_ellipsis" in result.detail
        assert len(result.lines) > 0

    def test_no_bare_pass_fails_for_docstring_with_pass_or_ellipsis(self, tmp_path):
        """Edge case: test functions with a docstring followed solely by pass or ellipsis must fail."""
        test_file = tmp_path / "test_docstring_stubs.py"
        test_file.write_text(textwrap.dedent('''\
            def test_docstring_pass():
                """TODO: implement this test."""
                pass

            def test_docstring_ellipsis():
                """Placeholder for future coverage."""
                ...
        '''))

        result = check_no_bare_pass(str(test_file))

        assert isinstance(result, ToolEvidence)
        assert result.tool == "no_bare_pass"
        assert result.verdict is False
        assert "test_docstring_pass" in result.detail or "test_docstring_ellipsis" in result.detail
        assert len(result.lines) >= 1

    def test_no_bare_pass_allows_pass_in_subordinate_blocks(self, tmp_path):
        """Edge case: a pass inside a try/except or if block in a non-empty test is allowed."""
        test_file = tmp_path / "test_pass_in_flow.py"
        test_file.write_text(textwrap.dedent("""\
            def test_exception_handling():
                try:
                    int("not-an-int")
                except ValueError:
                    pass
                assert True
        """))

        result = check_no_bare_pass(str(test_file))

        assert isinstance(result, ToolEvidence)
        assert result.tool == "no_bare_pass"
        assert result.verdict is True

    def test_no_bare_pass_ignores_non_test_functions(self, tmp_path):
        """Edge case: non-test helper function with bare pass is not flagged as a test stub."""
        test_file = tmp_path / "test_with_empty_helper.py"
        test_file.write_text(textwrap.dedent("""\
            def noop_callback():
                pass

            def test_something():
                assert noop_callback() is None
        """))

        result = check_no_bare_pass(str(test_file))

        assert isinstance(result, ToolEvidence)
        assert result.tool == "no_bare_pass"
        assert result.verdict is True


class TestFixturesAreNotTests:
    """A fixture named test_* is never run as a test, so neither check judges it (#1)."""

    SOURCE = textwrap.dedent("""\
        import pytest
        from pytest import fixture

        @pytest.fixture
        def test_workspace(tmp_path):
            return tmp_path

        @pytest.fixture(scope="module")
        def test_env():
            pass

        @fixture
        def test_db():
            ...

        def test_real(test_workspace):
            assert test_workspace
    """)

    def test_density_skips_fixtures(self, tmp_path):
        test_file = tmp_path / "test_fixtures.py"
        test_file.write_text(self.SOURCE)
        assert check_assertion_density(str(test_file)).verdict is True

    def test_bare_pass_skips_fixtures(self, tmp_path):
        test_file = tmp_path / "test_fixtures.py"
        test_file.write_text(self.SOURCE)
        assert check_no_bare_pass(str(test_file)).verdict is True

    def test_a_plain_test_with_the_same_body_is_still_a_stub(self, tmp_path):
        test_file = tmp_path / "test_stub.py"
        test_file.write_text("def test_env():\n    pass\n")
        result = check_no_bare_pass(str(test_file))
        assert (result.verdict, result.detail) == (False, "Bare pass/ellipsis stubs: test_env")


class TestSkipIsNotAnAssertion:
    """A skip or xfail declares that a test did not run; it asserts nothing (b1-verify review).

    pytest.fail / self.fail still count: they fail the test on the path they guard.
    """

    def _density(self, tmp_path, source: str):
        test_file = tmp_path / "test_skips.py"
        test_file.write_text(textwrap.dedent(source))
        return check_assertion_density(str(test_file))

    def test_skip_only_stubs_lack_assertions(self, tmp_path):
        result = self._density(tmp_path, """\
            import pytest
            import unittest

            def test_unwritten():
                pytest.skip("TODO")

            def test_later():
                pytest.xfail("later")

            class TestCase(unittest.TestCase):
                def test_pending(self):
                    self.skipTest("pending")
        """)
        assert (result.verdict, result.detail) == (
            False, "Tests lacking assertions: test_unwritten, test_later, test_pending"
        )

    def test_a_conditional_skip_does_not_stand_in_for_an_assertion(self, tmp_path):
        result = self._density(tmp_path, """\
            import pytest

            def test_guarded_stub():
                if True:
                    pytest.skip("TODO")
                value = 1 + 1
        """)
        assert (result.verdict, result.detail) == (False, "Tests lacking assertions: test_guarded_stub")

    def test_a_skip_guard_before_a_real_assertion_passes(self, tmp_path):
        result = self._density(tmp_path, """\
            import shutil
            import pytest

            def test_needs_git():
                if shutil.which("git") is None:
                    pytest.skip("git not installed")
                assert shutil.which("git")
        """)
        assert result.verdict is True, result.detail

    def test_unittest_self_fail_is_an_assertion(self, tmp_path):
        result = self._density(tmp_path, """\
            import unittest

            class TestCase(unittest.TestCase):
                def test_guard(self):
                    if 1 + 1 != 2:
                        self.fail("arithmetic broke")
        """)
        assert result.verdict is True, result.detail

    def test_an_environment_placeholder_for_a_real_test_passes(self, tmp_path):
        """`if HAVE_X: def test_a(): <real> else: def test_a(): pytest.skip(...)` judges only the real one."""
        result = self._density(tmp_path, """\
            import pytest

            try:
                import hypothesis
            except ImportError:
                hypothesis = None

            if hypothesis is not None:
                def test_property():
                    assert hypothesis
            else:
                def test_property():
                    pytest.skip("hypothesis is not installed")
        """)
        assert result.verdict is True, result.detail

    def test_the_real_branch_of_a_placeholder_pair_is_still_judged(self, tmp_path):
        result = self._density(tmp_path, """\
            import pytest

            if False:
                def test_property():
                    x = 1
            else:
                def test_property():
                    pytest.skip("not here")
        """)
        assert (result.verdict, result.lines) == (False, [4])

    def test_two_skip_only_twins_are_both_stubs(self, tmp_path):
        """The exemption needs a real twin: two placeholders do not excuse each other (b1-verify review)."""
        result = self._density(tmp_path, """\
            import sys
            import pytest

            if sys.platform == "linux":
                def test_a():
                    pytest.skip("not yet")
            else:
                def test_a():
                    pytest.skip("not yet")
        """)
        assert (result.verdict, result.lines) == (False, [5, 8])

    def test_a_placeholder_whose_twin_skips_then_asserts_is_exempt(self, tmp_path):
        result = self._density(tmp_path, """\
            import shutil
            import pytest

            if shutil.which("git"):
                def test_git():
                    if not shutil.which("git-lfs"):
                        pytest.skip("git-lfs missing")
                    assert shutil.which("git-lfs")
            else:
                def test_git():
                    pytest.skip("git missing")
        """)
        assert result.verdict is True, result.detail

    def test_a_skip_only_test_without_a_same_name_twin_is_a_stub(self, tmp_path):
        result = self._density(tmp_path, """\
            import pytest

            if False:
                def test_other():
                    assert True
            else:
                def test_property():
                    pytest.skip("no twin")
        """)
        assert (result.verdict, result.detail) == (False, "Tests lacking assertions: test_property")
