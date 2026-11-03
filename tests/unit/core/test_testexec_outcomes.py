"""Structured receipts through the public hermetic test-execution surface."""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

from aegis_core import testexec
from tests import helpers_verified as hv


def _run(root: Path, logical: list[str]):
    home = root / "home"
    home.mkdir()
    junit = root / "junit.xml"
    argv, words = testexec.plan_command(logical, junit)
    run = testexec.run_tests(argv, root, testexec.hermetic_env(home), 10.0, junit, root / "output.txt")
    return run, junit, words


def _unittest(root: Path, body: str, *arguments: str):
    (root / "test_example.py").write_text(body, encoding="utf-8")
    return _run(root, ["python", "-m", "unittest", *arguments])


def test_direct_unittest_success_and_skip_have_a_complete_case_receipt(tmp_path):
    run, junit, logical = _unittest(tmp_path, """import unittest
class Example(unittest.TestCase):
    def test_pass(self): self.assertEqual(2 + 2, 4)
    @unittest.skip('later')
    def test_skip(self): self.fail('not run')
""")
    assert logical == ["python", "-m", "unittest"]
    assert (run.exit, run.collected, run.passed, run.failed, run.skipped) == (0, 2, 1, 0, 1)
    assert run.complete and run.evidence and run.nodeid_digest
    assert testexec.parse_junit_cases(junit) == ({"test_example.Example::test_pass"}, set(), [])


def test_direct_unittest_failure_and_subtests_retain_all_terminal_cases(tmp_path):
    run, junit, _ = _unittest(tmp_path, """import unittest
class Example(unittest.TestCase):
    def test_fail(self): self.assertEqual(1, 2)
    def test_subtests(self):
        for value in (1, 2):
            with self.subTest(value=value): self.assertEqual(value, 1)
""", "test_example")
    assert (run.exit, run.collected, run.passed, run.failed, run.skipped) == (1, 3, 1, 2, 0)
    assert run.complete and not run.evidence
    passed, failed, errors = testexec.parse_junit_cases(junit)
    assert len(passed) == 1 and len(failed) == 2 and errors == []
    assert any("value=1" in identity for identity in passed)
    assert any("value=2" in identity for identity in failed)


def test_unittest_expected_failure_is_skipped_and_unexpected_success_is_a_failure(tmp_path):
    run, _junit, _ = _unittest(tmp_path, """import unittest
class Example(unittest.TestCase):
    @unittest.expectedFailure
    def test_expected(self): self.assertEqual(1, 2)
    @unittest.expectedFailure
    def test_unexpected(self): self.assertTrue(True)
""")
    assert (run.exit, run.passed, run.failed, run.skipped) == (1, 0, 1, 1)
    assert run.complete and not run.evidence


def test_unittest_zero_tests_is_complete_but_cannot_be_evidence(tmp_path):
    run, _junit, _ = _unittest(tmp_path, "# no tests\n", "discover", "-s", ".")
    assert run.exit in (0, 5) and (run.collected, run.passed) == (0, 0)
    assert run.complete and not run.evidence


def test_unittest_collection_failure_has_a_structured_error_and_never_evidence(tmp_path):
    run, junit, _ = _unittest(tmp_path, "def broken(\n")
    assert run.exit == 1 and run.failed == 1
    assert not run.complete and not run.evidence
    assert testexec.parse_junit_cases(junit)[2]


@pytest.mark.parametrize("all_skipped", [True, False])
def test_skipped_subtests_do_not_add_a_passing_parent_case(tmp_path, all_skipped):
    body = """import unittest
class Example(unittest.TestCase):
    def test_subtests(self):
        for value in (1, 2):
            with self.subTest(value=value):
                if ALL_SKIPPED or value == 2: self.skipTest('later')
                self.assertTrue(True)
""".replace("ALL_SKIPPED", repr(all_skipped))
    run, _junit, _ = _unittest(tmp_path, body)
    assert (run.exit, run.collected, run.passed, run.skipped) == (0, 2, 0 if all_skipped else 1,
                                                               2 if all_skipped else 1)
    assert run.complete and run.evidence == (not all_skipped)


def test_unittest_class_fixture_error_cannot_certify_an_incomplete_suite(tmp_path):
    run, junit, _ = _unittest(tmp_path, """import unittest
class Example(unittest.TestCase):
    @classmethod
    def setUpClass(cls): raise RuntimeError('fixture failed')
    def test_not_run(self): self.assertTrue(True)
""")
    assert run.exit in (1, 5) and run.failed == 1
    assert not run.complete and not run.evidence
    assert testexec.parse_junit_cases(junit)[2]


def test_a_wrapper_last_pytest_summary_without_junit_is_diagnostic_only(tmp_path):
    script = tmp_path / "wrapper.py"
    script.write_text("print('2 failed in 0.01s')\nprint('3 passed in 0.01s')\n", encoding="utf-8")
    run, _junit, _ = _run(tmp_path, ["python", str(script)])
    assert (run.exit, run.passed) == (0, 3)
    assert not run.complete and not run.evidence
    assert run.as_dict()["complete"] is False


@pytest.mark.parametrize("separate", [False, True])
def test_execution_can_separate_machine_output_from_diagnostics(tmp_path, separate):
    output, errors = tmp_path / "output.log", tmp_path / "stderr.log"
    options = {"stderr_output": errors} if separate else {}
    run = testexec.run_tests([sys.executable, "-c", "import sys; print('{}'); print('diagnostic', file=sys.stderr)"],
        tmp_path, testexec.hermetic_env(tmp_path), 10, tmp_path / "unused.xml", output, **options)
    assert run.exit == 0 and not run.evidence
    if separate:
        assert output.read_text() == "{}\n" and errors.read_text() == "diagnostic\n"
    else:
        assert set(output.read_text().splitlines()) == {"{}", "diagnostic"} and not errors.exists()


def test_wrapper_placeholder_expands_only_execution_argv_and_complete_report_is_evidence(tmp_path):
    script = tmp_path / "wrapper.py"
    script.write_text("import pathlib, sys\npathlib.Path(sys.argv[1]).write_text(\""
                      "<testsuite tests='2' failures='0' errors='0' skipped='0'>"
                      "<testcase classname='python' name='pass'/>"
                      "<testcase classname='native' name='pass'/></testsuite>\")\n", encoding="utf-8")
    logical = [sys.executable, str(script), "{junit}"]
    run, _junit, words = _run(tmp_path, logical)
    assert words == logical and testexec.command_digest(words) == testexec.command_digest(logical)
    assert (run.exit, run.collected, run.passed, run.failed) == (0, 2, 2, 0)
    assert run.complete and run.evidence


@pytest.mark.parametrize("arguments", [
    ["wrapper.py", "-m", "unittest"],
    ["-c", "print('wrapper')", "-m", "unittest"],
    ["wrapper.py", "-m", "pytest"],
    ["--unknown-python-option", "-m", "unittest"],
    ["-", "-m", "pytest"],
    ["--", "wrapper.py", "-m", "pytest"],
])
def test_module_words_in_wrapper_arguments_do_not_choose_an_automatic_adapter(tmp_path, arguments):
    logical = ["python", *arguments]
    argv, words = testexec.plan_command(logical, tmp_path / "junit.xml")
    assert words == logical and argv[4:] == arguments
    assert testexec.pytest_args(logical) is None


@pytest.mark.parametrize("flags", [["-W", "ignore", "-X", "dev"], ["-W", "-m"]])
def test_direct_unittest_with_interpreter_flags_still_has_a_complete_report(tmp_path, flags):
    (tmp_path / "test_example.py").write_text("import unittest\nclass Example(unittest.TestCase):\n"
                                            "    def test_pass(self): self.assertTrue(True)\n", encoding="utf-8")
    run, _junit, _ = _run(tmp_path, ["python", *flags, "-m", "unittest"])
    assert run.exit == 0 and run.passed == 1 and run.complete and run.evidence


@pytest.mark.parametrize("report", [
    "<testsuite>",
    "<testsuite tests='2'><testcase name='only_one'/></testsuite>",
    "<testsuite tests='1' failures='1'><testcase name='wrong_failure_count'/></testsuite>",
    "<testsuite tests='2'><testcase name='duplicate'/><testcase name='duplicate'/></testsuite>",
    "<testsuite tests='1'><testcase name='conflict'><failure/><skipped/></testcase></testsuite>",
    "<notjunit><testcase name='wrong_root'/></notjunit>",
])
def test_malformed_or_incomplete_wrapper_reports_cannot_be_evidence(tmp_path, report):
    (tmp_path / "junit.xml").write_text(report, encoding="utf-8")
    run, _junit, _ = _run(tmp_path, ["python", "-c", "print('1 passed in 0.01s')"])
    assert run.exit == 0 and not run.complete and not run.evidence
    assert testexec.parse_junit_cases(tmp_path / "junit.xml") == (set(), set(), [])


def test_a_reported_failure_cannot_be_evidence_even_with_exit_zero(tmp_path):
    (tmp_path / "junit.xml").write_text("<testsuite tests='2' failures='1'>"
                                        "<testcase name='pass'/><testcase name='fail'><failure/>"
                                        "</testcase></testsuite>", encoding="utf-8")
    run, _junit, _ = _run(tmp_path, ["python", "-c", "pass"])
    assert (run.exit, run.passed, run.failed) == (0, 1, 1)
    assert not run.evidence


@pytest.mark.parametrize("terminal", ["", "<failure/>"])
def test_normalized_duplicate_case_identities_cannot_be_a_complete_receipt(tmp_path, terminal):
    report = ("<testsuite tests='2'><testcase classname='suite' name='test'/>"
              f"<testcase classname=' suite ' name=' test '>{terminal}</testcase></testsuite>")
    (tmp_path / "junit.xml").write_text(report, encoding="utf-8")
    run, _junit, _ = _run(tmp_path, ["python", "-c", "pass"])
    assert (run.exit, run.collected, run.passed, run.failed) == (0, 2, 1 if terminal else 2, 1 if terminal else 0)
    assert run.nodeid_digest
    assert not run.complete and not run.evidence


@pytest.mark.parametrize("runner,expected", [
    (hv.PASSING, (0, 3, 3, 0)),
    (hv.FAILING, (1, 3, 2, 1)),
    (hv.NO_TESTS, (5, 0, 0, 0)),
    (hv.ZERO_PASSED, (0, 0, 0, 0)),
])
def test_verified_helper_runners_emit_explicit_complete_reports(tmp_path, runner, expected):
    (tmp_path / "run_checks.py").write_text(runner, encoding="utf-8")
    run, _junit, _ = _run(tmp_path, ["python", "run_checks.py", "{junit}"])
    assert (run.exit, run.collected, run.passed, run.failed) == expected
    assert run.complete
    assert run.evidence == (expected == (0, 3, 3, 0))


def test_a_junit_report_link_cannot_be_evidence(tmp_path):
    target = tmp_path / "outside.xml"
    target.write_text("<testsuite tests='1'><testcase name='pass'/></testsuite>", encoding="utf-8")
    try:
        (tmp_path / "junit.xml").symlink_to(target)
    except OSError:
        pytest.skip("report-link regression requires symlink support")
    run, _junit, _ = _run(tmp_path, ["python", "-c", "print('1 passed in 0.01s')"])
    assert not run.complete and not run.evidence


@pytest.mark.parametrize("report", [
    "<testsuites>" + "<testsuite tests='1'>" * 129 + "<testcase name='pass'/>"
    + "</testsuite>" * 129 + "</testsuites>",
    "<testsuite tests='1'><testcase name='pass'/>" + "<property/>" * 100_000 + "</testsuite>",
], ids=["depth", "elements"])
def test_junit_structure_limits_cannot_be_bypassed_by_a_small_byte_count(tmp_path, report):
    (tmp_path / "junit.xml").write_text(report, encoding="utf-8")
    run, _junit, _ = _run(tmp_path, ["python", "-c", "print('1 passed in 0.01s')"])
    assert not run.complete and not run.evidence
