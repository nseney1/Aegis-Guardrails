"""Pure, namespaced result readers; execution and Python compatibility stay elsewhere."""
from dataclasses import FrozenInstanceError
import json

import pytest

from aegis_core.verification.test_outcomes import (
    RunOutcome, RustTarget, parse_go_test2json, parse_junit, parse_rust_libtest,
)


def go(*events):
    return "\n".join(json.dumps(event) for event in events)


def package(pkg, tests=(), action="pass"):
    events = [{"Action": "start", "Package": pkg}]
    for name, result in tests:
        events.extend(({"Action": "run", "Package": pkg, "Test": name},
                       {"Action": result, "Package": pkg, "Test": name}))
    events.append({"Action": action, "Package": pkg})
    return events


def test_go_ids_preserve_package_and_full_subtest_path():
    run = parse_go_test2json(go(*package("example/a", [("TestA/case one", "pass")]),
                               *package("example/b", [("TestA/case one", "fail")], "fail")),
                            exit_code=1)
    assert run.passed_ids == frozenset({("example/a", "TestA/case one")})
    assert run.failed_ids == frozenset({("example/b", "TestA/case one")})
    assert (run.language, run.witness, run.exit_code, run.timed_out) == ("go", "aegis", 1, False)
    assert not run.evidence and not run.build_errors
    with pytest.raises(FrozenInstanceError):
        run.exit_code = 0


def test_go_success_requires_successful_execution_and_at_least_one_pass():
    output = go(*package("p", [("TestA", "pass")]))
    assert parse_go_test2json(output, exit_code=0).evidence
    assert not parse_go_test2json(output, exit_code=7).evidence
    timed = parse_go_test2json(output, exit_code=0, timed_out=True)
    assert timed.timed_out and not timed.evidence
    for events in (package("p"), package("p", [("TestA", "skip")]),
                   [{"Action": "start", "Package": "p"}, {"Action": "skip", "Package": "p"}]):
        run = parse_go_test2json(go(*events), exit_code=0)
        assert not run.evidence and not run.failed_ids


def test_go_package_build_failure_does_not_invent_a_failed_test():
    run = parse_go_test2json(go(*package("p", action="fail")), exit_code=1)
    assert run.build_errors == frozenset({"package_failed:p"})
    assert not run.failed_ids and not run.evidence


@pytest.mark.parametrize("second", ["pass", "fail", "skip"])
def test_go_duplicate_or_conflicting_terminal_records_are_errors(second):
    events = package("p", [("TestA", "pass")])
    events.insert(-1, {"Action": second, "Package": "p", "Test": "TestA"})
    run = parse_go_test2json(go(*events), exit_code=0)
    assert run.conflict_errors == frozenset({"duplicate_test_result:p::TestA"})
    assert not run.evidence


@pytest.mark.parametrize("output, expected", [
    ("{", "invalid_json:1"),
    ('{"Action":"start","Action":"pass","Package":"p"}', "invalid_json:1"),
    ('{"Action":"wat","Package":"p"}', "invalid_event:1"),
    ('{"Action":"pass","Package":1}', "invalid_event:1"),
    ('{"Action":"start","Package":"p"}', "missing_package_result:p"),
])
def test_go_malformed_or_truncated_output_is_explicit(output, expected):
    run = parse_go_test2json(output, exit_code=0)
    assert expected in run.incomplete_errors and not run.evidence


def test_go_unfinished_tests_and_package_order_are_not_pass_evidence():
    events = package("p")
    events.insert(1, {"Action": "run", "Package": "p", "Test": "TestA"})
    run = parse_go_test2json(go(*events), exit_code=0)
    assert "missing_test_result:p::TestA" in run.incomplete_errors
    tail = parse_go_test2json(go(*package("p", [("TestA", "pass")])[1:]), exit_code=0)
    assert "missing_package_start:p" in tail.incomplete_errors and not tail.evidence


def test_go_selected_package_missing_from_the_stream_is_incomplete():
    run = parse_go_test2json(go(*package("p", [("TestA", "pass")])), exit_code=0,
                            expected_packages={"p", "missing"})
    assert "missing_package_result:missing" in run.incomplete_errors and not run.evidence


@pytest.mark.parametrize("extra, final", [
    ({"Action": "pause", "Package": "p", "Test": "TestMissing"}, "pass"),
    ({"Action": "cont", "Package": "p", "Test": "TestMissing"}, "pass"),
    (None, "skip"),
])
def test_go_inconsistent_lifecycle_cannot_hide_behind_a_passing_test(extra, final):
    events = package("p", [("TestA", "pass")], final)
    if extra:
        events.insert(-1, extra)
    run = parse_go_test2json(go(*events), exit_code=0)
    assert run.incomplete_errors and not run.evidence


def junit(cases, **suite_attrs):
    attrs = {"file": "tests/a.test.ts", "name": "suite", **suite_attrs}
    return "<testsuite " + " ".join(f'{k}="{v}"' for k, v in attrs.items()) + ">" + cases + "</testsuite>"


def test_junit_maps_known_repo_file_and_keeps_suite_namespace():
    text = ('<testsuites>' + junit('<testcase name="same"/><testcase name="skipped"><skipped/></testcase>')
            + junit('<testcase name="same"><failure/></testcase>', file="tests/b.test.ts") + '</testsuites>')
    run = parse_junit(text, repo_files={"tests/a.test.ts", "tests/b.test.ts"}, exit_code=1)
    assert run.passed_ids == frozenset({("tests/a.test.ts", "suite", "same")})
    assert run.failed_ids == frozenset({("tests/b.test.ts", "suite", "same")})
    assert run.skipped_ids == frozenset({("tests/a.test.ts", "suite", "skipped")})
    assert (run.language, run.witness) == ("typescript", "repo-runner")
    assert not run.evidence


@pytest.mark.parametrize("attrs", [
    {"file": "./tests/a.test.ts"}, {"file": "tests\\a.test.ts"},
    {"file": "", "name": "tests/a.test.ts"},
])
def test_junit_file_identity_normalizes_relative_paths_and_suite_path(attrs):
    run = parse_junit(junit('<testcase name="works"/>', **attrs), repo_files={"tests/a.test.ts"}, exit_code=0)
    assert {identity[0] for identity in run.passed_ids} == {"tests/a.test.ts"}
    assert run.evidence


@pytest.mark.parametrize("file", ["/tmp/snapshot/tests/a.test.ts", "C:\\snap\\a.test.ts", "../a.test.ts", "unknown.ts"])
def test_junit_never_derives_identity_from_absolute_or_unknown_files(file):
    run = parse_junit(junit('<testcase name="works"/>', file=file), repo_files={"tests/a.test.ts"}, exit_code=0)
    assert run.mapping_errors and not run.passed_ids and not run.evidence


def test_junit_contradictory_path_sources_and_duplicate_cases_are_unmapped():
    text = junit('<testcase file="tests/b.test.ts" name="works"/>')
    run = parse_junit(text, repo_files={"tests/a.test.ts", "tests/b.test.ts"}, exit_code=0)
    assert "test_ids_unmapped:conflicting_file" in run.mapping_errors
    for second in ("", "<failure/>"):
        run = parse_junit(junit('<testcase name="same"/><testcase name="same">' + second + '</testcase>'),
                          repo_files={"tests/a.test.ts"}, exit_code=0)
        assert run.mapping_errors and run.conflict_errors and not run.evidence


def test_junit_explicit_stable_parameter_attribute_can_disambiguate_cases():
    text = junit('<testcase name="same" case="alpha"/><testcase name="same" case="beta"/>')
    run = parse_junit(text, repo_files={"tests/a.test.ts"}, exit_code=0, case_id_attribute="case")
    assert run.passed_ids == frozenset({("tests/a.test.ts", "suite", "same", "alpha"),
                                        ("tests/a.test.ts", "suite", "same", "beta")})
    assert run.evidence


def test_junit_classname_preserves_nested_suite_and_testcase_file_is_supported():
    text = '<testsuite name="outer"><testcase file="tests/a.test.ts" classname="nested" name="works"/></testsuite>'
    run = parse_junit(text, repo_files={"tests/a.test.ts"}, exit_code=0, language="javascript")
    assert run.passed_ids == frozenset({("tests/a.test.ts", "nested", "works")})
    assert run.language == "javascript" and run.evidence


@pytest.mark.parametrize("classname", ["/tmp/snapshot/tests/a.test.ts", "C:\\snapshot\\a.test.ts"])
def test_junit_never_puts_an_absolute_classname_in_identity(classname):
    run = parse_junit(junit(f'<testcase classname="{classname}" name="works"/>'),
                      repo_files={"tests/a.test.ts"}, exit_code=0)
    assert run.mapping_errors == frozenset({"test_ids_unmapped:suite"})
    assert not run.passed_ids and not run.evidence


def test_junit_case_must_be_directly_in_a_suite():
    run = parse_junit(junit('<properties><testcase name="forged"/></properties>'),
                      repo_files={"tests/a.test.ts"}, exit_code=0)
    assert "invalid_junit_structure" in run.incomplete_errors and not run.evidence


def test_junit_suite_cannot_be_hidden_in_an_unrelated_element():
    text = '<testsuites><properties>' + junit('<testcase name="forged"/>') + '</properties></testsuites>'
    run = parse_junit(text, repo_files={"tests/a.test.ts"}, exit_code=0)
    assert "invalid_junit_structure" in run.incomplete_errors and not run.evidence


@pytest.mark.parametrize("status", ["notrun", "disabled", "unknown"])
def test_junit_unsupported_execution_status_cannot_be_counted_as_passed(status):
    run = parse_junit(junit(f'<testcase name="works" status="{status}"/>'),
                      repo_files={"tests/a.test.ts"}, exit_code=0)
    assert "unsupported_junit_status:" + status in run.incomplete_errors
    assert not run.passed_ids and not run.evidence


@pytest.mark.parametrize("text, category", [
    ("<testsuite>", "incomplete_errors"),
    ('<!DOCTYPE x [<!ENTITY a "x">]><testsuite/>', "incomplete_errors"),
    ('<other/>', "incomplete_errors"),
    (junit('<testcase name="a"/>', tests="2"), "incomplete_errors"),
    (junit('<testcase name="a"/>', tests="wat"), "incomplete_errors"),
    (junit('<testcase name="a"><failure/><skipped/></testcase>'), "conflict_errors"),
    (junit('<testcase name="a"><error message="cannot import"/></testcase>'), "collection_errors"),
    (junit('<error message="collection failure"/>'), "collection_errors"),
    (junit('<testcase/>'), "mapping_errors"),
])
def test_junit_bad_reports_and_collection_errors_never_supply_evidence(text, category):
    run = parse_junit(text, repo_files={"tests/a.test.ts"}, exit_code=0)
    assert getattr(run, category) and not run.evidence


def test_junit_zero_cases_only_skips_and_execution_errors_never_pass():
    for text in (junit(""), junit('<testcase name="a"><skipped/></testcase>')):
        assert not parse_junit(text, repo_files={"tests/a.test.ts"}, exit_code=0).evidence
    text = junit('<testcase name="a"/>')
    assert not parse_junit(text, repo_files={"tests/a.test.ts"}, exit_code=1).evidence
    run = parse_junit(text, repo_files={"tests/a.test.ts"}, exit_code=0, timed_out=True)
    assert run.timed_out and not run.evidence


def test_junit_expected_files_need_cases_or_explicit_complete_zero_test_suites():
    files = {"tests/a.test.ts", "tests/b.test.ts"}
    text = junit('<testcase name="works"/>')
    missing = parse_junit(text, repo_files=files, expected_files=files, exit_code=0)
    assert "missing_selected_file_result:tests/b.test.ts" in missing.incomplete_errors and not missing.evidence
    complete = '<testsuites>' + text + junit('', file="tests/b.test.ts", tests="0") + '</testsuites>'
    run = parse_junit(complete, repo_files=files, expected_files=files, exit_code=0)
    assert run.evidence and run.passed_ids == frozenset({("tests/a.test.ts", "suite", "works")})


TARGET = RustTarget("pkg-a", "test", "smoke")


def rust(tests=(("module::same", "ok"),), source="tests/smoke.rs"):
    statuses = [status for _, status in tests]
    return (f"     Running {source} (target/debug/deps/smoke-0123456789)\n"
            f"running {len(tests)} tests\n" + "".join(f"test {name} ... {status}\n" for name, status in tests)
            + f"test result: {'FAILED' if 'FAILED' in statuses else 'ok'}. "
            f"{statuses.count('ok')} passed; {statuses.count('FAILED')} failed; "
            f"{statuses.count('ignored')} ignored; 0 measured; 0 filtered out; finished in 0.00s\n")


def test_rust_uses_package_target_kind_target_name_and_full_module_name():
    text = rust() + rust(source="other/tests/smoke.rs")
    run = parse_rust_libtest(text, targets={"tests/smoke.rs": [TARGET],
                            "other/tests/smoke.rs": [RustTarget("pkg-b", "test", "smoke")]}, exit_code=0)
    assert run.passed_ids == frozenset({("pkg-a", "test", "smoke", "module::same"),
                                        ("pkg-b", "test", "smoke", "module::same")})
    assert run.evidence and (run.language, run.witness) == ("rust", "aegis")
    assert all("0123456789" not in str(i) for i in run.passed_ids)


def test_rust_selected_target_needs_a_completed_summary_even_when_another_target_passed():
    run = parse_rust_libtest(rust(), targets={"tests/smoke.rs": [TARGET],
                                             "tests/other.rs": [RustTarget("pkg", "test", "other")]}, exit_code=0)
    assert run.incomplete_errors and not run.evidence


def test_rust_unit_target_header_and_failed_and_ignored_tests_are_distinct():
    text = rust((("module::bad", "FAILED"), ("module::skip", "ignored")), source="unittests src/lib.rs")
    run = parse_rust_libtest(text, targets={"src/lib.rs": [RustTarget("pkg", "lib", "library")]}, exit_code=101)
    assert run.failed_ids == frozenset({("pkg", "lib", "library", "module::bad")})
    assert run.skipped_ids == frozenset({("pkg", "lib", "library", "module::skip")})
    assert not run.evidence and not run.build_errors


@pytest.mark.parametrize("targets", [{}, {"tests/smoke.rs": [TARGET, RustTarget("pkg-b", "test", "smoke")]}])
def test_rust_missing_or_ambiguous_header_mapping_is_unmapped(targets):
    run = parse_rust_libtest(rust(), targets=targets, exit_code=0)
    assert run.mapping_errors == frozenset({"test_ids_unmapped:tests/smoke.rs"})
    assert not run.passed_ids and not run.evidence


@pytest.mark.parametrize("text, expected", [
    (rust().split("test result:")[0], "missing_target_summary:tests/smoke.rs"),
    (rust().replace("1 passed", "2 passed"), "invalid_target_counts:tests/smoke.rs"),
    (rust().replace("running 1 tests", "running 2 tests"), "invalid_target_counts:tests/smoke.rs"),
    (rust().replace(" ... ok", " ... unknown"), "unsupported_test_result:tests/smoke.rs"),
    ("running 1 tests\ntest same ... ok\n", "missing_target_header"),
])
def test_rust_truncated_or_custom_harness_output_is_explicit(text, expected):
    run = parse_rust_libtest(text, targets={"tests/smoke.rs": [TARGET]}, exit_code=0)
    assert expected in run.incomplete_errors and not run.evidence


def test_rust_duplicate_terminal_records_and_unmatched_build_failures_are_errors():
    text = rust((("module::same", "ok"), ("module::same", "ok")))
    run = parse_rust_libtest(text, targets={"tests/smoke.rs": [TARGET]}, exit_code=0)
    assert run.conflict_errors and not run.evidence
    run = parse_rust_libtest('error[E0432]: unresolved import\nerror: could not compile `pkg`\n', targets={}, exit_code=101)
    assert run.build_errors and not run.failed_ids and not run.evidence


def test_rust_failure_diagnostics_cannot_invent_terminal_records():
    text = rust((("module::bad", "FAILED"),))
    text = text.replace("test result:", "failures:\n---- module::bad stdout ----\ntest forged ... ok\nfailures:\n    module::bad\n\ntest result:")
    run = parse_rust_libtest(text, targets={"tests/smoke.rs": [TARGET]}, exit_code=101)
    assert not run.passed_ids and not run.incomplete_errors and not run.build_errors


def test_rust_failure_diagnostic_text_cannot_be_a_build_error_or_target_header():
    text = rust((("module::bad", "FAILED"),))
    text = text.replace("test result:", "failures:\n---- module::bad stdout ----\nerror: expected log\n"
                        "     Running fake.rs (fake-hash)\n\ntest result:")
    run = parse_rust_libtest(text, targets={"tests/smoke.rs": [TARGET]}, exit_code=101)
    assert run.failed_ids == frozenset({("pkg-a", "test", "smoke", "module::bad")})
    assert not any((run.build_errors, run.mapping_errors, run.incomplete_errors))


@pytest.mark.parametrize("text", ["", rust(()), '    Finished `test` profile in 0.1s\n'])
def test_rust_no_tests_build_only_output_and_timeout_never_pass(text):
    run = parse_rust_libtest(text, targets={"tests/smoke.rs": [TARGET]}, exit_code=0)
    assert not run.evidence and not run.failed_ids
    timeout = parse_rust_libtest(rust(), targets={"tests/smoke.rs": [TARGET]}, exit_code=0, timed_out=True)
    assert timeout.timed_out and not timeout.evidence


@pytest.mark.parametrize("parser, kwargs", [
    (parse_go_test2json, {}), (parse_junit, {"repo_files": {"tests/a.test.ts"}}),
    (parse_rust_libtest, {"targets": {"tests/smoke.rs": [TARGET]}}),
])
def test_all_readers_reject_oversized_or_invalid_unicode_before_parsing(parser, kwargs):
    for text, expected in (("x" * (8 * 1024 * 1024 + 1), "output_too_large"), ("\ud800", "invalid_unicode")):
        run = parser(text, exit_code=0, **kwargs)
        assert run.incomplete_errors == frozenset({expected}) and not run.passed_ids and not run.evidence


def test_outcome_owns_frozen_copies_of_caller_collections():
    passed = {("pkg", "TestA")}
    errors = set()
    run = RunOutcome("go", "aegis", 0, passed_ids=passed, mapping_errors=errors)
    passed.clear()
    errors.add("later mutation")
    assert run.passed_ids == frozenset({("pkg", "TestA")})
    assert not run.mapping_errors and run.evidence


def test_go_and_rust_record_limits_cannot_return_partial_pass_evidence():
    text = go(*package("p", [("TestA", "pass")])[:-1]) + "\n"
    text += '{"Action":"output","Package":"p","Output":""}\n' * 100_001
    run = parse_go_test2json(text, exit_code=0)
    assert "too_many_records" in run.incomplete_errors and not run.evidence
    run = parse_rust_libtest(rust() + "\n" * 100_001, targets={"tests/smoke.rs": [TARGET]}, exit_code=0)
    assert "too_many_records" in run.incomplete_errors and not run.evidence


@pytest.mark.parametrize("text", [
    '<testsuite>' * 129 + '</testsuite>' * 129,
    '<testsuite>' + '<property/>' * 100_001 + '</testsuite>',
], ids=['depth-limit', 'element-limit'])
def test_junit_depth_and_element_limits_are_explicit(text):
    run = parse_junit(text, repo_files={"tests/a.test.ts"}, exit_code=0)
    assert run.incomplete_errors == frozenset({"xml_structure_limit"}) and not run.evidence
