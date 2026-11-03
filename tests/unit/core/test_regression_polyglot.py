"""Native fail-to-pass behavior through real repositories and structured public results."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys

import pytest

from aegis_core.regression import check_ci_regressions
from aegis_core.verification.language_tests import LanguageTestPlan
from aegis_core.verification.test_outcomes import RunOutcome
from tests import helpers_humangate as hg


@pytest.fixture
def project(tmp_path, monkeypatch):
    home = hg.Home(tmp_path / "home")
    for key, value in home.env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    repo = hg.Repo(tmp_path / "repo", home)
    repo.write(".aegis/config.json", '{"v":1,"ast":{"packaged_drivers":["go"]}}')
    repo.write("src/__init__.py", "")
    repo.write("src/app.py", "def value(): return 1\n")
    repo.write("runner.py", TS_RUNNER)
    repo.commit("base")
    repo.branch("work")
    (repo.root / "node_modules").mkdir()
    return repo


TS_RUNNER = '''import pathlib,sys,xml.etree.ElementTree as ET
out,*files=sys.argv[1:]
source=pathlib.Path('src/app.py').read_text()
root=ET.Element('testsuites')
bad=False
for file in files:
 suite=ET.SubElement(root,'testsuite',file=file,name='suite',tests='1')
 case=ET.SubElement(suite,'testcase',name='works')
 if 'return 1' in source or 'HEAD_NATIVE_FAIL' in source:
  ET.SubElement(case,'failure'); bad=True
pathlib.Path(out).write_text(ET.tostring(root,encoding='unicode'))
raise SystemExit(int(bad))
'''


def configure(repo, **tests):
    path = repo.home.path / ".aegis"
    path.mkdir(exist_ok=True)
    (path / "config.json").write_text(json.dumps({"v": 1, "tests": tests}), encoding="utf-8")


def ts_runner(repo):
    configure(repo, languages={"ts": {"command": [sys.executable, "runner.py", "{junit}", "{files}"]}})


def fix(repo, file="tests/app.test.ts", *, native_fail=False):
    repo.write("src/app.py", "def value(): return 2\n" + ("# HEAD_NATIVE_FAIL\n" if native_fail else ""))
    repo.write(file, "test('works', () => {});\n")
    return repo.commit("fix: correct value")


@pytest.mark.parametrize("extension", ["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"])
def test_every_js_extension_has_stable_namespaced_fail_to_pass(project, extension):
    ts_runner(project)
    file = "tests/app.test." + extension
    fix(project, file)
    report = check_ci_regressions(project.root, "main")
    result = report.commits[0]
    assert result.status == "passed" and result.reason == "ok"
    native = result.as_dict()["languages"]
    assert native[0]["language"] == "ts" and native[0]["witness"] == "repo-runner"
    assert native[0]["fail_to_pass_tests"] == [[file, "suite", "works"]]
    assert native[0]["head"]["mapping_errors"] == []


def test_tests_directory_and_spec_names_are_selected_without_losing_module_extensions(project):
    ts_runner(project)
    fix(project, "src/__tests__/case.mts")
    assert check_ci_regressions(project.root, "main").commits[0].status == "passed"


def test_unconfigured_ts_is_explicitly_unverifiable(project):
    fix(project)
    report = check_ci_regressions(project.root, "main")
    assert report.commits[0].status == "unverifiable"
    assert report.commits[0].reason == "tests_runner_not_configured"
    assert report.findings[0].code == "tests_runner_not_configured"


def test_python_transition_does_not_mask_native_head_failure(project):
    ts_runner(project)
    fix(project, native_fail=True)
    project.write("src/app.py", "def value(): return 2\n# HEAD_NATIVE_FAIL\n# Python regression\n")
    project.write("tests/test_app.py", "from src.app import value\ndef test_value(): assert value() == 2\n")
    project.commit("fix: add second regression for value")
    report = check_ci_regressions(project.root, "main")
    assert report.commits[0].status == "failed"
    assert report.commits[0].reason == "failed_on_head"
    assert report.commits[1].status == "passed"


def test_native_pair_runs_only_twice_across_fix_commits(project, monkeypatch):
    from aegis_core import testexec

    ts_runner(project)
    fix(project)
    project.write("src/app.py", "def value(): return 2\n# second fix\n")
    project.write("tests/second.spec.ts", "test('works', () => {});\n")
    project.commit("fix: second correction")
    calls, original = [], testexec.run_tests

    def capture(argv, *args, **kwargs):
        if "runner.py" in argv:
            calls.append(tuple(argv))
        return original(argv, *args, **kwargs)

    monkeypatch.setattr(testexec, "run_tests", capture)
    report = check_ci_regressions(project.root, "main")
    assert all(row.status == "passed" for row in report.commits)
    assert len(calls) == 2


def test_global_wrapper_suppresses_native_adapter_and_does_not_certify_last_summary(project, tmp_path):
    counter = tmp_path / "calls.txt"
    project.write("wrapper.py", "import pathlib,sys\np=pathlib.Path(sys.argv[1])\n"
                  "p.write_text(p.read_text()+'x' if p.exists() else 'x')\nprint('1 passed in 0.01s')\n")
    project.commit("feat: wrapper")
    project.git("update-ref", "refs/heads/main", "HEAD")
    configure(project, command=[sys.executable, "wrapper.py", str(counter)],
              languages={"ts": {"command": ["never-run-native-adapter"]}})
    fix(project)
    report = check_ci_regressions(project.root, "main")
    assert report.commits[0].status == "unverifiable"
    assert report.commits[0].reason == "tests_runner_unsupported"
    assert counter.read_text() == "xx"


def test_configured_pytest_preserves_flags_and_base_collection_transition(project):
    configure(project, command=[sys.executable, "-m", "pytest", "-k", "selected"])
    project.write("src/app.py", "def value(): return 2\ndef added(): return 3\n")
    project.write("tests/test_app.py", "from src.app import added\n"
                  "def test_selected(): assert added()==3\ndef test_ignored(): assert False\n")
    project.commit("fix: add missing function")
    result = check_ci_regressions(project.root, "main").commits[0]
    assert result.status == "passed"
    assert result.fail_to_pass_tests == ("tests.test_app::test_selected",)


@pytest.mark.parametrize("configured", [False, True])
@pytest.mark.parametrize("corrupt", ["head", "base", "both", "base_collection"])
def test_incomplete_python_reports_cannot_prove_a_transition(project, configured, corrupt):
    if configured:
        configure(project, command=[sys.executable, "-m", "pytest", "-q"])
    project.write("conftest.py", """from pathlib import Path
import xml.etree.ElementTree as ET
def pytest_unconfigure(config):
    head = 'return 2' in Path('src/app.py').read_text()
    corrupt = CORRUPT
    if corrupt == 'both' or (head and corrupt == 'head') or (not head and corrupt.startswith('base')):
        path = Path(config.option.xmlpath)
        tree = ET.parse(path)
        tree.getroot().set('tests', '999')
        tree.write(path)
""".replace("CORRUPT", repr(corrupt)))
    base = project.commit("chore: instrument report counts")
    project.write("src/app.py", "def value(): return 2\ndef added(): return 3\n")
    body = ("from src.app import added\ndef test_value(): assert added() == 3\n"
            if corrupt == "base_collection" else
            "from src.app import value\ndef test_value(): assert value() == 2\n")
    project.write("tests/test_app.py", body)
    project.commit("fix: correct value")
    result = check_ci_regressions(project.root, base).commits[0]
    assert (result.status, result.reason) == ("unverifiable", "incomplete_test_output")
    assert result.fail_to_pass_tests == ()


@pytest.mark.parametrize("head_passes", [False, True])
def test_configured_python_timeout_precedes_an_incomplete_report(project, head_passes):
    configure(project, command=[sys.executable, "-m", "pytest", "-q"])
    fix(project, "tests/test_app.py")
    project.write("tests/test_app.py", "import time\nfrom src.app import value\n"
                  f"def test_value():\n    if value() == 1 or not {head_passes!r}: time.sleep(60)\n")
    project.write("conftest.py", """from pathlib import Path
import xml.etree.ElementTree as ET
def pytest_unconfigure(config):
    path = Path(config.option.xmlpath)
    tree = ET.parse(path)
    tree.getroot().set('tests', '999')
    tree.write(path)
""")
    project.commit("test: exercise the timeout")
    result = check_ci_regressions(project.root, "main", timeout=1.5).commits[0]
    assert (result.status, result.reason) == ("failed", "timeout")
    assert result.fail_to_pass_tests == ()


def test_go_package_and_subtest_identity_comes_from_real_tool_output(project, tmp_path):
    if not shutil.which("go"):
        pytest.skip("Go toolchain unavailable")
    from aegis_core.verification.regression_identity import prepare_native_selection

    project.write("go.mod", "module example.test/identity\n\ngo 1.21\n")
    for package in ("a", "b"):
        project.write(package + "/x_test.go", "package " + package + "\nimport \"testing\"\n"
                      "func TestX(t *testing.T) { t.Run(\"child\", func(t *testing.T) {}) }\n")
    files = ["a/x_test.go", "b/x_test.go"]
    selection = prepare_native_selection(project.root, project.root, "go", files, scratch=tmp_path / "selection")
    assert selection.plan.available, selection.plan.detail
    assert selection.belongs(("example.test/identity/a", "TestX/child"), "a/x_test.go")
    assert not selection.belongs(("example.test/identity/b", "TestX/child"), "a/x_test.go")


@pytest.mark.parametrize("head,base,reason", [
    (RunOutcome("go", "aegis", 0, passed_ids={("b", "TestX")}, skipped_ids={("a", "TestX")}),
     RunOutcome("go", "aegis", 1, failed_ids={("a", "TestX")}, passed_ids={("b", "TestX")}), "no_tests_collected"),
    (RunOutcome("go", "aegis", 0, passed_ids={("a", "TestX/child")}),
     RunOutcome("go", "aegis", 1, failed_ids={("b", "TestX/child")}), "passed_on_base"),
    (RunOutcome("go", "aegis", 0, passed_ids={("a", "TestX")}),
     RunOutcome("go", "aegis", 1, build_errors={"build_failed"}), "deps_unavailable"),
    (RunOutcome("go", "aegis", 0, passed_ids={("a", "TestX")}, incomplete_errors={"truncated"}),
     RunOutcome("go", "aegis", 1, failed_ids={("a", "TestX")}), "incomplete_test_output"),
    (RunOutcome("go", "aegis", 0, passed_ids={("a", "TestX")}, conflict_errors={"duplicate"}),
     RunOutcome("go", "aegis", 1, failed_ids={("a", "TestX")}), "conflicting_test_results"),
])
def test_judgment_never_uses_other_package_skip_build_or_incomplete_results(head, base, reason):
    from aegis_core.verification.regression_identity import NativeSelection
    from aegis_core.verification.regression_languages import judge_native

    selection = NativeSelection(LanguageTestPlan("go"), (("a/x_test.go", (("a", "TestX"),)),))
    assert judge_native(selection, ("a/x_test.go",), head, base)[0] == reason


def test_rust_same_test_names_in_different_targets_never_intersect():
    from aegis_core.verification.regression_identity import NativeSelection
    from aegis_core.verification.regression_languages import judge_native

    selection = NativeSelection(LanguageTestPlan("rust"), (("tests/a.rs", (("pkg", "test", "a", "same"),)),))
    head = RunOutcome("rust", "aegis", 0, passed_ids={("pkg", "test", "a", "same")})
    base = RunOutcome("rust", "aegis", 1, failed_ids={("pkg", "test", "b", "same")})
    assert judge_native(selection, ("tests/a.rs",), head, base) == ("passed_on_base", ())


@pytest.mark.parametrize("side", ["head", "base"])
@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize("extra,reason", [
    ({}, "deps_unavailable"),
    ({"timed_out": True}, "timeout"),
    ({"mapping_errors": {"unknown_target"}}, "test_ids_unmapped"),
    ({"conflict_errors": {"duplicate"}}, "conflicting_test_results"),
])
def test_dependency_failure_with_partial_results_never_proves_a_transition(side, partial, extra, reason):
    from dataclasses import replace
    from aegis_core.verification.regression_identity import NativeSelection
    from aegis_core.verification.regression_languages import language_evidence, NativeRuns

    identity = ("pkg", "test", "smoke", "works")
    selection = NativeSelection(LanguageTestPlan("rust"), (("tests/smoke.rs", (identity,)),))
    head = RunOutcome("rust", "aegis", 0, passed_ids={identity})
    base = RunOutcome("rust", "aegis", 101, failed_ids={identity})
    incomplete = {"missing_selected_target_result"} if partial else set()
    broken = replace(head if side == "head" else base, build_errors={"deps_unavailable"},
                     incomplete_errors=incomplete, **extra)
    evidence = language_evidence(NativeRuns(selection, broken if side == "head" else head,
                                           broken if side == "base" else base), ("tests/smoke.rs",))
    assert evidence["reason"] == reason and evidence["fail_to_pass_tests"] == []
    assert evidence[side]["build_errors"] == ["deps_unavailable"]
    assert evidence[side]["incomplete_errors"] == sorted(incomplete)


def test_missing_or_deleted_test_never_starts_native_runner(project):
    ts_runner(project)
    fix(project)
    project.git("rm", "tests/app.test.ts")
    project.commit("chore: remove obsolete test")
    result = check_ci_regressions(project.root, "main").commits[0]
    assert result.status == "failed" and result.reason == "no_tests_collected"


@pytest.fixture
def rust_metadata(project, tmp_path, monkeypatch):
    from aegis_core import testexec

    tools = tmp_path / "tools"
    tools.mkdir()
    for name in ("cargo", "rustup"):
        tool = tools / (name + (".exe" if sys.platform == "win32" else ""))
        tool.write_bytes(b"external tool boundary fixture")
        tool.chmod(0o755)
    monkeypatch.setenv("PATH", str(tools) + os.pathsep + os.environ.get("PATH", ""))
    targets, calls = [], []

    def run(argv, cwd, env, timeout, junit, output, *, stderr_output=None):
        if stderr_output is not None:
            Path(stderr_output).write_text("")
        calls.append(tuple(argv))
        if "toolchain" in argv:
            Path(output).write_text("stable-fixture (default)\n")
        else:
            assert argv[1:] == ("metadata", "--offline", "--locked", "--no-deps", "--format-version", "1")
            assert env["RUSTUP_AUTO_INSTALL"] == "0" and env["CARGO_NET_OFFLINE"] == "true"
            Path(output).write_text(json.dumps({"workspace_members": ["fixture"], "packages": [{"id": "fixture",
                "name": "pkg", "manifest_path": str(project.root / "Cargo.toml"), "targets": targets}]}))
        return testexec.TestsRun(exit=0)

    monkeypatch.setattr(testexec, "run_tests", run)
    return targets, calls


def test_rust_custom_integration_entry_uses_target_relative_ids(project, tmp_path, rust_metadata):
    from aegis_core.verification.regression_identity import prepare_native_selection

    project.write("checks/custom.rs", "#[test] fn same() {}\nmod inner {#[test] fn works() {}}\n")
    targets, calls = rust_metadata
    targets.append({"kind": ["test"], "name": "custom", "src_path": str(project.root / "checks/custom.rs")})
    selection = prepare_native_selection(project.root, project.root, "rust", ["checks/custom.rs"], scratch=tmp_path / "selection")
    assert selection.plan.available, selection.plan.detail
    assert selection.belongs(("pkg", "test", "custom", "inner::works"), "checks/custom.rs")
    assert not selection.belongs(("pkg", "test", "custom", "checks::custom::inner::works"), "checks/custom.rs")
    assert len(calls) == 2  # one installed-toolchain probe, one Cargo metadata command


def test_rust_shared_helper_ownership_is_unmapped(project, tmp_path, rust_metadata):
    from aegis_core.verification.regression_identity import prepare_native_selection

    targets, _calls = rust_metadata
    for name in ("a", "b"):
        project.write("tests/" + name + ".rs", "mod helper;\n")
        targets.append({"kind": ["test"], "name": name, "src_path": str(project.root / ("tests/" + name + ".rs"))})
    project.write("tests/helper.rs", "#[test] fn same() {}\n")
    selection = prepare_native_selection(project.root, project.root, "rust", ["tests/helper.rs"], scratch=tmp_path / "selection")
    assert selection.plan.reason == "test_ids_unmapped"
    assert "several targets" in selection.plan.detail


def test_expired_selection_deadline_starts_no_metadata_process(project, tmp_path, rust_metadata):
    from aegis_core.verification.regression_identity import prepare_native_selection

    project.write("tests/a.rs", "#[test] fn same() {}\n")
    selection = prepare_native_selection(project.root, project.root, "rust", ["tests/a.rs"],
                                         scratch=tmp_path / "selection", deadline=0.0)
    assert selection.plan.reason == "timeout"
    assert rust_metadata[1] == []


def test_go_without_native_driver_is_explicit_and_starts_no_process(project, tmp_path, monkeypatch):
    from aegis_core import testexec
    from aegis_core.verification.regression_identity import prepare_native_selection

    project.write(".aegis/config.json", '{"v":1}')
    project.write("pkg/a_test.go", "package pkg\n")

    def unexpected(*args, **kwargs):
        raise AssertionError("no native driver: no process should run")

    monkeypatch.setattr(testexec, "run_tests", unexpected)
    selection = prepare_native_selection(project.root, project.root, "go", ["pkg/a_test.go"], scratch=tmp_path / "selection")
    assert selection.plan.reason == "no_driver"


@pytest.mark.parametrize("scenario,reason", [
    ("missing_dependencies", "deps_unavailable"), ("missing_report", "incomplete_test_output"),
    ("timeout", "timeout"), ("invalid_config", "tests_runner_not_configured"),
])
def test_native_failures_keep_explicit_codes(project, scenario, reason):
    ts_runner(project)
    if scenario == "missing_dependencies":
        (project.root / "node_modules").rmdir()
    elif scenario == "missing_report":
        project.write("runner.py", "pass\n")
        project.commit("feat: runner without results")
        project.git("update-ref", "refs/heads/main", "HEAD")
    elif scenario == "timeout":
        configure(project, languages={"ts": {"command": [sys.executable, "-c", "import time;time.sleep(10)"], "timeout_s": 0.05}})
    else:
        configure(project, languages={"ts": {"timeout_s": 0}})
    fix(project)
    result = check_ci_regressions(project.root, "main").commits[0]
    assert result.reason == reason
    assert result.status != "passed"
    assert result.as_dict()["languages"][0]["reason"] == reason


def test_rust_inline_tests_are_explicitly_unverifiable(project, tmp_path, rust_metadata):
    from aegis_core.verification.regression_identity import prepare_native_selection

    project.write("src/lib.rs", "#[cfg(test)] mod tests {#[test] fn works() {}}\n")
    selection = prepare_native_selection(project.root, project.root, "rust", ["src/lib.rs"], scratch=tmp_path / "selection")
    assert selection.plan.reason == "tests_inline_with_source"


def test_malformed_native_source_retains_an_unmapped_reason(project, tmp_path, rust_metadata):
    from aegis_core.verification.regression_identity import prepare_native_selection

    project.write("tests/broken.rs", "#[test] fn broken(\n")
    rust_metadata[0].append({"kind": ["test"], "name": "broken", "src_path": str(project.root / "tests/broken.rs")})
    selection = prepare_native_selection(project.root, project.root, "rust", ["tests/broken.rs"], scratch=tmp_path / "selection")
    assert selection.plan.reason == "test_ids_unmapped"
    assert "unclosed" in selection.plan.detail


@pytest.mark.parametrize("payload", [b"\xff", b"{", None])
def test_unreadable_metadata_is_unmapped_without_uncategorized_codes(project, tmp_path, rust_metadata, monkeypatch, payload):
    from aegis_core import testexec
    from aegis_core.verification.regression_identity import prepare_native_selection

    project.write("tests/smoke.rs", "#[test] fn works() {}\n")
    original = testexec.run_tests

    def metadata(*args, **kwargs):
        result = original(*args, **kwargs)
        if "metadata" in args[0]:
            output = Path(args[5])
            output.unlink() if payload is None else output.write_bytes(payload)
        return result

    monkeypatch.setattr(testexec, "run_tests", metadata)
    selection = prepare_native_selection(project.root, project.root, "rust", ["tests/smoke.rs"], scratch=tmp_path / "selection")
    assert selection.plan.reason == "test_ids_unmapped"


def test_unknown_python_wrapper_is_unverifiable_instead_of_a_test_failure(project, tmp_path):
    counter = tmp_path / "calls"
    project.write("wrapper.py", "import pathlib,sys\np=pathlib.Path(sys.argv[1])\n"
                  "p.write_text(p.read_text()+'x' if p.exists() else 'x')\nprint('1 passed in 0.01s')\n")
    project.commit("feat: wrapper")
    project.git("update-ref", "refs/heads/main", "HEAD")
    configure(project, command=[sys.executable, "wrapper.py", str(counter)])
    project.write("src/app.py", "def value(): return 2\n")
    project.write("tests/test_app.py", "def test_value(): assert True\n")
    project.commit("fix: value")
    result = check_ci_regressions(project.root, "main").commits[0]
    assert result.status == "unverifiable" and result.reason == "tests_runner_unsupported"
    assert counter.read_text() == "xx"


@pytest.mark.parametrize("selection", ["file", "directory", "node", "delimited", "intermixed"])
def test_configured_absolute_pytest_paths_run_snapshot_tests_instead_of_dirty_live_files(project, selection):
    project.write("src/app.py", "def value(): return 2\n")
    body = "from src.app import value\ndef test_value(): assert value()==2\n"
    if selection == "node":
        body += "def test_unselected(): assert False, 'explicit node selection was broadened'\n"
    project.write("tests/test_app.py", body)
    project.commit("fix: value")
    chosen = str(project.root / ("tests" if selection == "directory" else "tests/test_app.py"))
    if selection == "node":
        chosen += "::test_value"
    # pytest 8 collects duplicate selections; pytest 9 otherwise hides this defect.
    selectors = ["--", chosen] if selection == "delimited" else [chosen]
    if selection == "intermixed":
        selectors += ["-k", "test_value"]
    configure(project, command=[sys.executable, "-m", "pytest", "--keep-duplicates", *selectors])
    project.write("tests/test_app.py", "def test_value(): assert False, 'dirty live source was used'\n")
    result = check_ci_regressions(project.root, "main").commits[0]
    assert result.status == "passed" and result.reason == "ok"
    assert result.fail_to_pass_tests == ("tests.test_app::test_value",)


def test_configured_pytest_automatic_selection_protects_leading_dash_directories(project):
    configure(project, command=[sys.executable, "-m", "pytest"])
    project.write("src/app.py", "def value(): return 2\n")
    project.write("-nested/tests/test_app.py", "from src.app import value\ndef test_value(): assert value()==2\n")
    project.commit("fix: value")
    project.write("-nested/tests/test_app.py", "def test_value(): assert False, 'dirty live source was used'\n")
    result = check_ci_regressions(project.root, "main").commits[0]
    assert (result.status, result.reason) == ("passed", "ok")
    assert result.fail_to_pass_tests == ("-nested.tests.test_app::test_value",)


def test_configured_pytest_option_value_is_not_a_directory_selection(project):
    project.write("tests/test_untouched.py", "def test_existing_failure(): assert False\n")
    project.commit("test: keep an unrelated existing failure")
    project.git("update-ref", "refs/heads/main", "HEAD")
    configure(project, command=[sys.executable, "-m", "pytest", "-k", "tests"])
    project.write("src/app.py", "def value(): return 2\n")
    project.write("tests/test_app.py", "from src.app import value\ndef test_value(): assert value()==2\n")
    project.commit("fix: value")
    result = check_ci_regressions(project.root, "main").commits[0]
    assert (result.status, result.reason) == ("passed", "ok")
    assert result.fail_to_pass_tests == ("tests.test_app::test_value",)


def test_configured_pytest_explicit_duplicate_selections_cannot_prove_a_transition(project):
    project.write("src/app.py", "def value(): return 2\n")
    project.write("tests/test_app.py", "from src.app import value\ndef test_value(): assert value()==2\n")
    project.commit("fix: value")
    selected = str(project.root / "tests/test_app.py")
    configure(project, command=[sys.executable, "-m", "pytest", "--keep-duplicates", selected, selected])
    result = check_ci_regressions(project.root, "main").commits[0]
    assert (result.status, result.reason) == ("unverifiable", "incomplete_test_output")
    assert result.fail_to_pass_tests == ()


@pytest.mark.skipif(os.name == "nt", reason="POSIX temporary-directory alias models macOS /var")
@pytest.mark.parametrize("option", [None, "-W", "-X"])
def test_configured_python_snapshot_identity_survives_a_temporary_directory_alias(project, tmp_path, monkeypatch, option):
    import tempfile

    physical, alias = tmp_path / "physical-temp", tmp_path / "alias-temp"
    physical.mkdir()
    alias.symlink_to(physical, target_is_directory=True)
    monkeypatch.setattr(tempfile, "tempdir", str(alias))
    flags = [] if option is None else [option, "-m"]
    configure(project, command=[sys.executable, *flags, "-m", "pytest"])
    project.write("src/app.py", "def value(): return 2\n")
    project.write("tests/test_app.py", "from src.app import value\ndef test_value(): assert value()==2\n")
    project.commit("fix: value")
    result = check_ci_regressions(project.root, "main").commits[0]
    assert (result.status, result.reason) == ("passed", "ok")
    assert result.fail_to_pass_tests == ("tests.test_app::test_value",)


def test_rust_fail_to_pass_overlays_only_owned_test_files(project, rust_metadata, monkeypatch):
    from aegis_core import testexec

    project.write("src/lib.rs", "pub fn value() -> i32 { 1 }\n")
    project.commit("feat: Rust baseline")
    project.git("update-ref", "refs/heads/main", "HEAD")
    project.write("src/lib.rs", "pub fn value() -> i32 { 2 }\n")
    project.write("tests/smoke.rs", "#[test] fn same() {assert_eq!(pkg::value(),2);}\n")
    project.commit("fix: Rust value")
    original = testexec.run_tests
    executions = []

    def run(argv, cwd, env, timeout, junit, output, *, stderr_output=None):
        if stderr_output is not None:
            Path(stderr_output).write_text("")
        if "metadata" in argv:
            Path(output).write_text(json.dumps({"workspace_members": ["fixture"], "packages": [{"id": "fixture",
                "name": "pkg", "manifest_path": str(Path(cwd) / "Cargo.toml"), "targets": [{"kind": ["test"],
                "name": "smoke", "src_path": str(Path(cwd) / "tests/smoke.rs")}]}]}))
            return testexec.TestsRun(exit=0)
        if len(argv) > 1 and argv[1] == "test":
            passed = "{ 2 }" in (Path(cwd) / "src/lib.rs").read_text()
            executions.append(passed)
            status = "ok" if passed else "FAILED"
            Path(output).write_text("Running tests/smoke.rs (target/debug/deps/smoke-ignored)\n"
                "running 1 test\ntest same ... " + status + "\ntest result: " + status + ". " +
                ("1 passed; 0 failed" if passed else "0 passed; 1 failed") +
                "; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n")
            return testexec.TestsRun(exit=0 if passed else 101)
        return original(argv, cwd, env, timeout, junit, output)

    monkeypatch.setattr(testexec, "run_tests", run)
    result = check_ci_regressions(project.root, "main").commits[0]
    assert executions == [True, False]
    assert result.status == "passed" and result.reason == "ok"
    assert result.as_dict()["languages"][0]["fail_to_pass_tests"] == [["pkg", "test", "smoke", "same"]]


@pytest.mark.parametrize("option", ["-W", "-X"])
def test_configured_python_option_value_is_not_confused_with_module_selector(project, option):
    configure(project, command=[sys.executable, option, "-m", "-m", "pytest"])
    project.write("src/app.py", "def value(): return 2\n")
    project.write("tests/test_app.py", "from src.app import value\ndef test_value(): assert value()==2\n")
    project.commit("fix: value")
    assert check_ci_regressions(project.root, "main").commits[0].status == "passed"
