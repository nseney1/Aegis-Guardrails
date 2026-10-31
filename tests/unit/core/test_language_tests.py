"""Language plans through real process-boundary substitutes, never host toolchains."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from aegis_core.verification.language_tests import GoTest, prepare_language_tests, run_language_snapshot
from aegis_core.verification.test_outcomes import RustTarget
from tests.conftest import symlink_or_skip


@pytest.fixture
def project(tmp_path, monkeypatch):
    home, workspace, snapshot, tools, scratch = [tmp_path / n for n in ("home", "workspace", "snapshot", "tools", "scratch")]
    for path in (home, workspace, snapshot, tools, scratch):
        path.mkdir()
    for base in (workspace, snapshot):
        for relative in ("pkg/a_test.go", "tests/smoke.rs", "tests/a.test.ts"):
            path = base / relative
            path.parent.mkdir(exist_ok=True)
            path.write_text("fixture test source")
    (workspace / "node_modules").mkdir()
    for key in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("PATH", str(tools))
    scenario = tools / "scenario.json"
    scenario.write_text('{}')
    script = tools / "runtime.py"
    script.write_text(
        "import json, os, pathlib, sys\n"
        f"settings=json.loads(pathlib.Path({str(scenario)!r}).read_text()); mode=settings.get('mode','pass')\n"
        "tool, args=sys.argv[1],sys.argv[2:]\n"
        "if tool=='rustup': print(settings.get('toolchains','stable-fixture (default)')); raise SystemExit(0)\n"
        f"if tool=='go' and args[0]=='env': print({str(tools / 'go-build')!r}+'\\n'+{str(tools / 'go-modules')!r}); raise SystemExit(0)\n"
        "if mode=='oversized': print('x'*(8*1024*1024+1)); raise SystemExit(0)\n"
        "if mode=='unicode': os.write(1,b'\\xff'); raise SystemExit(0)\n"
        "if tool=='go':\n"
        " events=[{'Action':'start','Package':'example/pkg'}]\n"
        " if mode!='empty': events += [{'Action':'run','Package':'example/pkg','Test':'TestA/case'},"
        " {'Action':'fail' if mode=='fail' else 'skip' if mode=='skip' else 'pass','Package':'example/pkg','Test':'TestA/case'}]\n"
        " if mode=='long': events += [{'Action':'output','Package':'example/pkg','Output':'x'*8192}]*40\n"
        " events += [{'Action':'fail' if mode=='fail' else 'pass','Package':'example/pkg'}]\n"
        " for e in events: print(json.dumps(e))\n"
        "elif tool=='cargo':\n"
        " if mode=='build': print('error: no matching package named missing found'); raise SystemExit(101)\n"
        " print('     Running tests/smoke.rs (target/debug/deps/smoke-012345)')\n"
        " print('running 1 test\\ntest module::works ... ok')\n"
        " print('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s')\n"
        "elif tool=='node':\n"
        " assert pathlib.Path('node_modules').is_dir()\n"
        " if mode=='deps': print('Cannot find module missing'); raise SystemExit(1)\n"
        " if mode=='missing': raise SystemExit(0)\n"
        " report=next(a.split('=',1)[1] for a in args if a.startswith('--report='))\n"
        " pathlib.Path(report).write_text('<testsuite file=\"tests/a.test.ts\" name=\"suite\"><testcase name=\"works\"/></testsuite>')\n"
        " if mode=='replace_link': pathlib.Path('node_modules').unlink(); pathlib.Path('node_modules').mkdir()\n"
        "raise SystemExit(1 if mode=='fail' else 0)\n", encoding="utf-8")
    paths = {}
    for name in ("go", "cargo", "rustup", "node"):
        path = tools / (name + ".exe" if os.name == "nt" else name)
        path.write_bytes(b"trusted runtime fixture, intercepted at Popen")
        path.chmod(0o700)
        paths[str(path)] = name
    calls, real_popen = [], subprocess.Popen

    def spawn(argv, **options):
        command = [str(v) for v in argv]
        if command[0] in paths:
            calls.append((command, options))
            command = [sys.executable, str(script), paths[command[0]], *command[1:]]
        return real_popen(command, **options)

    monkeypatch.setattr(subprocess, "Popen", spawn)
    return dict(home=home, workspace=workspace, snapshot=snapshot, tools=tools, scratch=scratch,
                scenario=scenario, calls=calls)


def configure(project, language, command):
    path = project["home"] / ".aegis"
    path.mkdir(exist_ok=True)
    (path / "config.json").write_text(json.dumps({"v": 1, "tests": {
        "command": ["all-suites-must-not-run"], "languages": {language: {"command": command}}}}))


def prepare(project, language="go", **options):
    defaults = {"go_tests": [GoTest("pkg/a_test.go", "example/pkg", "TestA")]} if language == "go" else {}
    if language == "rust":
        defaults["rust_targets"] = {"tests/smoke.rs": [RustTarget("pkg", "test", "smoke")]}
    defaults.update(options)
    files = {"go": ["pkg/a_test.go"], "rust": ["tests/smoke.rs"], "ts": ["tests/a.test.ts"]}[language]
    return prepare_language_tests(project["workspace"], language, files,
        scratch=project["scratch"] / "plan", **defaults)


def execute(project, plan, name="head", **options):
    return run_language_snapshot(plan, project["snapshot"], project["workspace"],
                                 project["scratch"] / name, **options)


def require_directory_link(project):
    probe = project["scratch"] / "directory-link-probe"
    symlink_or_skip(project["workspace"] / "node_modules", probe, target_is_directory=True)
    probe.unlink()


def test_go_plan_pins_absolute_runtime_and_defaults_once_for_head_and_base(project):
    plan = prepare(project)
    assert plan.available and Path(plan.command[0]).is_absolute()
    assert plan.command[1:] == ("test", "-json", "-count=1", "-run", "^(TestA)$", "example/pkg")
    assert plan.files == ("pkg/a_test.go",) and plan.timeout_s == 300
    with pytest.raises(FrozenInstanceError):
        plan.timeout_s = 3
    assert execute(project, plan).passed_ids == frozenset({("example/pkg", "TestA/case")})
    assert execute(project, plan, "base").evidence
    assert [argv[1] for argv, _ in project["calls"]] == ["env", "test", "test"]
    for argv, options in project["calls"]:
        env = options["env"]
        assert {k: env[k] for k in ("GOTOOLCHAIN", "GOPROXY", "GOWORK", "GOFLAGS", "GOENV")} == {
            "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOWORK": "off", "GOFLAGS": "-mod=readonly", "GOENV": "off"}
        assert project["workspace"] not in Path(options["cwd"]).parents


def test_go_metadata_is_explicit_complete_and_namespaced(project):
    plan = prepare(project, go_tests=[])
    assert plan.reason == "test_ids_unmapped" and not execute(project, plan).evidence
    assert project["calls"] == []
    plan = prepare(project, go_tests=[GoTest("pkg/a_test.go", "example/pkg", "TestA"),
                                     GoTest("pkg/b_test.go", "example/pkg", "TestA")])
    assert plan.available  # irrelevant file metadata never widens this selection


def test_go_selected_file_metadata_is_normalized_for_later_mapping(project):
    plan = prepare(project, go_tests=[GoTest("pkg\\a_test.go", "example/pkg", "TestA")])
    assert plan.available and plan.go_tests[0].file == "pkg/a_test.go"


@pytest.mark.parametrize("mode,field", [("fail", "failed_ids"), ("skip", "skipped_ids"),
                                       ("empty", "incomplete_errors"), ("oversized", "incomplete_errors"),
                                       ("unicode", "incomplete_errors")])
def test_execution_keeps_failure_skip_no_tests_and_complete_output_errors(project, mode, field):
    plan = prepare(project)
    project["scenario"].write_text(json.dumps({"mode": mode}))
    outcome = execute(project, plan)
    assert getattr(outcome, field) and not outcome.evidence


def test_complete_output_before_legacy_tail_is_preserved(project):
    plan = prepare(project)
    project["scenario"].write_text('{"mode":"long"}')
    outcome = execute(project, plan)
    assert outcome.passed_ids == frozenset({("example/pkg", "TestA/case")}) and outcome.evidence


def test_rust_installed_default_is_probed_in_empty_cwd_then_pinned(project, monkeypatch):
    monkeypatch.setenv("RUSTUP_TOOLCHAIN", "repo-absent")
    plan = prepare(project, "rust")
    assert plan.rust_toolchain == "stable-fixture"
    assert plan.command[1:] == ("test", "--offline", "--locked", "--no-fail-fast", "--color", "never",
                               "--package", "pkg", "--test", "smoke")
    outcome = execute(project, plan)
    assert outcome.passed_ids == frozenset({("pkg", "test", "smoke", "module::works")}) and outcome.evidence
    probe, run = project["calls"]
    assert probe[0][1:] == ["toolchain", "list"]
    assert "RUSTUP_TOOLCHAIN" not in probe[1]["env"]
    assert probe[1]["env"]["RUSTUP_AUTO_INSTALL"] == "0"
    env = run[1]["env"]
    assert env["RUSTUP_TOOLCHAIN"] == "stable-fixture" and env["CARGO_NET_OFFLINE"] == "true"
    assert env["RUSTUP_AUTO_INSTALL"] == "0" and project["workspace"] not in Path(env["CARGO_TARGET_DIR"]).parents


def test_rust_ambiguous_target_metadata_is_unmapped_without_execution(project):
    plan = prepare(project, "rust", rust_targets={"tests/smoke.rs": [RustTarget("a", "test", "smoke"),
                                                                 RustTarget("b", "test", "smoke")]})
    assert plan.reason == "test_ids_unmapped" and project["calls"] == []


def test_rust_build_or_offline_resolution_failure_never_invents_failed_id(project):
    plan = prepare(project, "rust")
    project["scenario"].write_text('{"mode":"build"}')
    outcome = execute(project, plan)
    assert "deps_unavailable" in outcome.build_errors and not outcome.failed_ids and not outcome.evidence


def test_ts_unconfigured_skips_and_never_uses_the_global_all_suite_wrapper(project):
    path = project["home"] / ".aegis"
    path.mkdir()
    (path / "config.json").write_text('{"v":1,"tests":{"command":["all-suites-must-not-run"]}}')
    plan = prepare(project, "ts")
    assert plan.reason == "tests_runner_not_configured"
    assert not execute(project, plan).evidence and not project["calls"]


def test_ts_user_command_runs_once_with_snapshot_dependencies_and_junit_identity(project):
    require_directory_link(project)
    configure(project, "ts", ["node", "runner.mjs", "--report={junit}", "{files}"])
    plan = prepare(project, "ts")
    outcome = execute(project, plan)
    assert outcome.passed_ids == frozenset({("tests/a.test.ts", "suite", "works")})
    assert outcome.evidence and (outcome.language, outcome.witness) == ("ts", "repo-runner")
    assert len(project["calls"]) == 1 and Path(project["calls"][0][1]["cwd"]) == project["snapshot"]
    assert not (project["snapshot"] / "node_modules").exists()
    assert (project["workspace"] / "node_modules").is_dir()


@pytest.mark.parametrize("kind", ["existing", "denied", "replace_link", "missing"])
def test_ts_link_and_report_failures_are_explicit_and_preserve_snapshot_entries(project, monkeypatch, kind):
    if kind in ("replace_link", "missing"):
        require_directory_link(project)
    configure(project, "ts", ["node", "runner.mjs", "--report={junit}", "{files}"])
    plan = prepare(project, "ts")
    link = project["snapshot"] / "node_modules"
    if kind == "existing":
        link.mkdir()
        (link / "keep").write_text("owner file")
    elif kind == "denied":
        def denied(*args, **kwargs):
            raise PermissionError("link privilege unavailable")
        monkeypatch.setattr(os, "symlink", denied)
    else:
        project["scenario"].write_text(json.dumps({"mode": kind}))
    outcome = execute(project, plan)
    assert not outcome.evidence and (outcome.build_errors or outcome.incomplete_errors)
    if kind == "existing":
        assert (link / "keep").read_text() == "owner file" and not project["calls"]
    if kind == "replace_link":
        assert link.is_dir() and not link.is_symlink()


def test_expired_aggregate_deadline_never_starts_another_snapshot_command(project):
    plan = prepare(project)
    before = len(project["calls"])
    outcome = execute(project, plan, deadline=-1)
    assert outcome.timed_out and not outcome.evidence and len(project["calls"]) == before


def test_existing_scratch_logs_are_preserved_without_a_command(project):
    plan = prepare(project)
    scratch = project["scratch"] / "head"
    scratch.mkdir()
    (scratch / "output.log").write_text("prior evidence")
    before = len(project["calls"])
    outcome = execute(project, plan)
    assert not outcome.evidence and outcome.build_errors
    assert (scratch / "output.log").read_text() == "prior evidence" and len(project["calls"]) == before


def test_missing_snapshot_test_file_never_executes_another_test(project):
    plan = prepare(project)
    (project["snapshot"] / "pkg/a_test.go").unlink()
    before = len(project["calls"])
    outcome = execute(project, plan)
    assert outcome.mapping_errors and not outcome.evidence and len(project["calls"]) == before


def test_symlinked_snapshot_test_cannot_select_a_file_outside_snapshot(project):
    plan = prepare(project)
    path = project["snapshot"] / "pkg/a_test.go"
    path.unlink()
    symlink_or_skip(project["workspace"] / "pkg/a_test.go", path)
    before = len(project["calls"])
    outcome = execute(project, plan)
    assert outcome.mapping_errors and not outcome.evidence and len(project["calls"]) == before


def test_ts_missing_report_retains_dependency_failure(project):
    require_directory_link(project)
    configure(project, "ts", ["node", "runner.mjs", "--report={junit}", "{files}"])
    plan = prepare(project, "ts")
    project["scenario"].write_text('{"mode":"deps"}')
    outcome = execute(project, plan)
    assert "deps_unavailable" in outcome.build_errors and "report_missing" in outcome.incomplete_errors


@pytest.mark.parametrize("language,diagnostic", [
    ("go", "pkg/value.go:2:8: missing go.sum entry for module providing package example.invalid/unavailable"),
    ("go", "pkg/value.go:2:8: module lookup disabled by GOPROXY=off"),
    ("rust", "error: no matching package named 'aegis_acceptance_absent_registry_crate' found"),
])
def test_offline_dependency_diagnostics_survive_incomplete_native_output(project, language, diagnostic):
    plan = prepare(project, language)
    (project["tools"] / "runtime.py").write_text(
        f"import sys\nprint({diagnostic!r}, file=sys.stderr)\nraise SystemExit(1)\n")
    outcome = execute(project, plan)
    assert outcome.build_errors and "deps_unavailable" in outcome.build_errors
    assert outcome.incomplete_errors and not outcome.evidence
    assert not outcome.passed_ids and not outcome.failed_ids
    assert (project["scratch"] / "head/output.log").read_text() == diagnostic + "\n"


@pytest.mark.parametrize("toolchains", ["no installed toolchains", "a (default)\nb (default)"])
def test_rust_missing_or_ambiguous_installed_default_is_unavailable(project, toolchains):
    project["scenario"].write_text(json.dumps({"toolchains": toolchains}))
    plan = prepare(project, "rust")
    assert plan.reason == "deps_unavailable" and not execute(project, plan).evidence
    assert len(project["calls"]) == 1


def test_go_user_command_can_defer_report_placeholder_and_retain_user_caches(project):
    configure(project, "go", ["go", "test", "-json", "--report={junit}", "{packages}"])
    plan = prepare(project, parent={"HOME": str(project["home"]), "GOCACHE": str(project["tools"] / "build"),
                                    "GOMODCACHE": str(project["tools"] / "modules")})
    assert plan.available and not project["calls"]
    assert execute(project, plan).evidence
    argv, options = project["calls"][0]
    assert "{junit}" not in " ".join(argv) and options["env"]["GOCACHE"] == str(project["tools"] / "build")


def test_rust_selected_target_missing_from_complete_output_is_incomplete(project):
    plan = prepare(project, "rust", rust_targets={"tests/smoke.rs": [RustTarget("pkg", "test", "smoke")],
                                                   "tests/other.rs": [RustTarget("pkg", "test", "other")]})
    assert plan.command[-4:] == ("--test", "other", "--test", "smoke")
    outcome = execute(project, plan)
    assert outcome.incomplete_errors and not outcome.evidence
    assert len(project["calls"]) == 2  # one metadata probe, one target command


def test_deadline_expiring_during_dependency_setup_never_starts_the_command(project, monkeypatch):
    from aegis_core.verification import language_tests

    require_directory_link(project)
    configure(project, "ts", ["node", "runner.mjs", "--report={junit}", "{files}"])
    plan = prepare(project, "ts")
    clock, symlink = [100.0], os.symlink
    monkeypatch.setattr(language_tests, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    def slow_link(*args, **kwargs):
        result = symlink(*args, **kwargs)
        clock[0] = 102.0
        return result

    monkeypatch.setattr(os, "symlink", slow_link)
    outcome = execute(project, plan, deadline=101.0)
    assert outcome.timed_out and not outcome.evidence and not project["calls"]
    assert not (project["snapshot"] / "node_modules").exists()


def test_absolute_user_runner_paths_with_equals_are_rebased_into_snapshot(project):
    require_directory_link(project)
    configure(project, "ts", ["node", str(project["workspace"] / "runner=fixture.mjs"),
                              "--report={junit}", "{files}"])
    plan = prepare(project, "ts")
    assert execute(project, plan).evidence
    assert project["calls"][0][0][1] == str(project["snapshot"] / "runner=fixture.mjs")
