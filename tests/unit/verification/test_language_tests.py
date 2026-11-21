"""Aggregate and language timeout attribution through snapshot execution."""
from __future__ import annotations

from dataclasses import replace
import json
import os
import sys
from types import SimpleNamespace

import pytest

from aegis_core import testexec
from aegis_core.verification import language_tests
from aegis_core.verification.language_tests import GoTest, LanguageTestPlan, run_language_snapshot
from aegis_core.verification.test_outcomes import RunOutcome, RustTarget
from tests.conftest import symlink_or_skip


@pytest.fixture(params=["go", "rust", "ts"])
def snapshot_run(tmp_path, monkeypatch, request):
    language = request.param
    workspace, snapshot, scratch = (tmp_path / name for name in ("workspace", "snapshot", "scratch"))
    workspace.mkdir()
    snapshot.mkdir()
    file = {"go": "a_test.go", "rust": "tests/a.rs", "ts": "a.test.ts"}[language]
    source = snapshot / file
    source.parent.mkdir(exist_ok=True)
    source.write_text("selected test source", encoding="utf-8")
    if language == "ts":
        (workspace / "node_modules").mkdir()
        if os.name != "nt":
            probe = tmp_path / "link-probe"
            symlink_or_skip(workspace / "node_modules", probe, target_is_directory=True)
            probe.unlink()
    plan = LanguageTestPlan(
        language, workspace=str(workspace.resolve()), command=(sys.executable,), files=(file,),
        go_tests=(GoTest(file, "example/pkg", "TestA"),) if language == "go" else (),
        rust_targets=((file, (RustTarget("pkg", "test", "a"),)),) if language == "rust" else (),
        rust_toolchain="stable-fixture" if language == "rust" else None,
        cargo_target=str(tmp_path / "cargo-target") if language == "rust" else None,
    )
    identity = {"go": ("example/pkg", "TestA"), "rust": ("pkg", "test", "a", "works"),
                "ts": (file, "suite", "works")}[language]
    output = {
        "go": "\n".join(json.dumps(event) for event in (
            {"Action": "start", "Package": "example/pkg"},
            {"Action": "run", "Package": "example/pkg", "Test": "TestA"},
            {"Action": "pass", "Package": "example/pkg", "Test": "TestA"},
            {"Action": "pass", "Package": "example/pkg"},
        )),
        "rust": ("Running tests/a.rs (target/debug/deps/a-012345)\n"
                 "running 1 test\ntest works ... ok\n"
                 "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"),
        "ts": "",
    }[language]
    report = '<testsuite file="a.test.ts" name="suite"><testcase name="works"/></testsuite>'
    state = dict(timed_out=True, output=output, report=report, calls=[])

    def run(argv, cwd, env, timeout, junit, output_path):
        state["calls"].append(timeout)
        if state["output"] is not None:
            output_path.write_text(state["output"], encoding="utf-8")
        if language == "ts" and state["report"] is not None:
            (scratch / "results.xml").write_text(state["report"], encoding="utf-8")
        return testexec.TestsRun(exit=124 if state["timed_out"] else 0, timed_out=state["timed_out"])

    monkeypatch.setattr(language_tests, "testexec", SimpleNamespace(run_tests=run))

    def execute(timeout_s, ticks, deadline):
        clock = iter(ticks)
        monkeypatch.setattr(language_tests, "time", SimpleNamespace(monotonic=lambda: next(clock)))
        return run_language_snapshot(replace(plan, timeout_s=timeout_s), snapshot, workspace, scratch,
                                     deadline=deadline)

    return state, execute, language, identity


@pytest.mark.parametrize("timeout_s,ticks,deadline,expected_timeout,aggregate", [
    (20.0, (100.0, 100.0), 110.0, 10.0, True),
    (5.0, (100.0, 108.0), 110.0, 2.0, True),
    (5.0, (100.0, 100.0), 110.0, 5.0, False),
    (10.0, (100.0, 100.0), 110.0, 10.0, False),
    (20.0, (), None, 20.0, False),
])
@pytest.mark.parametrize("timed_out", [True, False])
def test_snapshot_timeout_identifies_only_the_limiting_deadline(
        snapshot_run, timeout_s, ticks, deadline, expected_timeout, aggregate, timed_out):
    state, execute, language, identity = snapshot_run
    state["timed_out"] = timed_out
    outcome = execute(timeout_s, ticks, deadline)
    assert state["calls"] == [expected_timeout]
    assert outcome == RunOutcome(
        language, "repo-runner" if language == "ts" else "aegis", 124 if timed_out else 0,
        timed_out=timed_out, passed_ids=frozenset({identity}),
        incomplete_errors=frozenset({"deadline_exceeded"} if aggregate and timed_out else ()),
    )


@pytest.mark.parametrize("failure", ["missing_output", "malformed_report"])
def test_deadline_timeout_keeps_read_and_parse_errors(snapshot_run, failure):
    state, execute, language, identity = snapshot_run
    if failure == "missing_output":
        state["output"] = None
        expected_errors = {"report_missing"}
    elif language == "go":
        state["output"] += "\ninvalid-json"
        expected_errors = {"invalid_json:5"}
    elif language == "rust":
        state["output"] += "\ntest result: malformed"
        expected_errors = {"unsupported_target_summary"}
    else:
        state["report"] = "<testsuite"
        expected_errors = {"invalid_xml"}
    outcome = execute(20.0, (100.0, 100.0), 110.0)
    assert outcome == RunOutcome(
        language, "repo-runner" if language == "ts" else "aegis", 124, timed_out=True,
        passed_ids=frozenset({identity}) if failure != "missing_output" and language != "ts" else frozenset(),
        incomplete_errors=frozenset(expected_errors | {"deadline_exceeded"}),
    )
