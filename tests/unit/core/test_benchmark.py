"""aegis_core.benchmark: what `aegis benchmark` measures and what it refuses to claim (v4.2 #4).

The benchmark times three things on a built-in fixture workspace in a temporary directory:
the `aegis_scan` answer (latency, payload bytes, approximate tokens), `aegis hook run pre-tool`
as a host starts it (a Python subprocess on a fixture payload), and Layer 1 throughput. It
measures latency and size, never efficacy; these tests hold the numbers to what was run:

- percentiles are nearest-rank, so p50 and p95 are values that were measured;
- the corpus is frozen data: its digest is pinned here, because a changed corpus ends the
  comparison with earlier runs;
- the hook timing is refused unless the hook reached the scan gate (it fails open, so a
  fast exit 0 could be an early exit that measures nothing);
- the subprocess runs with an empty home, no Aegis environment and no host variables.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Dict, List

import pytest

from aegis_core import benchmark, events
from aegis_core.benchmark import BenchmarkError
from aegis_core.rules import load_rules
from aegis_core.scan import estimate_tokens

CORPUS_SHA256 = "87b60f1de624fdfbbb2ac2047845ec36d32ebb3f8c18636dbf56bc6ca55fc908"


class Ticks:
    """A clock that advances by the given step on every second call: each timed region
    (two calls) lasts exactly one step."""

    def __init__(self, *steps: float) -> None:
        self.steps = list(steps)
        self.now = 0.0
        self.calls = 0

    def __call__(self) -> float:
        self.calls += 1
        if self.calls % 2 == 0:
            self.now += self.steps[(self.calls // 2 - 1) % len(self.steps)]
        return self.now


@pytest.fixture(scope="module")
def corpus() -> benchmark.Corpus:
    return benchmark.load_corpus()


@pytest.fixture
def root(tmp_path: Path, corpus: benchmark.Corpus) -> Path:
    path = tmp_path / "fixture"
    benchmark.materialize(corpus, path)
    return path.resolve()


# ── percentiles ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("values,pct,expected", [
    ([7.0], 50, 7.0),
    ([7.0], 95, 7.0),
    ([float(n) for n in range(1, 11)], 50, 5.0),
    ([float(n) for n in range(1, 11)], 95, 10.0),
    ([float(n) for n in range(1, 21)], 50, 10.0),
    ([float(n) for n in range(1, 21)], 95, 19.0),
    ([float(n) for n in range(1, 101)], 95, 95.0),
    ([4.0, 1.0, 3.0, 2.0], 50, 2.0),
    ([2.0, 2.0, 9.0], 95, 9.0),
])
def test_a_percentile_is_the_nearest_rank_value_that_was_measured(values, pct, expected):
    assert benchmark.percentile(values, pct) == expected
    assert benchmark.percentile(values, pct) in values


def test_a_percentile_of_nothing_is_an_error():
    with pytest.raises(ValueError, match="no measurements"):
        benchmark.percentile([], 50)


def test_the_input_of_a_percentile_is_not_reordered():
    values = [3.0, 1.0, 2.0]
    benchmark.percentile(values, 50)
    assert values == [3.0, 1.0, 2.0]


def test_a_summary_is_in_milliseconds_rounded_to_a_microsecond():
    summary = benchmark.summarize([0.0123456, 0.020, 0.010, 0.030])
    assert summary == {"p50": 12.346, "p95": 30.0, "min": 10.0, "max": 30.0}


# ── the corpus ───────────────────────────────────────────────────────────────

def test_the_corpus_is_frozen_data_with_a_pinned_digest(corpus):
    assert corpus.sha256 == CORPUS_SHA256, (
        "the benchmark corpus changed: benchmark events written before this change can no longer be compared "
        "with new ones. If that is intended, update CORPUS_SHA256 here and say so in the changelog.")


def test_the_digest_is_the_sha256_of_the_sorted_files_and_rules(corpus):
    canonical = json.dumps({"files": dict(corpus.files), "rules": dict(corpus.rules)},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert corpus.sha256 == hashlib.sha256(canonical.encode("ascii")).hexdigest()


def test_the_corpus_has_the_shape_the_numbers_are_reported_against(corpus):
    assert corpus.name == "aegis-benchmark-corpus"
    assert len(corpus.files) == 25 and len(corpus.rules) == 10
    assert len(corpus.layer1_files) == 24 and len(corpus.scan_files) == 3
    assert set(corpus.layer1_files) | set(corpus.scan_files) | {corpus.hook_file} <= set(corpus.files)
    assert all(path.endswith(".py") for path in corpus.layer1_files)


def test_every_source_file_of_the_corpus_is_valid_python(corpus):
    for path, text in corpus.files.items():
        ast.parse(text, filename=path)


def test_the_corpus_names_no_machine_specific_path(corpus):
    blob = json.dumps({"files": dict(corpus.files), "rules": dict(corpus.rules)})
    assert "/home/" not in blob and "\\\\Users" not in blob and "/Users/" not in blob


def test_the_corpus_travels_in_the_package_data_of_aegis_core():
    pyproject = (Path(__file__).resolve().parents[3] / "pyproject.toml").read_text(encoding="utf-8")
    assert "benchmark_corpus/corpus.json" in pyproject


def test_materialize_builds_a_workspace_whose_rules_all_load_clean_and_are_served(root, corpus):
    ruleset = load_rules(root)
    assert [r.error for r in ruleset.rules if r.error] == []
    assert len(ruleset.served) == len(corpus.rules) == 10
    assert (root / "aegis_bench" / "__init__.py").is_file()


def test_materialize_writes_every_file_byte_for_byte_with_unix_line_endings(root, corpus):
    for path, text in corpus.files.items():
        assert (root / path).read_bytes() == text.encode("utf-8")
        assert b"\r" not in (root / path).read_bytes()
    for path, text in corpus.rules.items():
        assert (root / ".aegis" / "rules" / path).read_bytes() == text.encode("utf-8")


@pytest.mark.parametrize("bad", ["../escape.py", "/abs.py", "a/../../b.py", "a\\b.py", ""])
def test_materialize_refuses_a_path_that_leaves_the_destination(tmp_path, bad):
    hostile = benchmark.Corpus("x", "0" * 64, {bad: "x = 1\n"}, {}, (), (), bad)
    before = sorted(p.name for p in tmp_path.iterdir())
    with pytest.raises(BenchmarkError, match="corpus path"):
        benchmark.materialize(hostile, tmp_path / "dest")
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_a_corpus_file_that_is_not_the_expected_shape_is_refused(monkeypatch):
    monkeypatch.setattr(benchmark, "_read_corpus_bytes", lambda: b'{"v": 2}')
    with pytest.raises(BenchmarkError, match="benchmark corpus"):
        benchmark.load_corpus()
    monkeypatch.setattr(benchmark, "_read_corpus_bytes", lambda: b"not json")
    with pytest.raises(BenchmarkError, match="benchmark corpus"):
        benchmark.load_corpus()


# ── the scan measurement ─────────────────────────────────────────────────────

def test_the_scan_is_timed_over_runs_after_a_first_run_that_is_reported_apart(root, corpus):
    clock = Ticks(0.200, 0.010, 0.020, 0.030, 0.040)
    out = benchmark.measure_scan(root, corpus, runs=4, clock=clock)
    assert out["runs"] == 4
    assert out["first_run_ms"] == 200.0
    assert out["latency_ms"] == {"p50": 20.0, "p95": 40.0, "min": 10.0, "max": 40.0}
    assert clock.calls == 10  # a first run and four runs, two reads each


def test_the_scan_reports_the_bytes_and_approximate_tokens_of_the_payload_it_sent(root, corpus):
    from aegis_core.hosts import GENERIC
    from aegis_core.scan import scan
    from aegis_core.skills.slots import render_scan_result

    out = benchmark.measure_scan(root, corpus, runs=1, clock=Ticks(0.001))
    expected = json.dumps(render_scan_result(scan(str(root), changed_files=list(corpus.scan_files)), GENERIC, root))
    assert out["payload_bytes"] == len(expected.encode("utf-8")) > 1000
    assert out["approx_tokens"] == estimate_tokens(expected) > 100
    assert out["files"] == list(corpus.scan_files)
    assert out["rules_served"] == 3
    assert "not a model tokenizer" in out["approx_tokens_method"]


def test_a_scan_that_fails_closed_is_an_error_not_a_fast_answer(root, corpus):
    (root / ".aegis/rules/traps/trap-bare-except.md").write_text("no frontmatter\n", encoding="utf-8")
    with pytest.raises(BenchmarkError, match="the scan failed on the fixture workspace"):
        benchmark.measure_scan(root, corpus, runs=1, clock=Ticks(0.001))


# ── the Layer 1 measurement ──────────────────────────────────────────────────

def test_layer1_throughput_is_files_per_second_of_the_median_run(root, corpus):
    out = benchmark.measure_layer1(root, corpus, runs=3, clock=Ticks(0.5, 0.25, 1.0))
    assert out["files"] == 24 and out["runs"] == 3
    assert out["pass_ms"] == {"p50": 500.0, "p95": 1000.0, "min": 250.0, "max": 1000.0}
    assert out["files_per_second"] == 48.0


def test_layer1_reports_how_many_checks_ran_and_that_none_failed(root, corpus):
    out = benchmark.measure_layer1(root, corpus, runs=1, clock=Ticks(0.1))
    assert out["checks"] == 48  # call_graph and import_guard on each of the 24 files
    assert out["findings"] == 0


def test_layer1_with_a_finding_in_the_corpus_says_so(root, corpus):
    path = root / corpus.layer1_files[0]
    path.write_text(path.read_text(encoding="utf-8") + "\nvalue = eval('1')\n", encoding="utf-8")
    out = benchmark.measure_layer1(root, corpus, runs=1, clock=Ticks(0.1))
    assert out["findings"] == 1


# ── the hook measurement ─────────────────────────────────────────────────────

class FakeHook:
    """Stands in for subprocess.run: records the call and, like the real hook, appends the
    scan_gate event of an edit that was scanned."""

    def __init__(self, root: Path, code: int = 0, gate: bool = True, stdout: bytes = b"") -> None:
        self.root, self.code, self.gate, self.stdout = root, code, gate, stdout
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, argv, **kwargs):
        self.calls.append({"argv": list(argv), **kwargs})
        if self.gate:
            events.append(self.root, "scan_gate", "pass", {"paths": 1}, host="claude-code")
        return subprocess.CompletedProcess(argv, self.code, self.stdout, b"boom\n" if self.code else b"")


def test_the_hook_is_timed_as_a_host_starts_it(root, corpus):
    fake = FakeHook(root)
    out = benchmark.measure_hook(root, corpus, runs=3, clock=Ticks(0.100, 0.050, 0.200), spawn=fake)
    assert out["runs"] == 3 and out["exit_code"] == 0
    assert out["latency_ms"] == {"p50": 100.0, "p95": 200.0, "min": 50.0, "max": 200.0}
    assert len(fake.calls) == 4  # one warm-up, then the timed runs
    call = fake.calls[1]
    import_root = str(Path(benchmark.__file__).resolve().parent.parent)
    assert call["argv"] == [sys.executable, "-I", "-c", benchmark.HOOK_RUNNER, import_root,
                            "hook", "run", "pre-tool", "--host", "claude-code"]
    assert call["cwd"] == str(root) and call["timeout"] == benchmark.HOOK_TIMEOUT_S
    assert "isolated" in out["mode"] and "interpreter" in out["mode"]


def test_the_hook_payload_is_a_claude_write_of_a_scanned_file_of_the_fixture(root, corpus):
    fake = FakeHook(root)
    benchmark.measure_hook(root, corpus, runs=1, clock=Ticks(0.01), spawn=fake)
    payload = json.loads(fake.calls[0]["input"])
    assert payload["hook_event_name"] == "PreToolUse" and payload["tool_name"] == "Write"
    assert payload["cwd"] == str(root)
    assert payload["tool_input"]["file_path"] == str(root / corpus.hook_file)


def test_the_hook_runs_with_an_empty_home_and_none_of_the_callers_aegis_or_host_variables(root, corpus, monkeypatch):
    monkeypatch.setenv("AEGIS_WORKSPACE", "/somewhere")
    monkeypatch.setenv("AEGIS_CLIENT", "codex-cli")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", "/project")
    real_home = os.environ["HOME"]
    fake = FakeHook(root)
    benchmark.measure_hook(root, corpus, runs=1, clock=Ticks(0.01), spawn=fake)
    env = fake.calls[0]["env"]
    assert not [k for k in env if k.startswith("AEGIS_")]
    assert "CLAUDE_PROJECT_DIR" not in env
    assert env["HOME"] != real_home and env["USERPROFILE"] == env["HOME"]
    assert env["PATH"] == os.environ["PATH"]


def test_the_hook_home_is_removed_afterwards(root, corpus):
    fake = FakeHook(root)
    benchmark.measure_hook(root, corpus, runs=1, clock=Ticks(0.01), spawn=fake)
    assert not os.path.exists(fake.calls[0]["env"]["HOME"])


def test_a_scan_row_covers_the_edited_file_before_the_hook_runs(root, corpus):
    from aegis_core import scan_compliance

    seen = {}

    def spawn(argv, **kwargs):
        seen["covered"] = scan_compliance.scan_covers(root, [corpus.hook_file], 600)
        events.append(root, "scan_gate", "pass", {"paths": 1}, host="claude-code")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    benchmark.measure_hook(root, corpus, runs=1, clock=Ticks(0.01), spawn=spawn)
    assert seen["covered"] is True


def test_a_hook_that_exits_non_zero_is_an_error(root, corpus):
    with pytest.raises(BenchmarkError, match=r"hook run exited 2 on the fixture payload: boom"):
        benchmark.measure_hook(root, corpus, runs=1, clock=Ticks(0.01), spawn=FakeHook(root, code=2))


def test_a_hook_that_prints_on_stdout_is_an_error(root, corpus):
    with pytest.raises(BenchmarkError, match="hook run wrote to stdout"):
        benchmark.measure_hook(root, corpus, runs=1, clock=Ticks(0.01), spawn=FakeHook(root, stdout=b"x"))


def test_a_hook_that_never_reached_the_scan_gate_is_an_error_because_it_fails_open(root, corpus):
    with pytest.raises(BenchmarkError, match="did not reach the scan gate"):
        benchmark.measure_hook(root, corpus, runs=1, clock=Ticks(0.01), spawn=FakeHook(root, gate=False))


def test_a_hook_that_cannot_be_started_or_times_out_is_an_error(root, corpus):
    def missing(argv, **kwargs):
        raise OSError(2, "No such file or directory")

    def slow(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    with pytest.raises(BenchmarkError, match=r"hook run could not be started \(No such file or directory\)"):
        benchmark.measure_hook(root, corpus, runs=1, clock=Ticks(0.01), spawn=missing)
    with pytest.raises(BenchmarkError, match=rf"hook run did not finish in {benchmark.HOOK_TIMEOUT_S} s"):
        benchmark.measure_hook(root, corpus, runs=1, clock=Ticks(0.01), spawn=slow)


# ── the whole run ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("runs", [0, -1, benchmark.MAX_RUNS + 1, True, 2.5, "3", None])
def test_a_run_count_outside_one_to_the_maximum_is_refused(runs):
    with pytest.raises(BenchmarkError, match=rf"runs must be a whole number from 1 to {benchmark.MAX_RUNS}"):
        benchmark.run_benchmark(runs)


def test_a_real_run_measures_all_three_and_leaves_no_temporary_directory(tmp_path, monkeypatch):
    scratch = tmp_path / "tmp"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    result = benchmark.run_benchmark(2)
    assert set(result) == {"runs", "python", "platform", "corpus", "scan", "hook_run", "layer1"}
    assert list(scratch.iterdir()) == []
    assert result["runs"] == 2
    assert result["corpus"] == {"name": "aegis-benchmark-corpus", "sha256": CORPUS_SHA256, "files": 25,
                                "python_files": 24, "rules": 10}
    scan, hook, layer1 = result["scan"], result["hook_run"], result["layer1"]
    assert scan["latency_ms"]["p50"] <= scan["latency_ms"]["p95"] and scan["payload_bytes"] > 1000
    assert hook["exit_code"] == 0 and hook["latency_ms"]["p50"] > 0
    assert layer1["files"] == 24 and layer1["files_per_second"] > 0 and layer1["findings"] == 0
    assert result["python"] == sys.version.split()[0] and result["platform"] == sys.platform


def test_the_notice_says_this_is_latency_and_size_never_efficacy():
    notice = benchmark.NOTICE
    assert "not an efficacy measure" in notice
    assert "latency" in notice and "payload size" in notice and "throughput" in notice
    assert "same corpus" in notice and "same machine" in notice


@pytest.mark.parametrize("language", ["typescript", "javascript", "go", "rust"])
def test_unavailable_native_parsers_are_refused_instead_of_timing_legacy_drivers(language):
    with pytest.raises(BenchmarkError, match=language + " native parser implementation unavailable"):
        benchmark.run_benchmark(1, ast_language=language)


def test_the_event_detail_is_the_numbers_a_later_run_is_compared_with():
    result = {
        "runs": 5, "python": "3.12.3", "platform": "linux",
        "corpus": {"sha256": "ab" * 32},
        "scan": {"latency_ms": {"p50": 1.5, "p95": 2.5}, "payload_bytes": 4300, "approx_tokens": 1080},
        "hook_run": {"latency_ms": {"p50": 90.0, "p95": 120.0}},
        "layer1": {"files_per_second": 250.0},
    }
    assert benchmark.event_detail(result) == {
        "runs": 5, "corpus_sha256": "ab" * 32, "scan_p50_ms": 1.5, "scan_p95_ms": 2.5,
        "scan_payload_bytes": 4300, "scan_approx_tokens": 1080, "hook_p50_ms": 90.0, "hook_p95_ms": 120.0,
        "layer1_files_per_s": 250.0, "python": "3.12.3", "platform": "linux",
    }


def test_recording_appends_one_benchmark_event_to_the_workspace(tmp_path):
    ws = tmp_path / "ws"
    (ws / ".aegis").mkdir(parents=True)
    result = {"runs": 1, "python": "3", "platform": "x", "corpus": {"sha256": "0" * 64},
              "scan": {"latency_ms": {"p50": 1.0, "p95": 1.0}, "payload_bytes": 1, "approx_tokens": 1},
              "hook_run": {"latency_ms": {"p50": 1.0, "p95": 1.0}}, "layer1": {"files_per_second": 1.0}}
    benchmark.record(ws.resolve(), result)
    (row,) = events.read(ws.resolve(), "benchmark").rows
    assert row["result"] == "ok" and row["detail"] == benchmark.event_detail(result)
