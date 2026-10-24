"""`aegis benchmark`: how long Aegis takes and how much it sends, never whether it helps (v4.2 #4).

Three things are timed on a built-in fixture workspace that is built in a temporary
directory and removed afterwards, so the numbers compare across machines and releases and
nothing of the caller's repository is read or written:

- **scan**: what `aegis_scan` answers for the corpus's scan files: latency over N runs
  (p50, p95; the first, cold run apart), the payload's bytes and its approximate tokens;
- **hook run**: `aegis hook run pre-tool --host claude-code` on a fixture payload, started
  the way a host starts it, a fresh Python process, so the interpreter's start is in the
  number. The run is refused unless the hook reached the scan gate: the hook fails open,
  and a fast exit 0 could be an early exit that measures nothing;
- **Layer 1**: files per second of the Layer 1 checks (call graph, import guard,
  forbid_ast) over the corpus's source files.

Percentiles are nearest-rank, so p50 and p95 are values that were measured. The corpus
(``benchmark_corpus/corpus.json``, package data) is frozen: its sha256 is in every result,
and a different corpus ends the comparison with earlier runs.

**Not an efficacy measure.** Nothing here says whether Aegis makes an agent's code better;
:data:`NOTICE` says so in every output.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib.resources
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Mapping, Sequence, Tuple

from aegis_core import events, scan_compliance
from aegis_core.hosts import GENERIC
from aegis_core.primitives import safe_parts
from aegis_core.scan import estimate_tokens
from aegis_core.scan import scan as run_scan
from aegis_core.skills.slots import render_scan_result
from aegis_core.verification import runner
from aegis_core.workspace.layout import RULES_RELDIR

__all__ = [
    "DEFAULT_RUNS",
    "HOOK_RUNNER",
    "HOOK_TIMEOUT_S",
    "MAX_RUNS",
    "NOTICE",
    "BenchmarkError",
    "Corpus",
    "event_detail",
    "load_corpus",
    "materialize",
    "measure_hook",
    "measure_layer1",
    "measure_scan",
    "percentile",
    "record",
    "run_benchmark",
    "summarize",
]

DEFAULT_RUNS = 20
MAX_RUNS = 1000
HOOK_TIMEOUT_S = 30
# Shaped like the git pre-commit hook's runner: -I keeps the working directory and PYTHON*
# variables off sys.path, and the one directory aegis was installed in comes in as argv[1].
HOOK_RUNNER = "import sys; sys.path.insert(0, sys.argv[1]); from aegis_cli.cli import main; sys.exit(main(sys.argv[2:]))"
NOTICE = (
    "This measures latency, payload size and throughput of Aegis on a built-in fixture workspace, on this machine. "
    "It is not an efficacy measure: it says nothing about whether Aegis makes an agent's code better. "
    "Compare only runs of the same corpus (the corpus sha256) on the same machine."
)
_CORPUS_DIR = "benchmark_corpus"
_CORPUS_FILE = "corpus.json"
_CORPUS_KEYS = frozenset({"v", "name", "note", "files", "rules", "scan_files", "layer1_files", "hook_file"})
_APPROX_TOKENS_METHOD = ("heuristic, the larger of 1.35 per word and 1 per 4 ASCII characters "
                         "(aegis_core.scan.estimate_tokens); not a model tokenizer")
_HOOK_MODE = ("a fresh isolated Python process per run (python -I), so the interpreter's start is in the "
              "number; one untimed warm-up run first")


class BenchmarkError(RuntimeError):
    """A measurement that cannot be taken honestly; nothing is reported for it."""


# ── statistics ───────────────────────────────────────────────────────────────

def percentile(values: Sequence[float], pct: int) -> float:
    """The nearest-rank ``pct`` percentile of ``values``: the smallest value that at least
    ``pct`` percent of them do not exceed. Always one of the values."""
    if not values:
        raise ValueError("no measurements to take a percentile of")
    ordered = sorted(values)
    rank = -(-pct * len(ordered) // 100)  # ceil(pct * n / 100) in integers: no float rounding
    return ordered[max(rank, 1) - 1]


def summarize(seconds: Sequence[float]) -> Dict[str, float]:
    """p50, p95, min and max of ``seconds``, in milliseconds rounded to a microsecond."""
    ms = [s * 1000.0 for s in seconds]
    return {
        "p50": round(percentile(ms, 50), 3),
        "p95": round(percentile(ms, 95), 3),
        "min": round(min(ms), 3),
        "max": round(max(ms), 3),
    }


def _timed(clock: Callable[[], float], work: Callable[[], Any]) -> Tuple[float, Any]:
    start = clock()
    value = work()
    return clock() - start, value


# ── the corpus ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Corpus:
    """The fixture corpus: source files, rules (relative to ``.aegis/rules``) and which files
    each measurement uses."""

    name: str
    sha256: str
    files: Mapping[str, str]
    rules: Mapping[str, str]
    scan_files: Tuple[str, ...]
    layer1_files: Tuple[str, ...]
    hook_file: str


def _read_corpus_bytes() -> bytes:
    resource = importlib.resources.files("aegis_core").joinpath(_CORPUS_DIR).joinpath(_CORPUS_FILE)
    try:
        return resource.read_bytes()
    except OSError as exc:
        raise BenchmarkError(f"the benchmark corpus is missing from this installation ({exc.strerror or exc})") from None


def _damaged(why: str) -> BenchmarkError:
    return BenchmarkError(f"the benchmark corpus is damaged: {why}")


def _text_map(value: Any, what: str) -> Dict[str, str]:
    if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise _damaged(f'"{what}" must map file names to text')
    return value


def load_corpus() -> Corpus:
    """The packaged corpus, checked for shape; BenchmarkError when it is missing or damaged."""
    try:
        data = json.loads(_read_corpus_bytes().decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise _damaged(f"not valid JSON ({exc})") from None
    if not isinstance(data, dict) or set(data) != _CORPUS_KEYS or data["v"] != 1:
        raise _damaged("an unknown layout")
    files, rules = _text_map(data["files"], "files"), _text_map(data["rules"], "rules")
    lists = {}
    for key in ("scan_files", "layer1_files"):
        names = data[key]
        if not isinstance(names, list) or not names or not all(isinstance(n, str) and n in files for n in names):
            raise _damaged(f'"{key}" must name files of the corpus')
        lists[key] = tuple(names)
    if data["hook_file"] not in files or not isinstance(data["name"], str):
        raise _damaged('"hook_file" must name a file of the corpus')
    canonical = json.dumps({"files": files, "rules": rules}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return Corpus(data["name"], hashlib.sha256(canonical.encode("ascii")).hexdigest(), files, rules,
                  lists["scan_files"], lists["layer1_files"], data["hook_file"])


def _check_corpus_path(path: str) -> None:
    if safe_parts(path, windows=True) is None:  # one corpus, so one rule on every platform
        raise BenchmarkError(f"corpus path {path!r} is not a relative path inside the workspace")


def materialize(corpus: Corpus, dest: Path) -> None:
    """Write the corpus as a workspace under ``dest``: its files, and its rules in ``.aegis/rules``.
    Every path is checked before anything is written."""
    entries = [(rel, rel, text) for rel, text in corpus.files.items()]
    entries += [(rel, f"{RULES_RELDIR}/{rel}", text) for rel, text in corpus.rules.items()]
    for raw, _target, _text in entries:
        _check_corpus_path(raw)
    for _raw, target, text in entries:
        path = Path(dest) / target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))  # bytes: no newline translation on Windows


# ── the measurements ─────────────────────────────────────────────────────────

def measure_scan(root: Path, corpus: Corpus, runs: int, clock: Callable[[], float] = time.perf_counter) -> Dict[str, Any]:
    """The scan answer for ``corpus.scan_files``: what the MCP tool builds (scan, slot rendering,
    JSON), timed over ``runs`` runs after a first, cold run that is reported apart."""

    def once() -> Tuple[str, int]:
        result = run_scan(str(root), changed_files=list(corpus.scan_files))
        if result.get("status") == "FAIL":
            raise BenchmarkError(f"the scan failed on the fixture workspace: {result.get('error')}")
        served = len(result.get("relevant_rules") or [])
        return json.dumps(render_scan_result(result, GENERIC, root)), served

    first, (payload, served) = _timed(clock, once)
    timings = [_timed(clock, once)[0] for _ in range(runs)]
    return {
        "runs": runs,
        "files": list(corpus.scan_files),
        "rules_served": served,
        "first_run_ms": round(first * 1000.0, 3),
        "latency_ms": summarize(timings),
        "payload_bytes": len(payload.encode("utf-8")),
        "approx_tokens": estimate_tokens(payload),
        "approx_tokens_method": _APPROX_TOKENS_METHOD,
    }


def measure_layer1(root: Path, corpus: Corpus, runs: int, clock: Callable[[], float] = time.perf_counter) -> Dict[str, Any]:
    """Layer 1 over ``corpus.layer1_files``: ``runs`` timed passes after one untimed warm-up.
    ``checks`` is how many results a pass produced and ``findings`` how many of them failed,
    so a pass that checked nothing, or that found something, is visible."""

    def once() -> List[Any]:
        return runner.run_layer1(changed_files=list(corpus.layer1_files), repo_root=str(root), fast_mode=True)

    once()
    timings: List[float] = []
    results: List[Any] = []
    for _ in range(runs):
        elapsed, results = _timed(clock, once)
        timings.append(elapsed)
    median = percentile(timings, 50)
    return {
        "runs": runs,
        "files": len(corpus.layer1_files),
        "checks": len(results),
        "findings": sum(1 for r in results if not r.verdict),
        "pass_ms": summarize(timings),
        "files_per_second": round(len(corpus.layer1_files) / max(median, 1e-9), 1),
    }


def _hook_env(home: str) -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_") and k != "CLAUDE_PROJECT_DIR"}
    env.update({"HOME": home, "USERPROFILE": home, "XDG_CONFIG_HOME": os.path.join(home, ".config")})
    return env


def measure_hook(root: Path, corpus: Corpus, runs: int, clock: Callable[[], float] = time.perf_counter,
                 spawn: Callable[..., Any] = subprocess.run) -> Dict[str, Any]:
    """`aegis hook run pre-tool --host claude-code` on a Claude ``Write`` of ``corpus.hook_file``,
    which a scan row covers, with an empty home and none of the caller's Aegis or host
    variables. ``runs`` timed runs after an untimed warm-up; BenchmarkError unless every run
    exited 0, printed nothing and recorded a ``scan_gate`` pass in the fixture workspace."""
    home = tempfile.mkdtemp(prefix="aegis-bench-home-")
    try:
        scan_compliance.record(root, "scan", host=scan_compliance.CLI_HOST, session="aegis-benchmark",
                               files=[corpus.hook_file])
        payload = json.dumps({
            "session_id": "aegis-benchmark", "transcript_path": "", "cwd": str(root),
            "permission_mode": "default", "hook_event_name": "PreToolUse", "tool_name": "Write",
            "tool_input": {"file_path": str(root / corpus.hook_file), "content": "x = 1\n"},
            "tool_use_id": "toolu_aegis_benchmark",
        }).encode("utf-8")
        import_root = str(Path(__file__).resolve().parent.parent)
        argv = [sys.executable, "-I", "-c", HOOK_RUNNER, import_root, "hook", "run", "pre-tool", "--host", "claude-code"]
        env = _hook_env(home)

        def once() -> None:
            try:
                proc = spawn(argv, input=payload, cwd=str(root), env=env, capture_output=True, timeout=HOOK_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                raise BenchmarkError(f"hook run did not finish in {HOOK_TIMEOUT_S} s") from None
            except OSError as exc:
                raise BenchmarkError(f"hook run could not be started ({exc.strerror or exc})") from None
            if proc.returncode != 0:
                lines = proc.stderr.decode("utf-8", "replace").strip().splitlines()
                raise BenchmarkError(f"hook run exited {proc.returncode} on the fixture payload"
                                     + (f": {lines[-1][:200]}" if lines else ""))
            if proc.stdout:
                raise BenchmarkError("hook run wrote to stdout, which its contract forbids")

        once()
        timings = [_timed(clock, once)[0] for _ in range(runs)]
        passed = [row for row in events.read(root, "scan_gate").rows if row["result"] == "pass"]
        if len(passed) != runs + 1:
            raise BenchmarkError(
                f"the hook did not reach the scan gate on the fixture payload ({len(passed)} of {runs + 1} runs "
                "recorded a pass): it fails open, so these timings would be of an early exit")
    finally:
        shutil.rmtree(home, ignore_errors=True)
    return {
        "runs": runs,
        "exit_code": 0,
        "mode": _HOOK_MODE,
        "latency_ms": summarize(timings),
    }


# ── a whole run ──────────────────────────────────────────────────────────────

def _check_runs(runs: Any) -> int:
    if type(runs) is not int or not 1 <= runs <= MAX_RUNS:
        raise BenchmarkError(f"runs must be a whole number from 1 to {MAX_RUNS}, not {runs!r}")
    return runs


def run_benchmark(runs: int = DEFAULT_RUNS, *, clock: Callable[[], float] = time.perf_counter,
                  spawn: Callable[..., Any] = subprocess.run) -> Dict[str, Any]:
    """Measure the scan, Layer 1 and the hook on the fixture corpus; BenchmarkError when any
    cannot be measured honestly. The temporary workspace is removed whatever happens."""
    runs = _check_runs(runs)
    corpus = load_corpus()
    base = tempfile.mkdtemp(prefix="aegis-bench-")
    try:
        root = Path(base).resolve() / "workspace"
        materialize(corpus, root)
        scan = measure_scan(root, corpus, runs, clock)
        layer1 = measure_layer1(root, corpus, runs, clock)
        hook = measure_hook(root, corpus, runs, clock, spawn)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    return {
        "runs": runs,
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "corpus": {"name": corpus.name, "sha256": corpus.sha256, "files": len(corpus.files),
                   "python_files": len(corpus.layer1_files), "rules": len(corpus.rules)},
        "scan": scan,
        "hook_run": hook,
        "layer1": layer1,
    }


def event_detail(result: Mapping[str, Any]) -> Dict[str, Any]:
    """The numbers a later run is compared with: the ``benchmark`` event's detail."""
    return {
        "runs": result["runs"],
        "corpus_sha256": result["corpus"]["sha256"],
        "scan_p50_ms": result["scan"]["latency_ms"]["p50"],
        "scan_p95_ms": result["scan"]["latency_ms"]["p95"],
        "scan_payload_bytes": result["scan"]["payload_bytes"],
        "scan_approx_tokens": result["scan"]["approx_tokens"],
        "hook_p50_ms": result["hook_run"]["latency_ms"]["p50"],
        "hook_p95_ms": result["hook_run"]["latency_ms"]["p95"],
        "layer1_files_per_s": result["layer1"]["files_per_second"],
        "python": result["python"],
        "platform": result["platform"],
    }


def record(workspace: Any, result: Mapping[str, Any]) -> Dict[str, Any]:
    """Append one ``benchmark`` event for ``result`` to ``workspace``'s events log (what
    events.append raises is the caller's to handle: a metric never fails a benchmark)."""
    return events.append(workspace, "benchmark", "ok", event_detail(result))
