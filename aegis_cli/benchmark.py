"""aegis benchmark — how long Aegis takes and how much it sends, never whether it helps (v4.2 #4).

Times the aegis_scan answer (latency p50/p95, payload bytes, approximate tokens), the
`hook run pre-tool` hook as a host starts it, and Layer 1 throughput (files per second),
on a built-in fixture corpus in a temporary directory (aegis_core.benchmark), so nothing
of the repository is read or written. It appends one ``benchmark`` event to the events log
of the workspace it runs in; that is its only write. Every output says it is not an
efficacy measure.

Exit codes: 0 done (a failed event append is a warning), 1 a measurement that could not be
taken honestly (nothing is recorded), 2 usage or a directory that is not an Aegis workspace. With --json, stdout carries only the JSON
document, with ``source``, ``aegis_version``, ``checked_at`` (UTC) and ``scope``.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List

from aegis_core import primitives
from aegis_cli import resolve_root, sanitize_display
from aegis_cli.base import AegisCommand, CommandCategory
from aegis_core import benchmark
from aegis_core._version import __version__
from aegis_core.workspace.layout import is_aegis_workspace

__all__ = ["BenchmarkCommand", "run_benchmark"]

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
CORPUS_LABEL = "built-in fixture corpus"
MEASURES = [
    "aegis_scan latency (p50, p95), payload bytes and approximate tokens",
    "aegis hook run pre-tool latency (p50, p95) in a fresh Python process",
    "Layer 1 throughput (files per second)",
]
NOT_MEASURED = ["efficacy: whether Aegis makes an agent's code better"]


def _runs(value: str) -> int:
    try:
        runs = int(value)
    except ValueError:
        runs = 0
    if not 1 <= runs <= benchmark.MAX_RUNS:
        raise argparse.ArgumentTypeError(f"{value!r} is not a whole number from 1 to {benchmark.MAX_RUNS}")
    return runs


def _envelope(root: Any, runs: int) -> Dict[str, Any]:
    return primitives.envelope("aegis benchmark", {"workspace": str(root), "runs": runs, "corpus": CORPUS_LABEL})


def _text(value: object) -> str:
    text = str(value)
    return sanitize_display(text, max_len=len(text))


def _report(result: Dict[str, Any], recorded: bool) -> List[str]:
    corpus, scan, hook, layer1 = result["corpus"], result["scan"], result["hook_run"], result["layer1"]
    lines = [
        f"Aegis benchmark {__version__}: {CORPUS_LABEL} ({corpus['files']} files, {corpus['rules']} rules, "
        f"sha256 {corpus['sha256'][:12]}), {result['runs']} runs, Python {result['python']} on {result['platform']}",
        f"  aegis_scan   p50 {scan['latency_ms']['p50']} ms  p95 {scan['latency_ms']['p95']} ms  "
        f"first run {scan['first_run_ms']} ms; payload {scan['payload_bytes']} bytes (~{scan['approx_tokens']} tokens)",
        f"  hook run     p50 {hook['latency_ms']['p50']} ms  p95 {hook['latency_ms']['p95']} ms  "
        "(a fresh Python process per run, interpreter start included)",
        f"  Layer 1      {layer1['files_per_second']} files/s  ({layer1['files']} files, {layer1['checks']} checks, "
        f"{layer1['findings']} findings)",
        benchmark.NOTICE,
    ]
    if recorded:
        lines.append("Recorded a benchmark event.")
    return lines


def run_benchmark(args: argparse.Namespace) -> int:
    runs = getattr(args, "runs", benchmark.DEFAULT_RUNS)
    root = resolve_root(args)
    use_json = bool(getattr(args, "json", False))
    if not is_aegis_workspace(root):  # the event would otherwise create .aegis/state in any directory
        print(f"Error: not an Aegis workspace (no .aegis/ in {root}); run aegis init", file=sys.stderr)
        return EXIT_USAGE
    try:
        result = benchmark.run_benchmark(runs)
    except benchmark.BenchmarkError as exc:
        if use_json:
            print(json.dumps({**_envelope(root, runs), "status": "error", "error": str(exc)}, indent=2))
        else:
            print(f"Error: {_text(exc)}", file=sys.stderr)
        return EXIT_FAILED

    warnings: List[str] = []
    try:
        benchmark.record(root, result)
    except Exception as exc:  # a metric never fails the benchmark (events.append documents what it raises)
        warnings.append(f"the benchmark event could not be recorded ({type(exc).__name__}: {exc})")
    if use_json:
        doc = _envelope(root, runs)
        doc.update({"status": "ok", "notice": benchmark.NOTICE, "measures": MEASURES, "not_measured": NOT_MEASURED,
                    "recorded": not warnings, "warnings": warnings})
        doc.update({key: result[key] for key in ("runs", "python", "platform", "corpus", "scan", "hook_run", "layer1")})
        print(json.dumps(doc, indent=2))
        return EXIT_OK
    for line in _report(result, recorded=not warnings):
        print(line)
    for warning in warnings:
        print(f"Warning: {_text(warning)}", file=sys.stderr)
    return EXIT_OK


class BenchmarkCommand(AegisCommand):
    """Measure scan and hook latency, payload size and Layer 1 throughput."""

    name = "benchmark"
    category = CommandCategory.PLUMBING
    help = "Measure scan and hook latency, payload size and Layer 1 throughput (not an efficacy measure)"
    description = (
        "Time the aegis_scan answer (latency p50/p95, payload bytes, approximate tokens), the "
        "`aegis hook run pre-tool` hook as a host starts it (a fresh Python process), and Layer 1 "
        "throughput (files per second), on a built-in fixture corpus in a temporary directory: nothing in "
        "your repository is read or written. It appends one benchmark event to this workspace's events log. "
        "This is not an efficacy measure: it says nothing about whether Aegis makes an agent's code better. "
        "Compare only runs of the same corpus (its sha256 is in the output) on the same machine."
    )

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--runs", type=_runs, default=benchmark.DEFAULT_RUNS, metavar="N",
                            help=f"Timed runs of each measurement, 1 to {benchmark.MAX_RUNS} "
                                 f"(default {benchmark.DEFAULT_RUNS}); one untimed warm-up of the hook and Layer 1 comes first")

    def execute(self, args: argparse.Namespace) -> int:
        return run_benchmark(args)
