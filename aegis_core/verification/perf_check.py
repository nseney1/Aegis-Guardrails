"""Paired interleaved performance regression check (v4.3 spec §3 T7)."""
from __future__ import annotations

import importlib.util
import os, shlex, shutil, statistics, sys, tempfile, time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from aegis_core import gitsafe, pathlookup
from aegis_core.config import read_user_config
from aegis_core.verification import test_runner

MIN_ROUNDS = 15
DEFAULT_THRESHOLD = 0.05


def evaluate_paired_samples(
    base_samples: Sequence[float],
    head_samples: Sequence[float],
    threshold: float = DEFAULT_THRESHOLD,
) -> dict[str, Any]:
    """Evaluate paired base vs head timing samples with an A/A even/odd noise floor."""
    if len(base_samples) < MIN_ROUNDS or len(head_samples) < MIN_ROUNDS:
        raise ValueError(f"perf check requires at least {MIN_ROUNDS} rounds (got {min(len(base_samples), len(head_samples))})")
    if threshold <= 0:
        raise ValueError("threshold must be positive")

    even_base = [float(base_samples[i]) for i in range(0, len(base_samples), 2)]
    odd_base = [float(base_samples[i]) for i in range(1, len(base_samples), 2)]
    med_even, med_odd = statistics.median(even_base), statistics.median(odd_base)
    aa_drift = abs(med_even - med_odd) / max(min(med_even, med_odd), 1e-12)
    noisy = aa_drift > (threshold / 2.0)

    base_min, head_min = min(float(x) for x in base_samples), min(float(x) for x in head_samples)
    base_med, head_med = statistics.median(float(x) for x in base_samples), statistics.median(float(x) for x in head_samples)
    limit = 1.0 + threshold
    regressed = (not noisy) and (head_min > limit * base_min) and (head_med > limit * base_med)
    status = "unverified" if noisy else ("fail" if regressed else "pass")
    return {
        "status": status, "regressed": regressed, "noisy": noisy,
        "rounds": min(len(base_samples), len(head_samples)), "threshold": threshold,
        "aa_drift": aa_drift, "base_min": base_min, "head_min": head_min,
        "base_median": base_med, "head_median": head_med,
    }


_BENCHMARK_ARGV = ("-m", "pytest", "--benchmark-only", "-q", "-p", "no:cacheprovider", "-o", "addopts=")


def _perf_argv(workspace_root: Path, user_config_path: Path | str | None) -> tuple[list[str] | None, str]:
    """(argv, "") from user-scope ``perf.command`` (never repository config), else the pytest-benchmark
    argv when the plugin is importable; (None, reason) otherwise."""
    raw = read_user_config(workspace_root, path=user_config_path) or {}
    perf = raw.get("perf")
    cmd = perf.get("command") if isinstance(perf, Mapping) else None
    if isinstance(cmd, str) and cmd.strip():
        try:
            return shlex.split(cmd, posix=os.name != "nt"), ""
        except ValueError:  # unbalanced quotes
            return None, "perf.command cannot be parsed"
    if isinstance(cmd, list) and cmd and all(isinstance(x, str) and x.strip() for x in cmd):
        return [x.strip() for x in cmd], ""
    if importlib.util.find_spec("pytest_benchmark") is not None:
        return [sys.executable, *_BENCHMARK_ARGV], ""
    return None, "no perf.command configured and pytest-benchmark is not installed"


def _unverified(reason: str) -> dict[str, Any]:
    return {"status": "unverified", "reason": reason, "regressed": False, "noisy": False, "passed": True}


def _invoke_sample(cmd_runner: Callable[..., Any], argv: list[str], cwd: Path, timeout: int) -> tuple[float | None, str | None]:
    t0 = time.perf_counter()
    try:
        res = cmd_runner(argv, cwd=cwd, timeout=timeout)
    except Exception as exc:  # the type only: a message can embed paths
        return None, f"{argv[0]} could not run ({type(exc).__name__})"
    elapsed = time.perf_counter() - t0
    if not isinstance(res, Mapping):
        return None, f"{argv[0]} gave no run result"
    if res.get("missing_binary"):
        return None, str(res.get("stderr") or f"{argv[0]} binary not found")
    if res.get("timed_out"):
        return None, f"{argv[0]} timed out"
    if res.get("returncode", 0) != 0:
        return None, str(res.get("stderr") or f"{argv[0]} exited {res.get('returncode')}")
    dur = res.get("duration_s")
    return (float(dur) if isinstance(dur, (int, float)) else elapsed), None


def _default_runner(ws_root: Path) -> Callable[..., Any]:
    """``run_external_cmd`` with a bare ``argv[0]`` found only in an absolute PATH entry outside the
    workspace (an empty or relative entry names the repository); an explicit path runs as written."""
    def run(argv: Sequence[str], cwd: Path, env: Mapping[str, str] | None = None, timeout: int = 60) -> dict[str, Any]:
        exe = pathlookup.which(argv[0], outside=ws_root) if os.path.basename(argv[0]) == argv[0] else argv[0]
        if exe is None:
            return {"missing_binary": True, "stderr": f"{argv[0]} not found in an absolute PATH entry outside the workspace"}
        return test_runner.run_external_cmd([exe, *argv[1:]], cwd=cwd, env=env, timeout=timeout)
    return run


def run_perf_check(
    workspace_root: Path | str,
    base_ref: str = "HEAD~1",
    rounds: int = MIN_ROUNDS,
    threshold: float = DEFAULT_THRESHOLD,
    runner: Callable[..., Any] | None = None,
    *,
    user_config_path: Path | str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run paired interleaved benchmark rounds on an export of merge-base(base_ref, HEAD) vs the working tree.
    Anything that keeps it from measuring is ``unverified``; only ``rounds < MIN_ROUNDS`` raises."""
    if rounds < MIN_ROUNDS:
        raise ValueError(f"perf check requires at least {MIN_ROUNDS} rounds (got {rounds})")
    ws_root = Path(workspace_root).resolve()
    argv, why_not = _perf_argv(ws_root, user_config_path)
    if not argv:
        return _unverified(why_not)

    cmd_runner = runner or _default_runner(ws_root)
    # What the branch changed: merge-base(base, HEAD), never the base tip; only resolved oids reach git.
    commit = gitsafe.merge_base(ws_root, base_ref, "HEAD")
    if commit is None:
        why = "and HEAD share no history (a shallow clone needs fetch-depth: 0)" if gitsafe.resolve_commit(ws_root, base_ref) else "does not resolve to a commit"
        return _unverified(f"{base_ref} {why}")
    tmp_base = Path(tempfile.mkdtemp(prefix="aegis-perf-base-"))
    try:
        try:  # an export: repository filters off, no worktree registered
            gitsafe.export_tree(ws_root, commit, tmp_base)
        except gitsafe.GitError:
            return _unverified(f"cannot export the merge-base of {base_ref}")

        base_samples: list[float] = []
        head_samples: list[float] = []
        for r in range(rounds):
            order = (("base", tmp_base), ("head", ws_root)) if r % 2 == 0 else (("head", ws_root), ("base", tmp_base))
            for label, target_cwd in order:
                sample, err = _invoke_sample(cmd_runner, argv, target_cwd, timeout)
                if err is not None or sample is None:
                    return _unverified(err or "sample failed")
                (base_samples if label == "base" else head_samples).append(sample)

        result = evaluate_paired_samples(base_samples, head_samples, threshold=threshold)
        result.update(command=argv, passed=result["status"] != "fail")
        return result
    finally:
        shutil.rmtree(tmp_base, ignore_errors=True)
