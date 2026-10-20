"""Paired interleaved performance regression check (v4.3 spec §3 T7)."""
from __future__ import annotations

import os, shlex, shutil, statistics, tempfile, time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from aegis_core import gitsafe
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
        "status": status, "regressed": regressed, "noisy": noisy, "advisory": noisy,
        "rounds": min(len(base_samples), len(head_samples)), "threshold": threshold,
        "aa_drift": aa_drift, "base_min": base_min, "head_min": head_min,
        "base_median": base_med, "head_median": head_med,
    }


def _load_user_perf_command(workspace_root: Path, user_config_path: Path | str | None = None) -> list[str] | None:
    """Read perf.command from user-scope config only; never from repository config."""
    raw = read_user_config(workspace_root, path=user_config_path)
    if raw is None:
        return None
    perf = raw.get("perf")
    cmd = perf.get("command") if isinstance(perf, Mapping) else raw.get("perf.command")
    if isinstance(cmd, str) and cmd.strip():
        try:
            return shlex.split(cmd, posix=os.name != "nt")
        except ValueError:  # unbalanced quotes: unusable, like any other bad value
            return None
    if isinstance(cmd, list) and cmd and all(isinstance(x, str) and x.strip() for x in cmd):
        return [x.strip() for x in cmd]
    return None


def _invoke_sample(cmd_runner: Callable[..., Any], argv: list[str], cwd: Path, timeout: int) -> tuple[float | None, str | None]:
    t0 = time.perf_counter()
    res = cmd_runner(argv, cwd=cwd, timeout=timeout)
    elapsed = time.perf_counter() - t0
    if isinstance(res, (int, float)):
        return float(res), None
    if isinstance(res, Mapping):
        if res.get("missing_binary"):
            return None, str(res.get("stderr") or f"{argv[0]} binary not found")
        if res.get("timed_out"):
            return None, f"{argv[0]} timed out"
        if res.get("returncode", 0) != 0:
            return None, str(res.get("stderr") or f"{argv[0]} exited {res.get('returncode')}")
        dur = res.get("duration_s")
        return (float(dur) if isinstance(dur, (int, float)) else elapsed), None
    return elapsed, None


def run_perf_check(
    workspace_root: Path | str,
    base_ref: str = "HEAD~1",
    rounds: int = MIN_ROUNDS,
    threshold: float = DEFAULT_THRESHOLD,
    command: Sequence[str] | str | None = None,
    runner: Callable[..., Any] | None = None,
    *,
    user_config_path: Path | str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run paired interleaved benchmark rounds on a temporary base worktree vs head."""
    if rounds < MIN_ROUNDS:
        raise ValueError(f"perf check requires at least {MIN_ROUNDS} rounds (got {rounds})")
    ws_root = Path(workspace_root).resolve()
    if isinstance(command, str) and command.strip():
        argv: list[str] | None = shlex.split(command, posix=os.name != "nt")
    elif isinstance(command, Sequence) and command:
        argv = [str(x) for x in command]
    else:
        argv = _load_user_perf_command(ws_root, user_config_path=user_config_path)
    if not argv:
        return {"status": "unverified", "reason": "no perf.command configured in user-scope config", "regressed": False, "noisy": False}

    cmd_runner = runner or test_runner.run_external_cmd
    git_fn = getattr(gitsafe, "run_git", gitsafe.run)
    tmp_base = Path(tempfile.mkdtemp(prefix="aegis-perf-base-"))
    worktree_added = False
    try:
        commit = gitsafe.resolve_commit(ws_root, base_ref) or base_ref
        try:
            wt_res = git_fn(["worktree", "add", "--detach", str(tmp_base), commit], ws_root)
            worktree_added = getattr(wt_res, "returncode", 1) == 0
        except gitsafe.GitError:
            worktree_added = False
        if not worktree_added and runner is None:
            return {"status": "unverified", "reason": f"failed to create detached worktree for {base_ref}", "regressed": False, "noisy": False}

        base_samples: list[float] = []
        head_samples: list[float] = []
        for r in range(rounds):
            order = (("base", tmp_base), ("head", ws_root)) if r % 2 == 0 else (("head", ws_root), ("base", tmp_base))
            for label, target_cwd in order:
                sample, err = _invoke_sample(cmd_runner, argv, target_cwd, timeout)
                if err is not None or sample is None:
                    return {"status": "unverified", "reason": err or "sample failed", "regressed": False, "noisy": False}
                (base_samples if label == "base" else head_samples).append(sample)

        result = evaluate_paired_samples(base_samples, head_samples, threshold=threshold)
        result["command"] = argv
        return result
    finally:
        if worktree_added:
            try: git_fn(["worktree", "remove", "--force", str(tmp_base)], ws_root)
            except gitsafe.GitError: pass
        shutil.rmtree(tmp_base, ignore_errors=True)
