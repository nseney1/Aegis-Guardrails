"""Opt-in diff coverage verification over changed lines (v4.3 T9)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable, Optional

from aegis_core import gitsafe
from aegis_core.verification.test_runner import run_external_cmd
from aegis_core.workspace.layout import WorkspaceLayout as AegisLayout

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _to_ranges(lines: list[int]) -> list[tuple[int, int]]:
    if not lines:
        return []
    ordered = sorted(set(lines))
    ranges: list[tuple[int, int]] = []
    start = prev = ordered[0]
    for ln in ordered[1:]:
        if ln == prev + 1:
            prev = ln
        else:
            ranges.append((start, prev))
            start = prev = ln
    ranges.append((start, prev))
    return ranges


def parse_changed_lines(diff_text: str) -> dict[str, set[int]]:
    """Parse unified diff (e.g. git diff-tree -p -U0) into {rel_path: set[int]}."""
    changed: dict[str, set[int]] = {}
    current_file: Optional[str] = None
    cur_line: Optional[int] = None
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            current_file = None if target == "/dev/null" else (target[2:] if target.startswith("b/") else target).replace("\\", "/")
            cur_line = None
        elif raw.startswith("--- ") or raw.startswith("diff --git "):
            cur_line = None
        elif (m := _HUNK_RE.match(raw)):
            if current_file is None:
                cur_line = None
            else:
                count = int(m.group(2)) if m.group(2) is not None else 1
                cur_line = int(m.group(1)) if count > 0 else None
        elif current_file is not None and cur_line is not None:
            if raw.startswith("+") and not raw.startswith("+++"):
                changed.setdefault(current_file, set()).add(cur_line)
                cur_line += 1
            elif raw.startswith(" "):
                cur_line += 1
    return changed


def evaluate_diff_coverage(
    changed_lines: dict[str, set[int]],
    executed_lines_by_file: dict[str, Any],
    threshold: float = 0.80,
    executable_lines_by_file: Optional[dict[str, set[int]]] = None,
) -> dict[str, Any]:
    """Evaluate fraction of executable changed lines covered against threshold."""
    files_map = executed_lines_by_file
    if "files" in files_map and isinstance(files_map["files"], dict) and "files" not in changed_lines:
        files_map = files_map["files"]
    norm_cov = {k.replace("\\", "/"): v for k, v in files_map.items()}
    norm_exec = {k.replace("\\", "/"): set(v) for k, v in (executable_lines_by_file or {}).items()}
    total_exec = 0
    total_cov = 0
    uncovered_by_file: dict[str, list[int]] = {}
    uncovered_ranges: dict[str, list[tuple[int, int]]] = {}
    for raw_path, raw_lines in sorted(changed_lines.items()):
        rel = raw_path.replace("\\", "/")
        lines = set(raw_lines)
        entry = norm_cov.get(rel, norm_cov.get(raw_path))
        if isinstance(entry, dict):
            exec_set = set(entry.get("executed_lines", ()))
            miss_set = set(entry.get("missing_lines", ()))
            candidates = lines & (exec_set | miss_set) if (exec_set or miss_set) else lines
        else:
            exec_set = set(entry or ())
            candidates = (lines & norm_exec[rel]) if rel in norm_exec else lines
        covered = candidates & exec_set
        uncovered = sorted(candidates - exec_set)
        total_exec += len(candidates)
        total_cov += len(covered)
        if uncovered:
            uncovered_by_file[rel] = uncovered
            uncovered_ranges[rel] = _to_ranges(uncovered)
    ratio = 1.0 if total_exec == 0 else (total_cov / total_exec)
    return {
        "passed": bool(ratio >= threshold),
        "coverage": ratio,
        "ratio": ratio,
        "threshold": threshold,
        "covered_lines": total_cov,
        "executable_lines": total_exec,
        "uncovered_by_file": uncovered_by_file,
        "uncovered_ranges": uncovered_ranges,
    }


def run_diff_coverage(
    workspace_root: str | Path,
    base_ref: str = "HEAD~1",
    threshold: float = 0.80,
    runner: Optional[Callable[..., Any]] = None,
    diff_text: Optional[str] = None,
    timeout: int = 120,
) -> dict[str, Any]:
    """Run pytest under coverage into isolated state_dir and evaluate diff coverage."""
    root = Path(workspace_root).resolve()
    state_dir = AegisLayout(root).state_dir
    state_dir.mkdir(parents=True, exist_ok=True)
    cov_data = state_dir / f".coverage.{os.getpid()}"
    cov_json = state_dir / f"coverage_{os.getpid()}.json"
    for p in (cov_data, cov_json):
        if p.exists():
            p.unlink()
    env = {**os.environ, "COVERAGE_FILE": str(cov_data)}
    if sys.version_info >= (3, 12):
        env["COVERAGE_CORE"] = "sysmon"
    if diff_text is None:
        res = gitsafe.run(["diff-tree", "-p", "-U0", base_ref, "HEAD"], cwd=root)
        raw_out = res.stdout if res.returncode == 0 else b""
        diff_text = raw_out.decode("utf-8", "replace") if isinstance(raw_out, bytes) else (raw_out or "")
    changed = {k: v for k, v in parse_changed_lines(diff_text).items() if k.endswith(".py")}
    cmd = [sys.executable, "-m", "coverage", "run", "-m", "pytest", "-q"]
    if runner is not None:
        runner(cmd, cwd=str(root), env=env, json_path=str(cov_json))
    else:
        run_external_cmd(cmd, cwd=str(root), env=env, timeout=timeout)
        run_external_cmd([sys.executable, "-m", "coverage", "json", "-o", str(cov_json)], cwd=str(root), env=env, timeout=timeout)
    payload = json.loads(cov_json.read_text(encoding="utf-8")) if cov_json.exists() else {}
    return evaluate_diff_coverage(changed, payload, threshold=threshold)


verify_coverage_threshold = run_diff_coverage

