"""Centralized test runner discovery for Soma verification subsystem."""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from aegis_core import pathlookup
from aegis_core.errors import NoTestRunnerFoundError


def resolve_pytest_cmd(
    workspace: Any = None,
    required: bool = False,
) -> list[str]:
    """Resolve the appropriate pytest command for the workspace.

    Probing order:
    1. Active virtual environment ($VIRTUAL_ENV/bin/pytest or Scripts/pytest.exe)
    2. Local workspace virtual environment (.venv/bin/pytest or Scripts/pytest.exe)
    3. System pytest executable in an absolute PATH entry (aegis_core.pathlookup)
    4. Current Python interpreter if pytest package is installed

    Args:
        workspace: Optional Workspace instance or root Path/str.
        required: If True, raises NoTestRunnerFoundError if no runner is found.

    Returns:
        List of command arguments, e.g. ["/path/to/pytest"] or [sys.executable, "-m", "pytest"].
        Returns empty list [] if not found and required is False.

    Raises:
        NoTestRunnerFoundError: If required is True and no runner is discovered.
    """
    # 1. Active virtual environment
    venv_str = os.environ.get("VIRTUAL_ENV")
    if venv_str:
        venv_path = Path(venv_str)
        for cand in (venv_path / "bin" / "pytest", venv_path / "Scripts" / "pytest.exe"):
            if cand.is_file():
                if os.name == "nt" or os.access(cand, os.X_OK):
                    return [str(cand)]

    # 2. Local workspace virtual environment (.venv)
    root = None
    if workspace is not None:
        try:
            root = Path(workspace)  # a path, or a Workspace (os.PathLike)
        except Exception:
            root = None

    if root is not None:
        local_venv = Path(root) / ".venv"
        for cand in (local_venv / "bin" / "pytest", local_venv / "Scripts" / "pytest.exe"):
            if cand.is_file():
                if os.name == "nt" or os.access(cand, os.X_OK):
                    return [str(cand)]

    # 3. System pytest executable on PATH. Absolute entries only: an empty or relative
    # entry (and on Windows the current directory) names the cwd, not an install.
    which_pytest = pathlookup.which("pytest")
    if which_pytest:
        return [which_pytest]

    # 4. Current Python interpreter if pytest module is importable
    try:
        spec = importlib.util.find_spec("pytest")
        if spec is not None:
            return [sys.executable, "-m", "pytest"]
    except Exception:
        pass

    if required:
        raise NoTestRunnerFoundError("No pytest runner found in virtual environment, .venv, or PATH")

    return []


def discover_test_evidence(target_files: list[str], repo_root: str) -> tuple[list[str], str]:
    """Discover matching test files, parse test names via AST, and execute tests.

    Returns (test_names, test_results).
    """
    import ast
    import subprocess
    all_test_names: list[str] = []
    discovered_test_files: list[str] = []

    for tf in target_files:
        full_path = os.path.join(repo_root, tf) if not os.path.isabs(tf) else tf
        basename = os.path.basename(full_path)
        if basename.startswith("test_") and basename.endswith(".py"):
            if os.path.isfile(full_path) and full_path not in discovered_test_files:
                discovered_test_files.append(full_path)
            continue

        stem = os.path.splitext(basename)[0]
        parent = os.path.basename(os.path.dirname(tf))
        clean_parent = parent[6:] if parent.startswith("aegis_") else (parent[5:] if parent.startswith("soma_") else parent)

        # Candidate test file locations
        candidates = [
            os.path.join(repo_root, os.path.dirname(tf), f"test_{stem}.py"),
            os.path.join(repo_root, "tests", f"test_{stem}.py"),
            os.path.join(repo_root, "tests", f"test_{clean_parent}_{stem}.py"),
            os.path.join(repo_root, "tests", f"test_{parent}_{stem}.py"),
            os.path.join(repo_root, "tests", f"test_{clean_parent}.py"),
            os.path.join(repo_root, "tests", f"test_{parent}.py"),
            os.path.join(repo_root, f"test_{stem}.py"),
        ]
        # Also check tests/ directory matching prefix and recursive subdirectories
        tests_dir = os.path.join(repo_root, "tests")
        if os.path.isdir(tests_dir):
            try:
                for fname in os.listdir(tests_dir):
                    if (fname.startswith(f"test_{stem}") or fname.startswith(f"test_{clean_parent}")) and fname.endswith(".py"):
                        candidates.append(os.path.join(tests_dir, fname))
                for root, _, fnames in os.walk(tests_dir):
                    for fname in fnames:
                        if (fname.startswith(f"test_{stem}") or fname.startswith(f"test_{clean_parent}") or fname == f"test_{clean_parent}.py") and fname.endswith(".py"):
                            candidates.append(os.path.join(root, fname))
            except OSError:
                pass

        for cand in candidates:
            if os.path.isfile(cand) and cand not in discovered_test_files:
                discovered_test_files.append(cand)

    for test_file in discovered_test_files:
        try:
            with open(test_file, "r", encoding="utf-8", errors="ignore") as f:
                tree = ast.parse(f.read())
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name.startswith("test_") and node.name not in all_test_names:
                        all_test_names.append(node.name)
        except Exception:
            continue

    if not discovered_test_files:
        return ([], "")

    pytest_cmd = resolve_pytest_cmd(workspace=repo_root)
    if not pytest_cmd:
        raise NoTestRunnerFoundError(
            f"Found {len(discovered_test_files)} associated test file(s) for changed targets, "
            "but no pytest runner was discovered on PATH or in virtual environment."
        )

    # Run tests with resolved pytest command
    run_outputs = []
    for test_file in discovered_test_files:
        try:
            res = subprocess.run(
                pytest_cmd + [test_file, "-q", "--tb=no"],
                capture_output=True,
                text=True,
                timeout=15,
                cwd=repo_root,
            )
            out = (res.stdout or "") + (res.stderr or "")
            run_outputs.append(f"[{os.path.basename(test_file)}]\n{out.strip()}")
        except Exception as e:
            run_outputs.append(f"[{os.path.basename(test_file)}] error: {e}")

    return (all_test_names, "\n\n".join(run_outputs))


def run_external_cmd(
    argv: Sequence[str],
    cwd: Path | str,
    env: Mapping[str, str] | None = None,
    timeout: int | float = 60,
) -> dict[str, Any]:
    """Run an external command with shell=False and return structured execution status."""
    import subprocess
    import time
    from aegis_core import checkrun

    if not argv:
        return {
            "returncode": 127,
            "stdout": "",
            "stderr": "empty argv",
            "missing_binary": True,
            "timed_out": False,
            "duration_s": 0.0,
        }
    t0 = time.perf_counter()
    kwargs: dict[str, Any] = {}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(
            [str(a) for a in argv],
            cwd=str(cwd),
            env=dict(env) if env is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            **kwargs,
        )
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            checkrun.kill_group(proc)
            out_tail, err_tail = proc.communicate()
            return {
                "returncode": 124,
                "stdout": out_tail or "",
                "stderr": err_tail or "",
                "missing_binary": False,
                "timed_out": True,
                "duration_s": time.perf_counter() - t0,
            }
        finally:
            checkrun.kill_group(proc)
        return {
            "returncode": proc.returncode,
            "stdout": out or "",
            "stderr": err or "",
            "missing_binary": False,
            "timed_out": False,
            "duration_s": time.perf_counter() - t0,
        }
    except FileNotFoundError as exc:
        return {
            "returncode": 127,
            "stdout": "",
            "stderr": str(exc),
            "missing_binary": True,
            "timed_out": False,
            "duration_s": time.perf_counter() - t0,
        }
    except OSError as exc:
        return {
            "returncode": 126,
            "stdout": "",
            "stderr": str(exc),
            "missing_binary": False,
            "timed_out": False,
            "duration_s": time.perf_counter() - t0,
        }


__all__ = [
    "NoTestRunnerFoundError",
    "resolve_pytest_cmd",
    "discover_test_evidence",
    "run_external_cmd",
]

