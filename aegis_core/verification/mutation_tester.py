from __future__ import annotations

"""Lightweight mutation testing for the verification framework.

Parses a target function from a file using AST, generates mutations
(operator swaps, constant replacements, line removals), runs the given
test files against each mutant, and reports surviving mutations.
"""

import ast
from dataclasses import dataclass
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional, Sequence, Union

from aegis_core import checkrun
from aegis_core.ast.schema import MutationPoint, NormalizedAST
from aegis_core.primitives import key_within, real_key
from aegis_core.storage import atomic_write_text
from . import ToolEvidence

__all__ = ["check", "apply_mutation_point", "collect_mutations_from_ast"]


# ── AST Mutation Visitors ──────────────────────────────────────────────────

# Operator swap pairs
_BINOP_SWAPS: dict[type, type] = {
    ast.Add: ast.Sub,
    ast.Sub: ast.Add,
    ast.Mult: ast.Div,
    ast.Div: ast.Mult,
}

_UNARYOP_SWAPS: dict[type, type] = {
    ast.UAdd: ast.USub,
    ast.USub: ast.UAdd,
}

_CMPOP_SWAPS: dict[type, type] = {
    ast.Gt: ast.Lt,
    ast.Lt: ast.Gt,
    ast.GtE: ast.LtE,
    ast.LtE: ast.GtE,
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
}

_BOOLOP_SWAPS: dict[type, type] = {
    ast.And: ast.Or,
    ast.Or: ast.And,
}


class _Mutation:
    """Represents a single mutation to apply."""

    __slots__ = ("lineno", "apply")

    def __init__(self, lineno: int, apply):
        self.lineno = lineno
        self.apply = apply  # callable(tree) -> mutated tree


def _is_deletable_stmt(node: ast.AST) -> bool:
    # A docstring is an Expr too, but deleting it changes nothing a test can
    # observe: an equivalent mutant that would always "survive".
    if not isinstance(node, (ast.Assign, ast.AugAssign, ast.Expr)):
        return False
    return not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str))


def _is_mutable_return(node: ast.AST) -> bool:
    # `return None` -> `return None` is not a mutation.
    if not isinstance(node, ast.Return) or node.value is None:
        return False
    return not (isinstance(node.value, ast.Constant) and node.value.value is None)


_SCOPES = (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _defined_in(scope: ast.AST, name: str, kinds: tuple[type, ...]) -> Optional[ast.AST]:
    """The first ``kinds`` definition of ``name`` that belongs to ``scope`` itself: in its
    body or in a block there (if/else, try, with, loops), never inside a nested scope."""
    todo = list(ast.iter_child_nodes(scope))
    for node in todo:  # grows while iterated: breadth first, as runner._discover_functions
        if isinstance(node, _SCOPES):
            if isinstance(node, kinds) and node.name == name:
                return node
            continue
        todo.extend(ast.iter_child_nodes(node))
    return None


def _function_node(tree: ast.AST, function_name: str) -> Optional[ast.FunctionDef]:
    """The function ``function_name`` names: a module-level ``f``, a method ``Class.method``
    or a nested ``outer.inner`` (runner._discover_functions); the first definition when its
    scope defines it more than once."""
    *outer, name = function_name.split(".")
    scope: Optional[ast.AST] = tree
    for part in outer:
        scope = _defined_in(scope, part, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        if scope is None:
            return None
    found = _defined_in(scope, name, (ast.FunctionDef,))
    return found if isinstance(found, ast.FunctionDef) else None


def _collect_mutations(source: str, function_name: str) -> list[_Mutation]:
    """Walk the AST of *function_name* and collect all possible mutations."""
    func_node = _function_node(ast.parse(source), function_name)
    if func_node is None:
        return []

    mutations: list[_Mutation] = []

    for node in ast.walk(func_node):
        # 1) Binary operator swaps (+↔-, *↔/)
        if isinstance(node, ast.BinOp) and type(node.op) in _BINOP_SWAPS:
            mutations.append(_Mutation(node.lineno, None))

        # 2) Unary operator swaps
        if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARYOP_SWAPS:
            mutations.append(_Mutation(node.lineno, None))

        # 3) Constant replacement
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool):
                mutations.append(_Mutation(node.lineno, None))
            elif isinstance(node.value, (int, float)) and node.value != 0:
                mutations.append(_Mutation(node.lineno, None))

        # 4) Comparison operator swaps (<↔>, <=↔>=, ==↔!=)
        if isinstance(node, ast.Compare):
            for op in node.ops:
                if type(op) in _CMPOP_SWAPS:
                    mutations.append(_Mutation(node.lineno, None))
                    break  # One mutation per Compare node

        # 5) Boolean operator swaps (and↔or)
        if isinstance(node, ast.BoolOp) and type(node.op) in _BOOLOP_SWAPS:
            mutations.append(_Mutation(node.lineno, None))

    # 6) Statement deletion (replace with pass) — one per non-trivial stmt
    for node in ast.walk(func_node):
        if _is_deletable_stmt(node):
            mutations.append(_Mutation(node.lineno, None))

    # 7) Return value mutation (return X → return None)
    for node in ast.walk(func_node):
        if _is_mutable_return(node):
            mutations.append(_Mutation(node.lineno, None))

    return mutations


def _apply_mutation_by_index(
    source: str, function_name: str, mutation_index: int
) -> Optional[str]:
    """Apply the i-th mutation to *source* and return the mutated source."""
    tree2 = ast.parse(source)

    # Collect mutation targets in the exact order of _collect_mutations
    targets2: list[ast.AST] = []
    kinds2: list[str] = []
    func_node2 = _function_node(tree2, function_name)
    if func_node2 is None:
        return None

    for node in ast.walk(func_node2):
        if isinstance(node, ast.BinOp) and type(node.op) in _BINOP_SWAPS:
            targets2.append(node)
            kinds2.append("binop")
        if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARYOP_SWAPS:
            targets2.append(node)
            kinds2.append("unaryop")
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool):
                targets2.append(node)
                kinds2.append("bool_const")
            elif isinstance(node.value, (int, float)) and node.value != 0:
                targets2.append(node)
                kinds2.append("const")
        if isinstance(node, ast.Compare):
            for op in node.ops:
                if type(op) in _CMPOP_SWAPS:
                    targets2.append(node)
                    kinds2.append("cmpop")
                    break
        if isinstance(node, ast.BoolOp) and type(node.op) in _BOOLOP_SWAPS:
            targets2.append(node)
            kinds2.append("boolop")

    # Statement deletion targets
    for node in ast.walk(func_node2):
        if _is_deletable_stmt(node):
            targets2.append(node)
            kinds2.append("stmt_del")

    # Return value mutation targets
    for node in ast.walk(func_node2):
        if _is_mutable_return(node):
            targets2.append(node)
            kinds2.append("return_val")

    if mutation_index >= len(targets2):
        return None

    node_to_mutate = targets2[mutation_index]
    k = kinds2[mutation_index]

    if k == "binop":
        node_to_mutate.op = _BINOP_SWAPS[type(node_to_mutate.op)]()
    elif k == "unaryop":
        node_to_mutate.op = _UNARYOP_SWAPS[type(node_to_mutate.op)]()
    elif k == "bool_const":
        node_to_mutate.value = not node_to_mutate.value
    elif k == "const":
        if isinstance(node_to_mutate.value, int):
            node_to_mutate.value = node_to_mutate.value + 1
        else:
            node_to_mutate.value = node_to_mutate.value + 1.0
    elif k == "cmpop":
        node_to_mutate.ops = [
            _CMPOP_SWAPS.get(type(op), type(op))() for op in node_to_mutate.ops
        ]
    elif k == "boolop":
        node_to_mutate.op = _BOOLOP_SWAPS[type(node_to_mutate.op)]()
    elif k == "stmt_del":
        # Replace the statement with `pass`
        pass_node = ast.Pass()
        ast.copy_location(pass_node, node_to_mutate)
        # Find parent and replace
        for parent_node in ast.walk(tree2):
            for field, value in ast.iter_fields(parent_node):
                if isinstance(value, list):
                    for idx, item in enumerate(value):
                        if item is node_to_mutate:
                            value[idx] = pass_node
    elif k == "return_val":
        node_to_mutate.value = ast.Constant(value=None)
        ast.copy_location(node_to_mutate.value, node_to_mutate)

    ast.fix_missing_locations(tree2)
    try:
        return ast.unparse(tree2)
    except Exception:
        return None


# A mutant faces at most this many test files (the runner puts the convention file
# first), and each run may take longer the more files it has: 30 s for one file plus
# 15 s per extra file, never more than 300 s.
MAX_TEST_FILES = 15
_BASE_TIMEOUT_S = 30
_TIMEOUT_PER_EXTRA_FILE_S = 15
_MAX_TIMEOUT_S = 300


def _run_timeout(file_count: int) -> int:
    return min(_BASE_TIMEOUT_S + _TIMEOUT_PER_EXTRA_FILE_S * max(0, file_count - 1), _MAX_TIMEOUT_S)


def _bounded_test_files(test_file: Union[str, Sequence[str]]) -> tuple[list[str], int]:
    """The test files that run, in the caller's order, and how many the cap left out."""
    if isinstance(test_file, (str, os.PathLike)):
        test_file = [test_file]
    unique = list(dict.fromkeys(os.fspath(path) for path in test_file))
    return unique[:MAX_TEST_FILES], max(0, len(unique) - MAX_TEST_FILES)


def _files_note(ran: int, left_out: int) -> str:
    note = f"{ran} test file{'' if ran == 1 else 's'} ran"
    if left_out:
        note += f"; the {MAX_TEST_FILES}-file cap left out {left_out}"
    return note


_SWAP_PLUGIN = "_aegis_mutant_swap"

# A pytest plugin (loaded with -p, so before any conftest or test module imports code)
# that serves the staged source for whichever module resolves to the target file, under
# that module's own name and __file__. Every importer then sees one mutated module:
# `from pkg import mod`, `import pkg.mod`, and other modules that call the function.
# The mutant never touches the source tree. The marker records that the target loaded.
_SWAP_PLUGIN_BODY = """
import os
import sys
from importlib.abc import Loader
from importlib.util import spec_from_file_location

_KEY = os.path.normcase(os.path.realpath(_TARGET))
_STEM = os.path.splitext(os.path.basename(_TARGET))[0]


class _StagedSourceLoader(Loader):
    def __init__(self, source):
        self._source = source

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        code = compile(self._source, module.__spec__.origin, "exec", dont_inherit=True)
        exec(code, module.__dict__)


class _SwapFinder:
    @staticmethod
    def find_spec(fullname, path=None, target=None):
        if fullname.rpartition(".")[2] != _STEM:
            return None
        spec = None
        for finder in sys.meta_path:
            find = getattr(finder, "find_spec", None)
            if finder is _SwapFinder or find is None:
                continue
            spec = find(fullname, path, target)
            if spec is not None:
                break
        if spec is None or not spec.origin:
            return spec
        if os.path.normcase(os.path.realpath(spec.origin)) != _KEY:
            return spec
        with open(_SOURCE, encoding="utf-8") as fh:
            source = fh.read()
        with open(_LOADED, "w", encoding="utf-8") as fh:
            fh.write(fullname)
        return spec_from_file_location(fullname, spec.origin, loader=_StagedSourceLoader(source))


sys.meta_path.insert(0, _SwapFinder)
"""


class _ModuleSwap:
    """Stages a source for the target module of a pytest run (see _SWAP_PLUGIN_BODY)."""

    def __init__(self, target: Path, workdir: str):
        self.workdir = workdir
        self.source_file = os.path.join(workdir, "staged_source.txt")
        self.marker = os.path.join(workdir, "loaded.txt")
        header = (
            f"_TARGET = {os.path.abspath(target)!r}\n"
            f"_SOURCE = {self.source_file!r}\n"
            f"_LOADED = {self.marker!r}\n"
        )
        atomic_write_text(os.path.join(workdir, f"{_SWAP_PLUGIN}.py"), header + _SWAP_PLUGIN_BODY)

    def stage(self, source: str) -> str:
        """Stage ``source`` for the next run; returns the PYTHONPATH that loads the plugin."""
        atomic_write_text(self.source_file, source)
        Path(self.marker).unlink(missing_ok=True)
        inherited = os.environ.get("PYTHONPATH")
        return self.workdir + (os.pathsep + inherited if inherited else "")

    def loaded(self) -> bool:
        return os.path.exists(self.marker)


@dataclass
class TestRunResult:
    passed: bool
    status: str = "pass"  # "pass", "fail", "timeout", "missing_runner", "error"
    detail: str = ""
    loaded: bool = False  # the run imported the staged source for the target module


def _resolve_test_rootdir(test_files: Sequence[str]) -> Optional[str]:
    """Return a bounded pytest rootdir/confcutdir for *test_files*, or None if none exist on disk."""
    dirs = [os.path.dirname(os.path.abspath(f)) for f in test_files if f and os.path.exists(f)]
    if not dirs:
        return None
    try:
        common = os.path.commonpath(dirs)
    except ValueError:
        return None
    temp_root = os.path.normcase(os.path.realpath(tempfile.gettempdir()))
    cur = common
    conftest_root: Optional[str] = None
    while True:
        cur_norm = os.path.normcase(os.path.realpath(cur))
        base = os.path.basename(cur)
        if cur_norm == temp_root or base.startswith("pytest-of-"):
            break
        if any(os.path.exists(os.path.join(cur, marker)) for marker in ("pyproject.toml", "pytest.ini", "setup.cfg")):
            return cur
        if conftest_root is None and os.path.exists(os.path.join(cur, "conftest.py")):
            conftest_root = cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return conftest_root or common


def _filter_sys_path(entries: Sequence[str], test_files: Sequence[str], temp_root: str) -> list[str]:
    """The existing directories of *entries* a test run may import from: one under *temp_root* only
    when it holds a test file, so another run's scratch directory cannot shadow the code under test."""
    temp_key = real_key(temp_root)
    test_keys = [key for key in (real_key(f) for f in test_files if f and os.path.exists(f)) if key is not None]
    kept: list[str] = []
    for p in entries:
        if not p or not os.path.isdir(p):
            continue
        key = real_key(p)
        scratch = key is None or temp_key is None or key_within(key, temp_key)  # unresolvable counts as scratch
        if scratch and not (key is not None and any(key_within(t, key) for t in test_keys)):
            continue
        kept.append(p)
    return kept


def _check_tests(
    test_files: Sequence[str],
    timeout: int,
    swap: Optional[_ModuleSwap] = None,
    source: Optional[str] = None,
) -> TestRunResult:
    """Run pytest on *test_files* (with *source* staged for the target) and return a structured result."""
    from aegis_core.verification.test_runner import resolve_pytest_cmd

    pytest_cmd = resolve_pytest_cmd()
    if not pytest_cmd:
        return TestRunResult(
            passed=False,
            status="missing_runner",
            detail="pytest executable could not be resolved in active environment",
        )
    cmd = pytest_cmd + ["-x", "-q", "--no-header", "--tb=short", "-p", "no:cacheprovider"]
    rootdir = _resolve_test_rootdir(test_files)
    if rootdir is not None:
        cmd += [f"--rootdir={rootdir}", f"--confcutdir={rootdir}"]
    env_root = swap.workdir if swap is not None else tempfile.gettempdir()
    env = checkrun.hermetic_env(env_root)
    py_bin_dir = os.path.dirname(sys.executable)
    if py_bin_dir:
        existing_path = env.get("PATH", "")
        if py_bin_dir not in existing_path.split(os.pathsep):
            env["PATH"] = py_bin_dir + (os.pathsep + existing_path if existing_path else "")
    # No bytecode and no cache: the runs leave the tree as they found it.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    sys_dirs = os.pathsep.join(_filter_sys_path(sys.path, test_files, tempfile.gettempdir()))
    if swap is not None:
        cmd += ["-p", _SWAP_PLUGIN]
        staged = swap.stage(source or "")
        env["PYTHONPATH"] = staged + (os.pathsep + sys_dirs if sys_dirs else "")
    elif sys_dirs and not env.get("PYTHONPATH"):
        env["PYTHONPATH"] = sys_dirs
    cmd += list(test_files)
    try:
        popen_kwargs: dict[str, Any] = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "env": env,
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(cmd, **popen_kwargs)
        try:
            out_str, err_str = proc.communicate(timeout=timeout)
            returncode = proc.returncode
            stdout = out_str or ""
            stderr = err_str or ""
        except subprocess.TimeoutExpired:
            checkrun.kill_group(proc)
            try:
                proc.communicate()
            except Exception:
                pass
            raise
        finally:
            if os.name != "nt" or getattr(proc, "poll", lambda: None)() is None:
                checkrun.kill_group(proc)
    except subprocess.TimeoutExpired:
        return TestRunResult(
            passed=False,
            status="timeout",
            detail=f"timed out after {timeout}s",
            loaded=swap is not None and swap.loaded(),
        )
    except Exception as e:
        return TestRunResult(
            passed=False,
            status="error",
            detail=f"execution error: {e}",
        )
    loaded = swap is not None and swap.loaded()
    if returncode == 0:
        return TestRunResult(passed=True, status="pass", detail="", loaded=loaded)
    err_msg = (stderr or stdout or "").strip()
    tail = "\n".join(err_msg.splitlines()[-5:])
    return TestRunResult(
        passed=False,
        status="fail",
        detail=f"exit code {returncode}: {tail[:300]}",
        loaded=loaded,
    )


def _baseline_failure(run: TestRunResult, timeout: int, note: str) -> Optional[str]:
    """Why the unmutated code cannot be assessed, or None when its tests pass.

    A mutant counts as killed whenever the tests fail, so tests that cannot pass against
    the original code (syntax/import error, wrong assertion, timeout) would "kill" every
    mutant and pass (BUG-034). The caller fails closed instead.
    """
    if run.passed:
        return None
    if run.status == "timeout":
        return f"could not assess (timeout): the baseline run did not finish within {timeout}s ({note})"
    if run.status == "missing_runner":
        return f"Baseline tests fail against the unmutated code ({run.detail}); cannot assess mutations"
    return f"Baseline tests fail against the unmutated code ({run.detail}; {note}); cannot assess mutations"


def apply_mutation_point(source: str, point: MutationPoint) -> Optional[str]:
    """Apply a MutationPoint to source code using byte offsets or line/column coordinates.

    Returns the mutated source code, or None if the mutation cannot be applied safely.
    """
    orig = getattr(point, "original_op", None) or getattr(point, "original", "")
    repl = getattr(point, "replacement_op", None) or getattr(point, "mutated", "")
    if not orig:
        return None

    byte_offset = getattr(point, "byte_offset", None)
    # 1. Byte-offset fast path if offset is specified and matches
    if byte_offset is not None and 0 <= byte_offset <= len(source):
        orig_len = len(orig)
        if source[byte_offset : byte_offset + orig_len] == orig:
            return (
                source[: byte_offset]
                + repl
                + source[byte_offset + orig_len :]
            )

    # 2. Line and column coordinates
    lines = source.splitlines(keepends=True)
    if not (1 <= point.line <= len(lines)):
        return None

    target_line = lines[point.line - 1]
    col = getattr(point, "col", None)
    if col is None:
        col = getattr(point, "column", None)

    # Check at exact column
    if col is not None and 0 <= col < len(target_line):
        orig_len = len(orig)
        if target_line[col : col + orig_len] == orig:
            lines[point.line - 1] = (
                target_line[:col] + repl + target_line[col + orig_len :]
            )
            return "".join(lines)

    # Fallback: search for orig in the target line
    if orig in target_line:
        idx = target_line.find(orig)
        lines[point.line - 1] = (
            target_line[:idx] + repl + target_line[idx + len(orig) :]
        )
        return "".join(lines)

    return None


def collect_mutations_from_ast(
    norm_ast: NormalizedAST,
    target_function: Optional[str] = None,
) -> list[MutationPoint]:
    """Collect MutationPoints from a NormalizedAST filtered by function scope."""
    points = norm_ast.mutation_points or getattr(norm_ast, "mutations", ())
    if not points:
        return []
    if target_function is None:
        return list(points)
    return [
        m
        for m in points
        if getattr(m, "function_scope", None) is None or getattr(m, "function_scope", None) == target_function
    ]


# ── Public API ─────────────────────────────────────────────────────────────

def check(
    target_file: str,
    target_function: str,
    test_file: Union[str, Sequence[str]],
    max_mutations: int | None = None,
    target_lines: Optional[set[int]] = None,
    *,
    ast_runner: Any = None,
) -> ToolEvidence:
    """Run mutation testing on *target_function* in *target_file*.

    *test_file* is one test file or an ordered list of them; the first
    MAX_TEST_FILES run (the detail says how many ran and how many the cap left
    out), with a timeout that grows with their number. The baseline and every
    mutant run the same files. A mutant survives when the tests still pass
    against it (indicating a weak test); for Python targets it replaces the
    module for the whole test run, however the tests import it.

    Returns ToolEvidence with verdict=True if no mutations survive.
    """
    target_path = Path(target_file)
    source = target_path.read_text(encoding="utf-8")
    test_files, left_out = _bounded_test_files(test_file)
    timeout = _run_timeout(len(test_files))
    note = _files_note(len(test_files), left_out)

    def evidence(verdict: bool, detail: str, lines: Optional[list[int]] = None) -> ToolEvidence:
        return ToolEvidence(
            tool="mutation_tester",
            target=f"{target_file}::{target_function}",
            verdict=verdict,
            detail=detail,
            lines=lines or [],
        )

    if not test_files:
        return evidence(False, "could not assess: no test file to run")

    if target_path.suffix != ".py":
        from aegis_core.ast.runner import ASTDriverRunner
        runner = ast_runner or ASTDriverRunner()
        try:
            norm_ast = runner.parse_file(target_file)
        except Exception as e:
            return evidence(False, f"Failed to parse NormalizedAST via driver: {e}")

        mutation_points = collect_mutations_from_ast(norm_ast, target_function)
        if target_lines is not None:
            mutation_points = [m for m in mutation_points if m.line in target_lines]

        if not mutation_points:
            return evidence(True, "No mutations on modified lines")

        if max_mutations is not None:
            mutation_points = mutation_points[:max_mutations]

        total = len(mutation_points)
        survived: list[int] = []

        failure = _baseline_failure(_check_tests(test_files, timeout), timeout, note)
        if failure:
            return evidence(False, failure, [-1])

        # Stage non-Python mutants in an isolated temporary directory rather than
        # leaving sibling files beside the source tree.
        with tempfile.TemporaryDirectory(prefix="aegis-mutant-") as mutant_dir:
            for m in mutation_points:
                mutated_source = apply_mutation_point(source, m)
                if mutated_source is None:
                    continue
                tmp_path = os.path.join(mutant_dir, f"_mutant_{target_path.name}")
                atomic_write_text(tmp_path, mutated_source)
                try:
                    if _check_tests(test_files, timeout).passed:
                        survived.append(m.line)
                finally:
                    Path(tmp_path).unlink(missing_ok=True)

        return evidence(not survived, f"{len(survived)}/{total} survived ({note})", sorted(set(survived)))

    if _function_node(ast.parse(source), target_function) is None:
        return evidence(False, f"could not assess: no function named {target_function} in {target_path.name}")

    all_mutations = _collect_mutations(source, target_function)

    # Filter mutations to target_lines if restricted scope was provided
    mutation_candidates: list[tuple[int, _Mutation]] = []
    for idx, mut in enumerate(all_mutations):
        if target_lines is not None and mut.lineno not in target_lines:
            continue
        mutation_candidates.append((idx, mut))

    if target_lines is not None and not mutation_candidates:
        return evidence(True, "No mutations on modified lines")

    if max_mutations is not None:
        mutation_candidates = mutation_candidates[:max_mutations]

    total = len(mutation_candidates)
    if not total:
        return evidence(True, "0/0 survived (no mutations to apply)")

    try:
        # The baseline runs the unmutated module through the same unparse-and-load
        # path as the mutants, so a mutant run can differ from it only by the mutation.
        unmutated = ast.unparse(ast.parse(source))
    except Exception as exc:
        return evidence(False, f"could not assess: cannot regenerate {target_path.name}: {type(exc).__name__}: {exc}", [-1])

    survived = []
    with tempfile.TemporaryDirectory(prefix="aegis-mutants-") as workdir:
        swap = _ModuleSwap(target_path, workdir)
        baseline = _check_tests(test_files, timeout, swap, unmutated)
        failure = _baseline_failure(baseline, timeout, note)
        if failure:
            return evidence(False, failure, [-1])
        if not baseline.loaded:
            # Nothing that ran imports the module, so no test can detect any mutant.
            lines = sorted({mutation.lineno for _, mutation in mutation_candidates})
            return evidence(False, f"{total}/{total} survived: no test that ran imported {target_path.name} ({note})", lines)

        for orig_idx, mutation in mutation_candidates:
            mutated_source = _apply_mutation_by_index(source, target_function, orig_idx)
            if mutated_source is None:
                continue
            run = _check_tests(test_files, timeout, swap, mutated_source)
            if run.status == "timeout" and not run.loaded:
                run = _check_tests(test_files, timeout, swap, mutated_source)
            # Killed only by a failing (or hung) run; a non-timeout run that
            # never loaded the mutant says nothing about the tests.
            if run.status != "timeout" and (run.passed or not run.loaded):
                survived.append(mutation.lineno)

    return evidence(not survived, f"{len(survived)}/{total} survived ({note})", sorted(set(survived)))
