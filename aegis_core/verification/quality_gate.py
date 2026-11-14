"""Deterministic AST-based test quality checks (Phase 2H).

Layer 1 tools that parse a test module and judge each ``test_*`` function on its
own, without any LLM: one real assertion in a file must not cover for the stubs
next to it (#1). ``checkpoint_checks.check_assertion_density`` runs both checks
over a workspace's ``tests/`` tree.
"""
from __future__ import annotations

import ast
from typing import List, Tuple, Union

from aegis_core.ast.drivers.python import read_python_source

from . import ToolEvidence

_FuncDef = Union[ast.FunctionDef, ast.AsyncFunctionDef]
_FUNC_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef)

# pytest.fail / self.fail fail the test on the path they guard: an assertion.
# A skip or xfail only declares that the test did not run, so it asserts nothing.
_FAIL_CALLS = {("pytest", "fail"), ("self", "fail")}
_SKIP_CALLS = {("pytest", "skip"), ("pytest", "xfail"), ("self", "skipTest")}
_PYTEST_CONTEXT_ASSERTIONS = {"raises", "warns", "deprecated_call"}
# The call forms check on their own: pytest.raises(E, func, *args), pytest.warns(W, func),
# pytest.deprecated_call(func). With fewer arguments they only build an unused context manager.
_PYTEST_CALL_FORM_MIN_ARGS = {"raises": 2, "warns": 2, "deprecated_call": 1}


# ── Helpers ────────────────────────────────────────────────────────────────


def _is_fixture(func: _FuncDef) -> bool:
    """True for ``@pytest.fixture``, ``@pytest.fixture(...)`` and ``@fixture``."""
    for dec in func.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute) and target.attr == "fixture":
            return True
        if isinstance(target, ast.Name) and target.id == "fixture":
            return True
    return False


def _collect_test_functions(tree: ast.Module) -> list[_FuncDef]:
    """Return all ``test_*`` functions, top-level and in classes, except fixtures.

    A fixture may be named ``test_*`` (``def test_workspace(tmp_path)``); pytest
    never runs it as a test, so it is not judged as one.
    """
    funcs: list[_FuncDef] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("test_") and not _is_fixture(node):
                funcs.append(node)
    return funcs


def _callee_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _receiver(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id
    return ""


def _is_assertion_call(call: ast.Call) -> bool:
    """An assertion helper or an explicit failure.

    Recognized: any call whose name starts with ``assert``/``_assert`` (``self.assertEqual``,
    ``mock.assert_called_once_with``, ``np.testing.assert_equal``, a project helper such as
    ``assert_identical``), ``pytest.fail`` and ``self.fail``.
    """
    name = _callee_name(call)
    if name.startswith(("assert", "_assert")):
        return True
    return (_receiver(call), name) in _FAIL_CALLS


def _skips(func: _FuncDef) -> bool:
    return any(
        isinstance(node, ast.Call) and (_receiver(node), _callee_name(node)) in _SKIP_CALLS
        for node in ast.walk(func)
    )


def _environment_placeholders(tree: ast.Module) -> set[int]:
    """ids of skipping tests that stand in for a real same-name test in the other ``if`` branch.

    ``if HAVE_X: def test_a(): <real> else: def test_a(): pytest.skip(...)`` defines one
    test either way; the real branch is judged on its own, so the placeholder is exempt.
    A twin that is itself only a skip is not real: two placeholders never excuse each other.
    """
    exempt: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        branches = (node.body, node.orelse)
        real = [
            {f.name for f in branch if isinstance(f, _FUNC_TYPES) and (_has_assert(f) or not _skips(f))}
            for branch in branches
        ]
        for branch, other_real in zip(branches, reversed(real)):
            for func in branch:
                if isinstance(func, _FUNC_TYPES) and func.name in other_real and _skips(func):
                    exempt.add(id(func))
    return exempt


def _has_assert(func: _FuncDef) -> bool:
    """Return True if *func*'s body contains an assertion or assertion-equivalent."""
    for node in ast.walk(func):
        if isinstance(node, ast.Assert):
            return True
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                ctx = item.context_expr
                if (
                    isinstance(ctx, ast.Call)
                    and _receiver(ctx) == "pytest"
                    and _callee_name(ctx) in _PYTEST_CONTEXT_ASSERTIONS
                ):
                    return True
        if isinstance(node, ast.Call):
            if _is_assertion_call(node):
                return True
            min_args = _PYTEST_CALL_FORM_MIN_ARGS.get(_callee_name(node))
            if min_args and _receiver(node) == "pytest" and len(node.args) >= min_args:
                return True
    return False


def _is_docstring_node(node: ast.stmt) -> bool:
    """Return True if *node* is a standalone string-expression (docstring)."""
    return (
        isinstance(node, ast.Expr)
        # ast.Str was removed in Python 3.14; ast.Constant covers it since 3.8.
        and isinstance(node.value, ast.Constant)
        and isinstance(getattr(node.value, "value", None), str)
    )


def _is_pass_or_ellipsis(node: ast.stmt) -> bool:
    if isinstance(node, ast.Pass):
        return True
    return isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and node.value.value is ...


def _is_bare_pass_func(func: _FuncDef) -> bool:
    """True if the function body (ignoring a leading docstring) is only pass/ellipsis."""
    body = list(func.body)
    if body and _is_docstring_node(body[0]):
        body = body[1:]
    if not body:
        return True
    return len(body) == 1 and _is_pass_or_ellipsis(body[0])


def _parse(test_file: str) -> ast.Module:
    return ast.parse(read_python_source(test_file), filename=test_file)


def _evidence(tool: str, test_file: str, offenders: List[Tuple[str, int]], fail: str, ok: str) -> ToolEvidence:
    if offenders:
        return ToolEvidence(
            tool=tool,
            target=test_file,
            verdict=False,
            detail=f"{fail}: {', '.join(name for name, _ in offenders)}",
            lines=[lineno for _, lineno in offenders],
        )
    return ToolEvidence(tool=tool, target=test_file, verdict=True, detail=ok, lines=[])


def _assertion_density(tree: ast.Module, test_file: str) -> ToolEvidence:
    placeholders = _environment_placeholders(tree)
    missing = [
        (f.name, f.lineno)
        for f in _collect_test_functions(tree)
        if id(f) not in placeholders and not _has_assert(f)
    ]
    return _evidence("assertion_density", test_file, missing, "Tests lacking assertions", "All tests have assertions")


def _no_bare_pass(tree: ast.Module, test_file: str) -> ToolEvidence:
    stubs = [(f.name, f.lineno) for f in _collect_test_functions(tree) if _is_bare_pass_func(f)]
    return _evidence("no_bare_pass", test_file, stubs, "Bare pass/ellipsis stubs", "No bare pass stubs found")


# ── Public API ─────────────────────────────────────────────────────────────


def check_test_quality(test_file: str) -> Tuple[ToolEvidence, ToolEvidence]:
    """Read and parse once, returning density then bare-pass evidence.

    The tree is local to this call; input errors propagate to the caller.
    """
    tree = _parse(test_file)
    return _assertion_density(tree, test_file), _no_bare_pass(tree, test_file)


def check_assertion_density(test_file: str) -> ToolEvidence:
    """Check that every ``test_*`` function in *test_file* has ≥1 assertion.

    Syntactic, so these limits are accepted: an assertion anywhere in the body counts,
    including one in a nested def that is never called or under ``if False:``, and any
    call named ``assert*`` counts as an assertion helper.
    """
    return _assertion_density(_parse(test_file), test_file)


def check_no_bare_pass(test_file: str) -> ToolEvidence:
    """Check that no ``test_*`` function is a bare pass/ellipsis stub."""
    return _no_bare_pass(_parse(test_file), test_file)
