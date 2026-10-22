"""Ratchets for the L0 storage layer (ADR 0005 AD-3, build-sheet D12).

1. Every write of Aegis state or rule files goes through aegis_core.storage: no
   ``open(..., "w"|"a"|"x")``, ``write_text``, ``write_bytes`` or ``shutil.copy*``
   anywhere else in aegis_core/aegis_cli/aegis_mcp/aegis_sdk, except the writers listed below,
   which write files outside ``.aegis/``.
2. aegis_core/workspace/layout.py is the only module that spells an ``.aegis`` path.
   User-facing sentences may mention one; a string literal that *is* a path may not.
"""
from __future__ import annotations

import ast
from pathlib import Path
import re

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
PACKAGES = ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk")

# (file, enclosing function) -> what it writes. Adding an entry is a reviewed decision.
NON_AEGIS_WRITERS = {
    ("aegis_cli/verify.py", "_append_step_summary"): "$GITHUB_STEP_SUMMARY, appended once per run as every job step does (outside the workspace)",
    ("aegis_cli/hooks/management.py", "install_hook"): "the git pre-commit hook (.git/hooks)",
    ("aegis_cli/hooks/management.py", "uninstall_hook"): "the git pre-commit hook (.git/hooks)",
    ("aegis_cli/hooks/commitmsg.py", "install"): "the git prepare-commit-msg hook (.git/hooks)",
    ("aegis_core/baseline.py", "Sources._ast"): "a staged non-Python blob copied into a temporary directory for the AST driver",
    ("aegis_core/verification/runner.py", "snapshot_index"): "staged blobs in a temporary directory (aegis check --hook)",
    ("aegis_core/checkrun.py", "run_tests"): "the test run's output in a temporary directory (aegis check --record)",
    ("aegis_core/treeid.py", "bind"): "a copy of the git index in a private temporary directory (tree identity)",
    ("aegis_core/benchmark.py", "materialize"): "the fixture corpus in a temporary directory (aegis benchmark)",
    ("aegis_core/release_verify.py", "verify_release"): "the attestation subject in a temporary directory (aegis doctor --release)",
}
_WRITE_MODE = re.compile(r"[wax+]")
_COPIES = {"copy", "copy2", "copyfile", "copytree"}


def _sources():
    for pkg in PACKAGES:
        for path in sorted((ROOT / pkg).rglob("*.py")):
            yield path.relative_to(ROOT).as_posix(), ast.parse(path.read_text(encoding="utf-8"))


class _Writes(ast.NodeVisitor):
    def __init__(self) -> None:
        self.stack: list[str] = []
        self.found: list[tuple[str, int, str]] = []

    def _scope(self, node) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _scope

    def visit_Call(self, node: ast.Call) -> None:
        func, what = node.func, None
        if isinstance(func, ast.Name) and func.id == "open":
            what = self._mode(node, 1)
        elif isinstance(func, ast.Attribute):
            if func.attr in ("write_text", "write_bytes"):
                what = func.attr
            elif func.attr == "open":
                what = self._mode(node, 0)
            elif func.attr == "fdopen":
                what = self._mode(node, 1)
            elif func.attr in _COPIES and isinstance(func.value, ast.Name) and func.value.id == "shutil":
                what = f"shutil.{func.attr}"
        if what:
            self.found.append((".".join(self.stack) or "<module>", node.lineno, what))
        self.generic_visit(node)

    @staticmethod
    def _mode(node: ast.Call, index: int):
        mode = node.args[index] if len(node.args) > index else None
        for kw in node.keywords:
            if kw.arg == "mode":
                mode = kw.value
        if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and _WRITE_MODE.search(mode.value):
            return f"open({mode.value!r})"
        return None


def test_state_and_rule_writes_go_through_storage():
    offenders = []
    for rel, tree in _sources():
        if rel == "aegis_core/storage.py":
            continue
        visitor = _Writes()
        visitor.visit(tree)
        for scope, lineno, what in visitor.found:
            key = (rel, scope.split(".<")[0])
            if key in NON_AEGIS_WRITERS or (rel, scope) in NON_AEGIS_WRITERS:
                continue
            offenders.append(f"{rel}:{lineno} {scope} {what}")
    assert offenders == [], "write through aegis_core.storage, or list a non-.aegis writer"


def test_every_allowlisted_writer_still_exists():
    """A writer that was removed or renamed leaves a stale exemption behind."""
    present = set()
    for rel, tree in _sources():
        visitor = _Writes()
        visitor.visit(tree)
        present |= {(rel, scope) for scope, _lineno, _what in visitor.found}
    assert set(NON_AEGIS_WRITERS) - present == set()


_PATH_LITERAL = re.compile(r"^[~/\\]*\.aegis(?:[/\\][^\s]*)?$")


def _docstrings(tree: ast.AST) -> set:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def test_only_layout_spells_aegis_paths():
    offenders = []
    for rel, tree in _sources():
        if rel == "aegis_core/workspace/layout.py":
            continue
        skip = _docstrings(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip \
                    and _PATH_LITERAL.match(node.value):
                offenders.append(f"{rel}:{node.lineno} {node.value!r}")
    assert offenders == [], "ask aegis_core.workspace.layout for the path"
