"""Check-local AST results, including failures, shared by Layer 1 consumers."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from aegis_core.ast.policy import extract_normalized_ast
from aegis_core.ast.runner import ASTDriverRunner


class ASTParseSession:
    """Extract each requested AST at most once; close batch processes at pass end."""

    def __init__(self, workspace_root: str, *, confine_root: Optional[str] = None,
                 runner: Optional[ASTDriverRunner] = None, owns_runner: bool = True,
                 result_sink: Optional[dict[str, Any]] = None):
        self.workspace_root = workspace_root
        self.confine_root = confine_root
        self.runner = runner or ASTDriverRunner()
        self.owns_runner = owns_runner
        self.result_sink = result_sink
        self._cache_root = Path(confine_root or workspace_root).resolve()
        self._results: dict[str, Any] = {}

    def __enter__(self):
        self.runner.__enter__()
        return self

    def __exit__(self, *exc):
        if self.owns_runner:
            return self.runner.__exit__(*exc)

    def get(self, path: str):
        key = str(Path(path).resolve())
        if key not in self._results:
            try:
                self._results[key] = extract_normalized_ast(
                    key, workspace_root=self.workspace_root, ast_runner=self.runner,
                    confine_root=self.confine_root,
                )
            except Exception as exc:
                self._results[key] = exc
        result = self._results[key]
        if self.result_sink is not None and Path(key).is_relative_to(self._cache_root):
            self.result_sink[Path(key).relative_to(self._cache_root).as_posix()] = result
        if isinstance(result, Exception):
            raise result
        return result
