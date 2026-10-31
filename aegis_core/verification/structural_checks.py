"""Structural checks sharing the check-local non-Python parse result."""
from __future__ import annotations

import os
import posixpath
from typing import Any

from aegis_core.match import is_test_path
from aegis_core.verification import call_graph, import_guard


def run_checks(paths: list[tuple[str, str]], root: str, session: Any, *, fast_mode: bool,
               failure: Any, not_in_commit: Any = None) -> list:
    results = []
    checked = [(rel, path) for rel, path in paths
               if not (is_test_path(rel) or posixpath.basename(rel) == '__init__.py')]
    for rel, path in checked:
        try:
            if os.path.splitext(rel)[1].lower() == '.py':
                results.append(call_graph.check(path, root, exclude_names={'main', '_parse_args', 'parse_args'},
                                                fast_mode=fast_mode))
            else:
                tree = session.get(path)
                if tree is not None:
                    results.append(call_graph.check_normalized(
                        tree, root, exclude_names={'main', '_parse_args', 'parse_args'},
                        fast_mode=fast_mode, ast_runner=session.runner,
                    ))
        except Exception as exc:
            results.append(failure('call_graph', rel, exc))
    for rel, path in checked:
        if rel.endswith('.py'):
            try:
                result = import_guard.check(path, project_root=root)
                missing = not_in_commit(rel, path, root) if not_in_commit and not result.verdict else []
                if missing:
                    result.detail += (f"; {', '.join(missing)} {'is' if len(missing) == 1 else 'are'} not staged or "
                                      'tracked, so the commit would not include it')
                results.append(result)
            except Exception as exc:
                results.append(failure('import_guard', rel, exc))
    return results
