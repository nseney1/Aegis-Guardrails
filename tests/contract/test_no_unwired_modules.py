"""Reachability floor: runtime imports and exported names must have runtime consumers.

This is a static wiring check, not proof that a path runs. Lazy imports count; imports
in test files or script-only __main__ bodies do not. Exemptions start empty.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.contract.test_import_boundary import REPO, _module_files, import_edges, import_nodes
from tests.contract.test_process_ratchets import ScopedNames, import_bindings

MODULE_PREFIXES = ('aegis_core.verification', 'aegis_core.ast', 'aegis_cli.formatters')
EXPORT_PREFIXES = ('aegis_core.verification', 'aegis_cli.formatters')
UNWIRED_MODULES: frozenset[str] = frozenset()
UNWIRED_EXPORTS: frozenset[str] = frozenset()


def _under(name: str, prefixes: tuple[str, ...]) -> bool:
    return any(name == prefix or name.startswith(prefix + '.') for prefix in prefixes)


_runtime_nodes = import_nodes


def _runtime_imports(root: Path):
    # Keep the established module resolver. Filter script-only sites here too so this
    # guard works before and after the boundary scanner adds its own main exclusion.
    sites = {(module, node.lineno) for module, path in _module_files(root).items()
             for node in _runtime_nodes(ast.parse(path.read_text(encoding='utf-8')))
             if isinstance(node, (ast.Import, ast.ImportFrom, ast.Call))}
    return [edge for edge in import_edges(root)
            if (edge.source, int(edge.where.rsplit(':', 1)[1])) in sites]


def orphan_modules(root: Path) -> list[str]:
    modules = _module_files(root)
    imported = {edge.target for edge in _runtime_imports(root) if edge.source != edge.target}
    return sorted(module for module in modules if _under(module, MODULE_PREFIXES) and not any(target == module or target.startswith(module + ".") for target in imported))


def unused_exports(root: Path) -> list[str]:
    modules = _module_files(root)
    # Imports and attribute references share the script-body exclusion.
    sites = {(edge.source, int(edge.where.rsplit(':', 1)[1])) for edge in _runtime_imports(root)}
    exports = {}
    references = {}
    for module, path in modules.items():
        tree = ast.parse(path.read_text(encoding='utf-8'))
        rel = path.relative_to(root).as_posix()
        resolver = ScopedNames(tree, rel, runtime_only=True)
        used = set()
        for node in _runtime_nodes(tree):
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == '__all__'
                                                   for t in node.targets):
                if _under(module, EXPORT_PREFIXES):
                    # Refuse dynamic exports: an unevaluated list must not silently evade this guard.
                    names = ast.literal_eval(node.value)
                    assert isinstance(names, (list, tuple)) and all(isinstance(n, str) for n in names)
                    exports[module] = names
            if (module, getattr(node, 'lineno', None)) not in sites:
                continue
            if isinstance(node, ast.ImportFrom):
                # An explicit import is a reference, including an intentional re-export.
                used.update(import_bindings(node, rel).values())
        for node in _runtime_nodes(tree):
            if isinstance(node, ast.Attribute):
                used.update(resolver.resolve(node))
        references[module] = used
    return sorted(f'{module}.{name}' for module, names in exports.items() for name in names
                  if not any(f'{module}.{name}' in used for caller, used in references.items() if caller != module))


def test_every_selected_module_has_a_runtime_importer():
    assert orphan_modules(REPO) == sorted(UNWIRED_MODULES)


def test_every_declared_export_has_a_runtime_reference():
    assert unused_exports(REPO) == sorted(UNWIRED_EXPORTS)


def test_wiring_exemptions_remain_empty():
    assert UNWIRED_MODULES == UNWIRED_EXPORTS == frozenset()


def _write(root: Path, name: str, text: str):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


def test_only_runtime_importers_wire_a_module(tmp_path):
    _write(tmp_path, 'aegis_core/verification/new.py', 'def check(): pass\n')
    _write(tmp_path, 'tests/test_new.py', 'import aegis_core.verification.new\n')
    assert orphan_modules(tmp_path) == ['aegis_core.verification.new']
    _write(tmp_path, 'aegis_cli/check.py', 'if __name__ == "__main__":\n    import aegis_core.verification.new\n')
    assert orphan_modules(tmp_path) == ['aegis_core.verification.new']
    _write(tmp_path, 'aegis_cli/check.py', 'def run():\n    from aegis_core.verification import new\n')
    assert orphan_modules(tmp_path) == []


def test_export_guard_resolves_imports_and_ignores_unrelated_names(tmp_path):
    _write(tmp_path, 'aegis_core/verification/new.py', '__all__ = ["check", "orphan"]\ndef check(): pass\ndef orphan(): pass\norphan()\n')
    _write(tmp_path, 'tests/test_new.py', 'from aegis_core.verification.new import orphan\n')
    _write(tmp_path, 'aegis_cli/check.py', 'def run(other):\n    from aegis_core.verification import new as renamed\n    renamed.check()\n    other.orphan()\n')
    assert unused_exports(tmp_path) == ['aegis_core.verification.new.orphan']
    _write(tmp_path, 'aegis_cli/check.py', 'from aegis_core.verification.new import check, orphan\n')
    assert unused_exports(tmp_path) == []


def test_main_only_import_does_not_count_as_an_export_consumer(tmp_path):
    _write(tmp_path, 'aegis_core/verification/new.py', '__all__ = ["check"]\ndef check(): pass\n')
    _write(tmp_path, 'aegis_cli/check.py', 'if __name__ == "__main__":\n    from aegis_core.verification.new import check\n')
    assert unused_exports(tmp_path) == ['aegis_core.verification.new.check']
    _write(tmp_path, 'aegis_cli/check.py', 'from aegis_core.verification import new\nif __name__ == "__main__":\n    new.check()\n')
    assert unused_exports(tmp_path) == ['aegis_core.verification.new.check']
    _write(tmp_path, 'aegis_cli/check.py', 'from aegis_core.verification import new\nif __name__ == "__main__":\n    pass\nelse:\n    new.check()\n')
    assert unused_exports(tmp_path) == []


def test_dynamic_export_lists_fail_loudly(tmp_path):
    _write(tmp_path, 'aegis_core/verification/new.py', '__all__ = exported_names()\n')
    with pytest.raises(ValueError, match='malformed node or string'):
        unused_exports(tmp_path)


@pytest.mark.parametrize("reverse", [False, True])
def test_export_consumers_do_not_leak_between_sibling_scopes(tmp_path, reverse):
    _write(tmp_path, 'aegis_core/verification/new.py',
           '__all__ = ["check", "orphan"]\ndef check(): pass\ndef orphan(): pass\n')
    pieces = ['def unrelated():\n    import other as backend\n    backend.orphan()\n',
              'def real():\n    from aegis_core.verification import new as backend\n    backend.check()\n']
    _write(tmp_path, 'aegis_cli/check.py', '\n'.join(reversed(pieces) if reverse else pieces))
    assert unused_exports(tmp_path) == ['aegis_core.verification.new.orphan']


def test_export_parameter_shadows_a_module_alias(tmp_path):
    _write(tmp_path, 'aegis_core/verification/new.py', '__all__ = ["orphan"]\ndef orphan(): pass\n')
    _write(tmp_path, 'aegis_cli/check.py',
           'from aegis_core.verification import new as backend\ndef unrelated(backend):\n    backend.orphan()\n')
    assert unused_exports(tmp_path) == ['aegis_core.verification.new.orphan']
