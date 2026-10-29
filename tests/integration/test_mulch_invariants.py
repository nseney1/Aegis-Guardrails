"""Architectural invariants from the v0.96.0 Tempest Review that still hold in v4.

1. Symbol authority: every name in an aegis_core module's __all__ resolves.
2. Fail-closed confinement: workspace path confinement rejects relative and
   absolute traversal, Windows device names and alternate data streams.

Layer decoupling moved to tests/contract/test_import_boundary.py (AD-3). The
receipt, MCP rate-limit and bug-registry invariants were retired with the
features (ADR 0005 D2, D4, D8).
"""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from aegis_core.workspace import confine_path, resolve_workspace


REPO_ROOT = Path(resolve_workspace(__file__))


class TestInvariant2_SymbolAuthority:
    """Invariant 2: All symbols declared in __all__ across core modules must be resolvable."""

    def test_all_symbols_resolvable(self):
        core_dir = REPO_ROOT / "aegis_core"
        python_files = sorted(p for p in core_dir.rglob("*.py") if p.name != "__main__.py")

        missing_symbols = []
        for py_file in python_files:
            parts = list(py_file.relative_to(REPO_ROOT).with_suffix("").parts)
            if parts[-1] == "__init__":
                parts.pop()
            module_name = ".".join(parts)
            mod = importlib.import_module(module_name)
            if py_file.parent == core_dir and py_file.name != "__init__.py":
                assert hasattr(mod, "__all__"), f"{module_name} lacks __all__ declaration"
            exported = getattr(mod, "__all__", [])
            for sym in exported:
                if not hasattr(mod, sym):
                    missing_symbols.append((module_name, sym))

        assert not missing_symbols, f"Exported symbols missing from modules: {missing_symbols}"


class TestInvariant3_FailClosedConfinement:
    """Invariant 4: Path confinement rejects traversals, device names, and streams."""

    @pytest.mark.parametrize("bad_path", [
        "../outside.txt",
        "../../etc/passwd",
        "/etc/shadow",
        "foo/../../bar/../../baz",
        "COM1",
        "LPT2",
        "NUL",
        "CON",
        "CONIN$",
        "CONOUT$",
        "aux.txt",

        "safe.txt:hidden_stream",
        "file::$DATA",
    ])
    def test_confine_path_fails_closed(self, tmp_path, bad_path):
        with pytest.raises(ValueError):
            confine_path(bad_path, str(tmp_path))


def test_symbol_authority_includes_package_exports(monkeypatch):
    from aegis_core import command_safety
    monkeypatch.setattr(command_safety, "__all__", ["missing_export"])
    with pytest.raises(AssertionError, match="aegis_core.command_safety.*missing_export"):
        TestInvariant2_SymbolAuthority().test_all_symbols_resolvable()
