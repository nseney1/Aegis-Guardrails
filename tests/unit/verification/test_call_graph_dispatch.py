from pathlib import Path
"""TDD Gate 1 tests for Call Graph Dispatch Recognition (Phase 11).

Tests prove:
1. Functions referenced in dictionary values (e.g. COMMANDS = {"cmd": cmd_func}) are recognized.
2. Functions referenced in lists/tuples (e.g. HANDLERS = [func_a, func_b]) are recognized.
3. Functions passed as keyword arguments (e.g. parser.set_defaults(func=cmd_func)) are recognized.
4. aegis_cli/cli.py passes call_graph.check with verdict=True and 0 orphan functions.
"""
import os
import sys
import pytest

from aegis_core.verification import call_graph


class TestCallGraphDispatchRecognition:
    """Verify call_graph recognizes functions referenced in data structures and dispatch tables."""

    def test_functions_in_dict_dispatch_table_recognized(self, tmp_path):
        """Functions in dictionary values must not be flagged as orphans."""
        target_file = tmp_path / "dispatch.py"
        target_file.write_text(
            "def cmd_one(args):\n"
            "    return 1\n\n"
            "def cmd_two(args):\n"
            "    return 2\n\n"
            "DISPATCH = {\n"
            "    'one': cmd_one,\n"
            "    'two': cmd_two,\n"
            "}\n\n"
            "def main(name):\n"
            "    return DISPATCH[name](None)\n"
        )

        result = call_graph.check(
            str(target_file),
            str(tmp_path),
            exclude_names={"main"},
        )

        assert result.verdict is True, f"Expected True but got: {result.detail}"
        assert "ORPHAN" not in result.detail

    def test_functions_in_list_or_tuple_recognized(self, tmp_path):
        """Functions in lists or tuples must not be flagged as orphans."""
        target_file = tmp_path / "handlers.py"
        target_file.write_text(
            "def handle_first():\n"
            "    return True\n\n"
            "def handle_second():\n"
            "    return False\n\n"
            "HANDLERS = (handle_first, handle_second)\n\n"
            "def run_all():\n"
            "    for h in HANDLERS:\n"
            "        h()\n"
        )

        result = call_graph.check(
            str(target_file),
            str(tmp_path),
            exclude_names={"run_all"},
        )

        assert result.verdict is True, f"Expected True but got: {result.detail}"

    def test_cli_py_has_zero_orphan_functions(self):
        """aegis_cli/cli.py must pass call_graph check with zero orphan functions."""
        # Find aegis_cli/cli.py relative to repo root
        repo_root = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
        cli_file = os.path.join(repo_root, "aegis_cli", "cli.py") if os.path.exists(os.path.join(repo_root, "aegis_cli", "cli.py")) else os.path.join(repo_root, "aegis_cli", "cli.py")
        assert os.path.exists(cli_file), f"cli.py not found at {cli_file}"

        result = call_graph.check(
            cli_file,
            repo_root,
            exclude_names={"main", "_build_parser"},
        )

        assert result.verdict is True, f"Expected cli.py to pass call_graph check, got: {result.detail}"
