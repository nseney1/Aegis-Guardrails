"""Shrink-only source line and ast.stmt budgets (packing lines cannot evade them)."""
import ast
import json
from pathlib import Path
import sys

import pytest

REPO = Path(__file__).resolve().parents[2]
RECORD = Path(__file__).with_name("size_ratchet.json")
PACKAGES = ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk")
# Standalone Rust driver template; it is shipped to another interpreter, not imported.
EXEMPT = {"aegis_core/ast/drivers/templates/rust_ast.py"}


def test_size_record_matches_tree():
    assert size_errors(measure_sizes(REPO), json.loads(RECORD.read_text())) == []


def test_new_oversized_module_and_packed_function_fail(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "large.py"
    path.write_text("# line\n" * 1000 + "x = 1\n", encoding="utf-8")
    current = measure_sizes(tmp_path)
    assert size_errors(current, {"modules": {}, "functions": {}}) == ["new oversized module: aegis_core/large.py"]
    path.write_text("def go():\n" + "    x = 1\n" * 100, encoding="utf-8")
    before = measure_sizes(tmp_path)
    path.write_text(path.read_text() + "    x = 2; y = 3\n", encoding="utf-8")
    errors = size_errors(measure_sizes(tmp_path), before)
    assert any("aegis_core/large.py:go" in e and "stmts 101 -> 103" in e for e in errors)


def test_shrink_requires_lower_pin_and_write_cannot_raise(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "large.py"
    path.write_text("x = 1\n" * 1051, encoding="utf-8")
    before = measure_sizes(tmp_path)
    path.write_text("x = 1\n" * 1001, encoding="utf-8")
    current = measure_sizes(tmp_path)
    assert any("lower the ratchet" in e for e in size_errors(current, before))
    with pytest.raises(ValueError, match="refusing to raise"):
        lowered_sizes(current, before)
    assert lowered_sizes(before, current) == current


def test_syntax_error_is_not_skipped(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "bad.py").write_text("def broken(\n", encoding="utf-8")
    with pytest.raises(SyntaxError) as err:
        measure_sizes(tmp_path)
    assert err.value.filename == "aegis_core/bad.py"


def measure_sizes(root):
    result = {"modules": {}, "functions": {}}
    for package in PACKAGES:
        for path in sorted((root / package).rglob("*.py")):
            rel = path.relative_to(root).as_posix()
            if rel in EXEMPT:
                continue
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=rel)
            result["modules"][rel] = {"lines": len(source.splitlines()),
                                      "stmts": sum(isinstance(n, ast.stmt) for n in ast.walk(tree))}

            def functions(node, scope=""):
                for child in ast.iter_child_nodes(node):
                    name = scope
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        name = f"{scope}.{child.name}" if scope else child.name
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        first = min([child.lineno] + [d.lineno for d in child.decorator_list])
                        result["functions"][f"{rel}:{name}"] = {
                            "lines": child.end_lineno - first + 1,
                            "stmts": sum(isinstance(n, ast.stmt) for n in ast.walk(child))}
                    functions(child, name)
            functions(tree)
    return result


def oversized(current):
    return {kind: {k: v for k, v in rows.items() if v["lines"] > (1000 if kind == "modules" else 100)}
            for kind, rows in current.items()}


def size_errors(current, record):
    errors = []
    for kind, limit in (("modules", 1000), ("functions", 100)):
        for key, values in current[kind].items():
            pin = record[kind].get(key)
            if pin is None:
                if values["lines"] > limit:
                    errors.append(f"new oversized {kind[:-1]}: {key}")
            else:
                for metric in ("lines", "stmts"):
                    if values[metric] != pin[metric]:
                        note = "growth" if values[metric] > pin[metric] else "lower the ratchet"
                        errors.append(f"{key}: {metric} {pin[metric]} -> {values[metric]} ({note})")
        for key in record[kind].keys() - current[kind].keys():
            errors.append(f"{key}: removed; lower the ratchet")
    if current["modules"].get("aegis_core/gitsafe.py", {}).get("lines", 0) > 1250:
        errors.append("aegis_core/gitsafe.py: exceeds the 1250-line ceiling")
    return errors


def lowered_sizes(record, current):
    errors = [e for e in size_errors(current, record) if "lower the ratchet" not in e]
    if errors:
        raise ValueError("refusing to raise size records: " + repr(errors))
    # Keep lowered entries even below the threshold, so their recovered headroom cannot regrow.
    return {kind: {k: current[kind][k] for k in rows if k in current[kind]} for kind, rows in record.items()}


if __name__ == "__main__":
    if sys.argv[1:] != ["--write"]:
        sys.exit("usage: python3 tests/contract/test_module_size.py --write")
    record = json.loads(RECORD.read_text())
    try:
        updated = lowered_sizes(record, measure_sizes(REPO))
    except ValueError as exc:
        sys.exit(str(exc))
    RECORD.write_text(json.dumps(updated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
