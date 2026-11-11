"""Shrink-only line/ast.stmt budgets, with named tools exceptions until build end."""
import ast
import json
from pathlib import Path
import sys

import pytest

REPO = Path(__file__).resolve().parents[2]
RECORD = Path(__file__).with_name("size_ratchet.json")
PACKAGES = ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk", "tools")


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


@pytest.mark.parametrize("package_name", ["aegis_core", "tools"])
def test_new_packed_function_fails(tmp_path, package_name):
    package = tmp_path / package_name
    package.mkdir()
    (package / "packed.py").write_text(
        "def go():\n" + "    x = 1; y = 2; z = 3\n" * 50, encoding="utf-8")
    assert size_errors(measure_sizes(tmp_path), {"modules": {}, "functions": {}}) == [
        f"new oversized function: {package_name}/packed.py:go"]


@pytest.mark.parametrize("kind,limit", [("modules", 1000), ("functions", 100)])
@pytest.mark.parametrize("metric", ["lines", "stmts"])
def test_new_entries_enforce_each_metric_at_boundary(kind, limit, metric):
    current = {"modules": {}, "functions": {}}
    values = {"lines": 1, "stmts": 1, metric: limit}
    current[kind]["new"] = values
    record = {"modules": {}, "functions": {}}
    assert size_errors(current, record) == []
    values[metric] += 1
    assert size_errors(current, record) == [f"new oversized {kind[:-1]}: new"]


@pytest.mark.parametrize("kind", ["modules", "functions"])
def test_grandfathered_names_allow_growth_and_absence_but_not_other_names(kind):
    current = {"modules": {}, "functions": {}}
    current[kind]["tools/large.py:go" if kind == "functions" else "tools/large.py"] = {
        "lines": 2000, "stmts": 2000}
    name = next(iter(current[kind]))
    record = {"modules": {}, "functions": {},
              "grandfathered": {kind: {name: "existing tools entry", "absent": "in-flight lane"}}}
    assert size_errors(current, record) == []
    assert lowered_sizes(record, current) == record
    current[kind][name] = {"lines": 3000, "stmts": 3000}
    assert size_errors(current, record) == []
    assert lowered_sizes(record, current) == record
    current[kind]["other"] = {"lines": 2000, "stmts": 2000}
    assert size_errors(current, record) == [f"new oversized {kind[:-1]}: other"]
    with pytest.raises(ValueError, match="refusing to raise size records"):
        lowered_sizes(record, current)
    assert size_errors({"modules": {}, "functions": {}}, record) == []


@pytest.mark.parametrize("source", ["# line\n" * 1000 + "x = 1\n", "x = 1;" * 1001 + "\n"])
def test_new_tools_module_fails(tmp_path, source):
    package = tmp_path / "tools"
    package.mkdir()
    (package / "large.py").write_text(source, encoding="utf-8")
    assert size_errors(measure_sizes(tmp_path), {"modules": {}, "functions": {}}) == [
        "new oversized module: tools/large.py"]


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


def size_errors(current, record):
    errors = []
    for kind, limit in (("modules", 1000), ("functions", 100)):
        grandfathered = record.get("grandfathered", {}).get(kind, {})
        for key, values in current[kind].items():
            if key in grandfathered:
                continue
            pin = record[kind].get(key)
            if pin is None:
                if any(values[metric] > limit for metric in ("lines", "stmts")):
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
    lowered = {kind: {k: current[kind][k] for k in record[kind] if k in current[kind]}
               for kind in ("modules", "functions")}
    # Pending lanes may introduce absent names; --write must preserve their exemptions.
    if "grandfathered" in record:
        lowered["grandfathered"] = record["grandfathered"]
    return lowered


if __name__ == "__main__":
    if sys.argv[1:] != ["--write"]:
        sys.exit("usage: python3 tests/contract/test_module_size.py --write")
    record = json.loads(RECORD.read_text())
    try:
        updated = lowered_sizes(record, measure_sizes(REPO))
    except ValueError as exc:
        sys.exit(str(exc))
    RECORD.write_text(json.dumps(updated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
