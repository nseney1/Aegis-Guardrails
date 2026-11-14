"""Shrink-only budgets; baseline pins cannot exceed their pre-absorption sizes.

Absorbed team modules have unconditional size caps.
"""
import ast
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
import sys
from textwrap import indent

import pytest

REPO = Path(__file__).resolve().parents[2]
RECORD = Path(__file__).with_name("size_ratchet.json")
PACKAGES = ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk", "tools")
# Pre-absorption ceilings from size_ratchet.json at df8232ec. Pins can only shrink.
BASELINE_PINS = {
    "modules": {
        "aegis_cli/install_hosts.py": {"lines": 1034, "stmts": 630},
        "aegis_core/gitsafe.py": {"lines": 1225, "stmts": 682},
        "aegis_core/human_gate.py": {"lines": 1073, "stmts": 637},
        "aegis_core/migrate.py": {"lines": 273, "stmts": 213},
        "aegis_core/verification/runner.py": {"lines": 986, "stmts": 630},
    },
    "functions": {
        "aegis_cli/check.py:CheckCommand.configure_parser": {"lines": 186, "stmts": 29},
        "aegis_cli/rule.py:RuleCommand.configure_parser": {"lines": 108, "stmts": 65},
        "aegis_cli/rule.py:_run_insight": {"lines": 110, "stmts": 79},
        "aegis_cli/verify.py:run_verify": {"lines": 284, "stmts": 199},
        "aegis_core/command_safety/lexer.py:extract_subshell_commands": {"lines": 150, "stmts": 121},
        "aegis_core/command_safety/lexer.py:unwrap_command_stage": {"lines": 272, "stmts": 201},
        "aegis_core/config.py:RepoConfig.parse": {"lines": 132, "stmts": 86},
        "aegis_core/human_gate.py:detect_tier": {"lines": 141, "stmts": 90},
        "aegis_core/lifecycle/creation.py:create_rule": {"lines": 134, "stmts": 57},
        "aegis_core/sync.py:sync": {"lines": 102, "stmts": 72},
        "aegis_core/verification/arbiter.py:arbitrate": {"lines": 128, "stmts": 47},
        "aegis_core/verification/call_graph.py:check": {"lines": 154, "stmts": 69},
        "aegis_core/verification/call_graph.py:check_normalized": {"lines": 105, "stmts": 47},
        "aegis_core/verification/checkpoint_checks.py:_aegis_suite_candidates": {"lines": 117, "stmts": 113},
        "aegis_core/verification/import_guard.py:check": {"lines": 66, "stmts": 27},
        "aegis_core/verification/mutation_tester.py:check": {"lines": 134, "stmts": 79},
        "aegis_core/verification/runner.py:_layer1_on_snapshot": {"lines": 31, "stmts": 15},
        "aegis_core/verification/runner.py:run_layer1": {"lines": 100, "stmts": 49},
        "aegis_core/workspace/binding.py:resolve_binding": {"lines": 122, "stmts": 68},
    },
}


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
              "grandfathered": {kind: {name: "existing tools entry", "tools/absent.py": "in-flight lane"}}}
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
    path = package / "human_gate.py"
    path.write_text("# line\n" * 1051, encoding="utf-8")
    before = measure_sizes(tmp_path)
    path.write_text("# line\n" * 1001, encoding="utf-8")
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


@pytest.mark.parametrize("kind,key,lines,stmts", [
    ("modules", "aegis_cli/install_hosts.py", 1034, 630),
    ("modules", "aegis_core/gitsafe.py", 1225, 682),
    ("modules", "aegis_core/human_gate.py", 1073, 637),
    ("modules", "aegis_core/migrate.py", 273, 213),
    ("modules", "aegis_core/verification/runner.py", 986, 630),
    ("functions", "aegis_cli/check.py:CheckCommand.configure_parser", 186, 29),
    ("functions", "aegis_cli/rule.py:RuleCommand.configure_parser", 108, 65),
    ("functions", "aegis_cli/rule.py:_run_insight", 110, 79),
    ("functions", "aegis_cli/verify.py:run_verify", 284, 199),
    ("functions", "aegis_core/command_safety/lexer.py:extract_subshell_commands", 150, 121),
    ("functions", "aegis_core/command_safety/lexer.py:unwrap_command_stage", 272, 201),
    ("functions", "aegis_core/config.py:RepoConfig.parse", 132, 86),
    ("functions", "aegis_core/human_gate.py:detect_tier", 141, 90),
    ("functions", "aegis_core/lifecycle/creation.py:create_rule", 134, 57),
    ("functions", "aegis_core/sync.py:sync", 102, 72),
    ("functions", "aegis_core/verification/arbiter.py:arbitrate", 128, 47),
    ("functions", "aegis_core/verification/call_graph.py:check", 154, 69),
    ("functions", "aegis_core/verification/call_graph.py:check_normalized", 105, 47),
    ("functions", "aegis_core/verification/checkpoint_checks.py:_aegis_suite_candidates", 117, 113),
    ("functions", "aegis_core/verification/import_guard.py:check", 66, 27),
    ("functions", "aegis_core/verification/mutation_tester.py:check", 134, 79),
    ("functions", "aegis_core/verification/runner.py:_layer1_on_snapshot", 31, 15),
    ("functions", "aegis_core/verification/runner.py:run_layer1", 100, 49),
    ("functions", "aegis_core/workspace/binding.py:resolve_binding", 122, 68),
])
@pytest.mark.parametrize("metric", ["lines", "stmts"])
@pytest.mark.parametrize("operation", ["check", "write"])
def test_baseline_pins_cannot_raise_ceiling(kind, key, lines, stmts, metric, operation):
    # Fixed source: size_ratchet.json at df8232ec; no git history needed at runtime.
    ceiling = {"lines": lines, "stmts": stmts}
    record = {"modules": {}, "functions": {}}
    record[kind][key] = dict(ceiling)
    current = deepcopy(record)
    assert size_errors(current, record) == []
    assert lowered_sizes(record, current) == record
    current[kind][key][metric] -= 1
    lowered = lowered_sizes(record, current)
    assert lowered == current
    assert size_errors(current, lowered) == []
    # A lowered record still cannot recover its former headroom.
    with pytest.raises(ValueError, match="refusing to raise size records"):
        lowered_sizes(lowered, record)
    record[kind][key][metric] += 1
    current = deepcopy(record)
    before = deepcopy((current, record))
    expected = f"baseline pin exceeds {ceiling[metric]} {metric}: {key}"
    for _ in range(2):
        if operation == "check":
            assert size_errors(current, record) == [expected]
        else:
            with pytest.raises(ValueError) as err:
                lowered_sizes(record, current)
            assert str(err.value) == "refusing to raise size records: " + repr([expected])
    assert (current, record) == before
    # Validate the record even when a pin is absent or the snapshot has shrunk.
    for snapshot in ({"modules": {}, "functions": {}}, lowered):
        assert expected in size_errors(snapshot, record)
        with pytest.raises(ValueError) as err:
            lowered_sizes(record, snapshot)
        assert str(err.value) == "refusing to raise size records: " + repr([expected])
    record[kind][key] = dict(ceiling)
    assert size_errors(record, record) == []
    assert lowered_sizes(record, record) == record


@pytest.mark.parametrize("kind,limit", [("modules", 1000), ("functions", 100)])
@pytest.mark.parametrize("metric", ["lines", "stmts"])
@pytest.mark.parametrize("exemption", ["none", "pin", "grandfathered"])
@pytest.mark.parametrize("module", ["team_absorbed.py", "team_absorbed/part.py"])
def test_team_caps_cannot_be_bypassed(kind, limit, metric, exemption, module):
    key = "aegis_core/" + module + (":go" if kind == "functions" else "")
    current = {"modules": {}, "functions": {}}
    values = {"lines": 1, "stmts": 1, metric: limit}
    current[kind][key] = values
    record = {"modules": {}, "functions": {}}
    if exemption == "grandfathered":
        record["grandfathered"] = {kind: {key: "must not exempt absorbed code"}}
    elif exemption == "pin":
        record[kind][key] = dict(values)
    policy = [] if exemption == "none" else [f"unapproved {exemption}: {key}"]
    assert size_errors(current, record) == policy
    values[metric] += 1
    if exemption == "pin":
        record[kind][key] = dict(values)
    expected = policy + [f"team {kind[:-1]} exceeds {limit} {metric}: {key}"]
    assert size_errors(current, record) == expected
    # Repeated checks and --write cannot bless an oversize port.
    assert size_errors(current, record) == expected
    with pytest.raises(ValueError, match="refusing to raise size records"):
        lowered_sizes(record, current)
    values[metric] = limit
    if exemption == "pin":
        record[kind][key] = dict(values)
    assert size_errors(current, record) == policy


@pytest.mark.parametrize("source,kind,metric,limit", [
    ("# line\n" * 1001, "module", "lines", 1000),
    ("x = 1;" * 1001 + "\n", "module", "stmts", 1000),
    ("async def go():\n" + "    # padding\n" * 99 + "    pass\n", "function", "lines", 100),
    ("def go():\n" + "    x = 1; y = 2\n" * 50, "function", "stmts", 100),
], ids=["module-lines", "module-statements", "async-lines", "packed-statements"])
def test_nested_team_package_is_measured(tmp_path, source, kind, metric, limit):
    package = tmp_path / "aegis_core" / "team_absorbed" / "nested"
    package.mkdir(parents=True)
    path = package / "part.py"
    path.write_text(source, encoding="utf-8")
    key = "aegis_core/team_absorbed/nested/part.py" + (":go" if kind == "function" else "")
    current = measure_sizes(tmp_path)
    assert size_errors(current, {"modules": {}, "functions": {}}) == [
        f"team {kind} exceeds {limit} {metric}: {key}"]
    # The check is read-only and observes a subsequent corrected snapshot.
    assert path.read_text(encoding="utf-8") == source
    path.write_text("def go():\n    pass\n", encoding="utf-8")
    assert size_errors(measure_sizes(tmp_path), {"modules": {}, "functions": {}}) == []


def test_parallel_team_size_checks_do_not_mutate_inputs():
    key = "aegis_core/team_absorbed/part.py"
    current = {"modules": {key: {"lines": 1001, "stmts": 1}}, "functions": {}}
    record = {"modules": {}, "functions": {}}
    record["grandfathered"] = {"modules": {key: "cannot waive a team cap"}}
    before = deepcopy((current, record))
    expected = [f"unapproved grandfathered: {key}", f"team module exceeds 1000 lines: {key}"]
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(size_errors, current, record) for _ in range(6)]
        assert [future.result(timeout=5) for future in futures] == [expected] * 6
    assert (current, record) == before


def _repeated_definitions(style, first, second):
    if style == "property":
        return ("class C:\n    @property\n    def value(self):\n" + indent(first, "        ") +
                "    @value.setter\n    def value(self, value):\n" + indent(second, "        "))
    if style == "overload":
        return ("@overload\ndef value(x):\n" + indent(first, "    ") +
                "@overload\ndef value(x):\n" + indent(second, "    "))
    return ("if flag:\n    def value():\n" + indent(first, "        ") +
            "else:\n    def value():\n" + indent(second, "        "))


@pytest.mark.parametrize("style", ["property", "overload", "conditional"])
@pytest.mark.parametrize("metric", ["lines", "stmts"])
@pytest.mark.parametrize("reverse", [False, True])
def test_each_same_name_definition_obeys_caps(tmp_path, style, metric, reverse):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "team_collision.py"
    small = "pass\n"
    control = "\ndef sibling():\n    pass\n"
    path.write_text(_repeated_definitions(style, small, small) + control, encoding="utf-8")
    record = {"modules": {}, "functions": {}}
    assert size_errors(measure_sizes(tmp_path), record) == []
    large = "# padding\n" * 101 + "pass\n" if metric == "lines" else "x = 1; y = 2\n" * 51
    bodies = (small, large) if reverse else (large, small)
    path.write_text(_repeated_definitions(style, *bodies) + control, encoding="utf-8")
    current = measure_sizes(tmp_path)
    key = "aegis_core/team_collision.py:" + ("C.value" if style == "property" else "value")
    assert current["functions"][key][metric] > 100
    assert current["functions"]["aegis_core/team_collision.py:sibling"] == {"lines": 2, "stmts": 2}
    assert size_errors(current, record) == [f"team function exceeds 100 {metric}: {key}"]
    assert size_errors(measure_sizes(tmp_path), record) == size_errors(current, record)
    path.write_text(_repeated_definitions(style, small, small), encoding="utf-8")
    assert size_errors(measure_sizes(tmp_path), record) == []


def test_same_name_metrics_keep_independent_maxima(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "team_collision.py"
    path.write_text(_repeated_definitions("conditional", "# padding\n" * 101 + "pass\n",
                                         "x = 1; y = 2\n" * 51), encoding="utf-8")
    values = measure_sizes(tmp_path)["functions"]["aegis_core/team_collision.py:value"]
    assert values["lines"] > 100 and values["stmts"] > 100


@pytest.mark.parametrize("module", ["aegis_cli/team_mail.py", "aegis_mcp/team_mail.py",
                                    "aegis_core/storage_absorbed.py"])
@pytest.mark.parametrize("kind,limit", [("modules", 1000), ("functions", 100)])
@pytest.mark.parametrize("exemption", ["pin", "grandfathered"])
def test_absorbed_adapters_cannot_import_exemptions(module, kind, limit, exemption):
    key = module + (":main" if kind == "functions" else "")
    current = {"modules": {}, "functions": {}}
    current[kind][key] = {"lines": limit + 1, "stmts": 1}
    record = {"modules": {}, "functions": {}}
    if exemption == "pin":
        record[kind][key] = dict(current[kind][key])
    else:
        record["grandfathered"] = {kind: {key: "cannot relocate a tools exemption"}}
    errors = size_errors(current, record)
    assert f"unapproved {exemption}: {key}" in errors
    with pytest.raises(ValueError, match="refusing to raise size records"):
        lowered_sizes(record, current)
    assert size_errors(current, record) == errors
    # An unused exemption must also refuse, even without the corresponding file.
    empty = {"modules": {}, "functions": {}}
    assert f"unapproved {exemption}: {key}" in size_errors(empty, record)


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
                        key = f"{rel}:{name}"
                        values = {
                            "lines": child.end_lineno - first + 1,
                            "stmts": sum(isinstance(n, ast.stmt) for n in ast.walk(child))}
                        previous = result["functions"].get(key, {"lines": 0, "stmts": 0})
                        result["functions"][key] = {
                            metric: max(previous[metric], values[metric]) for metric in ("lines", "stmts")}
                    functions(child, name)
            functions(tree)
    return result


def size_errors(current, record):
    errors = []
    for kind, limit in (("modules", 1000), ("functions", 100)):
        grandfathered = record.get("grandfathered", {}).get(kind, {})
        errors.extend(f"unapproved grandfathered: {key}" for key in sorted(grandfathered)
                      if not key.startswith("tools/"))
        errors.extend(f"unapproved pin: {key}" for key in sorted(record[kind])
                      if not key.startswith("tools/") and key not in BASELINE_PINS[kind])
        for key, ceiling in BASELINE_PINS[kind].items():
            pin = record[kind].get(key)
            if pin is not None:
                errors.extend(f"baseline pin exceeds {ceiling[metric]} {metric}: {key}"
                              for metric in ("lines", "stmts") if pin[metric] > ceiling[metric])
        for key, values in current[kind].items():
            # Absorption must split legacy tools, never import their exemptions.
            over = [metric for metric in ("lines", "stmts")
                    if key.startswith("aegis_core/team_") and values[metric] > limit]
            if over:
                errors.extend(f"team {kind[:-1]} exceeds {limit} {metric}: {key}" for metric in over)
                continue
            if key in grandfathered and key.startswith("tools/"):
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
