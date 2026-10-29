"""Pin process, lookup, conversion and envelope sites by function and count."""
import ast
from collections import Counter
import json
from pathlib import Path
import sys

import pytest

REPO = Path(__file__).resolve().parents[2]
RECORD = Path(__file__).with_name("process_ratchet.json")
PACKAGES = ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk")
RAW = {"subprocess." + n for n in ("run", "Popen", "check_output", "call", "check_call")} | {"os.system", "os.popen"}


def test_process_census_matches_reviewed_sites():
    record = json.loads(RECORD.read_text())
    assert census_errors(process_sites(REPO), record) == []
    assert sum(v["count"] for k, v in record.items() if k.startswith("typeerror:")) <= 18
    assert sum(v["count"] for k, v in record.items() if k.startswith("envelope:")) <= 2
    assert all(v["reason"].strip() for v in record.values())


def test_census_detects_aliases_duplicate_calls_and_relocation(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "probe.py"
    path.write_text("from subprocess import run as spawn\ndef one():\n    spawn(['tool'])\n", encoding="utf-8")
    sites = process_sites(tmp_path)
    key = "process:aegis_core/probe.py:one:subprocess.run"
    assert sites == {key: [3]}
    record = {key: {"count": 1, "reason": "test boundary"}}
    path.write_text(path.read_text() + "    spawn(['more'])\n", encoding="utf-8")
    assert "1 -> 2" in census_errors(process_sites(tmp_path), record)[0]
    path.write_text("import subprocess as sp\ndef two():\n    sp.run(['tool'])\n", encoding="utf-8")
    assert any("unreviewed" in e and ":two:" in e for e in census_errors(process_sites(tmp_path), record))
    with pytest.raises(ValueError, match="refusing to raise"):
        lowered_census(record, process_sites(tmp_path))
    assert lowered_census(record, {}) == {}


def test_census_covers_conversion_lookup_envelope_and_bad_python(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "probe.py"
    path.write_text("from shutil import which as locate\ndef f():\n    locate('thing')\n    try: int(None)\n    except (ValueError, TypeError): pass\n    return {'aegis_version': 1, 'checked_at': 2}\n", encoding="utf-8")
    keys = process_sites(tmp_path)
    assert set(k.split(':')[0] for k in keys) == {"lookup", "typeerror", "envelope"}
    path.write_text("def f(\n", encoding="utf-8")
    with pytest.raises(SyntaxError) as err:
        process_sites(tmp_path)
    assert err.value.filename == "aegis_core/probe.py"


def module_trees(root):
    for package in PACKAGES:
        for path in sorted((root / package).rglob("*.py")):
            rel = path.relative_to(root).as_posix()
            yield rel, ast.parse(path.read_text(encoding="utf-8"), filename=rel)


def aliases_for(tree, rel):
    aliases = {}
    module = rel.removesuffix(".py").replace("/", ".")
    package = module.rsplit(".", 1)[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = package.split(".")
                base = ".".join(parts[:len(parts) - node.level + 1] + ([base] if base else []))
            for alias in node.names:
                aliases[alias.asname or alias.name] = base + "." + alias.name
    return aliases


def qualified(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return qualified(node.value, aliases) + "." + node.attr
    return ""


def process_sites(root):
    found = {}
    for rel, tree in module_trees(root):
        aliases = aliases_for(tree, rel)

        def visit(node, scope="<module>"):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scope = node.name if scope == "<module>" else scope + "." + node.name
            category, detail = None, ""
            name = qualified(node, aliases)
            if name in RAW:
                category, detail = "process", name
            elif isinstance(node, ast.Call):
                name = qualified(node.func, aliases)
                if rel.startswith("aegis_core/") and name in ("shutil.which", "aegis_core.pathlookup.which"):
                    # only_skipped passes its caller's outside fence as the third positional argument.
                    fenced = any(k.arg == "outside" for k in node.keywords) or (name.endswith("pathlookup.which") and len(node.args) >= 3)
                    if not fenced:
                        category, detail = "lookup", name
            elif isinstance(node, ast.ExceptHandler) and node.type:
                if any(isinstance(n, ast.Name) and n.id == "TypeError" for n in ast.walk(node.type)):
                    category, detail = "typeerror", "TypeError"
            elif isinstance(node, ast.Dict):
                keys = {n.value for n in node.keys if isinstance(n, ast.Constant) and isinstance(n.value, str)}
                if {"aegis_version", "checked_at"} <= keys:
                    category, detail = "envelope", "dict"
            if category:
                found.setdefault(f"{category}:{rel}:{scope}:{detail}", []).append(node.lineno)
            for child in ast.iter_child_nodes(node):
                visit(child, scope)
        visit(tree)
    return dict(sorted(found.items()))


def census_errors(current, record):
    errors = []
    for key, lines in current.items():
        if key not in record:
            errors.append(f"unreviewed {key} at lines {lines}")
        elif len(lines) != record[key]["count"]:
            errors.append(f"{key}: {record[key]['count']} -> {len(lines)} at lines {lines}; lower pins after removals")
    errors.extend(f"{key}: removed; lower the ratchet" for key in record.keys() - current.keys())
    return errors


def lowered_census(record, current):
    growth = [k for k, v in current.items() if k not in record or len(v) > record[k]["count"]]
    if growth:
        raise ValueError("refusing to raise process records: " + repr(growth))
    return {k: {"count": len(v), "reason": record[k]["reason"]} for k, v in current.items()}


def runner_violations(root, program):
    found = []
    for rel, tree in module_trees(root):
        aliases = aliases_for(tree, rel)
        comparisons = {id(n) for c in ast.walk(tree) if isinstance(c, ast.Compare) for n in c.comparators}
        transport = {"aegis_core/ghcli.py"} if program == "gh" else {"aegis_core/gitsafe.py", "aegis_core/treeid.py"}
        for node in ast.walk(tree):
            reason = None
            if (isinstance(node, (ast.List, ast.Tuple)) and id(node) not in comparisons and node.elts and
                    isinstance(node.elts[0], ast.Constant) and node.elts[0].value == program and rel not in transport):
                reason = f"{program} argv outside transport"
            elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
                name = qualified(node.func, aliases)
                if name in ("shutil.which", "aegis_core.pathlookup.which") and node.args[0].value == program:
                    resolver = "aegis_core/ghcli.py" if program == "gh" else "aegis_core/gitsafe.py"
                    if rel != resolver:
                        reason = f"{program} resolution outside transport"
            if (program == "git" and isinstance(node, ast.Call)
                    and qualified(node.func, aliases) == "aegis_core.gitsafe.git_executable" and rel not in transport):
                reason = "git executable outside transport"
            if program == "git":
                name = qualified(node, aliases)
                if name.startswith("aegis_core.gitsafe._") and rel != "aegis_core/gitsafe.py":
                    reason = "private gitsafe reach"
                if (isinstance(node, ast.Constant) and node.value == "refs/remotes/origin/HEAD"
                        and rel not in ("aegis_core/gitsafe.py", "aegis_core/gitevidence.py")):
                    reason = "default branch outside git evidence"
            if reason:
                found.append((rel, node.lineno, reason))
    return [f"{rel}:{line}: {reason}" for rel, line, reason in sorted(found)]


if __name__ == "__main__":
    if sys.argv[1:] != ["--write"]:
        sys.exit("usage: python3 tests/contract/test_process_ratchets.py --write")
    try:
        updated = lowered_census(json.loads(RECORD.read_text()), process_sites(REPO))
    except ValueError as exc:
        sys.exit(str(exc))
    RECORD.write_text(json.dumps(updated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
