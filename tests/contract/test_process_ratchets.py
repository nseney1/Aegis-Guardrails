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


def import_bindings(node, rel):
    """The bindings introduced by this import, independent of sibling scopes."""
    if isinstance(node, ast.Import):
        return {a.asname or a.name.split(".")[0]: a.name if a.asname else a.name.split(".")[0]
                for a in node.names}
    if isinstance(node, ast.ImportFrom):
        base = node.module or ""
        if node.level:
            package = rel.removesuffix(".py").replace("/", ".").split(".")[:-1]
            base = ".".join(package[:len(package) - node.level + 1] + ([base] if base else []))
        return {a.asname or a.name: base + "." + a.name for a in node.names}
    return {}


class _AliasScope:
    def __init__(self, parent=None, kind="module"):
        self.parent = parent
        self.kind = kind
        self.imports = {}
        self.bound = set()
        self.globals = set()
        self.nonlocals = set()

    def resolve(self, name):
        # A scope may import different things along different branches. Keep every
        # possible import there; never let another scope's last import overwrite it.
        if name in self.imports:
            return self.imports[name]
        if name in self.globals and self.parent is not None:
            root = self.parent
            while root.parent is not None:
                root = root.parent
            return root.resolve(name)
        if name in self.nonlocals and self.parent is not None:
            return self.parent.resolve(name)
        if name in self.bound:
            return set()
        return self.parent.resolve(name) if self.parent is not None else set()


def _lexical_parent(scope):
    # Methods, nested classes and comprehensions do not close over class locals.
    while scope.kind == "class":
        scope = scope.parent
    return scope


class ScopedNames:
    """Resolve import aliases lexically, not by a file-wide last assignment.

    This is not control-flow analysis: imports in alternative branches of one
    scope remain plausible. Parameters and local bindings shadow outer imports;
    defaults/decorators are evaluated in the enclosing scope. Assignment aliases
    and dynamic imports are outside this static resolver.
    """
    def __init__(self, tree, rel, *, runtime_only=False):
        self.rel = rel
        self.at = {}
        self.allowed = None
        if runtime_only:
            from tests.contract.test_import_boundary import import_nodes
            self.allowed = {id(n) for n in import_nodes(tree)}
        self._index(tree, _AliasScope())

    def _arguments(self, args, outer, inner):
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg):
            if arg is not None:
                inner.bound.add(arg.arg)
                self.at[id(arg)] = inner
                if arg.annotation is not None:
                    self._index(arg.annotation, outer)
        for value in (*args.defaults, *args.kw_defaults):
            if value is not None:
                self._index(value, outer)

    def _index(self, node, scope):
        if self.allowed is not None and id(node) not in self.allowed:
            return
        self.at[id(node)] = scope
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            if not isinstance(node, ast.Lambda):
                scope.bound.add(node.name)
                for value in node.decorator_list:
                    self._index(value, scope)
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
            inner = _AliasScope(_lexical_parent(scope), kind)
            if isinstance(node, ast.ClassDef):
                for value in (*node.bases, *node.keywords):
                    self._index(value, scope)
            else:
                self._arguments(node.args, scope, inner)
                if getattr(node, "returns", None) is not None:
                    self._index(node.returns, scope)
            for value in [node.body] if isinstance(node, ast.Lambda) else node.body:
                self._index(value, inner)
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            inner = _AliasScope(_lexical_parent(scope), "function")
            for index, generator in enumerate(node.generators):
                self._index(generator.iter, scope if index == 0 else inner)
                self._index(generator.target, inner)
                for condition in generator.ifs:
                    self._index(condition, inner)
            for value in (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,):
                self._index(value, inner)
            return
        for local, target in import_bindings(node, self.rel).items():
            scope.bound.add(local)
            scope.imports.setdefault(local, set()).add(target)
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            scope.bound.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            scope.bound.add(node.name)
        elif isinstance(node, ast.Global):
            scope.globals.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            scope.nonlocals.update(node.names)
        for child in ast.iter_child_nodes(node):
            self._index(child, scope)

    def resolve(self, node):
        if isinstance(node, ast.Name):
            scope = self.at.get(id(node))
            return scope.resolve(node.id) if scope is not None else set()
        if isinstance(node, ast.Attribute):
            return {base + "." + node.attr for base in self.resolve(node.value)}
        return set()


def process_sites(root):
    found = {}
    for rel, tree in module_trees(root):
        names = ScopedNames(tree, rel)

        def visit(node, scope="<module>"):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scope = node.name if scope == "<module>" else scope + "." + node.name
            sites = {("process", name) for name in names.resolve(node) & RAW}
            if isinstance(node, ast.Call) and rel.startswith("aegis_core/"):
                for name in names.resolve(node.func) & {"shutil.which", "aegis_core.pathlookup.which"}:
                    # only_skipped forwards its caller's fence positionally.
                    fenced = any(k.arg == "outside" for k in node.keywords) or (name.endswith("pathlookup.which") and len(node.args) >= 3)
                    if not fenced:
                        sites.add(("lookup", name))
            elif isinstance(node, ast.ExceptHandler) and node.type:
                if any(isinstance(n, ast.Name) and n.id == "TypeError" for n in ast.walk(node.type)):
                    sites.add(("typeerror", "TypeError"))
            elif isinstance(node, ast.Dict):
                keys = {n.value for n in node.keys if isinstance(n, ast.Constant) and isinstance(n.value, str)}
                if {"aegis_version", "checked_at"} <= keys:
                    sites.add(("envelope", "dict"))
            for category, detail in sorted(sites):
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
        names = ScopedNames(tree, rel)
        comparisons = {id(n) for c in ast.walk(tree) if isinstance(c, ast.Compare) for n in c.comparators}
        transport = {"aegis_core/ghcli.py"} if program == "gh" else {"aegis_core/gitsafe.py", "aegis_core/treeid.py"}
        for node in ast.walk(tree):
            reason = None
            if (isinstance(node, (ast.List, ast.Tuple)) and id(node) not in comparisons and node.elts and
                    isinstance(node.elts[0], ast.Constant) and node.elts[0].value == program and rel not in transport):
                reason = f"{program} argv outside transport"
            elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
                if names.resolve(node.func) & {"shutil.which", "aegis_core.pathlookup.which"} and node.args[0].value == program:
                    resolver = "aegis_core/ghcli.py" if program == "gh" else "aegis_core/gitsafe.py"
                    if rel != resolver:
                        reason = f"{program} resolution outside transport"
            if (program == "git" and isinstance(node, ast.Call)
                    and "aegis_core.gitsafe.git_executable" in names.resolve(node.func) and rel not in transport):
                reason = "git executable outside transport"
            if program == "git":
                if any(name.startswith("aegis_core.gitsafe._") for name in names.resolve(node)) and rel != "aegis_core/gitsafe.py":
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


@pytest.mark.parametrize("reverse", [False, True])
def test_process_aliases_do_not_leak_between_sibling_scopes(tmp_path, reverse):
    package = tmp_path / "aegis_core"
    package.mkdir()
    pieces = ["def launch():\n    import subprocess as backend\n    backend.run(['tool'])\n",
              "def decode():\n    import json as backend\n    backend.loads('{}')\n"]
    (package / "probe.py").write_text("\n".join(reversed(pieces) if reverse else pieces), encoding="utf-8")
    sites = process_sites(tmp_path)
    assert list(sites) == ["process:aegis_core/probe.py:launch:subprocess.run"]
    assert len(next(iter(sites.values()))) == 1


def test_process_aliases_respect_parameters_closures_and_default_expressions(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import subprocess as backend\n"
        "def ignored(backend):\n    backend.run([])\n"
        "def defaults(backend=backend.run):\n    backend([])\n"
        "def outer():\n    import subprocess as nested\n    def inner():\n        nested.run([])\n",
        encoding="utf-8")
    assert set(process_sites(tmp_path)) == {
        "process:aegis_core/probe.py:defaults:subprocess.run",
        "process:aegis_core/probe.py:outer.inner:subprocess.run"}
