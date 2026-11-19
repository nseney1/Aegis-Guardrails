"""aegis_core.redaction: one secret table, the same output through every entry point (R-structure-32).

The goldens were recorded on the w14 merge commit (e7e61536), before the table moved out of
aegis_core.verification.scanners, through the three entry points that exist on both sides of the
move: the hook command log (aegis_cli.hooks.redaction.redact_secrets), stored insight text
(aegis_core.insights.redact_insight_text) and a scanner finding's snippet (scan_secrets_text).
The unterminated-PEM golden is corrected in w16; the move-era output leaked its body.
Tokens are assembled at run time so push protection never sees a literal.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
from types import SimpleNamespace
from typing import Dict, Iterable, List, Tuple
import unicodedata

import pytest

import tests.helpers_reviewed_sources as reviewed_helper
from tests.conftest import symlink_or_skip
from tests.helpers_reviewed_sources import (
    census_guard, check_census_rows, run_census_fixture,
    git_environment as _git_environment, reviewed_python_paths, run_isolated_test as _run_isolated,
)

from aegis_cli.hooks.redaction import redact_secrets
from aegis_core import insights as insight_module
from aegis_core.gitsafe_policy import LOCAL_ENV
from aegis_core.insights import redact_insight_text
from aegis_core.primitives import real_path
from aegis_core.verification.scanners import TIER_A_PATTERNS, scan_secrets_text

REPO = Path(real_path(__file__)).parents[3]
# Reviewed parse-cost ratchet: retain headroom for ordinary source additions.
# Increasing this ceiling requires review; failures list all parsed paths.
# Coordinator CEILING RULING 2026-11-16T21:22:03Z reviewed these six additions:
# aegis_core/team_lease_custody.py, tests/helpers_reviewed_sources.py,
# aegis_core/primitives.py, tests/unit/core/test_primitives.py,
# aegis_core/pathlookup.py, tests/unit/core/test_gitsafe.py.
# Coordinator CEILING RULING TA-1a 2026-11-16T22:57:17Z also reviewed:
# aegis_core/team_mailbox_primitives.py (TA-1a).
# 78 -> 82 (2026-11-17 coordinator, shared reviewed raise after #617; tip measured 78): aegis_core/workspace/diagnostics.py and
# tests/unit/core/test_workspace_diagnostics.py (WORKSPACE-RECOVERY-FRAME, public clip_atomic_text), aegis_core/team_board.py (TA-1d),
# aegis_core/merge_queue.py (GM-9).
# Coordinator ROUND-5b RULING 2026-11-17T21:18:05Z: measured 83 parsed files; reviewed additions:
# aegis_core/team_host_qualify_evidence.py, tests/unit/core/test_team_host_qualify_evidence.py.
# Both were checked: neither imports a private redaction name.
REDACTION_PARSE_CEILING = 83


def assignment_values(statement):
    """Index ordinary annotated and nested tuple/list bindings conservatively."""
    def targets(target, value):
        if isinstance(value, ast.Starred):
            value = value.value
        if isinstance(target, ast.Name):
            yield target.id, value
        elif isinstance(target, ast.Starred):
            yield from targets(target.value, value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            values = (value.elts if isinstance(value, (ast.Tuple, ast.List))
                      and not any(isinstance(part, ast.Starred) for part in (*target.elts, *value.elts))
                      and len(value.elts) == len(target.elts) else [value] * len(target.elts))
            for child, origin in zip(target.elts, values):
                yield from targets(child, origin)

    if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)) and statement.value is not None:
        for target in statement.targets if isinstance(statement, ast.Assign) else [statement.target]:
            yield from targets(target, statement.value)
    elif (isinstance(statement, ast.Call) and isinstance(statement.func, ast.Attribute)
          and isinstance(statement.func.value, ast.Name) and statement.func.attr in {"append", "extend", "insert"}):
        for value in statement.args:
            yield statement.func.value.id, value


def census_dependencies(tree, roots):
    """Conservative lexical closure for honest module, class and callback helpers.

    Follow references as well as calls: a callback passed to map or an executor
    is still a dependency. Local value aliases retain their lexical scope.
    """
    module_values = {}
    methods = {}
    statements = list(tree.body)
    while statements:
        node = statements.pop()
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            module_values[node.name] = [node]
            if isinstance(node, ast.ClassDef):
                for method in node.body:
                    if isinstance(method, ast.FunctionDef):
                        methods.setdefault(method.name, []).append(method)
        else:
            for name, value in assignment_values(node):
                module_values.setdefault(name, []).append(value)
            statements.extend(ast.iter_child_nodes(node))
    local_values = {}
    pending = list(roots)
    seen = set()
    found = []
    while pending:
        node, scope = pending.pop()
        identity = (id(node), id(scope))
        if identity in seen:
            continue
        seen.add(identity)
        found.append((node, scope))
        if scope not in local_values:
            values = {}
            statements = list(scope.body) if isinstance(scope, (ast.FunctionDef, ast.ClassDef)) else []
            while statements:
                statement = statements.pop()
                if isinstance(statement, (ast.FunctionDef, ast.ClassDef)):
                    values.setdefault(statement.name, []).append(statement)
                    continue
                for name, value in assignment_values(statement):
                    values.setdefault(name, []).append(value)
                statements.extend(ast.iter_child_nodes(statement))
            local_values[scope] = values
        for reference in ast.walk(node):
            if isinstance(reference, ast.Name) and isinstance(reference.ctx, ast.Load):
                local = local_values[scope].get(reference.id)
                for value in local if local is not None else module_values.get(reference.id, []):
                    owner = scope if local is not None else tree
                    if isinstance(value, (ast.FunctionDef, ast.ClassDef)):
                        owner = value
                    pending.append((value, owner))
            elif isinstance(reference, ast.Attribute):
                pending.extend((method, method) for method in methods.get(reference.attr, []))
    return found


def has_live_tree_enumeration(node, tree):
    imports = {}
    for statement in ast.walk(tree):
        if isinstance(statement, ast.Import):
            imports.update({alias.asname or alias.name: alias.name for alias in statement.names})
        elif isinstance(statement, ast.ImportFrom) and statement.module:
            imports.update({alias.asname or alias.name: statement.module + "." + alias.name
                            for alias in statement.names})
    for reference in ast.walk(node):
        if isinstance(reference, ast.Attribute) and reference.attr in {"rglob", "glob", "iglob", "iterdir"}:
            return True
        parts = []
        base = reference
        while isinstance(base, ast.Attribute):
            parts.insert(0, base.attr)
            base = base.value
        if isinstance(base, ast.Name):
            qualified = ".".join([imports.get(base.id, base.id), *parts])
            if qualified in {"os.walk", "os.fwalk", "os.listdir", "os.scandir", "glob.glob", "glob.iglob"}:
                return True
    return False


def source_uses_frozen_inventory(tree, expression, scope):
    """Trace returned source values, binding ordinary function/method callbacks.

    Unknown source producers refuse. Reading the inventory as an unused local
    or passing it to a helper that discards the argument is not provenance.
    """
    scopes = {}
    methods = {}
    for definition in tree.body:
        if isinstance(definition, ast.ClassDef):
            for method in definition.body:
                if isinstance(method, ast.FunctionDef):
                    methods.setdefault(method.name, []).append(method)

    def values(owner):
        if owner in scopes:
            return scopes[owner]
        bindings = {}
        if isinstance(owner, (ast.FunctionDef, ast.Lambda)):
            arguments = [*owner.args.posonlyargs, *owner.args.args]
            for argument, default in zip(arguments[len(arguments) - len(owner.args.defaults):], owner.args.defaults):
                bindings[argument.arg] = [default]
        statements = [] if isinstance(owner, ast.Lambda) else list(owner.body)
        while statements:
            statement = statements.pop()
            if isinstance(statement, (ast.FunctionDef, ast.ClassDef)):
                bindings.setdefault(statement.name, []).append(statement)
                continue
            for name, value in assignment_values(statement):
                bindings.setdefault(name, []).append(value)
            statements.extend(ast.iter_child_nodes(statement))
        scopes[owner] = bindings
        return bindings

    def resolve(node, owner, arguments, seen=frozenset()):
        key = (id(node), id(owner))
        if key in seen:
            return []
        if isinstance(node, ast.Name):
            if node.id in arguments:
                return resolve(*arguments[node.id], seen | {key})
            local = values(owner).get(node.id)
            definitions = local if local is not None else values(tree).get(node.id, [])
            if definitions and node.id != "_REVIEWED_PYTHON_PATHS":
                defining_scope = owner if local is not None else tree
                return [result for value in definitions
                        for result in resolve(value, defining_scope, arguments, seen | {key})]
        elif isinstance(node, ast.Attribute) and node.attr in methods:
            return [(method, method, {}) for method in methods[node.attr]]
        return [(node, owner, arguments)]

    def returned(function):
        if isinstance(function, ast.Lambda):
            return [function.body]
        results = []
        statements = list(function.body)
        while statements:
            statement = statements.pop()
            if isinstance(statement, ast.Return):
                results.append(statement.value)
            elif not isinstance(statement, (ast.FunctionDef, ast.ClassDef, ast.Lambda)):
                statements.extend(ast.iter_child_nodes(statement))
        return results

    def frozen(node, owner, arguments, active=frozenset()):
        key = (id(node), id(owner))
        if key in active:
            return False
        active = active | {key}
        if isinstance(node, ast.Name):
            if node.id == "_REVIEWED_PYTHON_PATHS" and node.id not in arguments and node.id not in values(owner):
                return True
            origins = resolve(node, owner, arguments)
            return bool(origins) and all(value is not node and frozen(value, source, bound, active)
                                         for value, source, bound in origins)
        if isinstance(node, ast.IfExp):
            test = node.test
            if (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Is)
                    and isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value is None):
                choices = resolve(test.left, owner, arguments)
                if choices and all(isinstance(value, ast.Constant) and value.value is None
                                   for value, _, _ in choices):
                    return frozen(node.body, owner, arguments, active)
            return frozen(node.body, owner, arguments, active) and frozen(node.orelse, owner, arguments, active)
        if isinstance(node, (ast.ListComp, ast.GeneratorExp)):
            return bool(node.generators) and frozen(node.generators[0].iter, owner, arguments, active)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {"list", "tuple", "sorted", "iter", "map", "filter"}:
                return bool(node.args) and frozen(node.args[-1], owner, arguments, active)
            targets = resolve(node.func, owner, arguments)
            results = []
            for function, _, captured in targets:
                if not isinstance(function, (ast.FunctionDef, ast.Lambda)):
                    return False
                parameters = [*function.args.posonlyargs, *function.args.args]
                if parameters and parameters[0].arg in {"self", "cls"}:
                    parameters = parameters[1:]
                bound = dict(captured)
                bound.update({parameter.arg: (argument, owner, arguments)
                              for parameter, argument in zip(parameters, node.args)})
                bound.update({keyword.arg: (keyword.value, owner, arguments)
                              for keyword in node.keywords if keyword.arg is not None})
                outputs = returned(function)
                results.append(bool(outputs) and all(frozen(value, function, bound, active) for value in outputs))
            return bool(results) and all(results)
        if isinstance(node, ast.Subscript):
            return frozen(node.value, owner, arguments, active)
        return False

    return frozen(expression, scope, {})


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
def test_live_censuses_use_one_index_helper(caller, source=None):
    tree = ast.parse((REPO / "tests" / "unit" / "core" / caller).read_text(encoding="utf-8")
                     if source is None else source)
    imports = [node for node in tree.body if isinstance(node, ast.ImportFrom)
               and node.module == "tests.helpers_reviewed_sources"]
    assert any(alias.name == "reviewed_python_paths" for node in imports for alias in node.names)
    frozen = [node.value for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == "_REVIEWED_PYTHON_PATHS"
                      for target in node.targets)]
    assert len(frozen) == 1
    assert ast.dump(frozen[0]) == ast.dump(ast.parse("reviewed_python_paths(REPO)", mode="eval").body)
    assert not any(isinstance(node, ast.FunctionDef) and node.name == "_reviewed_python_paths"
                   for node in tree.body)
    helper = ast.parse((REPO / "tests" / "helpers_reviewed_sources.py").read_text(encoding="utf-8"))
    entry_name = ("test_no_module_imports_a_private_name_of_redaction" if caller == "test_redaction.py"
                  else "test_every_name_in_insights_all_is_used_outside_the_module")
    entry = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == entry_name)
    reachable = census_dependencies(tree, [(entry, entry)])
    assert not any(has_live_tree_enumeration(node, tree) for node, _ in reachable), (
        "live-tree census enumeration is forbidden")
    assert not has_live_tree_enumeration(helper, helper), "live-tree census enumeration is forbidden"
    source_positions = {"private_imports": 0, "_defined_names_referenced_outside": 1}
    inputs = [(call.args[source_positions[call.func.id]], scope)
              for node, scope in reachable for call in ast.walk(node)
              if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
              and call.func.id in source_positions]
    assert inputs, "live census must check source input"
    for expression, scope in inputs:
        assert source_uses_frozen_inventory(tree, expression, scope), (
            "source input must use the shared frozen inventory")
    runner = next(node for node in helper.body if isinstance(node, ast.FunctionDef) and node.name == "git")
    timeouts = [kw.value for node in ast.walk(runner) if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute) and node.func.attr == "run"
                for kw in node.keywords if kw.arg == "timeout"]
    assert len(timeouts) == 1 and ast.dump(timeouts[0]) == ast.dump(ast.Name(id="GIT_TIMEOUT", ctx=ast.Load()))
    ceiling = next(node.value.value for node in helper.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "GIT_TIMEOUT" for target in node.targets))
    assert 0 < ceiling <= 60


def census_source_variant(caller, replacement, extra="", prelude=""):
    source = (REPO / "tests" / "unit" / "core" / caller).read_text(encoding="utf-8")
    entry = ("test_no_module_imports_a_private_name_of_redaction" if caller == "test_redaction.py"
             else "test_every_name_in_insights_all_is_used_outside_the_module")
    function = next(node for node in ast.parse(source).body
                    if isinstance(node, ast.FunctionDef) and node.name == entry)
    lines = source.splitlines(keepends=True)
    body = "".join(lines[function.lineno - 1:function.end_lineno])
    original = "_python_sources() if sources is None else sources"
    assert body.count(original) == 1
    body = body.replace(original, replacement)
    body = body.replace("    real_parse = ast.parse", prelude + "    real_parse = ast.parse", 1)
    return ("".join(lines[:function.lineno - 1]) + body
            + "".join(lines[function.end_lineno:]) + extra)


def run_census_variant(tmp_path, caller, source, checkout=None):
    """Execute the real entry point in a child with its own module namespace."""
    variant = tmp_path / caller if checkout is None else checkout / "tests" / "unit" / "core" / caller
    variant.parent.mkdir(parents=True, exist_ok=True)
    variant.write_text(source, encoding="utf-8")
    program = (
        "import importlib\nfrom pathlib import Path\nimport pytest\n"
        "module = importlib.import_module('tests.unit.core.' + sys.argv[2][:-3])\n"
        "if sys.argv[4] == 'fixture':\n"
        "    module.__file__ = sys.argv[3]\n"
        "    sys.path.insert(0, str(Path(module.__file__).parents[3]))\n"
        "exec(compile(Path(sys.argv[3]).read_text(encoding='utf-8'), module.__file__, 'exec'), module.__dict__)\n"
        "entry = ('test_no_module_imports_a_private_name_of_redaction' if sys.argv[2] == 'test_redaction.py'\n"
        "         else 'test_every_name_in_insights_all_is_used_outside_the_module')\n"
        "with pytest.MonkeyPatch.context() as patcher:\n"
        "    if hasattr(module, 'round4_other_test'):\n"
        "        getattr(module, entry)(patcher)\n"
        "        try:\n            module.round4_other_test()\n"
        "        except AssertionError:\n            pass\n"
        "    getattr(module, entry)(patcher)\n"
        "    if hasattr(module, 'round4_after_census'):\n        module.round4_after_census()\n"
    )
    return _run_isolated(program, caller, variant, "fixture" if checkout is not None else "variant")


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("binding", [
    'if (REPO / "aegis_core").is_dir():\n    core_files = list((REPO / "aegis_core").rglob("*.py"))',
    '*core_files, = (REPO / "aegis_core").rglob("*.py")',
])
def test_round4_precheck_indexes_compound_and_starred_bindings(caller, binding):
    source = census_source_variant(
        caller, "_python_sources() if sources is None else sources", "\n" + binding + "\n",
        "    assert len(core_files) == sum(name.startswith('aegis_core/') for name in _REVIEWED_PYTHON_PATHS)\n",
    )
    with pytest.raises(AssertionError, match="live-tree census enumeration is forbidden"):
        test_live_censuses_use_one_index_helper(caller, source)


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("location", ["compound-import", "starred-import", "other-test", "after-last-census"])
def test_round4_runtime_records_the_whole_module_lifetime(tmp_path, caller, location):
    if location == "compound-import":
        extra = ('\nif (REPO / "aegis_core").is_dir():\n'
                 '    core_files = list((REPO / "aegis_core").rglob("*.py"))\n')
    elif location == "starred-import":
        extra = '\n*core_files, = (REPO / "aegis_core").rglob("*.py")\n'
    else:
        name = "round4_other_test" if location == "other-test" else "round4_after_census"
        extra = ('\ndef ' + name + '():\n'
                 '    return list((REPO / "aegis_core").iterdir())\n')
    prelude = ("    assert len(core_files) == sum(name.startswith('aegis_core/') for name in _REVIEWED_PYTHON_PATHS)\n"
               if location in {"compound-import", "starred-import"} else "")
    source = census_source_variant(caller, "_python_sources() if sources is None else sources", extra, prelude)
    result = run_census_variant(tmp_path, caller, source)
    assert result.returncode != 0, "census forgot an enumeration before its call"
    assert b"live-tree census enumeration is forbidden" in result.stderr, result.stderr.decode()
    assert str(REPO).encode() in result.stderr


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("rebind", ["filter", "slice", "concatenate", "unchanged"])
def test_round4_retains_membership_and_detects_tracked_bad_sources(tmp_path, caller, rebind):
    checkout = tmp_path / "checkout"
    if caller == "test_redaction.py":
        benign, bad = "# redaction\n", "from aegis_core.redaction import _private\n"
    else:
        benign = "from aegis_core.insights import " + ", ".join(insight_module.__all__) + "\n"
        bad = "insights syntax (\n"
    reviewed_helper.freeze_fixture_sources(checkout, [("aegis_core/reviewed.py", benign), ("tests/bad.py", bad)])
    extra = {
        "filter": "\n_REVIEWED_PYTHON_PATHS: tuple = tuple(p for p in _REVIEWED_PYTHON_PATHS if not p.startswith('tests/'))\n",
        "slice": "\n_REVIEWED_PYTHON_PATHS: tuple = _REVIEWED_PYTHON_PATHS[:1]\n",
        "concatenate": "\n_REVIEWED_PYTHON_PATHS: tuple = _REVIEWED_PYTHON_PATHS[:1] + _REVIEWED_PYTHON_PATHS[:1]\n",
        "unchanged": "",
    }[rebind]
    source = census_source_variant(caller, "_python_sources() if sources is None else sources", extra)
    result = run_census_variant(tmp_path, caller, source, checkout=checkout)
    assert result.returncode != 0, "census accepted a caller-rebound reference inventory"
    if rebind == "unchanged":
        assert (b"AssertionError" if caller == "test_redaction.py" else b"SyntaxError") in result.stderr
    else:
        assert b"census rows must equal the frozen inventory" in result.stderr, result.stderr.decode()


def test_round4_package_shape_uses_the_frozen_inventory():
    source = (REPO / "tests/unit/core/test_insights.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    entry = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name == "test_insights_is_a_package_of_four_modules")
    assert not has_live_tree_enumeration(entry, tree), "package-shape census must use the frozen inventory"


def test_round4_helper_retains_the_first_index_even_after_later_staging(tmp_path):
    retained = reviewed_helper.freeze_fixture_sources(tmp_path, [("tests/first.py", "# retained\n")])
    (tmp_path / "tests/later.py").write_text("# later\n", encoding="utf-8")
    reviewed_helper.git(tmp_path, "add", ".")
    assert reviewed_python_paths(tmp_path) is retained
    assert retained == ("tests/first.py",)


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("binding", [
    'core_files = []\ncore_files += list((REPO / "aegis_core").rglob("*.py"))',
    'if (core_files := list((REPO / "aegis_core").rglob("*.py"))):\n    pass',
    'core_files = []\ncore_files.append(list((REPO / "aegis_core").rglob("*.py")))',
    'core_files = []\ncore_files.extend((REPO / "aegis_core").rglob("*.py"))',
    'core_files = []\ncore_files.insert(0, list((REPO / "aegis_core").rglob("*.py")))',
    '*core_files, last = ([], *(REPO / "aegis_core").rglob("*.py"))',
])
def test_round4_correctness_precheck_indexes_accumulation(caller, binding):
    source = census_source_variant(
        caller, "_python_sources() if sources is None else sources", "\n" + binding + "\n",
        "    assert len(core_files) == sum(name.startswith('aegis_core/') for name in _REVIEWED_PYTHON_PATHS)\n")
    with pytest.raises(AssertionError, match="live-tree census enumeration is forbidden"):
        test_live_censuses_use_one_index_helper(caller, source)


def test_round4_correctness_external_glob_avoids_windows39_resolve(monkeypatch, tmp_path):
    class Windows39Path(type(tmp_path)):
        def resolve(self, *args, **kwargs):
            if "*" in str(self):
                raise OSError(123, "Windows 3.9 rejects wildcard resolution")
            return super().resolve(*args, **kwargs)

    monkeypatch.setattr(reviewed_helper, "Path", Windows39Path)
    monkeypatch.setattr(reviewed_helper, "sys", SimpleNamespace(**{**vars(sys), "version_info": (3, 9)}))
    with census_guard(REPO):
        sys.audit("glob.glob", str(tmp_path / "*.py"), False)


def test_round4_correctness_primary_glob_event_defers_to_root_dir():
    if sys.version_info < (3, 10):
        pytest.skip("glob root_dir audit event requires Python 3.10")
    with census_guard(REPO):
        sys.audit("glob.glob", str(REPO / "*.py"), False)


def test_round4_correctness_windows_extended_long_and_rooted_globs(tmp_path):
    if os.name != "nt":
        pytest.skip("Windows drive and extended-length path spellings")
    program = (
        "import glob, os, pytest\nfrom pathlib import Path\n"
        "from tests.helpers_reviewed_sources import census_guard\n"
        "root, outside = Path(sys.argv[2]), Path(sys.argv[3])\n"
        "with census_guard(root):\n"
        "    assert glob.glob(str(outside / ('a' * 180) / ('b' * 180) / '*.py')) == []\n"
        "extended = '\\\\\\\\?\\\\' + str(root)\n"
        "with pytest.raises(AssertionError, match='live-tree census enumeration is forbidden'):\n"
        "    with census_guard(Path(extended)):\n        os.listdir(str(Path(extended)))\n"
        "if sys.version_info >= (3, 10):\n"
        "    drive, tail = os.path.splitdrive(str(root))\n"
        "    other = next(value for value in ('C:', 'D:', 'E:') if value.lower() != drive.lower())\n"
        "    with census_guard(root):\n"
        "        assert glob.glob(os.path.join(tail, '*.py'), root_dir=other + '\\\\outside') == []\n"
    )
    result = _run_isolated(program, REPO, tmp_path)
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
def test_round4_correctness_local_uncached_checkout_import_passes(tmp_path, caller):
    checkout = tmp_path / "checkout"
    text = "# redaction\n" if caller == "test_redaction.py" else (
        "from aegis_core.insights import " + ", ".join(insight_module.__all__) + "\n")
    reviewed_helper.freeze_fixture_sources(checkout, [("aegis_core/reviewed.py", text)])
    package = checkout / "fixture_uncached" / "nested"
    package.mkdir(parents=True)
    (package.parent / "__init__.py").write_text("", encoding="utf-8")
    (package / "__init__.py").write_text("", encoding="utf-8")
    prelude = ("    listed = []\n"
               "    def watch_import(event, args):\n"
               "        if event == 'os.listdir':\n            listed.append(str(args[0]))\n"
               "    sys.addaudithook(watch_import)\n"
               "    import fixture_uncached.nested\n"
               "    assert any(os.path.normcase(str(REPO)) in os.path.normcase(name) for name in listed), 'fixture did not exercise FileFinder'\n")
    source = census_source_variant(caller, "_python_sources() if sources is None else sources", prelude=prelude)
    result = run_census_variant(tmp_path, caller, source, checkout=checkout)
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
def test_round4_correctness_import_frame_names_do_not_grant_an_exception(tmp_path, caller):
    extra = ("\ndef _fill_cache():\n    return os.listdir(REPO)\n"
             "def find_spec():\n    return _fill_cache()\n")
    source = census_source_variant(caller, "_python_sources() if sources is None else sources", extra,
                                   "    find_spec()\n")
    result = run_census_variant(tmp_path, caller, source)
    assert result.returncode != 0
    assert b"live-tree census enumeration is forbidden" in result.stderr, result.stderr.decode()


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("bypass", ["inline", "swallowed-mismatch"])
def test_round4_correctness_requires_a_successful_checker(tmp_path, caller, bypass):
    if bypass == "inline":
        source = census_source_variant(caller, "_python_sources() if sources is None else sources")
        entry_name = ("test_no_module_imports_a_private_name_of_redaction" if caller == "test_redaction.py"
                      else "test_every_name_in_insights_all_is_used_outside_the_module")
        entry = next(node for node in ast.parse(source).body
                     if isinstance(node, ast.FunctionDef) and node.name == entry_name)
        lines = source.splitlines(keepends=True)
        source = ("".join(lines[:entry.lineno])
                  + "    for label, text in _python_sources():\n        ast.parse(text, filename=str(label))\n"
                  + "".join(lines[entry.end_lineno:]))
        message = b"census did not check its source rows"
    else:
        call = ("private_imports(fabricated)" if caller == "test_redaction.py" else
                "_defined_names_referenced_outside(Path(core_insights.__file__), fabricated, set())")
        prelude = ("    original = _python_sources()\n"
                   "    fabricated = ((original[0][0], '# fabricated\\n'), *original[1:])\n"
                   "    try:\n        " + call + "\n    except AssertionError:\n        pass\n")
        source = census_source_variant(caller, "_python_sources() if sources is None else sources", prelude=prelude)
        message = b"census rows must equal the frozen inventory"
    result = run_census_variant(tmp_path, caller, source)
    assert result.returncode != 0, "census passed without a successful complete source check"
    assert message in result.stderr, result.stderr.decode()


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("binding", [
    'core_files: list = list((REPO / "aegis_core").rglob("*.py"))',
    'core_files, = (list((REPO / "aegis_core").rglob("*.py")),)',
    '[core_files] = [list((REPO / "aegis_core").rglob("*.py"))]',
])
def test_live_census_precheck_indexes_annotated_and_destructured_bindings(caller, binding):
    source = census_source_variant(
        caller, "_python_sources() if sources is None else sources", "\n" + binding + "\n",
        "    assert len(core_files) == sum(name.startswith('aegis_core/') for name in _REVIEWED_PYTHON_PATHS)\n",
    )
    with pytest.raises(AssertionError, match="live-tree census enumeration is forbidden"):
        test_live_censuses_use_one_index_helper(caller, source)


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("operation", [
    "annotated-rglob", "typed-walk-extend", "glob", "iglob", "listdir", "scandir", "iterdir",
    "relative-listdir", "bytes-listdir", "thread-callback", "caught-refusal",
])
def test_live_census_runtime_rejects_reviewer_enumerations(tmp_path, caller, operation):
    extra = "\nimport glob\nfrom concurrent.futures import ThreadPoolExecutor\n"
    replacement = "_python_sources() if sources is None else sources"
    if operation == "annotated-rglob":
        prelude = (
            '    core_files: list = list((REPO / "aegis_core").rglob("*.py"))\n'
            "    assert len(core_files) == sum(name.startswith('aegis_core/') for name in _REVIEWED_PYTHON_PATHS)\n"
        )
    elif operation == "typed-walk-extend":
        extra += "\nfrom typing import Callable\nwalk_sources: Callable = os.walk\n"
        prelude = (
            "    rows = list(_python_sources()) if sources is None else sources\n"
            "    rows.extend((Path(d) / n, '') for d, _, names in walk_sources(REPO / 'tests' / 'new_consumers')\n"
            "                for n in names if n.endswith('.py'))\n"
        )
        replacement = "rows"
    else:
        prelude = {
            "glob": "    glob.glob(str(REPO / '*.py'))\n",
            "iglob": "    list(glob.iglob(str(REPO / '*.py')))\n",
            "listdir": "    os.listdir(REPO)\n",
            "scandir": "    with os.scandir(REPO) as entries:\n        list(entries)\n",
            "iterdir": "    list(REPO.iterdir())\n",
            "relative-listdir": "    os.listdir('.')\n",
            "bytes-listdir": "    os.listdir(os.fsencode(REPO))\n",
            "thread-callback": ("    with ThreadPoolExecutor(max_workers=1) as pool:\n"
                                "        pool.submit(os.listdir, REPO).result(timeout=5)\n"),
            "caught-refusal": "    try:\n        os.listdir(REPO)\n    except AssertionError:\n        pass\n",
        }[operation]
    result = run_census_variant(tmp_path, caller, census_source_variant(caller, replacement, extra, prelude))
    assert result.returncode != 0, "live census accepted checkout enumeration"
    assert b"live-tree census enumeration is forbidden" in result.stderr, result.stderr.decode()
    assert str(REPO).encode() in result.stderr


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("runner", ["reviewed_helper.git", "_git"])
@pytest.mark.parametrize("target", [
    "checkout", "checkout-child", "caught-refusal", "-C", "-Cjoined",
    "--git-dir", "--git-dir=", "--work-tree", "--work-tree=",
    "outside-C", "outside-git-dir", "outside-work-tree",
    "absolute-root", "absolute-child", "option-root", "option-child",
])
def test_live_census_git_refuses_live_index_listings(tmp_path, caller, runner, target):
    fixture = tmp_path / "fixture"
    reviewed_helper.freeze_fixture_sources(fixture, [("tests/reviewed.py", "# redaction\n")])
    cwd = repr(str(fixture))
    options = {
        "-C": "'-C', str(REPO)", "-Cjoined": "'-C' + str(REPO)",
        "--git-dir": "'--git-dir', str(REPO / '.git')",
        "--git-dir=": "'--git-dir=' + str(REPO / '.git')",
        "--work-tree": "'--work-tree', str(REPO)",
        "--work-tree=": "'--work-tree=' + str(REPO)",
        "outside-C": "'-C', " + cwd,
        "outside-git-dir": "'--git-dir=' + str(Path(" + cwd + ") / '.git')",
        "outside-work-tree": "'--work-tree=' + " + cwd,
    }
    args = "'ls-files', '--cached', '-z', '--', 'aegis_core'"
    if target in {"checkout", "caught-refusal"}:
        cwd = "REPO"
    elif target == "checkout-child":
        cwd = "REPO / 'aegis_core'"
    elif target in options:
        args = options[target] + ", 'ls-files', '--cached', '-z'"
    else:
        path = "REPO / 'aegis_core'" if target.endswith("child") else "REPO"
        argument = "'--exclude=' + str(" + path + ")" if target.startswith("option") else "'--', str(" + path + ")"
        args = "'ls-files', '--cached', '-z', " + argument
    call = runner + "(Path(" + cwd + "), " + args + ")"
    if target == "caught-refusal":
        prelude = "    try:\n        " + call + "\n    except AssertionError:\n        pass\n"
    else:
        prelude = "    listed = " + call + ".stdout\n"
        if target == "checkout":
            prelude += (
                "    live = {os.fsdecode(p) for p in listed.split(b'\\0') if p.endswith(b'.py')}\n"
                "    assert live == {p for p in _REVIEWED_PYTHON_PATHS if p.startswith('aegis_core/')}\n"
            )
    extra = "\nimport tests.helpers_reviewed_sources as reviewed_helper\nfrom tests.helpers_reviewed_sources import git as _git\n"
    source = census_source_variant(caller, "_python_sources() if sources is None else sources", extra, prelude)
    result = run_census_variant(tmp_path, caller, source)
    assert result.returncode != 0, "live census accepted a second Git index listing"
    assert b"live-tree census enumeration is forbidden" in result.stderr, result.stderr.decode()


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("runner", ["reviewed_helper.git", "_git"])
def test_live_census_git_allows_fixture_index_listings(tmp_path, caller, runner):
    fixture = tmp_path / "fixture"
    reviewed_helper.freeze_fixture_sources(fixture, [("tests/reviewed.py", "# redaction\n")])
    extra = "\nimport tests.helpers_reviewed_sources as reviewed_helper\nfrom tests.helpers_reviewed_sources import git as _git\n"
    prelude = ("    listed = " + runner + "(Path(" + repr(str(fixture)) + "), 'ls-files', '-z').stdout\n"
               "    assert listed.split(b'\\0') == [b'tests/reviewed.py', b'']\n")
    source = census_source_variant(caller, "_python_sources() if sources is None else sources", extra, prelude)
    result = run_census_variant(tmp_path, caller, source)
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("runner", ["reviewed_helper.git", "_git"])
@pytest.mark.parametrize("target", ["checkout", "-C", "--git-dir", "--work-tree", "caught-refusal", "fixture"])
def test_live_census_git_checks_worker_callbacks(tmp_path, caller, runner, target):
    fixture = tmp_path / "fixture"
    reviewed_helper.freeze_fixture_sources(fixture, [("tests/reviewed.py", "# redaction\n")])
    cwd = "REPO" if target in {"checkout", "caught-refusal"} else "Path(" + repr(str(fixture)) + ")"
    args = "'ls-files', '--cached', '-z', '--', 'aegis_core'"
    if target == "-C":
        args = "'-C', str(REPO), 'ls-files', '--cached', '-z'"
    elif target == "--git-dir":
        args = "'--git-dir=' + str(REPO / '.git'), 'ls-files', '--cached', '-z'"
    elif target == "--work-tree":
        args = "'--work-tree=' + str(REPO), 'ls-files', '--cached', '-z'"
    elif target == "fixture":
        args = "'ls-files', '-z'"
    submission = "pool.submit(" + runner + ", " + cwd + ", " + args + ").result(timeout=5).stdout"
    prelude = "    with ThreadPoolExecutor(max_workers=1) as pool:\n"
    if target == "caught-refusal":
        prelude += "        try:\n            " + submission + "\n        except AssertionError:\n            pass\n"
    else:
        prelude += "        listed = " + submission + "\n"
        if target == "checkout":
            prelude += (
                "    live = {os.fsdecode(p) for p in listed.split(b'\\0') if p.endswith(b'.py')}\n"
                "    assert live == {p for p in _REVIEWED_PYTHON_PATHS if p.startswith('aegis_core/')}\n"
            )
        elif target == "fixture":
            prelude += "    assert listed.split(b'\\0') == [b'tests/reviewed.py', b'']\n"
    extra = ("\nfrom concurrent.futures import ThreadPoolExecutor\n"
             "import tests.helpers_reviewed_sources as reviewed_helper\n"
             "from tests.helpers_reviewed_sources import git as _git\n")
    source = census_source_variant(caller, "_python_sources() if sources is None else sources", extra, prelude)
    result = run_census_variant(tmp_path, caller, source)
    if target == "fixture":
        assert result.returncode == 0, result.stderr.decode()
    else:
        assert result.returncode != 0, "worker callback bypassed the active census"
        assert b"live-tree census enumeration is forbidden" in result.stderr, result.stderr.decode()
        assert str(REPO).encode() in result.stderr


def test_git_worker_without_a_census_can_read_the_index():
    program = (
        "from concurrent.futures import ThreadPoolExecutor\nfrom pathlib import Path\n"
        "from tests.helpers_reviewed_sources import git\n"
        "with ThreadPoolExecutor(max_workers=1) as pool:\n"
        "    listed = pool.submit(git, Path(sys.argv[2]), 'ls-files', '--cached', '-z').result(timeout=5).stdout\n"
        "assert b'tests/helpers_reviewed_sources.py' in listed.split(b'\\0')\n"
    )
    result = _run_isolated(program, REPO)
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("mutation", ["extend", "append", "concatenate", "omit", "duplicate"])
def test_live_census_runtime_requires_exact_frozen_rows(tmp_path, caller, mutation):
    prelude = "    rows = list(_python_sources())\n"
    row = "('tests/unreviewed.py', '')" if caller == "test_redaction.py" else "(REPO / 'tests/unreviewed.py', '')"
    prelude += {
        "extend": f"    rows.extend([{row}])\n",
        "append": f"    rows.append({row})\n",
        "concatenate": f"    rows = tuple(rows) + ({row},)\n",
        "omit": "    rows.pop()\n",
        "duplicate": "    rows.append(rows[0])\n",
    }[mutation]
    result = run_census_variant(tmp_path, caller, census_source_variant(caller, "rows", prelude=prelude))
    assert result.returncode != 0, "live census accepted changed inventory membership"
    assert b"census rows must equal the frozen inventory" in result.stderr, result.stderr.decode()


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("binding", [
    'EXTRA_PATHS: list = list((REPO / "aegis_core").rglob("*.py"))',
    'EXTRA_PATHS, = (list((REPO / "aegis_core").rglob("*.py")),)',
])
def test_live_census_argon_extra_paths_are_prechecked(caller, binding):
    source = census_source_variant(
        caller, "tuple(row for row in _python_sources() for extra in EXTRA_PATHS)", "\n" + binding + "\n")
    with pytest.raises(AssertionError, match="live-tree census enumeration is forbidden"):
        test_live_censuses_use_one_index_helper(caller, source)


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("fabrication", ["filter", "slice", "map", "parameter", "fake-text", "repeated"])
def test_live_census_argon_rejects_fabricated_rows(tmp_path, caller, fabrication):
    prelude = "    original_rows = _python_sources()\n    first = original_rows[0][0]\n"
    fake = "(row[0], '# benign fixture\\n') if row[0] == first else row"
    replacement = {
        "filter": "tuple(row for row in original_rows if row[0] != first)",
        "slice": "original_rows[1:]",
        "map": f"tuple(map(lambda row: {fake}, original_rows))",
        "parameter": "_python_sources() if sources is None else sources",
        "fake-text": f"tuple({fake} for row in original_rows)",
        "repeated": "(original_rows[0],) * len(original_rows)",
    }[fabrication]
    if fabrication == "parameter":
        prelude += f"    sources = tuple({fake} for row in original_rows)\n"
    result = run_census_variant(tmp_path, caller, census_source_variant(caller, replacement, prelude=prelude))
    assert result.returncode != 0, "live census accepted fabricated source rows"
    assert b"census rows must equal the frozen inventory" in result.stderr, result.stderr.decode()


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("argument", ["fabricated", "*[fabricated]", "**{'sources': fabricated}"])
def test_live_census_argon_rejects_nonempty_wrappers(tmp_path, caller, argument):
    prelude = ("    original_rows = _python_sources()\n"
               "    fabricated = ((original_rows[0][0], '# benign fixture\\n'), *original_rows[1:])\n")
    source = census_source_variant(caller, "_python_sources() if sources is None else sources", prelude=prelude)
    entry_name = ("test_no_module_imports_a_private_name_of_redaction" if caller == "test_redaction.py"
                  else "test_every_name_in_insights_all_is_used_outside_the_module")
    entry = next(node for node in ast.parse(source).body
                 if isinstance(node, ast.FunctionDef) and node.name == entry_name)
    sink_name = "private_imports" if caller == "test_redaction.py" else "_defined_names_referenced_outside"
    sink = next(node for node in ast.walk(entry) if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name) and node.func.id == sink_name)
    sink_source = ast.get_source_segment(source, sink)
    lines = source.splitlines(keepends=True)
    body = "".join(lines[entry.lineno - 1:entry.end_lineno])
    body = body.replace(sink_source, f"_run_census({argument})", 1)
    source = "".join(lines[:entry.lineno - 1]) + body + "".join(lines[entry.end_lineno:])
    source += "\ndef _run_census(sources=None):\n    return " + sink_source + "\n"
    result = run_census_variant(tmp_path, caller, source)
    assert result.returncode != 0, "live census accepted a wrapper's fabricated explicit argument"
    assert b"census rows must equal the frozen inventory" in result.stderr, result.stderr.decode()


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
def test_live_census_runtime_allows_external_globs_and_resets(tmp_path, caller):
    extra = "\nimport glob\nexternal_files = glob.glob(" + repr(str(tmp_path / "*.py")) + ")\n"
    prelude = "    glob.glob(" + repr(str(tmp_path / "*.py")) + ")\n"
    if sys.version_info >= (3, 10):
        prelude += "    glob.glob('*.py', root_dir=" + repr(str(tmp_path)) + ")\n"
    source = census_source_variant(caller, "_python_sources() if sources is None else sources", extra, prelude)
    result = run_census_variant(tmp_path, caller, source)
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
def test_live_census_source_rows_are_immutable(caller):
    import importlib

    module = importlib.import_module("tests.unit.core." + caller[:-3])
    assert isinstance(module._REVIEWED_PYTHON_PATHS, tuple)
    assert isinstance(module._python_sources(), tuple)


def test_live_census_runtime_flag_resets_after_refusal_and_other_errors():
    program = (
        "import os, pytest\nfrom pathlib import Path\n"
        "from tests.helpers_reviewed_sources import census_guard\n"
        "root = Path(sys.argv[2])\n"
        "for failure in (AssertionError, ValueError):\n"
        "    with pytest.raises(failure):\n"
        "        with census_guard(root):\n"
        "            if failure is ValueError:\n                raise ValueError('fixture error')\n"
        "            os.listdir(root)\n"
        "    assert 'tests' in os.listdir(root)\n"
    )
    result = _run_isolated(program, REPO)
    assert result.returncode == 0, result.stderr.decode()


def test_live_census_runtime_installs_one_hook_across_reimports():
    program = (
        "import importlib, os, runpy\nfrom pathlib import Path\n"
        "seen = []\n"
        "def observe(event, args):\n"
        "    if event == 'sys.addaudithook':\n        seen.append(event)\n"
        "sys.addaudithook(observe)\n"
        "from tests import helpers_reviewed_sources as helper\n"
        "importlib.reload(helper)\n"
        "runpy.run_path(helper.__file__)\n"
        "assert len(seen) == 1, seen\n"
        "for attempt in range(2):\n"
        "    try:\n"
        "        with helper.census_guard(Path(sys.argv[2])):\n            os.listdir(sys.argv[2])\n"
        "    except AssertionError as exc:\n"
        "        assert 'live-tree census enumeration is forbidden' in str(exc)\n"
        "    else:\n        raise AssertionError('reimport disabled the audit hook')\n"
        "    assert 'tests' in os.listdir(sys.argv[2])\n"
    )
    result = _run_isolated(program, REPO)
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("external", [False, True])
@pytest.mark.parametrize("operation", ["listdir", "scandir", "glob-dir-fd"])
def test_live_census_runtime_resolves_descriptor_paths(tmp_path, external, operation):
    if os.name != "posix" or not Path("/proc/self/fd").is_dir():
        pytest.skip("descriptor physical-path probe requires POSIX procfs")
    if operation == "glob-dir-fd" and sys.version_info < (3, 10):
        pytest.skip("glob dir_fd requires Python 3.10")
    program = (
        "import glob, os, pytest\nfrom pathlib import Path\n"
        "from tests.helpers_reviewed_sources import census_guard\n"
        "root, directory, operation, external = Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5] == 'True'\n"
        "descriptor = os.open(directory, os.O_RDONLY)\n"
        "try:\n"
        "    def enumerate_directory():\n"
        "        if operation == 'listdir':\n            return os.listdir(descriptor)\n"
        "        if operation == 'scandir':\n"
        "            with os.scandir(descriptor) as entries:\n                return list(entries)\n"
        "        return glob.glob('*.py', dir_fd=descriptor)\n"
        "    if external:\n"
        "        with census_guard(root):\n            assert enumerate_directory() == []\n"
        "    else:\n"
        "        with pytest.raises(AssertionError, match='live-tree census enumeration is forbidden'):\n"
        "            with census_guard(root):\n                enumerate_directory()\n"
        "finally:\n    os.close(descriptor)\n"
    )
    result = _run_isolated(program, REPO, tmp_path if external else REPO, operation, external)
    assert result.returncode == 0, result.stderr.decode()


def test_live_census_runtime_refuses_an_unsupported_descriptor_probe(monkeypatch):
    def unsupported_readlink(path):
        raise OSError("physical descriptor paths unavailable")

    monkeypatch.setattr(reviewed_helper, "os", SimpleNamespace(**{**vars(os), "readlink": unsupported_readlink}))
    with pytest.raises(AssertionError, match="live-tree census enumeration is forbidden: cannot resolve 77"):
        with census_guard(REPO):
            sys.audit("os.listdir", 77)


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("enumeration", [
    '(REPO / "aegis_core").rglob("*.py")',
    'os.walk(REPO)',
    'glob.glob(str(REPO / "**" / "*.py"), recursive=True)',
    'glob.iglob(str(REPO / "**" / "*.py"), recursive=True)',
])
@pytest.mark.parametrize("dependency", ["inline", "function", "class", "callback"])
def test_live_census_guard_rejects_enumeration_from_entrypoints(caller, enumeration, dependency):
    extra = "\nimport glob\n"
    if dependency == "inline":
        replacement = enumeration
    elif dependency == "function":
        extra += "\ndef round2_sources():\n    return " + enumeration + "\n"
        replacement = "round2_sources()"
    elif dependency == "class":
        extra += "\nclass Round2Sources:\n    def collect(self):\n        return " + enumeration + "\n"
        replacement = "Round2Sources().collect()"
    else:
        extra += ("\ndef round2_sources():\n    return " + enumeration + "\n"
                  "def round2_callback(reader):\n    return reader()\n")
        replacement = "round2_callback(round2_sources)"
    source = census_source_variant(caller, replacement, extra)
    for _ in range(2):
        with pytest.raises(AssertionError, match="live-tree census enumeration is forbidden"):
            test_live_censuses_use_one_index_helper(caller, source)


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
def test_live_census_guard_requires_frozen_source_input(caller):
    source = census_source_variant(caller, "[]")
    for _ in range(2):
        with pytest.raises(AssertionError, match="source input must use the shared frozen inventory"):
            test_live_censuses_use_one_index_helper(caller, source)


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("replacement,extra", [
    ("round2_sources()", "\ndef round2_sources():\n    return _python_sources()\n"),
    ("Round2Sources().collect()", "\nclass Round2Sources:\n    def collect(self):\n        return _python_sources()\n"),
    ("round2_callback(_python_sources)", "\ndef round2_callback(reader):\n    return reader()\n"),
    ("round2_sources()", "\ndef round2_sources():\n    reader = _python_sources\n    return reader()\n"),
    ("round2_callback(Round2Sources().collect)",
     "\nclass Round2Sources:\n    def collect(self):\n        return _python_sources()\n"
     "def round2_callback(reader):\n    return reader()\n"),
], ids=["function", "method", "callback", "local-alias", "method-callback"])
def test_live_census_guard_accepts_frozen_helpers_and_callbacks(caller, replacement, extra):
    test_live_censuses_use_one_index_helper(caller, census_source_variant(caller, replacement, extra))


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("replacement,extra", [
    ("enumerate_sources(REPO)", "\nfrom os import walk as enumerate_sources\n"),
    ("enumerate_sources(str(REPO / '**' / '*.py'))", "\nfrom glob import iglob as enumerate_sources\n"),
    ("round2_sources()", "\ndef round2_sources():\n    reader = (REPO / 'tests').rglob\n    return reader('*.py')\n"),
], ids=["walk-alias", "glob-alias", "bound-callback"])
def test_live_census_guard_rejects_enumeration_aliases(caller, replacement, extra):
    source = census_source_variant(caller, replacement, extra)
    with pytest.raises(AssertionError, match="live-tree census enumeration is forbidden"):
        test_live_censuses_use_one_index_helper(caller, source)


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
def test_live_census_guard_rejects_unused_frozen_input(caller):
    # A separate frozen read in the census body must not bless another source input.
    source = census_source_variant(caller, "round2_sources()", "\ndef round2_sources():\n    return []\n",
                                   prelude="    unused = _python_sources()\n")
    with pytest.raises(AssertionError, match="source input must use the shared frozen inventory"):
        test_live_censuses_use_one_index_helper(caller, source)


@pytest.mark.parametrize("caller", ["test_redaction.py", "test_insights.py"])
@pytest.mark.parametrize("replacement,extra", [
    ("round2_sources()", "\ndef round2_sources():\n    unused = _python_sources()\n    return []\n"),
    ("round2_sources(_python_sources())", "\ndef round2_sources(unused):\n    return []\n"),
    ("round2_callback(_python_sources)", "\ndef round2_callback(unused):\n    return []\n"),
], ids=["unused-local", "unused-argument", "unused-callback"])
def test_live_census_guard_rejects_discarded_frozen_inputs(caller, replacement, extra):
    source = census_source_variant(caller, replacement, extra)
    for _ in range(2):
        with pytest.raises(AssertionError, match="source input must use the shared frozen inventory"):
            test_live_censuses_use_one_index_helper(caller, source)


@pytest.fixture(scope="module", params=["parent", "competing-tests"])
def redaction_import_path(request, tmp_path_factory):
    paths = list(sys.path)
    if request.param == "competing-tests":
        root = tmp_path_factory.mktemp("competing-tests-redaction")
        package = root / "tests"
        package.mkdir()
        (package / "__init__.py").write_text("# Installed regular tests package.\n", encoding="utf-8")
        paths.insert(0, str(root))
    return paths


def test_redaction_isolated_import_bootstrap(redaction_import_path):
    program = (
        "from pathlib import Path\n"
        "import tests\n"
        "assert Path(tests.__path__[0]) == Path(sys.argv[2])\n"
        "assert 'tests.conftest' not in sys.modules\n"
        "from tests.unit.core import test_redaction\n"
        "assert Path(test_redaction.__file__).resolve() == Path(sys.argv[3])\n"
    )
    result = _run_isolated(program, REPO / "tests", Path(__file__).resolve(), import_path=redaction_import_path)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


@pytest.fixture(params=["test_redaction.py", "test_insights.py"])
def reviewed_census_checkout(tmp_path_factory, request):
    source = REPO / "tests" / "unit" / "core" / request.param
    # Retained inventories outlive a test. Keep each fixture checkout alive for
    # the session so passed-test cleanup cannot recycle its canonical identity.
    checkout = tmp_path_factory.mktemp(f"reviewed-census-{source.stem}") / "checkout"
    module = checkout / "tests" / "unit" / "core" / source.name
    module.parent.mkdir(parents=True)
    shutil.copyfile(source, module)
    reviewed = ("aegis_core/reviewed.py", ".github/scripts/reviewed script.py")
    for name in reviewed:
        path = checkout / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# reviewed\n", encoding="utf-8")
    expected = tuple(sorted((*reviewed, module.relative_to(checkout).as_posix())))
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
    subprocess.run(["git", "init", "-q", str(checkout)], env=env, check=True, capture_output=True, timeout=60)
    subprocess.run(["git", "add", "."], cwd=checkout, env=env, check=True, capture_output=True, timeout=60)
    return checkout, module, env, expected


def test_both_censuses_freeze_the_index_and_retry_missing_sources(reviewed_census_checkout):
    checkout, module, env, expected = reviewed_census_checkout
    late = checkout / "tests" / "untracked.py"
    late.write_text("invalid syntax (\n", encoding="utf-8")
    scope = runpy.run_path(str(module))
    assert scope["_REVIEWED_PYTHON_PATHS"] == expected
    scan = scope["_python_sources"]
    initial = scan()
    assert ".github/scripts/reviewed script.py" in scope["_REVIEWED_PYTHON_PATHS"]
    assert "tests/untracked.py" not in scope["_REVIEWED_PYTHON_PATHS"]
    # A parallel worker may even stage a new file after collection.
    subprocess.run(["git", "add", "."], cwd=checkout, env=env, check=True, capture_output=True, timeout=60)
    for _ in range(2):
        assert scan() == initial
    reviewed = checkout / "aegis_core" / "reviewed.py"
    reviewed.unlink()
    for _ in range(2):
        with pytest.raises(FileNotFoundError) as failure:
            scan()
        assert failure.value.filename == str(reviewed)
    reviewed.write_text("# restored\n", encoding="utf-8")
    assert scan() != initial


def test_both_censuses_ignore_all_inherited_git_controls(reviewed_census_checkout, redaction_import_path):
    checkout, module, env, expected = reviewed_census_checkout
    assert runpy.run_path(str(module))["_REVIEWED_PYTHON_PATHS"] == expected
    env.update({"GIT_DIR": str(checkout / "absent"), "GIT_INDEX_FILE": str(checkout / "absent-index"),
                "GIT_CONFIG_COUNT": "invalid", "GIT_CONFIG_GLOBAL": str(checkout / "absent-config"),
                "git_dir": "invalid"})
    program = (
        "import json, os, runpy, sys\n"
        "def clean_git(event, args):\n"
        "    if event == 'subprocess.Popen' and 'ls-files' in args[1]:\n"
        "        actual = {key: value for key, value in args[3].items() if key.upper().startswith('GIT_')}\n"
        "        assert actual == {'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1',\n"
        "                          'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0'}, actual\n"
        "sys.addaudithook(clean_git)\n"
        "for attempt in range(2):\n"
        "    print(json.dumps(runpy.run_path(sys.argv[2])['_REVIEWED_PYTHON_PATHS']))\n"
    )
    result = _run_isolated(program, module, env=env, import_path=redaction_import_path)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert [json.loads(line) for line in result.stdout.splitlines()] == [list(expected)] * 2


def test_both_censuses_accept_gitfiles_without_history(reviewed_census_checkout):
    checkout, module, _, expected = reviewed_census_checkout
    assert runpy.run_path(str(module))["_REVIEWED_PYTHON_PATHS"] == expected
    metadata = checkout / ".git"
    metadata.rename(checkout / "metadata")
    metadata.write_text("gitdir: metadata\n", encoding="utf-8")
    for _ in range(2):
        assert runpy.run_path(str(module))["_REVIEWED_PYTHON_PATHS"] == expected


@pytest.mark.parametrize("marker", ["missing", "dangling"])
def test_both_censuses_refuse_absent_indexes(reviewed_census_checkout, marker):
    checkout, module, _, _ = reviewed_census_checkout
    metadata = checkout / ".git"
    metadata.rename(checkout / "metadata")
    if marker == "dangling":
        symlink_or_skip(checkout / "absent", metadata, target_is_directory=True)
    for _ in range(2):
        with pytest.raises(subprocess.CalledProcessError) as failure:
            runpy.run_path(str(module))
        assert failure.value.returncode == 128


def test_both_censuses_propagate_git_timeout(reviewed_census_checkout, redaction_import_path):
    checkout, module, env, _ = reviewed_census_checkout
    # Inject an OS process-boundary failure in an isolated interpreter. No shared
    # subprocess module or pytest teardown dependency is monkeypatched.
    program = (
        "import runpy, subprocess, sys\n"
        "def timed_out(event, args):\n"
        "    if event == 'subprocess.Popen' and 'ls-files' in args[1]:\n"
        "        raise subprocess.TimeoutExpired(args[1], 60)\n"
        "sys.addaudithook(timed_out)\n"
        "for attempt in range(2):\n"
        "    try:\n"
        "        runpy.run_path(sys.argv[2])\n"
        "    except subprocess.TimeoutExpired as failure:\n"
        "        assert failure.timeout == 60\n"
        "        assert 'ls-files' in failure.cmd\n"
        "    else:\n"
        "        raise AssertionError('Git timeout did not propagate')\n"
    )
    result = _run_isolated(program, module, env=env, import_path=redaction_import_path)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def _tok(*parts: str) -> str:
    return "".join(parts)


def _samples() -> Dict[str, str]:
    """The 11 Tier A formats, assembled as tests/unit/verification/test_scanners.py does."""
    return {
        "aws-access-key-id": _tok("AK", "IA", "9F8E7D6C5B4A3210"),
        "github-pat": _tok("gh", "p_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
        "github-fine-grained-pat": _tok("github", "_pat_", "11ABCDEFG0123456789_abcdefghijklmnop"),
        "slack-token": _tok("xox", "b-", "123456789012-ABCDEFGHIJKLMN"),
        "stripe-live-secret": _tok("sk", "_live_", "9876543210abcdefghijklmnoPQR"),
        "openai-api-key": _tok("sk", "-proj-", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd"),
        "anthropic-api-key": _tok("sk", "-ant-", "api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345"),
        "google-api-key": _tok("AI", "za", "SyD-9876543210abcdefghijklmnopqrstu"),
        "private-key-pem": _tok("-----BEGIN ", "RSA ", "PRIVATE KEY-----", "\\n", "MIIEowIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9OiJ"),
        "jwt-three-segment": _tok("eyJ", "hbGciOiJIUzI1NiJ9", ".", "eyJ", "zdWIiOiIxMjM0NTY3ODkwIn0", ".",
                                  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
        "url-basic-auth": _tok("https://", "svc_admin", ":", "p9Q8r7S6t5U4", "@api.internal.corp/v1"),
    }


# "deploy --opt <sample> --next" through (hook log, insight text, scanner findings as (rule, tier, snippet)).
GOLDENS: Dict[str, Tuple[str, str, List[Tuple[str, str, str]]]] = {
    "aws-access-key-id": (
        "deploy --opt AKIA_REDACTED --next",
        "deploy --opt [REDACTED_AWS] --next",
        [("aws-access-key-id", "gate", "deploy --opt AKIA...10 --next")],
    ),
    "github-pat": (
        "deploy --opt ghp_REDACTED --next",
        "deploy --opt [REDACTED_VCS_TOKEN] --next",
        [("github-pat", "gate", "deploy --opt ghp_...r8 --next")],
    ),
    "github-fine-grained-pat": (
        "deploy --opt github_pat_REDACTED --next",
        "deploy --opt [REDACTED_VCS_TOKEN] --next",
        [("github-fine-grained-pat", "gate", "deploy --opt gith...op --next")],
    ),
    "slack-token": (
        "deploy --opt [REDACTED_TOKEN] --next",
        "deploy --opt [REDACTED_TOKEN] --next",
        [("slack-token", "gate", "deploy --opt xoxb...MN --next")],
    ),
    "stripe-live-secret": (
        "deploy --opt [REDACTED_API_KEY] --next",
        "deploy --opt [REDACTED_API_KEY] --next",
        [("stripe-live-secret", "gate", "deploy --opt sk_l...QR --next")],
    ),
    "openai-api-key": (
        "deploy --opt sk-REDACTED --next",
        "deploy --opt [REDACTED_API_KEY] --next",
        [("openai-api-key", "gate", "deploy --opt sk-p...cd --next")],
    ),
    "anthropic-api-key": (
        "deploy --opt sk-REDACTED --next",
        "deploy --opt [REDACTED_API_KEY] --next",
        [("anthropic-api-key", "gate", "deploy --opt sk-a...45 --next")],
    ),
    "google-api-key": (
        "deploy --opt AIzaSy_REDACTED --next",
        "deploy --opt [REDACTED_TOKEN] --next",
        [("google-api-key", "gate", "deploy --opt AIza...tu --next")],
    ),
    # Without a complete END marker, everything after the header may still be key material.
    "private-key-pem": (
        "deploy --opt [REDACTED_PEM]",
        "deploy --opt [REDACTED_PEM]",
        [("private-key-pem", "gate", "deploy --opt ----...--\\nMII...iJ --next")],
    ),
    "jwt-three-segment": (
        "deploy --opt [REDACTED_JWT] --next",
        "deploy --opt [REDACTED_JWT] --next",
        [("jwt-three-segment", "gate", "deploy --opt eyJh...5c --next")],
    ),
    "url-basic-auth": (
        "deploy --opt https://svc_admin:[REDACTED]@api.internal.corp/v1 --next",
        "deploy --opt https://svc_admin:[REDACTED]@api.internal.corp/v1 --next",
        [("url-basic-auth", "gate", "deploy --opt https://s...rp/v1 --next")],
    ),
}


def _scan(text: str) -> List[Tuple[str, str, str]]:
    return [(f.rule_id, f.tier, f.snippet) for f in scan_secrets_text(text)]


def test_the_goldens_cover_every_tier_a_format():
    assert set(GOLDENS) == set(_samples()) == set(TIER_A_PATTERNS)


@pytest.mark.parametrize("rule_id", list(GOLDENS))
def test_every_entry_point_writes_its_golden(rule_id: str):
    """Given a Tier A token inside a command line, When it runs through the hook log redactor, the
    insight redactor and the scanner, Then each output matches its golden, including the corrected unterminated-PEM result."""
    line = f"deploy --opt {_samples()[rule_id]} --next"
    hook, insight, scan = GOLDENS[rule_id]
    assert redact_secrets(line) == hook
    assert redact_insight_text(line) == insight
    assert _scan(line) == scan


@pytest.mark.parametrize("near_miss", [_tok("gh", "p_", "A1b2C3d4E5"), _tok("AK", "IA", "9F8E7D6C5B4A321")],
                         ids=["ghp-plus-10", "akia-plus-15"])
def test_a_near_miss_is_left_as_it_is(near_miss: str):
    line = f"deploy --opt {near_miss} --next"
    assert (redact_secrets(line), redact_insight_text(line), _scan(line)) == (line, line, [])


@pytest.mark.parametrize("rule_id", list(GOLDENS))
def test_a_second_pass_changes_nothing(rule_id: str):
    line = f"deploy --opt {_samples()[rule_id]} --next"
    for redact in (redact_secrets, redact_insight_text):
        once = redact(line)
        assert redact(once) == once


def test_redaction_truncation_never_leaves_partial_redacted_tag():
    prefix = "A" * 292
    secret = "".join(["ghp_", "1234567890abcdefghijklmnopqrstuvwxyzABCD"])
    out = redact_insight_text(f"{prefix} {secret}", max_len=300)
    assert len(out) <= 300
    assert "".join(["gh", "p_"]) not in out
    assert not out.endswith("[REDACTED")


def test_a_line_with_two_secrets_loses_both():
    samples = _samples()
    line = f"deploy --a {samples['github-pat']} --b {samples['aws-access-key-id']} --next"
    snippet = "deploy --a ghp_...r8 --b AKIA...10 --next"
    assert redact_secrets(line) == "deploy --a ghp_REDACTED --b AKIA_REDACTED --next"
    assert redact_insight_text(line) == "deploy --a [REDACTED_VCS_TOKEN] --b [REDACTED_AWS] --next"
    assert _scan(line) == [("aws-access-key-id", "gate", snippet), ("github-pat", "gate", snippet)]


# ── One definition, at L0 ─────────────────────────────────────────────────────

def test_redaction_is_one_definition_at_l0():
    """Given the finished tree, When aegis_core/redaction.py is parsed, Then it imports only the
    standard library; the hook adapter and the insights package hand out its objects, not copies."""
    from aegis_cli.hooks import redaction as hook_redaction
    from aegis_core import insights, redaction
    from aegis_core.verification.import_guard import is_stdlib

    tree = ast.parse((REPO / "aegis_core" / "redaction.py").read_text(encoding="utf-8"))
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert imported and sorted(m for m in imported if not is_stdlib(m)) == []
    assert all(hasattr(redaction, name) for name in redaction.__all__)
    assert hook_redaction.SECRET_REPLACEMENTS is redaction.SECRET_REPLACEMENTS
    assert insights.redact_insight_text is redaction.redact_insight_text


def test_scanners_defines_no_redaction_table_and_no_redactor():
    tree = ast.parse((REPO / "aegis_core" / "verification" / "scanners.py").read_text(encoding="utf-8"))
    defined = [n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
    assigned = [t.id for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                for t in (n.targets if isinstance(n, ast.Assign) else [n.target]) if isinstance(t, ast.Name)]
    assert [name for name in defined if name.lstrip("_").startswith("redact")] == []
    assert [name for name in assigned if name.endswith(("REDACTIONS", "REPLACEMENTS"))] == []


def private_imports(sources: Iterable[Tuple[str, str]]) -> List[str]:
    """``label:line: aegis_core.redaction._name`` for each import of an underscore name of the module."""
    sources = tuple(sources)
    check_census_rows(sources)
    found = []
    for label, text in sources:
        # Python normalizes identifiers with NFKC before exposing them in the AST.
        if "redaction" not in text and (text.isascii() or "redaction" not in unicodedata.normalize("NFKC", text)):
            continue
        for node in ast.walk(ast.parse(text, filename=label)):
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "aegis_core.redaction":
                found += [f"{label}:{node.lineno}: aegis_core.redaction.{a.name}" for a in node.names
                          if a.name.startswith("_")]
    return found


_REVIEWED_PYTHON_PATHS = reviewed_python_paths(REPO)


def _python_sources(root: Path = REPO) -> tuple:
    # Freeze membership, not contents: edited or missing reviewed sources still fail.
    return tuple((name, (root / name).read_text(encoding="utf-8")) for name in _REVIEWED_PYTHON_PATHS)


@census_guard(REPO, module_file=__file__)
def test_no_module_imports_a_private_name_of_redaction(monkeypatch: pytest.MonkeyPatch, sources=None):
    real_parse = ast.parse
    parse_count = 0
    parsed = []

    def counted_parse(text, filename):
        nonlocal parse_count
        parse_count += 1
        parsed.append(filename)
        return real_parse(text, filename=filename)

    counted_ast = SimpleNamespace(**vars(ast))
    counted_ast.parse = counted_parse
    monkeypatch.setattr(sys.modules[__name__], "ast", counted_ast)
    assert private_imports(_python_sources() if sources is None else sources) == []
    assert 0 < parse_count <= REDACTION_PARSE_CEILING, (
        f"redaction parse census: {parse_count} files; reviewed ceiling {REDACTION_PARSE_CEILING}. "
        "Review source additions before raising the ceiling. Parsed files:\n" + "\n".join(parsed)
    )


@pytest.mark.parametrize("indexed", [True, False], ids=["git-index", "gitfile-index"])
def test_private_import_census_ignores_files_created_after_collection(tmp_path: Path, indexed: bool):
    """Both source inventories stay fixed across parallel-test writes and repeated scans."""
    module = tmp_path / "tests" / "unit" / "core" / "test_redaction.py"
    module.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__), module)
    reviewed = tmp_path / "aegis_core" / "reviewed.py"
    reviewed.parent.mkdir()
    reviewed.write_text("from aegis_core.redaction import SECRET_REPLACEMENTS\n", encoding="utf-8")
    scripts = tmp_path / ".github" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "reviewed script.py").write_text("# redaction\n", encoding="utf-8")
    ignored = tmp_path / "tools"
    ignored.mkdir()
    (ignored / "outside_census.py").write_text("redaction syntax (\n", encoding="utf-8")
    cache = reviewed.parent / "__pycache__"
    cache.mkdir()
    (cache / "cached.py").write_text("redaction syntax (\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], env=_git_environment(), check=True, timeout=60)
    subprocess.run(["git", "add", "."], cwd=tmp_path, env=_git_environment(), check=True, timeout=60)
    if not indexed:
        (tmp_path / ".git").rename(tmp_path / "metadata")
        (tmp_path / ".git").write_text("gitdir: metadata\n", encoding="utf-8")
    (tmp_path / "tests" / "untracked_before_collection.py").write_text(
        "from aegis_core.redaction import _unreviewed\n", encoding="utf-8")
    scan = runpy.run_path(str(module))["_python_sources"]
    initial = scan()
    assert {"aegis_core/reviewed.py", ".github/scripts/reviewed script.py"} <= {label for label, _ in initial}
    assert not any("untracked_before_collection" in label for label, _ in initial)
    assert not any("outside_census" in label or "__pycache__" in label for label, _ in initial)
    # Interleave a worker's write with a source read, without patching pathlib globally.
    during_scan = tmp_path / "tests" / "created_during_scan.py"

    class InterleavedPath(type(tmp_path)):
        def read_text(self, *args, **kwargs):
            during_scan.write_text("from aegis_core.redaction import _late\n", encoding="utf-8")
            return super().read_text(*args, **kwargs)

    assert scan(InterleavedPath(tmp_path)) == initial
    assert during_scan.is_file()
    # Another worker can create, replace and remove these between census attempts.
    for directory in (reviewed.parent, tmp_path / "tests", scripts):
        late = directory / "late.py"
        for source in ("from aegis_core.redaction import _late\n", "redaction syntax (\n"):
            late.write_text(source, encoding="utf-8")
            assert scan() == initial
        late.unlink()
        assert scan() == initial
    reviewed.write_text("from aegis_core.redaction import _changed\n", encoding="utf-8")
    assert "aegis_core/reviewed.py:1: aegis_core.redaction._changed" in private_imports(scan())
    reviewed.unlink()
    with pytest.raises(FileNotFoundError):
        scan()


def test_private_import_census_refuses_an_unreadable_index(tmp_path: Path):
    module = tmp_path / "tests" / "unit" / "core" / "test_redaction.py"
    module.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__), module)
    (tmp_path / ".git").write_text("not a git directory\n", encoding="utf-8")
    for _ in range(2):
        with pytest.raises(subprocess.CalledProcessError):
            runpy.run_path(str(module))


@pytest.mark.parametrize("count", [1, 66, REDACTION_PARSE_CEILING])
def test_private_import_census_accepts_additions_within_reviewed_ceiling(tmp_path, count):
    sources = [(f"tests/reviewed_{index}.py", "# redaction\n") for index in range(count)]
    result = run_census_fixture(tmp_path, "test_redaction.py", sources)
    assert result.returncode == 0, result.stderr.decode()


def test_private_import_census_ceiling_failure_lists_every_parsed_file(tmp_path):
    count = REDACTION_PARSE_CEILING + 1
    sources = [(f"tests/reviewed_{index}.py", "# redaction\n") for index in range(count)]
    result = run_census_fixture(tmp_path, "test_redaction.py", sources)
    assert result.returncode != 0
    message = result.stderr.decode()
    assert f"redaction parse census: {count} files; reviewed ceiling {REDACTION_PARSE_CEILING}." in message
    assert all(label in message for label, _ in sources)


@pytest.fixture
def redaction_selector_checkout(tmp_path: Path):
    """An own index with a violation and an external index captured before it existed."""
    checkout = tmp_path / "checkout"
    module = checkout / "tests" / "unit" / "core" / "test_redaction.py"
    module.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__), module)
    package = checkout / "aegis_core"
    package.mkdir()
    (package / "reviewed.py").write_text("# redaction\n", encoding="utf-8")
    env = _git_environment()
    subprocess.run(["git", "init", "-q", str(checkout)], env=env, check=True, timeout=10)
    subprocess.run(["git", "add", "."], cwd=checkout, env=env, check=True, timeout=10)
    external_index = tmp_path / "external-index"
    shutil.copyfile(checkout / ".git" / "index", external_index)
    (package / "violating.py").write_text("from aegis_core.redaction import _violation\n", encoding="utf-8")
    subprocess.run(["git", "add", "aegis_core/violating.py"], cwd=checkout, env=env, check=True, timeout=10)
    external = tmp_path / "external"
    subprocess.run(["git", "init", "-q", str(external)], env=env, check=True, timeout=10)
    return module, external_index, external


@pytest.mark.parametrize("selector", ["GIT_INDEX_FILE", "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "combined", "all-local"])
@pytest.mark.parametrize("operation", ["census", "fixture"])
def test_private_import_census_and_fixture_ignore_inherited_git_selectors(
        tmp_path: Path, redaction_selector_checkout, selector: str, operation: str, redaction_import_path):
    module, external_index, external = redaction_selector_checkout
    env = _git_environment()
    if selector == "all-local":
        env.update({key: "invalid-inherited-selector" for key in LOCAL_ENV})
    env["GIT_INDEX_FILE"] = str(external_index)
    redirects = {"GIT_DIR": str(external / ".git"), "GIT_WORK_TREE": str(external),
                 "GIT_COMMON_DIR": str(external / ".git")}
    env.update(redirects if selector in ("combined", "all-local") else
               {key: value for key, value in redirects.items() if key == selector})
    before = external_index.read_bytes()
    program = (
        "import json, runpy, sys\n"
        "from pathlib import Path\n"
        "scope = runpy.run_path(sys.argv[2])\n"
        "if sys.argv[4] == 'census':\n"
        "    print(json.dumps(scope['private_imports'](scope['_python_sources']())))\n"
        "else:\n"
        "    scope['test_private_import_census_ignores_files_created_after_collection'](Path(sys.argv[3]), True)\n"
    )
    for attempt in range(2):
        result = _run_isolated(program, module, tmp_path / f"fixture_{attempt}", operation,
                               env=env, import_path=redaction_import_path)
        assert external_index.read_bytes() == before, "fixture changed the caller's external index"
        assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
        if operation == "census":
            assert json.loads(result.stdout) == ["aegis_core/violating.py:1: aegis_core.redaction._violation"]


def test_an_import_of_a_private_redaction_name_is_named_with_its_line():
    src = "import os\nfrom aegis_core.redaction import SECRET_REPLACEMENTS, _x\n"
    assert private_imports([("fixture.py", src)]) == ["fixture.py:2: aegis_core.redaction._x"]


@pytest.mark.parametrize("irrelevant", ["invalid syntax (\n", "# \u2500\ninvalid syntax (\n", "# \u00e9\ninvalid syntax (\n"])
def test_private_redaction_import_scan_skips_sources_without_the_needle(irrelevant: str):
    sources = [("irrelevant.py", irrelevant),
               ("caller.py", "import os\nfrom aegis_core.redaction import _x\n")]
    assert private_imports(sources) == ["caller.py:2: aegis_core.redaction._x"]


def test_private_redaction_import_scan_reports_nfkc_normalized_imports():
    source = "from aegis_core.redacti\uff4fn import _SECRET_REDACTIONS\n"
    assert "redaction" not in source
    assert private_imports([("caller.py", source)]) == ["caller.py:1: aegis_core.redaction._SECRET_REDACTIONS"]


@pytest.mark.parametrize("source", ["redaction syntax (\n", "# \uff52edaction\ninvalid syntax (\n"])
def test_private_redaction_import_scan_still_rejects_malformed_candidates(source: str):
    with pytest.raises(SyntaxError):
        private_imports([("caller.py", source)])


_HOOK_ADAPTER_IMPORTS = (
    "import json, sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "import aegis_cli.hooks.redaction\n"
    "sys.stdout.write(json.dumps(sorted(m for m in sys.modules if m.split('.')[0] in "
    "('aegis_cli', 'aegis_core', 'aegis_mcp', 'aegis_sdk'))))\n"
)


def test_the_hook_adapter_loads_no_scanner_stack(tmp_path: Path):
    """Given a fresh interpreter, When aegis_cli.hooks.redaction is imported, Then neither the
    scanner stack nor gitsafe loads, and at most 7 Aegis modules in all (14 on the w14 tree).

    Seven, not the spec's derived 6: aegis_cli/__init__.py imports aegis_core.primitives, so any
    aegis_cli import first loads aegis_cli, aegis_core, aegis_core._version and primitives."""
    env = {"HOME": str(tmp_path), "USERPROFILE": str(tmp_path), "PATH": os.environ.get("PATH", ""),
           "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
    proc = subprocess.run([sys.executable, "-I", "-c", _HOOK_ADAPTER_IMPORTS, str(REPO)], input=b"",
                          capture_output=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    loaded = set(json.loads(proc.stdout.decode("utf-8")))
    scanner_stack = {"aegis_core.verification", "aegis_core.verification.scanners",
                     "aegis_core.verification.test_runner", "aegis_core.gitsafe", "aegis_core.pathlookup",
                     "aegis_core.errors"}
    assert sorted(loaded & scanner_stack) == []
    assert len(loaded) <= 7, sorted(loaded)


def test_url_credential_removal_and_atomic_clip_live_only_in_redaction():
    """URL removal and atomic clipping are defined once, in aegis_core.redaction."""
    import aegis_core.redaction as redaction
    from aegis_core import guidance_grammar
    from aegis_core.proposals import model as proposal_model

    model_tree = ast.parse((REPO / "aegis_core" / "proposals" / "model.py").read_text(encoding="utf-8"))
    defined = {node.name for node in model_tree.body if isinstance(node, ast.FunctionDef)}
    assert {"_strip_url_secrets", "_clip_text", "_ambiguous_authority"}.isdisjoint(defined)
    redaction_tree = ast.parse((REPO / "aegis_core" / "redaction.py").read_text(encoding="utf-8"))
    redaction_defined = {node.name for node in redaction_tree.body if isinstance(node, ast.FunctionDef)}
    assert {"remove_url_credentials", "clip_atomic_text"}.issubset(redaction_defined)
    assert redaction.remove_url_credentials.__module__ == "aegis_core.redaction"
    assert redaction.clip_atomic_text.__module__ == "aegis_core.redaction"
    assert "remove_url_credentials" in redaction.__all__
    assert "clip_atomic_text" in redaction.__all__
    source = (REPO / "aegis_core" / "proposals" / "model.py").read_text(encoding="utf-8")
    assert "remove_url_credentials" in source and "clip_atomic_text" in source
    assert proposal_model.remove_url_credentials is redaction.remove_url_credentials
    assert proposal_model.clip_atomic_text is redaction.clip_atomic_text
    assert guidance_grammar.clip_atomic_text is redaction.clip_atomic_text
    assert guidance_grammar.remove_url_credentials is redaction.remove_url_credentials
    assert proposal_model.clean_text("https://ci.example/path", 64) == "https://ci.example/path"


@pytest.mark.parametrize("name", ["remove_url_credentials", "clip_atomic_text"])
@pytest.mark.parametrize("policy", ["proposal", "guidance"])
@pytest.mark.parametrize("bad", [None, b"text", 1, ["text"]],
                         ids=["none", "bytes", "number", "list"])
def test_shared_cleaners_refuse_malformed_text_then_retry(name, policy, bad):
    from aegis_core import redaction

    cleaner = getattr(redaction, name)
    for _ in range(2):
        with pytest.raises(redaction.RedactionRefusal, match="^invalid$") as caught:
            cleaner(bad, limit=32, policy=policy)
        assert caught.value.code == "invalid"
        assert cleaner("plain", limit=32, policy=policy) == "plain"


@pytest.mark.parametrize("name", ["remove_url_credentials", "clip_atomic_text"])
@pytest.mark.parametrize("policy", ["proposal", "guidance"])
@pytest.mark.parametrize("limit", [-1, True, None, 1.5, "32"])
def test_shared_cleaners_refuse_invalid_limits_then_retry(name, policy, limit):
    from aegis_core import redaction

    cleaner = getattr(redaction, name)
    with pytest.raises(redaction.RedactionRefusal, match="^invalid$") as caught:
        cleaner("private input", limit=limit, policy=policy)
    assert caught.value.code == "invalid"
    assert cleaner("plain", limit=32, policy=policy) == "plain"


@pytest.mark.parametrize("name", ["remove_url_credentials", "clip_atomic_text"])
def test_shared_cleaner_input_ceiling_and_concurrent_refusal_recovery(name):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core import redaction

    cleaner = getattr(redaction, name)
    text = "z" * redaction.MAX_GUIDANCE_CHARS
    assert cleaner(text, limit=len(text)) == text

    def refusing_then_retry(_):
        with pytest.raises(redaction.RedactionRefusal, match="^too_large$") as caught:
            cleaner(text + "z", limit=3)
        assert caught.value.code == "too_large"
        return cleaner("plain", limit=32)

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(refusing_then_retry, range(6))) == ["plain"] * 6


@pytest.mark.parametrize("policy", ["proposal", "guidance"])
def test_named_cleaner_policies_preserve_url_and_whitespace_contracts(policy):
    from aegis_core.redaction import clip_atomic_text, remove_url_credentials

    masked = "ftp://u:[REDACTED]@ci.example/p?q=hidden#private"
    expected = ("ftp://ci.example/p" if policy == "proposal" else
                "ftp://u:[REDACTED]@ci.example/p#private")
    assert remove_url_credentials(masked, limit=300, policy=policy) == expected
    assert remove_url_credentials(expected, limit=300, policy=policy) == expected
    expected = "plain" if policy == "proposal" else "plain "
    assert clip_atomic_text("plain tail", 6, policy=policy) == expected
    assert clip_atomic_text(expected, 6, policy=policy) == expected
    expected = "xxghp_" if policy == "proposal" else "xx"
    assert clip_atomic_text("xxghp_REDACTED tail", 6, policy=policy) == expected


@pytest.mark.parametrize("name", ["remove_url_credentials", "clip_atomic_text"])
@pytest.mark.parametrize("policy", ["guidance", "proposal"])
def test_named_cleaner_policies_bound_input_and_retry_concurrently(name, policy):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core import redaction

    cleaner = getattr(redaction, name)
    ceiling = 1024 * 1024 if policy == "guidance" else redaction.MAX_GUIDANCE_CHARS
    text = "z" * ceiling
    assert cleaner(text, limit=ceiling, policy=policy) == text
    oversized = text + "z"

    def refusing_then_retry(_):
        with pytest.raises(redaction.RedactionRefusal, match="^too_large$") as caught:
            cleaner(oversized, limit=3, policy=policy)
        assert caught.value.code == "too_large"
        return cleaner("plain", limit=32, policy=policy)

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(refusing_then_retry, range(6))) == ["plain"] * 6


@pytest.mark.parametrize("name", ["remove_url_credentials", "clip_atomic_text"])
@pytest.mark.parametrize("policy", [None, [], True, "unknown"],
                         ids=["none", "list", "bool", "unknown"])
def test_shared_cleaners_refuse_unknown_policy_without_echo(name, policy):
    from aegis_core import redaction

    cleaner = getattr(redaction, name)
    with pytest.raises(redaction.RedactionRefusal, match="^invalid$") as caught:
        cleaner("private input", limit=32, policy=policy)
    assert caught.value.code == "invalid"
    assert cleaner("plain", limit=32, policy="guidance") == "plain"


def test_guidance_wrappers_use_the_shared_named_policy():
    from aegis_core import guidance_grammar as grammar

    assert grammar.clip_redacted("plain tail", 6) == "plain "
    assert grammar.redact_labeled("plain", [0] * 5, 32) == ("plain", [0] * 5)
    text = "ftp://u:pass@ci.example/p?q=hidden#private"
    expected = "ftp://u:[REDACTED]@ci.example/p#private"
    assert grammar.redact_labeled(text, [0] * len(text), 300) == (expected, [0] * len(expected))
    assert grammar.clip_redacted("xxghp_REDACTED tail", 6) == "xx"
    with pytest.raises(ValueError, match="^guidance_projection_limit$"):
        grammar.clip_redacted("plain", -1)
    with pytest.raises(ValueError, match="^guidance_projection_limit$"):
        grammar.redact_labeled("plain", None, 3)
    assert grammar.clip_redacted("retry", 32) == "retry"


def test_guidance_query_removal_preserves_list_item_attribution():
    from aegis_core.guidance_projection import project_field

    source = ["https://h/p?sig=hidden#anchor", "SECOND"]
    assert project_field(source) == ["https://h/p#anchor", "SECOND"]
    assert source == ["https://h/p?sig=hidden#anchor", "SECOND"]
    masked = ["https://user:pass@h/p?sig=hidden#anchor", "token=secret", "SECOND"]
    assert project_field(masked) == ["https://user:[REDACTED]@h/p#anchor", "token=REDACTED", "SECOND"]


def test_guidance_query_removal_keeps_each_retained_character_label():
    from aegis_core.guidance_grammar import redact_labeled

    text = "https://h/p?sig=hidden#anchor\nSECOND https://h/next?q=other#last"
    source_labels = list(range(len(text)))
    shown, labels = redact_labeled(text, source_labels, 300)
    assert shown == "https://h/p#anchor\nSECOND https://h/next#last"
    assert len(labels) == len(shown)
    assert labels == (list(range(text.index("?")))
                      + list(range(text.index("#"), text.index("?q=")))
                      + list(range(text.index("#last"), len(text))))
    assert all(char == text[label] for char, label in zip(shown, labels))
    assert source_labels == list(range(len(text)))


def test_guidance_query_removal_keeps_detail_line_boundary():
    from aegis_core.guidance_projection import project_detail

    body = "\n".join(["https://h/p?sig=hidden#anchor"] + [f"line{n}" for n in range(1, 9)])
    assert project_detail(body) == "https://h/p#anchor " + " ".join(f"line{n}" for n in range(1, 8))


def test_guidance_query_removal_preserves_masks_and_proposal_policy():
    from aegis_core.guidance_projection import redact_clean_text
    from aegis_core.redaction import remove_url_credentials

    text = "  HTTPS://user:pass@h/p?sig=hidden#anchor\nNEXT\t"
    expected = "  HTTPS://user:[REDACTED]@h/p#anchor\nNEXT\t"
    assert redact_clean_text(text) == expected
    assert redact_clean_text(expected) == expected
    assert remove_url_credentials(text, limit=300, policy="proposal") == "HTTPS://h/p NEXT"
    unchanged = "  file:///home/...\nhttps://h/p#anchor?fragment\tNEXT"
    assert redact_clean_text(unchanged) == unchanged


@pytest.mark.parametrize("text,expected", [
    ("https://h/p?sig=hidden#anchor", "https://h/p#anchor"),
    ("https://h/p#anchor?fragment", "https://h/p#anchor?fragment"),
    ("https://h/p?sig=(hidden)", "https://h/p)"),
    ("`https://h/p?sig=hidden`", "`https://h/p`"),
    ("https://h/p?token=[REDACTED]", "https://h/p"),
    ("https://h/p?sig=hidden?)", "https://h/p)"),
    ("https://h/p?#anchor", "https://h/p#anchor"),
    ("why?  file:///home/...\nNEXT", "why?  file:///home/...\nNEXT"),
], ids=["anchor", "fragment-question", "closer", "code", "mask", "query-edge", "empty", "non-query"])
def test_guidance_query_spans_preserve_other_url_components(text, expected):
    from aegis_core.redaction import remove_guidance_url_queries, remove_url_credentials

    shown, spans = remove_guidance_url_queries(text, limit=300)
    assert shown == expected
    assert remove_url_credentials(text, limit=300, policy="guidance") == expected
    assert isinstance(spans, tuple)
    assert all(type(start) is int and type(end) is int and 0 <= start < end <= len(text)
               for start, end in spans)
    assert all(left[1] <= right[0] for left, right in zip(spans, spans[1:]))
    assert remove_guidance_url_queries(shown, limit=300) == (expected, ())


def test_guidance_query_spans_are_offsets_in_the_original_input():
    from aegis_core.redaction import remove_guidance_url_queries

    text = "one https://h/p?sig=hidden#anchor\nhttps://h/next?q=other#last END"
    shown, spans = remove_guidance_url_queries(text, limit=300)
    assert shown == "one https://h/p#anchor\nhttps://h/next#last END"
    assert spans == ((text.index("?sig="), text.index("#anchor")),
                     (text.index("?q="), text.index("#last")))


def test_guidance_query_removal_preserves_refusals_and_retry():
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import GuidanceProjectionError, redact_clean_text
    from aegis_core.redaction import RedactionRefusal, remove_guidance_url_queries, remove_url_credentials

    ceiling = 1024 * 1024
    assert remove_guidance_url_queries("z" * ceiling, limit=ceiling) == ("z" * ceiling, ())
    for text, limit in (("z" * (ceiling + 1), ceiling + 1), ("https://h/p?sig=hidden", 12)):
        for cleaner in (remove_guidance_url_queries,
                        lambda value, *, limit: remove_url_credentials(value, limit=limit, policy="guidance")):
            with pytest.raises(RedactionRefusal, match="^too_large$") as caught:
                cleaner(text, limit=limit)
            assert caught.value.code == "too_large"
        with pytest.raises(ValueError, match="^guidance_projection_limit$"):
            redact_labeled(text, None, limit)
    with pytest.raises(GuidanceProjectionError, match="^guidance_projection_limit$"):
        redact_clean_text("z" * (ceiling + 1))
    for value, limit in ((None, 32), (b"text", 32), ([], 32), ("plain", -1), ("plain", True)):
        with pytest.raises(RedactionRefusal, match="^invalid$") as caught:
            remove_guidance_url_queries(value, limit=limit)
        assert caught.value.code == "invalid"
    assert remove_guidance_url_queries("https://h/p?sig=hidden#anchor", limit=300) == (
        "https://h/p#anchor", ((11, 22),))


@pytest.mark.parametrize("text,expected,secret", [
    ("https://u:secretPrefix?tail@h", "[REDACTED_URL]", "secretPrefix"),
    ("https://h/?-----BEGIN " + "PRIVATE KEY-----\nsynthetic_private_body\n-----END " + "PRIVATE KEY-----",
     "[REDACTED_URL]", "synthetic_private_body"),
], ids=["userinfo-query", "pem-query"])
def test_guidance_round4_masks_original_secrets_before_query_deletion(text, expected, secret):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text

    assert redact_clean_text(text) == expected
    assert project_field([text, "SECOND"]) == [expected, "SECOND"]
    source = text + "\nSECOND"
    source_labels = [0] * len(text) + [None] + [1] * len("SECOND")
    shown, labels = redact_labeled(source, source_labels, 300)
    assert shown == expected + "\nSECOND"
    assert labels == [0] * len(expected) + [None] + [1] * len("SECOND")
    assert len(labels) == len(shown) and secret not in shown
    assert redact_clean_text(shown) == shown


@pytest.mark.parametrize("text,expected", [
    ("[docs](https://h/p#anchor)[job](https://h/p?sig=hunter2)",
     "[docs](https://h/p#anchor)[job](https://h/p)"),
    ("[a](https://h/p#anchor),[b](https://ci.example/job?sig=hunter2)",
     "[a](https://h/p#anchor),[b](https://ci.example/job)"),
    ("[a](https://h/p?q=x#anchor),[b](https://ci.example/job?sig=hunter2)",
     "[a](https://h/p#anchor),[b](https://ci.example/job)"),
    ("[job](https://h/p?sig=hidden),NEXT", "[job](https://h/p),NEXT"),
    ("https://h/p?q=x#anchor,https://ci.example/job?sig=hidden#last",
     "https://h/p"),
    ("[a](https://[2001:db8::1]:443/job(1)?sig=hidden#anchor),[b](https://h/?q=x#last)",
     "[a](https://[2001:db8::1]:443/job(1)#anchor),[b](https://h/#last)"),
    ("[job](https://h/p?sig=[REDACTED]),NEXT", "[job](https://h/p),NEXT"),
    ("[a](CUSTOM+v1://h/p?q=x#anchor)[b](ftp://h/p?q=y#last)",
     "[a](CUSTOM+v1://h/p#anchor)[b](ftp://h/p#last)"),
], ids=["adjacent", "comma-later-query", "two-queries", "suffix", "later-fragment",
        "ipv6-path-parentheses", "opaque-query-mask", "other-schemes"])
def test_guidance_round4_each_url_has_its_own_query_and_boundaries(text, expected):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries, remove_url_credentials

    assert redact_clean_text(text) == expected
    assert project_field([text, "SECOND"]) == [expected, "SECOND"]
    assert remove_url_credentials(text, limit=300, policy="guidance") == expected
    shown, spans = remove_guidance_url_queries(text, limit=300)
    assert shown == expected
    expected_labels = [index for index in range(len(text))
                       if not any(start <= index < end for start, end in spans)]
    labeled, labels = redact_labeled(text, list(range(len(text))), 300)
    assert labeled == expected and labels == expected_labels
    assert len(labels) == len(labeled)
    assert all(char == text[label] for char, label in zip(labeled, labels))
    assert remove_guidance_url_queries(expected, limit=300) == (expected, ())
    assert redact_clean_text(expected) == expected


def test_guidance_round4_original_input_is_bounded_before_masking():
    from aegis_core.guidance_grammar import redact_labeled

    pem = "https://h/?-----BEGIN " + "PRIVATE KEY-----\nbody\n-----END " + "PRIVATE KEY-----"
    for text, limit in ((pem, len(pem) - 1),
                        (pem + "x" * (1024 * 1024), 2 * 1024 * 1024)):
        with pytest.raises(ValueError, match="^guidance_projection_limit$"):
            redact_labeled(text, None, limit)
    for value, limit in ((None, 300), (b"text", 300), ("text", True), ("text", -1)):
        with pytest.raises(ValueError, match="^guidance_projection_limit$"):
            redact_labeled(value, None, limit)


@pytest.mark.parametrize("username,helper_expected,source_spans,head_expected,head_spans", [
    ("u#ser", "https://u#ser:pass@ci.example/path?sig=hidden#anchor", (),
     "https://u#ser:pass@ci.example/path#anchor", ()),
    ("u?ser", "https://u#anchor", ((9, 45),), "https://u#anchor", ((9, 34),)),
], ids=["fragment-in-user", "query-in-user"])
def test_guidance_round4_userinfo_delimiters_are_not_url_delimiters(
        username, helper_expected, source_spans, head_expected, head_spans):
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries

    head = f"https://{username}:pass@ci.example/path"
    source = head + "?sig=hidden#anchor"
    expected = "[REDACTED_URL]"
    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    assert remove_guidance_url_queries(source, limit=300) == (
        helper_expected, source_spans)
    assert remove_guidance_url_queries(head + "#anchor", limit=300) == (head_expected, head_spans)
    assert remove_guidance_url_queries(helper_expected, limit=300) == (helper_expected, ())
    assert redact_clean_text(expected) == expected


def test_guidance_round4_new_secret_joined_by_removal_is_masked():
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text

    secret = "AKIA" + "A" * 16
    source = "https://h/AKIA?x=" + "A" * 16 + "://tail"
    expected = "https://h/AKIA"
    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    assert redact_labeled(source, [0] * len(source), 300) == (expected, [0] * len(expected))
    assert secret not in redact_clean_text(source)
    assert redact_clean_text(expected) == expected


@pytest.mark.parametrize("prefix", ["Bearer ", "Authorization: basic ", "password is ", "token= "],
                         ids=["bearer", "authorization", "natural-password", "keyed"])
def test_guidance_round4_mask_families_survive_query_header_removal(prefix):
    from aegis_core.guidance_projection import project_field, redact_clean_text

    secret = "synthetic_credential_value_1234"
    source = "https://h/?" + prefix + secret
    shown = redact_clean_text(source)
    assert secret not in shown and "REDACTED" in shown
    assert project_field([source, "SECOND"]) == [shown, "SECOND"]
    assert redact_clean_text(shown) == shown


@pytest.mark.parametrize("source,helper_expected,removed_span,expected", [
    ("https://user:p#ss@ci.example/path?sig=SECRET", "https://user:p#ss@ci.example/path?sig=SECRET", None,
     "[REDACTED_URL]"),
    ("https://user:p?ss@ci.example/path?sig=SECRET", "https://user:p", (14, 44),
     "[REDACTED_URL]"),
    ("https://u#ser:[REDACTED]@ci.example/path?sig=SECRET",
     "https://u#ser:[REDACTED]@ci.example/path?sig=SECRET", None, "[REDACTED_URL]"),
    ("https://u?ser:[REDACTED]@ci.example/path", "https://u", (9, 40),
     "[REDACTED_URL]"),
], ids=["password-fragment", "password-query", "masked-username-fragment", "masked-username-query"])
def test_guidance_round4_argon_authority_precedes_query_detection(source, helper_expected, removed_span, expected):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries

    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    assert redact_labeled(source, [0] * len(source), 300) == (expected, [0] * len(expected))
    shown, spans = remove_guidance_url_queries(source, limit=300)
    assert shown == helper_expected
    assert spans == (() if removed_span is None else (removed_span,))
    assert remove_guidance_url_queries(shown, limit=300) == (shown, ())
    assert redact_clean_text(expected) == expected


@pytest.mark.parametrize("suffix", ["", "?sig=SECRET#anchor"], ids=["no-query", "query"])
@pytest.mark.parametrize("userinfo,masked", [
    (":pass", ":[REDACTED]"),
    ("u:", "u:[REDACTED]"),
    (":", ":[REDACTED]"),
    ("u:p@ss", "u:[REDACTED]"),
    ("u" * 129 + ":pass", "u" * 129 + ":[REDACTED]"),
    ("u:" + "p" * 513, "u:[REDACTED]"),
    ("u", "u"),
    ("", ""),
], ids=["empty-user", "empty-password", "empty-both", "last-at", "long-user", "long-password",
        "username-only", "empty-userinfo"])
def test_guidance_round5_structural_password_masking(userinfo, masked, suffix):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries

    head = "https://" + userinfo + "@ci.example/path"
    source = head + suffix
    fragment = "#anchor" if suffix else ""
    expected = "https://" + masked + "@ci.example/path" + fragment
    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    joined, labels = redact_labeled(source + "\nSECOND", [0] * len(source) + [None] + [1] * 6, 2000)
    assert joined == expected + "\nSECOND"
    assert labels == [0] * len(expected) + [None] + [1] * 6
    shown, spans = remove_guidance_url_queries(source, limit=2000)
    assert shown == head + fragment
    query = source.find("?sig=")
    assert spans == (() if query < 0 else ((query, source.index("#anchor")),))
    assert remove_guidance_url_queries(shown, limit=2000) == (shown, ())
    assert redact_clean_text(expected) == expected


@pytest.mark.parametrize("source,expected,query_expected", [
    ("https://h/a;b?sig=SECRET", "https://h/a;b", "https://h/a;b"),
    ("https://h/a,b?sig=SECRET", "https://h/a,b", "https://h/a,b"),
    ("https://h/a'b?sig=SECRET", "https://h/a'b", "https://h/a'b"),
    ('https://h/a"b?sig=SECRET', 'https://h/a"b', "https://h/a\"b"),
    ("https://h/a)b?sig=SECRET", "https://h/a)b", "https://h/a)b"),
    ("https://h/a]b?sig=SECRET", "https://h/a]b", "https://h/a]b"),
    ("https://h/p?x=a,b&sig=SECRET", "https://h/p", "https://h/p"),
    ("https://h/p?x=a;b&sig=SECRET", "https://h/p", "https://h/p"),
    ("https://h/p?x=a'b&sig=SECRET", "https://h/p", "https://h/p"),
    ('https://h/p?sig="hunter2"', 'https://h/p"', "https://h/p\""),
    ("https://h/p?a=[]&sig=SECRET", "https://h/p", "https://h/p"),
    ("https://h/p?a=(x)&sig=SECRET", "https://h/p", "https://h/p"),
    ("https://h/p?a={x}&sig=SECRET", "https://h/p", "https://h/p"),
    ("[job](https://h/p?x=(a,b)&sig=SECRET),NEXT", "[job](https://h/p),NEXT", "[job](https://h/p),NEXT"),
    ("[job](https://h/a(b)c?sig=SECRET#anchor),NEXT", "[job](https://h/a(b)c#anchor),NEXT", "[job](https://h/a(b)c#anchor),NEXT"),
    ("https://h/a;b?x=a,b&sig=SECRET#anchor", "https://h/a;b#anchor", "https://h/a;b#anchor"),
    ("https://h/p?x=a,b&sig=SECRET),NEXT", "[REDACTED_URL]", "https://h/p"),
    ("https://h/p?x=a,b&sig=SECRET https://h/next?sig=SECRET#last", "https://h/p https://h/next#last", "https://h/p https://h/next#last"),
], ids=["semicolon-path", "comma-path", "apostrophe-path", "quote-path", "parenthesis-path",
        "bracket-path", "comma-query", "semicolon-query", "apostrophe-query", "quote-query",
        "bracket-query", "parenthesis-query", "brace-query", "markdown-query-parentheses",
        "markdown-path-parentheses", "punctuation-and-anchor", "uncertain-prose-end", "whitespace-end"])
def test_guidance_round5_url_internal_punctuation(source, expected, query_expected):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries, remove_url_credentials

    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    assert remove_url_credentials(source, limit=2000, policy="guidance") == query_expected
    shown, spans = remove_guidance_url_queries(source, limit=2000)
    assert shown == query_expected
    retained = [index for index in range(len(source))
                if not any(start <= index < stop for start, stop in spans)]
    expected_labels = retained if expected == query_expected else [0] * len(expected)
    assert redact_labeled(source, list(range(len(source))), 2000) == (expected, expected_labels)
    assert len(expected_labels) == len(expected)
    assert len(retained) == len(query_expected)
    assert all(char == source[index] for char, index in zip(query_expected, retained))
    assert remove_guidance_url_queries(query_expected, limit=2000) == (query_expected, ())
    assert redact_clean_text(expected) == expected


@pytest.mark.parametrize("source,expected", [
    ("[job](https://h/a\\)b?sig=SECRET),NEXT", "[job](https://h/a\\)b),NEXT"),
    ("[job](https://h/a\\(b?sig=SECRET),NEXT", "[job](https://h/a\\(b),NEXT"),
    ("[job](https://h/p?x=\\)&sig=SECRET),NEXT", "[job](https://h/p),NEXT"),
    ("[job](https://h/p?x=\\(&sig=SECRET),NEXT", "[job](https://h/p),NEXT"),
    ("[job](https://h/p?x=\\\\),NEXT", "[job](https://h/p),NEXT"),
], ids=["escaped-path-close", "escaped-path-open", "escaped-query-close", "escaped-query-open",
        "escaped-backslash-control"])
def test_guidance_round5_markdown_escaped_parentheses(source, expected):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries

    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    shown, spans = remove_guidance_url_queries(source, limit=300)
    assert shown == expected
    retained = [index for index in range(len(source))
                if not any(start <= index < stop for start, stop in spans)]
    assert redact_labeled(source, list(range(len(source))), 300) == (expected, retained)
    assert len(retained) == len(expected)
    assert redact_clean_text(expected) == expected
    assert remove_guidance_url_queries(expected, limit=300) == (expected, ())


def test_guidance_round5_structural_masker_refusals():
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.redaction import RedactionRefusal, mask_guidance_url_authorities

    source = "https://u:@h/p"
    for labels in ([], [0], tuple(range(len(source))), 1):
        with pytest.raises(RedactionRefusal, match="^invalid$") as caught:
            mask_guidance_url_authorities(source, labels, limit=300)
        assert caught.value.code == "invalid"
    for value, limit in ((None, 300), (b"text", 300), ("text", True), ("text", -1)):
        with pytest.raises(RedactionRefusal, match="^invalid$") as caught:
            mask_guidance_url_authorities(value, None, limit=limit)
        assert caught.value.code == "invalid"
    for labels in (None, [0] * len(source)):
        with pytest.raises(RedactionRefusal, match="^too_large$") as caught:
            mask_guidance_url_authorities(source, labels, limit=len(source))
        assert caught.value.code == "too_large"
        with pytest.raises(ValueError, match="^guidance_projection_limit$"):
            redact_labeled(source, labels, len(source))


@pytest.mark.parametrize("source,helper_expected,removed_span", [
    ("https://u#ser:@ci.example/path?sig=SECRET", "https://u#ser:@ci.example/path?sig=SECRET", None),
    ("https://u?ser:@ci.example/path?sig=SECRET", "https://u", (9, 41)),
    ("https://u#ser@ci.example/path?sig=SECRET", "https://u#ser@ci.example/path?sig=SECRET", None),
    ("https://u:p@ss#rest@ci.example/path?sig=SECRET", "https://u:p@ss#rest@ci.example/path?sig=SECRET", None),
    ("https://h?sig=SECRET@ci.example/path?sig=SECRET", "https://h", (9, 47)),
], ids=["empty-password-fragment-user", "empty-password-query-user", "username-only-fragment",
        "last-at-fragment", "query-as-userinfo"])
def test_guidance_round5_ambiguous_authority_masks_the_whole_url(source, helper_expected, removed_span):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries

    # The offset-only primitive still performs query removal independently of
    # masking; the serving projection must refuse ambiguous authority contents.
    raw, spans = remove_guidance_url_queries(source, limit=300)
    assert raw == helper_expected and spans == (() if removed_span is None else (removed_span,))
    assert remove_guidance_url_queries(raw, limit=300) == (raw, ())
    expected = "[REDACTED_URL]"
    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    assert redact_labeled(source + "\nSECOND", [0] * len(source) + [None] + [1] * 6, 300) == (
        expected + "\nSECOND", [0] * len(expected) + [None] + [1] * 6)
    assert redact_clean_text(expected) == expected


@pytest.mark.parametrize("source,expected", [
    ("https://u?ser@ci.example/path?sig=SECRET).", "[REDACTED_URL])."),
    ("pre [job](https://u?ser@ci.example/path?sig=SECRET),NEXT", "pre [job]([REDACTED_URL]),NEXT"),
    ("https://u?ser@[2001:db8::1]", "[REDACTED_URL]"),
    ("https://u?ser@[2001:db8::1]).", "[REDACTED_URL])."),
    ("https://u?ser@[REDACTED]).", "[REDACTED_URL])."),
    ("https://u?ser@ci.example/path?sig=SECRET?#anchor", "[REDACTED_URL]"),
], ids=["terminal-punctuation", "markdown-suffix", "ipv6-host", "ipv6-punctuation", "opaque-host",
        "query-fragment"])
def test_guidance_round5_whole_url_mask_keeps_attribution_and_closers(source, expected):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import mask_guidance_url_authorities

    prefix, suffix = expected.split("[REDACTED_URL]")
    first, last = len(prefix), len(source) - len(suffix)
    labels = list(range(first)) + [first] * len("[REDACTED_URL]") + list(range(last, len(source)))
    assert mask_guidance_url_authorities(source, list(range(len(source))), limit=300) == (expected, labels)
    assert redact_labeled(source, list(range(len(source))), 300) == (expected, labels)
    assert len(expected) == len(labels)
    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    assert redact_clean_text(expected) == expected
    assert mask_guidance_url_authorities(expected, labels, limit=300) == (expected, labels)


def test_guidance_round5_ambiguous_marker_respects_limit():
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.redaction import RedactionRefusal, mask_guidance_url_authorities

    source = "a://?@h"
    for labels in (None, [0] * len(source)):
        with pytest.raises(RedactionRefusal, match="^too_large$") as caught:
            mask_guidance_url_authorities(source, labels, limit=len(source))
        assert caught.value.code == "too_large"
        with pytest.raises(ValueError, match="^guidance_projection_limit$"):
            redact_labeled(source, labels, len(source))


def test_guidance_round5_ambiguous_url_never_breaks_original_pem_masking():
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text

    source = "https://u?ser@h/-----BEGIN " + "PRIVATE KEY-----\nsynthetic_private_body\n-----END " + "PRIVATE KEY-----"
    expected = "[REDACTED_URL]"
    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    assert redact_labeled(source + "\nSECOND", [0] * len(source) + [None] + [1] * 6, 300) == (
        expected + "\nSECOND", [0] * len(expected) + [None] + [1] * 6)
    assert redact_clean_text(expected) == expected


@pytest.mark.parametrize("source,expected,secrets", [
    ("token=redis://:prefix,hunter2@localhost/0?sig=SECRET", "[REDACTED_URL]", ("prefix", "hunter2", "SECRET")),
    ("password is redis://:prefix,hunter2@localhost/0?sig=SECRET", "[REDACTED_URL]", ("prefix", "hunter2", "SECRET")),
    ("token=redis://" + "u" * 129 + ":prefix,hunter2@localhost/0?sig=SECRET", "[REDACTED_URL]",
     ("prefix", "hunter2", "SECRET")),
    ("[job](https://u:(pass@h/p)?sig=SECRET)", "[job]([REDACTED_URL])", ("pass", "SECRET")),
    ("[job](https://:(pass@h/p)?sig=SECRET)", "[job]([REDACTED_URL])", ("pass", "SECRET")),
    ("[job](https://h/p?token=(abcd,foo)&sig=SECRET)", "[job]([REDACTED_URL])", ("abcd", "foo", "SECRET")),
], ids=["keyed-empty-user", "natural-label", "keyed-long-user", "password-parenthesis",
        "empty-user-parenthesis", "query-parenthesis"])
def test_guidance_round6_original_url_spans_are_atomic(source, expected, secrets):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text

    assert redact_clean_text(source) == expected
    assert all(secret not in redact_clean_text(source) for secret in secrets)
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    shown, labels = redact_labeled(source + "\nSECOND", [0] * len(source) + [None] + [1] * 6, 2000)
    assert shown == expected + "\nSECOND"
    assert labels == [0] * len(expected) + [None] + [1] * 6
    assert len(shown) == len(labels)
    assert redact_clean_text(expected) == expected


@pytest.mark.parametrize("prefix", [".", "9", "+", "-"], ids=["dot", "digit", "plus", "minus"])
@pytest.mark.parametrize("userinfo,masked", [("", ""), (":hunter2@", ":[REDACTED]@")],
                         ids=["query", "empty-user-password"])
def test_guidance_round6_prefixed_schemes_are_detected(prefix, userinfo, masked):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries

    head = prefix + "https://" + userinfo + "ci.example/job"
    source = head + "?sig=SECRET"
    expected = prefix + "https://" + masked + "ci.example/job"
    assert redact_clean_text(source) == expected
    assert "hunter2" not in expected and "SECRET" not in redact_clean_text(source)
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    shown, labels = redact_labeled(source, [0] * len(source), 300)
    assert shown == expected and labels == [0] * len(expected)
    assert len(shown) == len(labels)
    assert remove_guidance_url_queries(source, limit=300) == (head, ((len(head), len(source)),))
    assert remove_guidance_url_queries(head, limit=300) == (head, ())
    assert redact_clean_text(expected) == expected


def test_guidance_round6_no_scheme_letters_fail_closed():
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text

    source = "://:hunter2@localhost/0?sig=SECRET"
    expected = "[REDACTED_URL]"
    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    assert redact_labeled(source, [0] * len(source), 300) == (expected, [0] * len(expected))
    assert redact_clean_text(expected) == expected


def test_guidance_round6_large_non_url_completes():
    script = (
        "from aegis_core.guidance_grammar import redact_labeled\n"
        "source = 'a' * (1024 * 1024)\n"
        "shown, labels = redact_labeled(source, None, len(source))\n"
        "assert shown == source and labels is None\n"
        "print(len(shown))\n"
    )
    # Bound a stuck child; this checks completion/output, not elapsed-time speed.
    result = subprocess.run([sys.executable, "-c", script], cwd=REPO, capture_output=True,
                            text=True, check=True, timeout=20)
    assert result.stdout.strip() == str(1024 * 1024)


@pytest.mark.parametrize("tail", ["9hunter2://x", ".hunter2://x", "+hunter2://x",
                                  "-hunter2://x", "12345hunter2://x", "1https://b",
                                  "9hunter2://x#last", "9hunter2://x?next=SECRET"],
                         ids=["digit", "dot", "plus", "minus", "digits", "nested-https",
                              "nested-anchor", "nested-query"])
@pytest.mark.parametrize("markdown", [False, True], ids=["plain", "markdown"])
def test_guidance_round6d_query_owns_later_scheme_markers(tail, markdown):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries, remove_url_credentials

    prefix, suffix = ("[job](", "),NEXT") if markdown else ("", "")
    head = prefix + "https://h/p"
    source = head + "?sig=" + tail + suffix
    expected = head + suffix
    spans = ((len(head), len(source) - len(suffix)),)
    retained = list(range(len(head))) + list(range(spans[0][1], len(source)))
    assert remove_guidance_url_queries(source, limit=1000) == (expected, spans)
    assert remove_url_credentials(source, limit=1000, policy="guidance") == expected
    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    shown, labels = redact_labeled(source, list(range(len(source))), 1000)
    assert shown == expected and labels == retained
    assert len(labels) == len(shown)
    assert all(char == source[label] for char, label in zip(shown, labels))
    assert redact_labeled(source + "\nSECOND", [0] * len(source) + [None] + [1] * 6, 1000) == (
        expected + "\nSECOND", [0] * len(expected) + [None] + [1] * 6)
    assert "hunter2" not in shown and "SECRET" not in shown
    assert remove_guidance_url_queries(expected, limit=1000) == (expected, ())
    assert remove_url_credentials(expected, limit=1000, policy="guidance") == expected
    assert redact_labeled(shown, labels, 1000) == (shown, labels)
    assert redact_clean_text(expected) == expected


@pytest.mark.parametrize("source,expected", [
    ("https://a/x?q=1https://b", "https://a/x"),
    ("https://h/p#anchor,https://ci.example/job?sig=hunter2#last", "https://h/p"),
    ("https://h/path/https://inner/path?sig=hunter2#last", "https://h/path/https://inner/path"),
    ("https://h/path/https://inner/path", "https://h/path/https://inner/path"),
    ("https://h/p?sig=hidden#anchor", "https://h/p#anchor"),
], ids=["exact-reproducer", "fragment-owns-marker", "path-owns-marker", "path-no-query", "ordinary-anchor"])
def test_guidance_round6d_one_url_ends_before_next_whitespace(source, expected):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries, remove_url_credentials

    shown, spans = remove_guidance_url_queries(source, limit=1000)
    assert shown == expected
    retained = [i for i in range(len(source)) if not any(lo <= i < hi for lo, hi in spans)]
    assert redact_labeled(source, list(range(len(source))), 1000) == (expected, retained)
    assert len(retained) == len(expected)
    assert all(char == source[label] for char, label in zip(expected, retained))
    assert remove_url_credentials(source, limit=1000, policy="guidance") == expected
    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    assert remove_guidance_url_queries(expected, limit=1000) == (expected, ())
    assert remove_url_credentials(expected, limit=1000, policy="guidance") == expected
    assert redact_labeled(expected, retained, 1000) == (expected, retained)
    assert redact_clean_text(expected) == expected


def test_guidance_round6d_nested_path_userinfo_is_not_the_owning_authority():
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text

    source = "https://h/path/https://u:hunter2@inner/path"
    expected = "[REDACTED_URL]"
    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    assert redact_labeled(source, [0] * len(source), 1000) == (expected, [0] * len(expected))
    assert "hunter2" not in redact_clean_text(source)
    assert redact_clean_text(expected) == expected


@pytest.mark.parametrize("source,query_expected,serving_expected", [
    ("https://ci.example?user=a@b&sig=SECRET", "https://ci.example", "[REDACTED_URL]"),
    ("https://ci.example?sig=SECRET@x/y", "https://ci.example", "[REDACTED_URL]"),
    ("https://ci.example?sig=SECRET@x/y#anchor", "https://ci.example#anchor", "[REDACTED_URL]"),
    ("https://ci.example/job?next=https://app.example/done&sig=SECRET",
     "https://ci.example/job", "https://ci.example/job"),
    ("https://ci.example/job?sig=v1://SECRET", "https://ci.example/job", "https://ci.example/job"),
    ("https://ci.example/job?sig=://SECRET", "https://ci.example/job", "https://ci.example/job"),
], ids=["query-at", "query-at-before-slash", "query-at-anchor", "redirect", "version", "bare-marker"])
def test_guidance_round6e_authority_stops_before_query_contents(source, query_expected, serving_expected):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries, remove_url_credentials

    query = source.index("?")
    stop = source.index("#") if "#" in source else len(source)
    spans = ((query, stop),)
    assert remove_guidance_url_queries(source, limit=1000) == (query_expected, spans)
    assert remove_url_credentials(source, limit=1000, policy="guidance") == query_expected
    assert "SECRET" not in query_expected
    assert redact_clean_text(source) == serving_expected
    assert project_field([source, "SECOND"]) == [serving_expected, "SECOND"]
    retained = list(range(query)) + list(range(stop, len(source)))
    labels = retained if serving_expected == query_expected else [0] * len(serving_expected)
    shown, attribution = redact_labeled(source, list(range(len(source))), 1000)
    assert shown == serving_expected and attribution == labels
    assert len(shown) == len(attribution)
    assert redact_labeled(source + "\nSECOND", [0] * len(source) + [None] + [1] * 6, 1000) == (
        serving_expected + "\nSECOND", [0] * len(serving_expected) + [None] + [1] * 6)
    assert redact_labeled(shown, attribution, 1000) == (shown, attribution)
    assert redact_clean_text(serving_expected) == serving_expected
    assert remove_guidance_url_queries(query_expected, limit=1000) == (query_expected, ())
    assert remove_url_credentials(query_expected, limit=1000, policy="guidance") == query_expected


@pytest.mark.parametrize("url,secrets", [
    ("https://user:pass://hunter2@ci.example/path?sig=SECRET", ("pass", "hunter2", "SECRET")),
    ("redis://:prefix://hunter2@localhost/0", ("prefix", "hunter2")),
    ("https://user:p#a://hunter2@ci.example/path?sig=SECRET", ("p#a", "hunter2", "SECRET")),
], ids=["password-marker", "empty-user-marker", "password-fragment-marker"])
@pytest.mark.parametrize("markdown", [False, True], ids=["plain", "markdown"])
def test_guidance_round6e_embedded_userinfo_fails_closed(url, secrets, markdown):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries, remove_url_credentials

    prefix, suffix = ("[job](", "),NEXT") if markdown else ("", "")
    source = prefix + url + suffix
    query_expected = prefix + suffix
    expected = prefix + "[REDACTED_URL]" + suffix
    first, last = len(prefix), len(prefix) + len(url)
    assert remove_guidance_url_queries(source, limit=1000) == (query_expected, ((first, last),))
    assert remove_url_credentials(source, limit=1000, policy="guidance") == query_expected
    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    labels = list(range(first)) + [first] * len("[REDACTED_URL]") + list(range(last, len(source)))
    shown, attribution = redact_labeled(source, list(range(len(source))), 1000)
    assert shown == expected and attribution == labels
    assert len(shown) == len(attribution)
    assert all(secret not in shown and secret not in query_expected for secret in secrets)
    assert redact_labeled(shown, attribution, 1000) == (shown, attribution)
    assert redact_labeled(source + "\nSECOND", [0] * len(source) + [None] + [1] * 6, 1000) == (
        expected + "\nSECOND", [0] * len(expected) + [None] + [1] * 6)
    assert redact_clean_text(expected) == expected
    assert remove_guidance_url_queries(query_expected, limit=1000) == (query_expected, ())
    assert remove_url_credentials(query_expected, limit=1000, policy="guidance") == query_expected


def test_guidance_round6e_query_only_helper_retains_literal_fragment():
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries, remove_url_credentials

    source = "https://ci.example#anchor@v1?detail=visible"
    assert remove_guidance_url_queries(source, limit=1000) == (source, ())
    assert remove_url_credentials(source, limit=1000, policy="guidance") == source
    expected = "[REDACTED_URL]"
    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    assert redact_labeled(source, [0] * len(source), 1000) == (expected, [0] * len(expected))
    assert redact_clean_text(expected) == expected


@pytest.mark.parametrize("nested,sensitive", [
    ("redis://:hunter2@localhost/0", ("hunter2",)),
    ("redis://:hunter2@inner/0", ("hunter2",)),
    ("redis://" + "u" * 129 + ":hunter2@inner/0", ("u" * 129, "hunter2")),
    ("redis://user:" + "p" * 513 + "@inner/0", ("user", "p" * 513)),
    ("redis://us@er:hunter2@inner/0", ("us@er", "hunter2")),
    ("redis://:@inner/0", ()),
    ("redis://viewer@inner", ("viewer",)),
], ids=["empty-user-localhost", "empty-user-inner", "long-user", "long-password", "at-in-user",
        "empty-components", "username-only-terminal"])
@pytest.mark.parametrize("location", ["/path/", "/p?next=", "/p#next="], ids=["path", "query", "fragment"])
@pytest.mark.parametrize("query", ["", "?sig=SECRET"], ids=["no-query", "following-query"])
@pytest.mark.parametrize("markdown", [False, True], ids=["plain", "markdown"])
def test_guidance_round6f_embedded_userinfo_masks_owner(nested, sensitive, location, query, markdown):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries, remove_url_credentials

    prefix, suffix = ("[job](", "),NEXT") if markdown else ("", "")
    url = "https://h" + location + nested + query
    source = prefix + url + suffix
    expected = prefix + "[REDACTED_URL]" + suffix
    first, last = len(prefix), len(prefix) + len(url)
    labels = list(range(first)) + [first] * len("[REDACTED_URL]") + list(range(last, len(source)))
    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    shown, attribution = redact_labeled(source, list(range(len(source))), 8192)
    assert shown == expected and attribution == labels
    assert len(shown) == len(attribution)
    assert all(part not in shown for part in sensitive + ("SECRET",))
    assert redact_labeled(source + "\nSECOND", [0] * len(source) + [None] + [1] * 6, 8192) == (
        expected + "\nSECOND", [0] * len(expected) + [None] + [1] * 6)
    assert redact_labeled(shown, attribution, 8192) == (shown, attribution)
    assert redact_clean_text(expected) == expected
    # Compatibility helpers represent fail-closed consumption as deletion.
    helper_expected = prefix + suffix
    assert remove_guidance_url_queries(source, limit=8192) == (helper_expected, ((first, last),))
    assert remove_url_credentials(source, limit=8192, policy="guidance") == helper_expected
    assert remove_guidance_url_queries(helper_expected, limit=8192) == (helper_expected, ())
    assert remove_url_credentials(helper_expected, limit=8192, policy="guidance") == helper_expected


@pytest.mark.parametrize("source,helper_expected,expected", [
    ("https://h/path/redis://inner/0", "https://h/path/redis://inner/0", "https://h/path/redis://inner/0"),
    ("https://h/path/redis://inner/path@revision", "https://h/path/redis://inner/path@revision",
     "https://h/path/redis://inner/path@revision"),
    ("https://h/path/redis://inner?contact=x@y", "https://h/path/redis://inner", "[REDACTED_URL]"),
    ("https://h/path/redis://inner#anchor@revision", "https://h/path/redis://inner", "[REDACTED_URL]"),
    ("https://h/p/a://inner/b://target/path", "https://h/p/a://inner/b://target/path",
     "https://h/p/a://inner/b://target/path"),
    ("https://h/p?next=redis://inner/path#anchor", "https://h/p", "https://h/p"),
    ("https://h/p#next=redis://inner/path", "https://h/p", "https://h/p"),
], ids=["no-userinfo", "path-at", "query-at", "fragment-at", "multiple-markers", "owning-query",
        "owning-fragment"])
def test_guidance_round6f_embedded_authority_boundaries(source, helper_expected, expected):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries, remove_url_credentials

    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    shown, labels = redact_labeled(source, [0] * len(source), 8192)
    assert shown == expected and labels == [0] * len(expected)
    assert len(shown) == len(labels)
    assert remove_guidance_url_queries(source, limit=8192)[0] == helper_expected
    assert remove_url_credentials(source, limit=8192, policy="guidance") == helper_expected
    assert redact_labeled(shown, labels, 8192) == (shown, labels)
    assert redact_clean_text(expected) == expected
    assert remove_guidance_url_queries(helper_expected, limit=8192) == (helper_expected, ())


@pytest.mark.parametrize("prefix,suffix", [("", ""), ("[", "]"), ("[job](", "),NEXT")],
                         ids=["plain", "prose-brackets", "markdown"])
def test_guidance_round6f_unresolved_embedded_authority_fails_closed(prefix, suffix):
    from aegis_core.guidance_grammar import redact_labeled
    from aegis_core.guidance_projection import project_field, redact_clean_text
    from aegis_core.redaction import remove_guidance_url_queries, remove_url_credentials

    url = "https://h/path/redis://" + "x" * 5000 + "/0"
    source = prefix + url + suffix
    expected = prefix + "[REDACTED_URL]" + suffix
    first, last = len(prefix), len(prefix) + len(url)
    labels = list(range(first)) + [first] * len("[REDACTED_URL]") + list(range(last, len(source)))
    assert redact_clean_text(source) == expected
    assert project_field([source, "SECOND"]) == [expected, "SECOND"]
    assert redact_labeled(source, list(range(len(source))), 8192) == (expected, labels)
    assert len(labels) == len(expected)
    assert redact_labeled(expected, labels, 8192) == (expected, labels)
    assert redact_clean_text(expected) == expected
    assert remove_guidance_url_queries(source, limit=8192) == (
        prefix + suffix, ((first, last),))
    assert remove_url_credentials(source, limit=8192, policy="guidance") == prefix + suffix


def test_guidance_round6f_many_embedded_markers_complete():
    script = (
        "from aegis_core.guidance_grammar import redact_labeled\n"
        "source = 'https://h/path/' + 'a://h/' * 10000\n"
        "shown, labels = redact_labeled(source, None, len(source))\n"
        "assert shown == source and labels is None\n"
        "print(len(shown))\n"
    )
    result = subprocess.run([sys.executable, "-c", script], cwd=REPO, capture_output=True,
                            text=True, check=True, timeout=20)
    assert result.stdout.strip() == str(len("https://h/path/") + len("a://h/") * 10000)
