"""The doctor family's module structure (R-structure-26, R-structure-27).

Given the aegis_cli/doctor*.py modules, When each one is imported first in a fresh interpreter,
Then none fails: a module that works only after a sibling has been imported is a cycle that the
usual import order (aegis_cli.doctor first, through the registry) hides.

Given their source, When the imports are read at every depth (function bodies and TYPE_CHECKING
included), Then they form one DAG: doctor -> render -> {findings, repair} -> doctor_base ->
commands_table, no shard reaches back into aegis_cli.doctor, and each seam a test patches has one
owning module that reads it at call time.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Dict, List, Sequence, Set, Tuple

import pytest

REPO = Path(__file__).resolve().parents[3]
PKG = "aegis_cli"

# One child interpreter (-I: no PYTHONPATH, no user site, no editable finder of another
# checkout). Before each import every module under the prefix leaves sys.modules.
_FRESH_IMPORTS = r"""
import importlib, json, sys
root, prefix, names = sys.argv[1], sys.argv[2], sys.argv[3:]
sys.path.insert(0, root)
failures = {}
for name in names:
    for key in [k for k in sys.modules if k.startswith(prefix)]:
        del sys.modules[key]
    try:
        importlib.import_module(name)
    except Exception as exc:
        failures[name] = f"{type(exc).__name__}: {exc}"
sys.stdout.write(json.dumps(failures))
"""


def fresh_import_failures(root: Path, prefix: str, modules: Sequence[str], home: Path) -> Dict[str, str]:
    """{module: 'ExcType: message'} for each module that fails to import first."""
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_CONFIG_DIR", "CODEX_HOME")}
    env.update(HOME=str(home), USERPROFILE=str(home))
    proc = subprocess.run([sys.executable, "-I", "-c", _FRESH_IMPORTS, str(root), prefix, *modules],
                          input=b"", capture_output=True, env=env, timeout=300)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    return json.loads(proc.stdout.decode("utf-8"))


def _family() -> List[str]:
    return sorted(f"aegis_cli.{path.stem}" for path in (REPO / "aegis_cli").glob("doctor*.py")) + [
        "aegis_cli.commands_table"]


def test_each_doctor_module_imports_first_in_a_fresh_interpreter(tmp_path):
    modules = _family()
    assert {"aegis_cli.doctor_repair", "aegis_cli.doctor_base"} <= set(modules)
    assert fresh_import_failures(REPO, "aegis_", modules, tmp_path) == {}


# ── The import graph, read from the source ──────────────────────────────────

# Who may import whom inside the family; anything else (a lazy import in a function body or one
# under TYPE_CHECKING too) is a back edge. The CLI dispatcher is never imported: doctor_repair
# reading cli's table closed the cycle {cli, registry, doctor, doctor_*}.
ALLOWED = {
    "aegis_cli.doctor": {"aegis_cli.doctor_base", "aegis_cli.doctor_findings", "aegis_cli.doctor_render",
                         "aegis_cli.doctor_repair"},
    "aegis_cli.doctor_render": {"aegis_cli.doctor_base", "aegis_cli.doctor_findings", "aegis_cli.doctor_repair"},
    "aegis_cli.doctor_findings": {"aegis_cli.doctor_base"},
    "aegis_cli.doctor_repair": {"aegis_cli.doctor_base"},
    "aegis_cli.doctor_base": {"aegis_cli.commands_table"},
    "aegis_cli.commands_table": set(),
}
WATCHED = set(ALLOWED) | {"aegis_cli.cli", "aegis_cli.registry"}


def _source(module: str) -> Tuple[str, ast.Module]:
    path = REPO.joinpath(*module.split(".")).with_suffix(".py")
    rel = path.relative_to(REPO).as_posix()
    return rel, ast.parse(path.read_bytes().decode("utf-8"), filename=rel)


def _imports(tree: ast.Module) -> List[Tuple[str, Set[str], int]]:
    """(imported module, the names it binds as written and as bound, line) for every import at
    any depth; `from aegis_cli import doctor_base` names the submodule and binds nothing watched."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(alias.name, set(), node.lineno) for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                sub = f"{node.module}.{alias.name}"
                names = {alias.name, alias.asname or alias.name}
                found.append((sub, set(), node.lineno) if sub in WATCHED else (node.module, names, node.lineno))
    return found


def test_no_shard_imports_aegis_cli_doctor_at_any_depth():
    offenders = [f"{rel}:{line}" for module in sorted(set(ALLOWED) - {"aegis_cli.doctor"})
                 for rel, tree in [_source(module)] for target, _names, line in _imports(tree)
                 if target == "aegis_cli.doctor"]
    assert offenders == []


def test_the_family_imports_form_the_agreed_dag():
    back = [f"{rel}:{line}: {module} -> {target}" for module in sorted(ALLOWED)
            for rel, tree in [_source(module)] for target, _names, line in _imports(tree)
            if target in WATCHED and target != module and target not in ALLOWED[module]]
    assert back == []


def test_every_name_doctor_imports_from_a_shard_is_read_or_exported():
    _rel, tree = _source("aegis_cli.doctor")
    exported: Set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "__all__" for t in node.targets):
            exported = set(ast.literal_eval(node.value))
    read = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
    bound = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith(f"{PKG}.doctor_"):
            bound |= {alias.asname or alias.name for alias in node.names}
        if isinstance(node, ast.ImportFrom) and node.module == PKG:
            bound |= {alias.asname or alias.name for alias in node.names if alias.name.startswith("doctor_")}
    assert bound, "doctor.py imports nothing from its shards"
    assert sorted(bound - read - exported) == []


# ── Seams: one owner, read at call time ─────────────────────────────────────

SEAMS = [("which", "doctor_base"), ("only_skipped", "doctor_base"), ("_present", "doctor_base"),
         ("_stdin_is_tty", "doctor_base"), ("_confirm", "doctor_base"), ("_platform", "doctor_base"),
         ("_V3_SHIPPED_RULE_SHA256", "doctor_base")]
# The names the seams had on aegis_cli.doctor in 4.3, where tests patched them.
OLD_NAMES = {"_V3_SHIPPED_RULE_SHA256": "V3_SHIPPED_RULE_SHA256"}


@pytest.mark.parametrize("seam,owner", SEAMS, ids=[s for s, _ in SEAMS])
def test_each_patched_seam_has_one_owner_and_is_never_imported_by_value(seam, owner, monkeypatch):
    import importlib

    from aegis_cli import doctor

    assert hasattr(importlib.import_module(f"{PKG}.{owner}"), seam)
    by_value = [f"{rel}:{line}" for module in sorted(ALLOWED) if module != f"{PKG}.{owner}"
                for rel, tree in [_source(module)] for _target, names, line in _imports(tree)
                if {seam, seam.lstrip("_")} & names]
    assert by_value == []
    # A test still patching the 4.3 home finds no attribute instead of silently patching nothing.
    with pytest.raises(AttributeError):
        monkeypatch.setattr(doctor, OLD_NAMES.get(seam, seam), None)


def test_the_new_doctor_modules_are_covered_by_their_suites(tmp_path):
    """The repository's own `aegis check` maps each source file to a test file; the two new
    modules are covered by the doctor and removed-command suites."""
    from aegis_core.verification.checkpoint_checks import check_test_coverage

    for rel in ("aegis_cli/doctor_base.py", "aegis_cli/commands_table.py", "tests/unit/cli/test_doctor.py",
                "tests/unit/cli/test_cli_removed_commands.py"):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x = 1\n" if rel.startswith("aegis_cli") else b"def test_x():\n    assert True\n")
    messages = [issue["message"] for issue in check_test_coverage(tmp_path)]
    assert [m for m in messages if "doctor_base" in m or "commands_table" in m] == []


def test_a_back_import_through_a_partly_initialized_module_is_named(tmp_path):
    # The shape of the doctor_findings tail import: fin imports rep's name at its end, rep
    # imports fin at its top. fin first works; rep first does not.
    pkg = tmp_path / "w14fix_pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_bytes(b"")
    (pkg / "rep.py").write_bytes(b"from w14fix_pkg.fin import F\nL = 1\n")
    (pkg / "fin.py").write_bytes(b"F = 1\nfrom w14fix_pkg.rep import L\n")
    failures = fresh_import_failures(tmp_path, "w14fix_", ["w14fix_pkg.fin", "w14fix_pkg.rep"], tmp_path)
    assert list(failures) == ["w14fix_pkg.rep"]
    assert failures["w14fix_pkg.rep"].startswith(
        "ImportError: cannot import name 'L' from partially initialized module 'w14fix_pkg.rep'")
