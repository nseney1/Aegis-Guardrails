"""The doctor family's module structure (R-structure-26, R-structure-27).

Given the aegis_cli/doctor*.py modules, When each one is imported first in a fresh interpreter,
Then none fails: a module that works only after a sibling has been imported is a cycle that the
usual import order (aegis_cli.doctor first, through the registry) hides.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Dict, List, Sequence

REPO = Path(__file__).resolve().parents[3]

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
    return sorted(f"aegis_cli.{path.stem}" for path in (REPO / "aegis_cli").glob("doctor*.py"))


def test_each_doctor_module_imports_first_in_a_fresh_interpreter(tmp_path):
    modules = _family()
    assert "aegis_cli.doctor_repair" in modules
    assert fresh_import_failures(REPO, "aegis_", modules, tmp_path) == {}


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
