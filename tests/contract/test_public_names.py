"""The public-names pin (invariant-decomposition-merge-gate, check 2).

`public_names_4_3_3.json` holds every public name of the modules the 4.3.4/4.4.0
decomposition items move, as shipped at cdb527b (v4.3.3). A pinned name must still
resolve, or be listed in `removed` as ``module.name`` with a ``Breaking:`` line naming
it in a CHANGELOG section newer than 4.3.3. Names bound to modules and ``__future__``
features are exempt (import hygiene, not API), as are underscore names (D-public-names).

The baseline is never regenerated: it is the 4.3.3 surface. `removed` only grows, and
only together with its CHANGELOG line.
"""
from __future__ import annotations

import ast
import importlib
import json
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Tuple

REPO = Path(__file__).resolve().parents[2]
PIN = Path(__file__).with_name("public_names_4_3_3.json")
BASELINE_HEADER = "## [4.3.3]"


def missing_names(modules: Dict[str, List[str]], removed: Iterable[str],
                  resolve: Callable[[str, str], bool]) -> List[str]:
    gone = set(removed)
    return [f"{mod}.{name}" for mod, names in sorted(modules.items()) for name in names
            if f"{mod}.{name}" not in gone and not resolve(mod, name)]


def unlisted_removals(removed: Iterable[str], changelog: str) -> List[str]:
    # Only sections above the 4.3.3 header are newer releases; a Breaking line in an
    # old section cannot cover a removal made now.
    newer = changelog.split(BASELINE_HEADER, 1)[0]
    breaking = [line for line in newer.splitlines() if "Breaking:" in line]
    return [name for name in removed if not any(name in line for line in breaking)]


def unresolved_imports(sources: Iterable[Tuple[str, str]],
                       resolve: Callable[[str, str], bool]) -> List[str]:
    # Only aegis packages: the waves move aegis names; the scripts' stdlib imports are
    # not part of the surface this pin guards.
    bad = []
    for label, text in sources:
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module \
                    and node.module.split(".")[0].startswith("aegis_"):
                bad += [f"{label}: {node.module}.{a.name}" for a in node.names
                        if a.name != "*" and not resolve(node.module, a.name)]
    return bad


def _resolves(mod: str, name: str) -> bool:
    try:
        module = importlib.import_module(mod)
    except ImportError:
        return False
    if hasattr(module, name):
        return True
    try:  # `from pkg import submodule` resolves without the package binding it
        importlib.import_module(f"{mod}.{name}")
    except ImportError:
        return False
    return True


def _pin() -> dict:
    return json.loads(PIN.read_text(encoding="utf-8"))


def test_every_pinned_name_resolves_or_is_removed():
    pin = _pin()
    assert missing_names(pin["modules"], pin["removed"], _resolves) == []


def test_every_removed_name_has_a_breaking_line():
    changelog = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    assert unlisted_removals(_pin()["removed"], changelog) == []


def test_ci_scripts_import_only_names_that_exist():
    scripts = sorted((REPO / ".github" / "scripts").glob("*.py"))
    assert scripts, "no CI scripts found"
    sources = [(p.name, p.read_text(encoding="utf-8")) for p in scripts]
    assert unresolved_imports(sources, _resolves) == []


def test_a_dropped_name_without_a_changelog_line_is_named():
    modules = {"pkg.mod": ["kept", "dropped"]}
    assert missing_names(modules, [], lambda m, n: n == "kept") == ["pkg.mod.dropped"]
    assert missing_names(modules, ["pkg.mod.dropped"], lambda m, n: n == "kept") == []


def test_a_removal_without_a_breaking_line_fails():
    changelog = ("## [4.3.4]\n- Breaking: `pkg.mod.other` is gone.\n- `pkg.mod.dropped` moved.\n"
                 "## [4.3.3] - 2026-10-17\n- Breaking: pkg.mod.dropped\n")
    assert unlisted_removals(["pkg.mod.dropped"], changelog) == ["pkg.mod.dropped"]
    assert unlisted_removals(["pkg.mod.other"], changelog) == []


def test_a_script_importing_a_missing_name_fails():
    src = "import os\nfrom aegis_core import storage\nfrom aegis_core.storage import no_such_name\n"
    assert unresolved_imports([("smoke.py", src)], _resolves) == \
        ["smoke.py: aegis_core.storage.no_such_name"]
