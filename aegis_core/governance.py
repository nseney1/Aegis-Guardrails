"""The governance file set (v4.3 spec §2.3): the files whose change needs a human approval.

A change to any of these is a change to what binds the agent, so it earns no credit and
needs a ``human_gate`` approval (``aegis_core.human_gate``) before it counts:

- ``rules``: ``.aegis/rules/**``;
- ``aegis-state``: ``.aegis/config.json``, ``.aegis/team.json``, ``.aegis/baseline.json``
  (this and ``rules`` at any depth: a workspace below the repository root has its own ``.aegis``);
- ``signers``: ``allowed_signers`` (the keys that may approve) and ``CODEOWNERS``;
- ``workflows``: ``.github/workflows/**`` (the pinned Aegis version lives in a workflow or in
  ``.aegis/config.json``, both covered);
- ``test-infra``: ``conftest.py``, the files that hold pytest's configuration (``pytest.ini``,
  ``tox.ini``, ``setup.cfg``, ``pyproject.toml``, ``pytest.toml``), ``sitecustomize.py``,
  ``*.pth``, the ``Makefile`` and a root module that shadows the runner (``RUNNER_MODULES``:
  ``pytest.py``, ``_pytest/__init__.py``, ``pluggy``, ``py``, ``iniconfig`` and their compiled forms);
- ``tests-deleted``: a deleted test file (``match.is_test_path``); an approval's hash binds the
  ones deleted since the base (``human_gate.governance_tree_hash``).

A path-only table cannot see inside a file, so ``pyproject.toml``, ``setup.cfg`` and the
``Makefile`` count whole (a version bump in ``pyproject.toml`` is a governance change here),
and a skipped or weakened test is not a path at all: the lane gate's integrity findings
(``aegis_core.lane_gate``) and the CI weakening check carry those. Nor can it name every module
``python -m pytest`` imports: a root ``argparse.py`` or ``json.py`` can still replace what runs,
so a ``witness: aegis`` row stays a label. This module answers only
"does this path belong to the set". Matching is case-folded, as a case-insensitive checkout
sees the names, and uses the one matcher (``aegis_core.match``) so a pattern means here what
it means everywhere.
"""
from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

from aegis_core import match
from aegis_core.workspace.layout import AEGIS_DIRNAME, RULES_RELDIR

__all__ = ["CATEGORIES", "DELETED_TESTS", "RUNNER_MODULES", "category_of", "touches_governance"]

#: What ``python -m pytest`` imports first from the snapshot root (first on sys.path), so a root
#: module or package of one of these names replaces the runner. A package counts by its
#: ``__init__.py`` only: a directory without one is a namespace portion the installed package beats.
RUNNER_MODULES = ("pytest", "_pytest", "pluggy", "py", "iniconfig")
_RUNNER_SUFFIXES = (".py", ".pyc", ".so", ".*.so", ".pyd", ".*.pyd", "/__init__.py")

# (category, patterns), in the order touches_governance reports them. A pattern with no "/"
# also matches the file's basename at any depth (aegis_core.match).
CATEGORIES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("rules", (f"**/{RULES_RELDIR}/**",)),
    ("aegis-state", tuple(f"**/{AEGIS_DIRNAME}/{name}" for name in ("config.json", "team.json", "baseline.json"))),
    ("signers", ("allowed_signers", "CODEOWNERS")),
    ("workflows", (".github/workflows/**",)),
    ("test-infra", (
        "conftest.py", "pytest.ini", ".pytest.ini", "pytest.toml", ".pytest.toml", "tox.ini", "setup.cfg",
        "pyproject.toml", "sitecustomize.py", "*.pth", "Makefile",
        *(f"{name}{suffix}" for name in RUNNER_MODULES for suffix in _RUNNER_SUFFIXES),
    )),
)
#: The category a deleted test file belongs to (a present test file is not governance).
DELETED_TESTS = "tests-deleted"


def _folded(patterns: Iterable[str]) -> Tuple[str, ...]:
    return tuple(p.casefold() for p in patterns)


_FOLDED = tuple((name, _folded(patterns)) for name, patterns in CATEGORIES)


def category_of(path: str, deleted: bool = False) -> Optional[str]:
    """The governance category of the repo-relative ``path``, or None when it is outside the set.

    ``deleted`` says the change removed the file: a deleted test file is governance
    (``tests-deleted``), a present one is not.
    """
    if not isinstance(path, str) or not path:
        return None
    folded = match.normalize_path(path).casefold()
    for name, patterns in _FOLDED:
        if any(match.matches(pattern, folded) for pattern in patterns):
            return name
    if deleted and match.is_test_path(folded):
        return DELETED_TESTS
    return None


def touches_governance(paths: Iterable[str], deleted: Iterable[str] = ()) -> List[str]:
    """The governance categories that the changed ``paths`` (posix, repo-relative) touch.

    ``deleted`` lists the paths the change removed (they count as changed too). Categories
    come back in the table's order, each once; an empty list means the change is outside the set.
    """
    gone = {match.normalize_path(p).casefold() for p in deleted if isinstance(p, str)}
    found = set()
    for path in [*paths, *deleted]:
        if not isinstance(path, str):
            continue
        category = category_of(path, deleted=match.normalize_path(path).casefold() in gone)
        if category:
            found.add(category)
    order = [name for name, _patterns in CATEGORIES] + [DELETED_TESTS]
    return [name for name in order if name in found]
