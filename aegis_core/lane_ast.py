"""Pure AST test-integrity scanners and zero-dependency pytest config readers for ``aegis_core.lane_gate``.

Scans Python test sources and pytest configuration files without importing or executing
repository code:

- ``collected_ids``: test ids (``name``, ``Class::name``, ``Outer::Inner::name``: functions
  and methods named ``test*``, as pytest's default discovery collects them) mapped to
  whether each is defined unconditionally. A class that defines ``__init__`` or ``__new__``
  contributes none, nor does a function decorated with ``@pytest.fixture`` (or an alias).
- ``skip_forms``: occurrences per scope of ``pytest.mark.skip``, ``skipif`` or ``xfail``;
  ``unittest.skip``, ``skipIf``, ``skipUnless`` or ``expectedFailure``; module- or
  class-level ``pytestmark`` or ``__test__`` (or either set as an attribute);
  ``pytest.skip``, ``pytest.xfail`` or ``pytest.importorskip``; ``.skipTest``;
  ``unittest.SkipTest``; or ``pytest.exit`` and ``os._exit``. Import aliases, star
  imports and simple assignments are resolved to a fixed point across the module, and
  surrounding control-flow guards are included in each occurrence key.
- ``collection_hooks``: watched names in ``conftest.py`` (``collect_ignore``,
  ``collect_ignore_glob``, ``pytest_*``) or plugin hook definitions when ``hooks_only=True``.
- ``pytest_settings``: zero-dependency INI and TOML reader for ``COLLECTION_KEYS`` across
  ``PYTEST_CONFIG_FILES``.
"""
from __future__ import annotations

import ast
import configparser
import hashlib
import re
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

__all__ = [
    "COLLECTION_KEYS",
    "COVERED",
    "LIMITS",
    "PYTEST_CONFIG_FILES",
    "collected_ids",
    "collection_hooks",
    "pytest_config_view",
    "pytest_settings",
    "skip_forms",
]

COVERED = ("python",)
COLLECTION_KEYS = ("addopts", "testpaths", "python_files", "python_classes", "python_functions", "norecursedirs")
# pytest's own search order; it reads the first that holds a configuration.
PYTEST_CONFIG_FILES = ("pytest.toml", ".pytest.toml", "pytest.ini", ".pytest.ini", "pyproject.toml", "tox.ini",
                       "setup.cfg")
LIMITS = (
    "Assert weakening is not detected: a test that still exists but checks less passes.",
    "Only Python test files and pytest's config files are checked; other test files are listed as not checked.",
    "Test ids follow pytest's default discovery (functions and methods named test*), whatever "
    "python_functions or python_classes the repository configures.",
    "Skips reached indirectly are not detected: through a fixture or helper function, a marker imported "
    "from another module, or getattr or setattr with a string.",
    "A skip is compared by its own text and the blocks around it (if, while, for, try, with, match, a "
    "conditional expression, and/or), not by what its condition evaluates to: a condition set elsewhere "
    "(a module constant such as SLOW = True, an environment variable, a helper) or an earlier "
    "'if ...: return' can change without a finding.",
    "A decorator that replaces a test with something pytest does not collect (one that returns None, say) "
    "is not detected; pytest.fixture is.",
    "Trimming @pytest.mark.parametrize cases is not detected, nor are tests generated at import time "
    "(exec, globals(), loops), which have no def to compare, or removed through globals() or vars().",
    "Of the ways to end the run early only pytest.exit and os._exit are detected, not os.kill, a signal or "
    "a plugin outside the test files.",
    "The test command itself (a CI workflow, a Makefile, tox commands) is not read; containment and the "
    "protection on .github/** cover the workflow.",
    "Only committed changes are checked: the range is merge-base(base, HEAD)..HEAD.",
)


# ── Python test files ────────────────────────────────────────────────────────

def _unbind(state: Dict[str, bool], key: str, conditional: bool, keep: bool = False) -> None:
    """A name rebound in a body: the test ids it held (itself, or a class's members) are
    gone, or only conditionally there when the rebinding is conditional."""
    for found in [k for k in state if k == key or k.startswith(key + "::")]:
        if keep and found == key:
            continue
        if conditional:
            state[found] = False
        else:
            del state[found]


def _target_names(node: ast.AST) -> List[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for element in node.elts for name in _target_names(element)]
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    return []


def _bound_names(stmt: ast.stmt) -> List[str]:
    """Names a statement binds in its own body (assignment, deletion, import)."""
    if isinstance(stmt, (ast.Import, ast.ImportFrom)):
        return [(alias.asname or alias.name).split(".")[0] for alias in stmt.names if alias.name != "*"]
    if isinstance(stmt, (ast.Assign, ast.Delete)):
        targets = stmt.targets
    elif isinstance(stmt, ast.AugAssign) or (isinstance(stmt, ast.AnnAssign) and stmt.value is not None):
        targets = [stmt.target]
    else:
        targets = []
    return [name for target in targets for name in _target_names(target)]


def _compound_names(stmt: ast.stmt) -> List[str]:
    """Names a compound statement binds itself: loop targets, ``with ... as``, handlers."""
    names = _target_names(getattr(stmt, "target", None)) if isinstance(stmt, (ast.For, ast.AsyncFor)) else []
    for item in getattr(stmt, "items", ()) or ():
        if item.optional_vars is not None:
            names.extend(_target_names(item.optional_vars))
    names.extend(handler.name for handler in getattr(stmt, "handlers", ()) or () if handler.name)
    return names


def _blocks(stmt: ast.stmt) -> List[List[ast.stmt]]:
    blocks = [getattr(stmt, field) for field in ("body", "orelse", "finalbody")
              if isinstance(getattr(stmt, field, None), list)]
    blocks.extend(handler.body for handler in getattr(stmt, "handlers", ()) or ())
    blocks.extend(case.body for case in getattr(stmt, "cases", ()) or ())
    return blocks


def _constructs(cls: ast.ClassDef) -> bool:
    """A class pytest will not collect: it defines ``__init__`` or ``__new__``."""
    for stmt in cls.body:
        names = [stmt.name] if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) else _bound_names(stmt)
        if "__init__" in names or "__new__" in names:
            return True
    return False


def _fixture(func: Any, aliases: _Aliases) -> bool:
    """A function decorated with ``pytest.fixture`` (called or not, through any alias):
    pytest collects it as a fixture, never as a test, whatever its name."""
    return any(chain in _FIXTURES
               for decorator in func.decorator_list
               for chain in _resolve(decorator.func if isinstance(decorator, ast.Call) else decorator, aliases))


def _scan_ids(body: Sequence[ast.stmt], prefix: str, conditional: bool, state: Dict[str, bool],
              aliases: _Aliases) -> None:
    for stmt in body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            key = prefix + stmt.name
            test = stmt.name.startswith("test") and not _fixture(stmt, aliases)
            _unbind(state, key, conditional, keep=test)
            if test:
                # A conditional redefinition of a test keeps a test there either way.
                state[key] = state.get(key, False) if conditional else True
        elif isinstance(stmt, ast.ClassDef):
            key = prefix + stmt.name
            _unbind(state, key, conditional)
            if not _constructs(stmt):
                _scan_ids(stmt.body, key + "::", conditional, state, aliases)
        else:
            for name in _bound_names(stmt):
                _unbind(state, prefix + name, conditional)
            for name in _compound_names(stmt):
                _unbind(state, prefix + name, True)
            for block in _blocks(stmt):
                _scan_ids(block, prefix, True, state, aliases)


def collected_ids(source: bytes) -> Dict[str, bool]:
    """The test ids pytest's default discovery collects from ``source``, each mapped to
    whether it is defined unconditionally (directly in the module or class body, not
    under an ``if``, ``try``, ``with`` or loop). Functions and methods named ``test*``,
    in classes of any name at any nesting; a class with ``__init__`` or ``__new__``
    contributes none, nor does a ``pytest.fixture``; the last binding of a name wins.
    Raises SyntaxError, ValueError or RecursionError for source that does not parse."""
    tree = ast.parse(source)
    state: Dict[str, bool] = {}
    _scan_ids(tree.body, "", False, state, _aliases(tree))
    return state


_FORMS = (
    ("pytest", "mark", "skip"),
    ("pytest", "mark", "skipif"),
    ("pytest", "mark", "xfail"),
    ("pytest", "skip"),
    ("pytest", "xfail"),
    ("pytest", "importorskip"),
    ("unittest", "skip"),
    ("unittest", "skipIf"),
    ("unittest", "skipUnless"),
    ("unittest", "expectedFailure"),
    ("unittest", "SkipTest"),
    # They end the whole run, so the tests after them never run; pytest.exit with
    # returncode=0 and os._exit(0) even report success.
    ("pytest", "exit"),
    ("os", "_exit"),
)
# Calls that return a skip or xfail decorator: a name bound to one is the form itself.
_DECORATOR_FACTORIES = frozenset({
    ("pytest", "mark", "skip"), ("pytest", "mark", "skipif"), ("pytest", "mark", "xfail"),
    ("unittest", "skip"), ("unittest", "skipIf"), ("unittest", "skipUnless"),
})
# pytest.fixture(...) returns a decorator too; neither is a skip form.
_FIXTURES = frozenset({("pytest", "fixture"), ("pytest", "yield_fixture")})
_PREFIXES = frozenset(form[:i] for form in _FORMS + tuple(_FIXTURES) for i in range(1, len(form)))
_MARKERS = ("pytestmark", "__test__")
_Chain = Tuple[str, ...]
# Every chain each name is bound to anywhere in the module; stored chains are forms,
# prefixes or fixture decorators only, so the sets stay small and the fixed point ends.
_Aliases = Dict[str, Set[_Chain]]


def _canonical(chain: Tuple[str, ...]) -> Tuple[str, ...]:
    return ("unittest",) + chain[2:] if chain[:2] == ("unittest", "case") else chain


def _form_of(chain: Optional[Tuple[str, ...]]) -> Optional[Tuple[str, ...]]:
    if chain:
        for form in _FORMS:
            if chain[:len(form)] == form:
                return form
    return None


def _resolve(node: ast.AST, aliases: _Aliases) -> List[_Chain]:
    """Every chain a ``Name`` or ``a.b.c`` chain may stand for, as dotted parts: as
    written, then with its head replaced by each alias bound to it anywhere in the
    module. A name rebound elsewhere (``import unittest as pytest`` in a function that
    never runs) so adds a reading and never hides one."""
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return []
    tail = tuple(reversed(parts))
    return [_canonical(head + tail) for head in [(node.id,)] + sorted(aliases.get(node.id, ()))]


def _first_form(chains: Sequence[_Chain]) -> Optional[_Chain]:
    return next((form for form in map(_form_of, chains) if form is not None), None)


def _aliasable(chain: _Chain) -> Optional[_Chain]:
    """What a name bound to ``chain`` is recorded as: the skip form it starts with (so
    ``pytest.skip.Exception`` is ``pytest.skip``), or itself when it is a part of a form
    or a fixture decorator; None for anything else."""
    form = _form_of(chain)
    if form is not None:
        return form
    return chain if chain in _PREFIXES or chain in _FIXTURES else None


def _alias_values(value: ast.AST, aliases: _Aliases) -> Set[_Chain]:
    if isinstance(value, ast.Call):
        chains = _resolve(value.func, aliases)
        return ({chain for chain in chains if chain in _FIXTURES}
                | {form for form in map(_form_of, chains) if form in _DECORATOR_FACTORIES})
    return {alias for alias in map(_aliasable, _resolve(value, aliases)) if alias is not None}


def _bind(aliases: _Aliases, name: str, chain: _Chain) -> None:
    alias = _aliasable(chain)
    if alias is not None:
        aliases.setdefault(name, set()).add(alias)


def _star_names(module: Tuple[str, ...]) -> Dict[str, Tuple[str, ...]]:
    """What ``from <module> import *`` binds among the known names: each one that
    starts a skip form or fixture decorator under ``module``."""
    depth = len(module)
    return {chain[depth]: chain[:depth + 1] for chain in _FORMS + tuple(_FIXTURES)
            if len(chain) > depth and chain[:depth] == module}


def _aliases(tree: ast.AST) -> _Aliases:
    """Names bound, anywhere in the module, to pytest, unittest, os, a part of a skip
    form, a skip decorator or pytest.fixture: by import (a star import of those
    modules binds each such name), or by assignment followed to a fixed point. Every
    binding is kept, whatever the order or the branch it is in."""
    aliases: _Aliases = {}
    assigned: List[Tuple[str, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:  # without one, the name bound is the module itself
                    _bind(aliases, alias.asname, _canonical(tuple(alias.name.split("."))))
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            module = _canonical(tuple(node.module.split(".")))
            for alias in node.names:
                if alias.name == "*":
                    for name, chain in _star_names(module).items():
                        _bind(aliases, name, chain)
                else:
                    _bind(aliases, alias.asname or alias.name, _canonical(module + (alias.name,)))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            assigned.extend((target.id, node.value) for target in targets if isinstance(target, ast.Name))
    # Each round adds a chain to some name or ends; the chains come from a finite set.
    while True:
        grown = False
        for name, value in assigned:
            new = _alias_values(value, aliases) - aliases.get(name, set())
            if new:
                aliases.setdefault(name, set()).update(new)
                grown = True
        if not grown:
            return aliases


def _shown(node: ast.AST) -> str:
    try:
        text = ast.unparse(node)
    except (RecursionError, ValueError, AttributeError):
        text = ast.dump(node)
    text = " ".join(text.split())
    if len(text) > 120:
        digest = hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()[:12]
        text = f"{text[:96]}... sha256:{digest}"
    return text


def _flat_targets(node: ast.AST) -> Iterator[ast.AST]:
    if isinstance(node, (ast.Tuple, ast.List)):
        for element in node.elts:
            yield from _flat_targets(element)
    elif isinstance(node, ast.Starred):
        yield from _flat_targets(node.value)
    else:
        yield node


class _FormCounter(ast.NodeVisitor):
    """Counts skip and xfail forms per scope (``Class::method``, ``<module>``)."""

    def __init__(self, aliases: _Aliases) -> None:
        self.aliases = aliases
        self.scope: List[Tuple[str, bool]] = []  # (name, is a class)
        # The blocks around the node being visited, outermost first, across scopes: a
        # decorator under a module-level ``if`` is guarded by it, and so is the body.
        self.guards: List[str] = []
        self.counts: Dict[Tuple[str, str], int] = {}

    def _add(self, form: str) -> None:
        # The guards are part of the occurrence, so removing or changing the condition
        # around an existing skip (``if win: pytest.skip()`` -> ``pytest.skip()``) is new.
        if self.guards:
            form = f"{form} under {' > '.join(self.guards)}"
        key = ("::".join(name for name, _ in self.scope) or "<module>", form)
        self.counts[key] = self.counts.get(key, 0) + 1

    def _under(self, guard: str, nodes: Sequence[ast.AST]) -> None:
        self.guards.append(guard)
        for node in nodes:
            self.visit(node)
        self.guards.pop()

    def _branches(self, word: str, test: ast.AST, body: Sequence[ast.AST], orelse: Sequence[ast.AST]) -> None:
        self.visit(test)
        shown = _shown(test)
        self._under(f"{word} {shown}", body)
        if orelse:
            self._under(f"else of {word} {shown}", orelse)

    def visit_If(self, node: ast.If) -> None:
        self._branches("if", node.test, node.body, node.orelse)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self._branches("if", node.test, [node.body], [node.orelse])

    def visit_While(self, node: ast.While) -> None:
        self._branches("while", node.test, node.body, node.orelse)

    def visit_For(self, node: Any) -> None:
        self.visit(node.target)
        self.visit(node.iter)
        loop = f"for {_shown(node.target)} in {_shown(node.iter)}"
        self._under(loop, node.body)
        if node.orelse:
            self._under(f"else of {loop}", node.orelse)

    visit_AsyncFor = visit_For

    def visit_Try(self, node: Any) -> None:
        self._under("try", node.body)
        for handler in node.handlers:
            if handler.type is not None:
                self.visit(handler.type)
            self._under("except" if handler.type is None else f"except {_shown(handler.type)}", handler.body)
        if node.orelse:
            self._under("else of try", node.orelse)
        if node.finalbody:
            self._under("finally", node.finalbody)

    visit_TryStar = visit_Try  # Python 3.11+

    def visit_With(self, node: Any) -> None:
        for item in node.items:
            self.visit(item)
        self._under("with " + ", ".join(_shown(item) for item in node.items), node.body)

    visit_AsyncWith = visit_With

    def visit_Match(self, node: Any) -> None:  # Python 3.10+
        self.visit(node.subject)
        subject = _shown(node.subject)
        for case in node.cases:
            if case.guard is not None:
                self.visit(case.guard)
            guard = "" if case.guard is None else f" if {_shown(case.guard)}"
            self._under(f"match {subject} case {_shown(case.pattern)}{guard}", case.body)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        # Each operand runs only after the ones before it: ``win or pytest.skip()``.
        word = "and" if isinstance(node.op, ast.And) else "or"
        depth = len(self.guards)
        for value in node.values:
            self.visit(value)
            self.guards.append(f"{_shown(value)} {word}")
        del self.guards[depth:]

    def _enter(self, node: Any, is_class: bool) -> None:
        self.scope.append((node.name, is_class))
        self.generic_visit(node)  # decorators count in the scope they decorate
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter(node, False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter(node, False)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._enter(node, True)

    def _marker(self, node: Any, targets: Sequence[ast.AST]) -> None:
        # pytestmark and __test__ act as names in a module or class body, and as
        # attributes of a test or class anywhere (test_x.__test__ = False); the whole
        # statement is the form, so any change to what it holds is a new occurrence.
        marker_level = not self.scope or self.scope[-1][1]
        for target in (t for whole in targets for t in _flat_targets(whole)):
            if (isinstance(target, ast.Attribute) and target.attr in _MARKERS) or (
                    marker_level and isinstance(target, ast.Name) and target.id in _MARKERS):
                self._add(_shown(node))
                return
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._marker(node, node.targets)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._marker(node, [node.target] if node.value is not None else [])

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._marker(node, [node.target])

    def _reference(self, node: ast.AST) -> Optional[str]:
        """The canonical form a name, attribute chain or callee refers to, or None."""
        form = _first_form(_resolve(node, self.aliases))
        if form is not None:
            return ".".join(form)
        return "skipTest" if isinstance(node, ast.Attribute) and node.attr == "skipTest" else None

    def _add_form(self, canonical: str, node: ast.AST) -> None:
        # The whole expression is the occurrence, so a weakened condition or another
        # reason is a new skip: skipif(sys.platform == "win32") -> skipif(True).
        shown = _shown(node)
        self._add(canonical if shown == canonical else f"{canonical}: {shown}")

    def visit_Call(self, node: ast.Call) -> None:
        canonical = self._reference(node.func)
        if canonical is None:
            self.generic_visit(node)
            return
        self._add_form(canonical, node)
        for argument in [*node.args, *node.keywords]:
            self.visit(argument)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        canonical = self._reference(node) if isinstance(node.ctx, ast.Load) else None
        if canonical is None:
            self.generic_visit(node)
            return
        self._add_form(canonical, node)

    def visit_Name(self, node: ast.Name) -> None:
        canonical = self._reference(node) if isinstance(node.ctx, ast.Load) else None
        if canonical is not None:
            self._add_form(canonical, node)


def skip_forms(source: bytes) -> Dict[Tuple[str, str], int]:
    """How often each skip or xfail occurrence is in ``source``, by (scope, form): the
    scope is the enclosing ``Class::function`` chain or ``<module>``; the form is the
    canonical name (``pytest.mark.skipif``, ``unittest.SkipTest``, ``skipTest``), then
    ``: `` and the whole expression (the call, or the alias used) when that is spelled
    otherwise, or a whole ``pytestmark``/``__test__`` statement. Raises SyntaxError,
    ValueError or RecursionError for source that does not parse."""
    tree = ast.parse(source)
    counter = _FormCounter(_aliases(tree))
    counter.visit(tree)
    return counter.counts


def _watched(name: str) -> bool:
    return name in ("collect_ignore", "collect_ignore_glob") or name.startswith("pytest_")


def _names_in(stmt: ast.stmt) -> Iterator[str]:
    for node in ast.walk(stmt):
        if isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node.name
        elif isinstance(node, ast.alias):
            yield (node.asname or node.name).split(".")[0]


def collection_hooks(source: bytes, hooks_only: bool = False) -> Dict[str, Tuple[str, ...]]:
    """For a conftest: each watched name (``collect_ignore``, ``collect_ignore_glob``,
    any ``pytest_*`` hook or ``pytest_plugins``) mapped to the sorted AST dumps of the
    top-level statements that mention it, so formatting and comments do not count
    and any change to what they do does. With ``hooks_only`` (any other Python test
    file, which acts on collection only as a plugin), just its top-level ``pytest_*``
    function definitions. Raises like ``collected_ids``."""
    found: Dict[str, List[str]] = {}
    for stmt in ast.parse(source).body:
        if hooks_only:
            hook = isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name.startswith("pytest_")
            names = {stmt.name} if hook else set()  # type: ignore[union-attr]
        else:
            names = {name for name in _names_in(stmt) if _watched(name)}
        if names:
            dump = ast.dump(stmt)
            for name in names:
                found.setdefault(name, []).append(dump)
    return {name: tuple(sorted(dumps)) for name, dumps in found.items()}


# ── pytest's config files ────────────────────────────────────────────────────

_INI_SECTIONS = {"pytest.ini": "pytest", ".pytest.ini": "pytest", "tox.ini": "pytest", "setup.cfg": "tool:pytest"}


def pytest_settings(filename: str, data: bytes) -> Optional[Dict[str, str]]:
    """The pytest collection settings in a config file named ``filename``: None when the
    file holds no pytest configuration, else ``{"[section] key": value}`` for the
    COLLECTION_KEYS it sets (``{}`` for a configuration without them; a
    ``pytest.toml``, ``.pytest.toml``, ``pytest.ini`` or ``.pytest.ini`` is one even
    when empty, as pytest reads it). Values are compared as text: whitespace around ini
    lines and, in TOML, whitespace and comments outside strings do not count. Raises
    ValueError for a file that cannot be read."""
    text = bytes(data).decode("utf-8-sig")
    if filename == "pyproject.toml":
        return _toml_settings(text, _PYPROJECT_TABLES, always=False)
    if filename in ("pytest.toml", ".pytest.toml"):
        return _toml_settings(text, _PYTEST_TOML_TABLES, always=True)
    section = _INI_SECTIONS.get(filename)
    if section is None:
        raise ValueError(f"{filename} is not a pytest configuration file")
    # As pytest's own ini reader: no [DEFAULT] inheritance, case-sensitive keys, and a
    # duplicated section or key is an error (then the file is unreadable, a finding).
    parser = configparser.ConfigParser(interpolation=None, strict=True, default_section="\x00")
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise ValueError(f"not a valid ini file ({type(exc).__name__})") from None
    if not parser.has_section(section):
        return {} if filename in ("pytest.ini", ".pytest.ini") else None
    return {
        f"[{section}] {key}": "\n".join(line.strip() for line in parser.get(section, key).splitlines()
                                        if line.strip())
        for key in COLLECTION_KEYS if parser.has_option(section, key)
    }


_VIEW_SECTIONS = {"tox.ini": "pytest", "setup.cfg": "tool:pytest"}


def pytest_config_view(filename: str, data: bytes) -> Optional[Dict[str, str]]:
    """Everything pytest reads from ``pyproject.toml`` (``[tool.pytest]`` and its sub-tables,
    headers included: an empty ``[tool.pytest.ini_options]`` still makes it the config file),
    ``tox.ini`` (``[pytest]``) or ``setup.cfg`` (``[tool:pytest]``), with the parsers of
    ``pytest_settings`` and every key, not only COLLECTION_KEYS. None when the file holds no
    pytest configuration; ValueError when it cannot be read (or is not one of the three)."""
    text = bytes(data).decode("utf-8-sig")
    if filename == "pyproject.toml":
        root = ("tool", "pytest")
        found: Dict[str, str] = {}
        table: Tuple[str, ...] = ()
        for is_table, key, value in _toml_statements(text):
            full = key if is_table else table + key
            if is_table:
                table = key
            # A header counts from tool.pytest down; a value also above it (``tool = {...}``),
            # whatever the inline table's keys look like.
            if _key_may_be(full, root) if is_table else _keys_may_meet(full, root):
                name = f"[{'.'.join(full)}]" if is_table else ".".join(full)
                # A key or array-table header seen twice keeps both, so neither copy can change unseen.
                found[name] = value if name not in found else f"{found[name]}\0{value}"
        return found or None
    section = _VIEW_SECTIONS.get(filename)
    if section is None:
        raise ValueError(f"{filename} is not compared by its pytest section")
    parser = configparser.ConfigParser(interpolation=None, strict=True, default_section="\x00")
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise ValueError(f"not a valid ini file ({type(exc).__name__})") from None
    if not parser.has_section(section):
        return None
    return {
        key: "\n".join(line.strip() for line in parser.get(section, key).splitlines() if line.strip())
        for key in parser.options(section)
    }


# The tables pytest reads settings from, the last being the root of its configuration.
_PYPROJECT_TABLES = (("tool", "pytest", "ini_options"), ("tool", "pytest"))
_PYTEST_TOML_TABLES = (("pytest",),)
_TOML_BARE = re.compile(r"[A-Za-z0-9_-]+")


class _EscapedKey(str):
    """A quoted TOML key part spelled with a backslash escape, kept as written. What it decodes
    to is not trusted (TOML and JSON differ on ``\\U``, ``\\x``, ``\\e`` and ``\\/``), so it may
    stand for any name: ``"py\\u0074est"`` is ``pytest`` to pytest."""


def _keys_may_meet(key: Tuple[str, ...], names: Tuple[str, ...]) -> bool:
    """Whether ``key`` may name ``names``, a table above it or a key below it."""
    return all(isinstance(part, _EscapedKey) or part == name for part, name in zip(key, names))


def _key_may_be(key: Tuple[str, ...], names: Tuple[str, ...]) -> bool:
    """Whether ``key`` may name ``names`` or a key below it."""
    return len(key) >= len(names) and _keys_may_meet(key, names)


def _toml_settings(text: str, tables: Tuple[Tuple[str, ...], ...], always: bool) -> Optional[Dict[str, str]]:
    root = tables[-1]
    holders = {watched[:i] for watched in tables for i in range(1, len(watched) + 1)}
    found: Dict[str, str] = {}
    present = always
    table: Tuple[str, ...] = ()
    for is_table, key, value in _toml_statements(text):
        if is_table:
            table = key
            present = present or _key_may_be(key, root)
            continue
        full = table + key
        present = present or _key_may_be(full, root)
        for watched in tables:
            if (len(full) == len(watched) + 1 and _keys_may_meet(full, watched)
                    and (full[-1] in COLLECTION_KEYS or isinstance(full[-1], _EscapedKey))):
                found[f"[{'.'.join(watched)}] {full[-1]}"] = value
        # An inline table that holds the pytest tables: kept whole, so any change counts. Above the
        # root (``tool = {...}``) too, whatever it mentions: its keys may be escaped.
        if value.startswith("{") and any(len(full) == len(h) and _keys_may_meet(full, h) for h in holders):
            present = True
            found[f"{'.'.join(full)} (inline table)"] = value
    return found if present else None


def _toml_skip(text: str, i: int, newlines: bool) -> int:
    """Past spaces, tabs and comments (and newlines when ``newlines``)."""
    while i < len(text):
        char = text[i]
        if char == "#":
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        elif char in " \t" or (newlines and char in "\r\n"):
            i += 1
        else:
            break
    return i


def _toml_line_end(text: str, i: int) -> int:
    i = _toml_skip(text, i, newlines=False)
    if i < len(text) and text[i] == "\r":
        i += 1
    if i < len(text) and text[i] != "\n":
        raise ValueError("unexpected text after a TOML statement")
    return i + 1


def _toml_string_end(text: str, i: int) -> int:
    quote = text[i]
    if text.startswith(quote * 3, i):
        j = i + 3
        while True:
            k = text.find(quote * 3, j)
            if k < 0:
                raise ValueError("unterminated multi-line TOML string")
            backslashes = len(text[j:k]) - len(text[j:k].rstrip("\\"))
            if quote == '"' and backslashes % 2:
                j = k + 1
                continue
            end = k + 3
            while end < len(text) and text[end] == quote and end - k < 5:  # up to two quotes of content
                end += 1
            return end
    j = i + 1
    while j < len(text) and text[j] != "\n":
        if quote == '"' and text[j] == "\\":
            j += 2
            continue
        if text[j] == quote:
            return j + 1
        j += 1
    raise ValueError("unterminated TOML string")


def _toml_key(text: str, i: int, stop: str) -> Tuple[Tuple[str, ...], int]:
    parts: List[str] = []
    while True:
        i = _toml_skip(text, i, newlines=False)
        if i < len(text) and text[i] in "\"'":
            end = _toml_string_end(text, i)
            raw = text[i:end]
            parts.append(_EscapedKey(raw) if raw[0] == '"' and "\\" in raw else raw[1:-1])
            i = end
        else:
            bare = _TOML_BARE.match(text, i)
            if bare is None:
                raise ValueError("invalid TOML key")
            parts.append(bare.group())
            i = bare.end()
        i = _toml_skip(text, i, newlines=False)
        if i < len(text) and text[i] == ".":
            i += 1
        elif i < len(text) and text[i] == stop:
            return tuple(parts), i
        else:
            raise ValueError("invalid TOML key")


def _toml_value(text: str, i: int) -> Tuple[str, int]:
    """A value as text without whitespace and comments outside strings (arrays and
    inline tables may span lines), and the index of the end of its line."""
    out: List[str] = []
    depth = 0
    i = _toml_skip(text, i, newlines=False)
    while i < len(text):
        char = text[i]
        if char in "\"'":
            end = _toml_string_end(text, i)
            out.append(text[i:end])
            i = end
            continue
        if char == "#":
            i = _toml_skip(text, i, newlines=False)
            continue
        if char == "\n" and depth == 0:
            break
        if char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced brackets in a TOML value")
        if not char.isspace():
            out.append(char)
        i += 1
    if depth:
        raise ValueError("unterminated TOML array or inline table")
    if not out:
        raise ValueError("a TOML key without a value")
    return "".join(out), i


def _toml_statements(text: str) -> Iterator[Tuple[bool, Tuple[str, ...], str]]:
    """(is a table header, dotted key, value text) for each statement of a TOML file."""
    i = 0
    while True:
        i = _toml_skip(text, i, newlines=True)
        if i >= len(text):
            return
        if text[i] == "[":
            close = "]]" if text.startswith("[[", i) else "]"
            key, i = _toml_key(text, i + len(close), "]")
            if not text.startswith(close, i):
                raise ValueError("unterminated TOML table header")
            i = _toml_line_end(text, i + len(close))
            yield True, key, ""
        else:
            key, i = _toml_key(text, i, "=")
            value, i = _toml_value(text, i + 1)
            i = _toml_line_end(text, i)
            yield False, key, value
