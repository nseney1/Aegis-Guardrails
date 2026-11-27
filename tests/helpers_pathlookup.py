"""Clean-host marker model and source guards shared by pathlookup tests.

The trust boundary is this helper's first import. The import-time snapshot below
is the baseline; writes before it are outside this guard's scope and belong to
the opt-in global guard in tests/conftest.py. The static import-order check keeps
guarded consumers behind this boundary, and keeps this helper's bootstrap limited
to imports and the read-only snapshot before other helper code can run.

The two guarded files use closed collection grammars. Pytest marks and fixtures
are direct decorators; arguments are literals, builtin exception names, literal
platform comparisons, or the reviewed os/sys capability and path expressions
below, combined only through not/and/or and tuple/list containers. Mark methods,
callbacks and argument expansion are refused. The only other decorators are
contextmanager and contextlib.contextmanager. A literal-argument mark assigned
to pytestmark is the reviewed module/class-marker form.
Module and class bodies contain only imports, definitions, literal assignments
to names and docstrings, plus exact reviewed helper initializers, the platform
EXE assignment and class-local visit_* method aliases. Collection hooks remain
forbidden. Ordinary collection classes use standard bases without metaclasses;
factory and grammar names retain their canonical bindings. Checks run at import,
so skip and deselection cannot bypass them. Deferred function bodies retain the
runtime guard, and fixture references outside direct decorators are refused.
Every broader-scope fixture must declare governed_module_session as a required
parameter. The exact reviewed session-check fixture is the dependency root and
cannot depend on itself. Runtime finalizer ordering is not extended further.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
import os
from types import SimpleNamespace

import pytest

class _ModuleSnapshot:
    """Retain original identities without displaying module values in errors."""

    def __init__(self, module):
        self.module = module
        self.label = module.__name__
        self.kind = type(module)
        self.attributes = dict(vars(module))


from aegis_core import gitsafe, pathlookup, primitives
_GOVERNED_BASELINE = tuple(_ModuleSnapshot(module) for module in (pathlookup, gitsafe, primitives))

from collections import deque
from pathlib import Path

__all__ = ["clean_host_os", "governed_module_session", "governed_module_state", "monkeypatch",
           "owned_module_patch", "pathlookup_import_order", "pathlookup_patch_writes",
           "pathlookup_source_contract_errors"]

_OWNED_CONTEXTS = []
_ABSENT = object()


def _assert_module_state(snapshots, *, allow_owned=True):
    changes = []
    for saved in snapshots:
        current = dict(vars(saved.module))
        expected = dict(saved.attributes)
        for context in _OWNED_CONTEXTS if allow_owned else ():
            for (module, name), value in context.attributes.items():
                if module is saved.module:
                    if value is _ABSENT:
                        expected.pop(name, None)
                    else:
                        expected[name] = value
        # Interpreter-managed warning bookkeeping is created by warnings.warn for any caller.
        current.pop("__warningregistry__", None)
        expected.pop("__warningregistry__", None)
        for name in sorted(current.keys() - expected.keys()):
            changes.append(f"{saved.label}.{name} added")
        for name in sorted(expected.keys() - current.keys()):
            changes.append(f"{saved.label}.{name} removed")
        for name in sorted(expected.keys() & current.keys()):
            if expected[name] is not current[name]:
                changes.append(f"{saved.label}.{name} replaced")
        if type(saved.module) is not saved.kind:
            changes.append(f"{saved.label}.__class__ replaced")
    assert not changes, "unrestored governed module attributes: " + "; ".join(changes)


@pytest.fixture(scope="session", autouse=True)
def governed_module_session():
    """Run the last comparison after every module/class finalizer and owned undo."""
    yield
    _assert_module_state(_GOVERNED_BASELINE, allow_owned=False)
    assert not _OWNED_CONTEXTS, "owned governed module patch contexts left open"


@pytest.fixture(autouse=True)
def governed_module_state(governed_module_session):
    """Compare with the import-time baseline after the function patcher undoes."""
    yield
    _assert_module_state(_GOVERNED_BASELINE)


@pytest.fixture
def monkeypatch(governed_module_state):
    """Own the patch context inside the state-check fixture's lifetime."""
    with pytest.MonkeyPatch.context() as patcher:
        yield patcher


class _OwnedModulePatch:
    """Record bindings under nested-with ownership, never a module exemption.

    An outer handle cannot write a binding owned by a newer live context. That
    refusal precedes mutation; closing the inner context permits outer retry.
    Different bindings remain independent while contexts overlap.
    """

    def __init__(self, patcher, scope):
        self.patcher = patcher
        self.scope = scope
        self.attributes = {}

    def _check_target(self, module, name):
        if self not in _OWNED_CONTEXTS:
            raise RuntimeError("owned module patch context is closed")
        if not any(module is saved.module for saved in _GOVERNED_BASELINE):
            raise ValueError("owned module patches require a governed module")
        if not isinstance(name, str) or name in {"__class__", "__dict__"}:
            raise ValueError("owned module patches require a module namespace attribute")
        newer = False
        for context in _OWNED_CONTEXTS:
            if context is self:
                newer = True
            elif newer and (module, name) in context.attributes:
                raise ValueError("owned module patch cannot shadow a newer live context")

    def setattr(self, module, name, value):
        self._check_target(module, name)
        self.patcher.setattr(module, name, value)
        self.attributes[(module, name)] = value

    def delattr(self, module, name):
        self._check_target(module, name)
        self.patcher.delattr(module, name)
        self.attributes[(module, name)] = _ABSENT


@contextmanager
def owned_module_patch(request):
    """Own strict MonkeyPatch writes for a live broader-scope pytest fixture.

    The fixture request supplies the scope and starts the session check before
    the context, so its undo always precedes the session's final comparison.
    Only bindings written through this API are allowed during per-test checks.
    """
    if request.scope not in {"class", "module", "package", "session"}:
        raise ValueError("owned module patches require a broader-scope fixture")
    request.getfixturevalue("governed_module_session")
    owned = None
    try:
        with pytest.MonkeyPatch.context() as patcher:
            owned = _OwnedModulePatch(patcher, request.scope)
            _OWNED_CONTEXTS.append(owned)
            yield owned
    finally:
        if owned is not None:
            _OWNED_CONTEXTS.remove(owned)


def _bootstrap_statement(node):
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
        return isinstance(node.value.value, str)
    if isinstance(node, ast.Import):
        return all(alias.name in {"ast", "os", "pytest"} and alias.asname is None for alias in node.names)
    if isinstance(node, ast.ImportFrom):
        allowed = {"__future__": {"annotations"}, "contextlib": {"contextmanager"},
                   "types": {"SimpleNamespace"}}
        return (not node.level and node.module in allowed
                and all(alias.name in allowed[node.module] and alias.asname is None for alias in node.names))
    if isinstance(node, ast.ClassDef) and node.name == "_ModuleSnapshot":
        # This is the trusted bootstrap, so pin its entire read-only operation.
        # Checking just its name would allow a constructor write to become the
        # baseline before the ordinary runtime comparison can observe it.
        reviewed = ast.parse(
            'class _ModuleSnapshot:\n'
            '    """Retain original identities without displaying module values in errors."""\n'
            '    def __init__(self, module):\n'
            '        self.module = module\n'
            '        self.label = module.__name__\n'
            '        self.kind = type(module)\n'
            '        self.attributes = dict(vars(module))\n'
        ).body[0]
        return ast.dump(node) == ast.dump(reviewed)
    return False


def _pathlookup_source_trees(root):
    for relative in ("tests/unit/core/test_pathlookup.py", "tests/helpers_pathlookup.py"):
        path = root / relative
        yield relative, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def pathlookup_import_order(root):
    """Require consumer import first and an uninterrupted read-only bootstrap.

    Importing this helper starts its own boundary; it cannot import itself to
    establish it. Its sole governed import and snapshot must therefore be an
    adjacent bootstrap pair, preceded only by the reviewed snapshot declaration
    and standard-library/pytest imports. Every other helper statement follows.
    Tracked-source reads stay plain and cross-platform.
    """
    return _import_order_errors(_pathlookup_source_trees(root))


def _import_order_errors(sources):
    errors = []
    for relative, tree in sources:
        body = list(tree.body)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            body.pop(0)
        while body and isinstance(body[0], ast.ImportFrom) and body[0].module == "__future__":
            body.pop(0)
        if relative.endswith("test_pathlookup.py"):
            if not (body and isinstance(body[0], ast.ImportFrom) and not body[0].level
                    and body[0].module == "tests.helpers_pathlookup"
                    and {"governed_module_session", "governed_module_state", "monkeypatch"}
                    <= {alias.name for alias in body[0].names}):
                errors.append((relative, body[0].lineno if body else 1,
                               "helper import must be the first executable statement"))
            continue
        capture = ast.parse("_GOVERNED_BASELINE = tuple(_ModuleSnapshot(module) "
                            "for module in (pathlookup, gitsafe, primitives))").body[0]
        governed_import = ast.parse("from aegis_core import gitsafe, pathlookup, primitives").body[0]
        for index, node in enumerate(body):
            if ast.dump(node) == ast.dump(governed_import):
                if index + 1 >= len(body) or ast.dump(body[index + 1]) != ast.dump(capture):
                    errors.append((relative, node.lineno, "governed import must immediately capture the baseline"))
                break
            if not _bootstrap_statement(node):
                errors.append((relative, node.lineno, "helper bootstrap must precede executable code"))
                break
        else:
            errors.append((relative, 1, "helper import-time baseline is missing"))
    return errors


_REVIEWED_COLLECTION_STATEMENTS = (
    "_GOVERNED_BASELINE = tuple(_ModuleSnapshot(module) for module in (pathlookup, gitsafe, primitives))",
    "_ABSENT = object()",
    "_enforce_source_contract(Path(__file__).resolve().parents[1])",
)
_REVIEWED_COLLECTION_EXPRESSIONS = (
    # Existing helper default, matched by its exact AST shape.
    ("tests/helpers_pathlookup.py", "frozenset()"),
)
_REVIEWED_PLATFORM_ASSIGNMENT = "EXE = '.exe' if os.name == 'nt' else ''"
_BUILTIN_EXCEPTION_NAMES = (
    "BaseException", "Exception", "GeneratorExit", "KeyboardInterrupt", "SystemExit",
    "ArithmeticError", "AssertionError", "AttributeError", "BufferError", "EOFError",
    "ImportError", "LookupError", "MemoryError", "NameError", "OSError", "ReferenceError",
    "RuntimeError", "StopAsyncIteration", "StopIteration", "SyntaxError", "SystemError",
    "TypeError", "ValueError", "Warning", "FloatingPointError", "OverflowError", "ZeroDivisionError",
    "BytesWarning", "DeprecationWarning", "FutureWarning", "ImportWarning", "PendingDeprecationWarning",
    "ResourceWarning", "RuntimeWarning", "SyntaxWarning", "UnicodeWarning", "UserWarning",
    "BlockingIOError", "ChildProcessError", "ConnectionError", "FileExistsError", "FileNotFoundError",
    "InterruptedError", "IsADirectoryError", "NotADirectoryError", "PermissionError", "ProcessLookupError",
    "TimeoutError", "IndentationError", "IndexError", "KeyError", "ModuleNotFoundError",
    "NotImplementedError", "RecursionError", "UnboundLocalError", "UnicodeError", "BrokenPipeError",
    "ConnectionAbortedError", "ConnectionRefusedError", "ConnectionResetError", "TabError",
    "UnicodeDecodeError", "UnicodeEncodeError", "UnicodeTranslateError", "EnvironmentError", "IOError",
    "WindowsError", "EncodingWarning", "BaseExceptionGroup", "ExceptionGroup",
)
_REVIEWED_SESSION_ROOT = (
    '@pytest.fixture(scope="session", autouse=True)\n'
    'def governed_module_session():\n'
    '    """Run the last comparison after every module/class finalizer and owned undo."""\n'
    '    yield\n'
    '    _assert_module_state(_GOVERNED_BASELINE, allow_owned=False)\n'
    '    assert not _OWNED_CONTEXTS, "owned governed module patch contexts left open"\n'
)


def _source_nodes(tree, exempt):
    """Walk in breadth-first order and record the separate collection order.

    Collection visits decorators before signature expressions and excludes
    deferred bodies. Keep both orders so the first refusal never changes
    when two rules find different problems in the same source.
    """
    pending = deque([(tree, None, ())])
    while pending:
        node, parent, position = pending.popleft()
        yield node, parent, position
        children = ast.iter_child_nodes(node)
        if position is None:
            pending.extend((child, node, None) for child in children)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            evaluated = [node.args]
            if not isinstance(node, ast.Lambda):
                evaluated = [*node.decorator_list, node.args]
                if node.returns is not None:
                    evaluated.append(node.returns)
            positions = {child: (*position, index) for index, child in enumerate(evaluated)}
            pending.extend((child, node, positions.get(child)) for child in children)
        else:
            pending.extend((child, node, (*position, index) if child not in exempt else None)
                           for index, child in enumerate(children))


def _syntax_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _syntax_name(node.value)
        return owner + "." + node.attr if owner else ""
    return ""


def _collection_factory(node, pytest_names, fixture_names, context_names):
    name = _syntax_name(node)
    return (name in fixture_names | context_names
            or any(name == prefix + ".fixture" or (name.startswith(prefix + ".mark.")
                   and len(name.split(".")) == len(prefix.split(".")) + 2)
                   for prefix in pytest_names))


def _pytest_declaration_kind(node, pytest_names, fixture_names):
    name = _syntax_name(node)
    if name in fixture_names or name in {prefix + ".fixture" for prefix in pytest_names}:
        return "fixture"
    if name in {prefix + ".mark.parametrize" for prefix in pytest_names}:
        return "parametrize"
    return None


def _literal_value(node):
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_literal_value(value) for value in node.elts)
    if isinstance(node, ast.Dict):
        return all(key is not None and _literal_value(key) and _literal_value(value)
                   for key, value in zip(node.keys, node.values))
    return (isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub))
            and isinstance(node.operand, ast.Constant)
            and type(node.operand.value) in {int, float, complex})


def _string_value(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _decorator_argument(node):
    """The closed, read-only expression grammar approved in round 1l."""
    if _literal_value(node):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_decorator_argument(value) for value in node.elts)
    if isinstance(node, ast.Name):
        return node.id in _BUILTIN_EXCEPTION_NAMES
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _decorator_argument(node.operand)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
        return all(_decorator_argument(value) for value in node.values)
    if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
        other = node.comparators[0]
        return (_syntax_name(node.left) in {"os.name", "sys.platform"}
                and ((isinstance(node.ops[0], (ast.Eq, ast.NotEq)) and _string_value(other))
                     or (isinstance(node.ops[0], ast.In) and (_string_value(other)
                         or isinstance(other, (ast.Tuple, ast.List)) and all(_string_value(value) for value in other.elts)))))
    if not isinstance(node, ast.Call) or node.keywords:
        return False
    name = _syntax_name(node.func)
    if name == "os.path.join":
        return bool(node.args) and all(_string_value(value) for value in node.args)
    if name == "hasattr":
        return (len(node.args) == 2 and _syntax_name(node.args[0]) in {"os", "sys"}
                and _string_value(node.args[1]))
    return (name in {"os.path.isdir", "os.path.exists"} and len(node.args) == 1
            and _string_value(node.args[0]))


def _closed_body_statement(node, *, methods, reviewed, platform, pytest_names):
    if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return True
    if isinstance(node, ast.Expr) and _string_value(node.value):
        return True
    if ast.dump(node) in reviewed or ast.dump(node) == platform:
        return True
    if not isinstance(node, ast.Assign) or not all(isinstance(target, ast.Name) for target in node.targets):
        return False
    if _literal_value(node.value):
        return True
    if (methods is not None and len(node.targets) == 1 and node.targets[0].id.startswith("visit_")
            and isinstance(node.value, ast.Name) and node.value.id.startswith("visit_")
            and node.value.id in methods):
        return True
    return (len(node.targets) == 1 and node.targets[0].id == "pytestmark"
            and isinstance(node.value, ast.Call)
            and any(_syntax_name(node.value.func).startswith(prefix + ".mark.")
                    and len(_syntax_name(node.value.func).split(".")) == len(prefix.split(".")) + 2
                    for prefix in pytest_names)
            and all(_literal_value(value) for value in node.value.args)
            and all(keyword.arg is not None and _literal_value(keyword.value) for keyword in node.value.keywords))


def _proof_suite_disabling_mark(tree, pytest_names):
    """Protect the actual proof suite while allowing marked synthetic consumers."""
    anchors = {"test_pathlookup_child_proof_census_covers_every_rule",
               "test_additional_pathlookup_rules_in_child", "_CHILD_PROOF_TESTS"}
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)]
    if not (any(isinstance(node, ast.FunctionDef) and node.name in anchors for node in tree.body)
            or any(isinstance(target, ast.Name) and target.id in anchors
                   for node in assignments for target in node.targets)):
        return None
    disabling = {prefix + ".mark." + mark for prefix in pytest_names
                 for mark in ("skip", "skipif", "xfail", "parametrize")}
    return next((node for node in assignments if isinstance(node.value, ast.Call)
                 and _syntax_name(node.value.func) in disabling
                 and any(isinstance(target, ast.Name) and target.id == "pytestmark" for target in node.targets)),
                None)


def pathlookup_source_contract_errors(root):
    """Enforce the closed declaration/body grammars and fixture dependencies.

    Return the first refusal in each file. Exact helper initializer/root shapes
    and the reviewed platform assignment confer no broader exemption. Names used
    by the expression grammar keep their canonical bindings. Every scan owns its
    state and reads only the two named repository sources, including on retry.
    """
    return _source_contract_errors(_pathlookup_source_trees(root))


def _source_contract_errors(sources):
    errors = []
    reviewed = {ast.dump(ast.parse(source).body[0]) for source in _REVIEWED_COLLECTION_STATEMENTS}
    expressions = {(relative, ast.dump(ast.parse(source, mode="eval").body))
                   for relative, source in _REVIEWED_COLLECTION_EXPRESSIONS}
    session_root = ast.dump(ast.parse(_REVIEWED_SESSION_ROOT).body[0])
    for relative, tree in sources:
        start = len(errors)
        helper = relative == "tests/helpers_pathlookup.py"
        platform = None if helper else ast.dump(ast.parse(_REVIEWED_PLATFORM_ASSIGNMENT).body[0])
        exempt = {statement for statement in tree.body
                  if helper and isinstance(statement, (ast.Assign, ast.Expr)) and ast.dump(statement) in reviewed}
        pytest_names, fixture_names, context_names = {"pytest"}, {"fixture"}, {"contextmanager", "contextlib.contextmanager"}
        functions, definitions, assignments, references, collection = [], [], [], [], []
        for node, parent, position in _source_nodes(tree, exempt):
            if isinstance(node, ast.Import):
                pytest_names.update(alias.asname or alias.name for alias in node.names if alias.name == "pytest")
            elif isinstance(node, ast.ImportFrom) and node.module == "pytest":
                fixture_names.update(alias.asname or alias.name for alias in node.names if alias.name == "fixture")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                definitions.append(node)
                if not isinstance(node, ast.ClassDef):
                    functions.append(node)
            elif isinstance(node, ast.Assign) and isinstance(parent, (ast.Module, ast.ClassDef)):
                assignments.append(node)
            elif isinstance(node, (ast.Name, ast.Attribute)):
                references.append((node, parent))
            if position and isinstance(node, (ast.Import, ast.ImportFrom, ast.Name, ast.Attribute, ast.Call,
                                               ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                collection.append((position, node))
        reserved = (pytest_names | fixture_names | {name.split(".")[0] for name in context_names}
                    | set(_BUILTIN_EXCEPTION_NAMES)
                    | {"staticmethod", "classmethod", "property", "object", "ast", "os", "sys", "hasattr", "frozenset"})
        imports = {name: "pytest" for name in pytest_names}
        imports.update({name: "pytest.fixture" for name in fixture_names})
        imports.update({"ast": "ast", "os": "os", "sys": "sys", "contextlib": "contextlib",
                        "contextmanager": "contextlib.contextmanager"})
        imports.update({name: "builtins." + name for name in _BUILTIN_EXCEPTION_NAMES})
        imports.update({name: "builtins." + name for name in
                        ("staticmethod", "classmethod", "property", "object", "hasattr", "frozenset")})
        fixture_targets = {
            decorator.func if isinstance(decorator, ast.Call) else decorator
            for node in functions
            for decorator in node.decorator_list
            if _pytest_declaration_kind(decorator.func if isinstance(decorator, ast.Call) else decorator,
                                        pytest_names, fixture_names) == "fixture"
        }
        declaration_targets = {
            decorator.func if isinstance(decorator, ast.Call) else decorator
            for node in definitions
            for decorator in node.decorator_list
        }
        marker_calls = {
            node.value for node in assignments
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "pytestmark"
            and isinstance(node.value, ast.Call)
            and _closed_body_statement(node, methods=None, reviewed=set(), platform=None, pytest_names=pytest_names)
        }
        declaration_targets.update(node.func for node in marker_calls)
        for node in functions:
            if helper and node.name == "governed_module_session" and ast.dump(node) == session_root:
                continue
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                name = _syntax_name(target)
                if not (name in fixture_names or name in {prefix + ".fixture" for prefix in pytest_names}):
                    continue
                if isinstance(decorator, ast.Call) and (decorator.args or any(
                        keyword.arg is None for keyword in decorator.keywords)):
                    errors.append((relative, node.lineno, "fixture scope must be a literal supported pytest scope"))
                    continue
                scopes = [keyword.value for keyword in decorator.keywords if keyword.arg == "scope"] if isinstance(decorator, ast.Call) else []
                scope = scopes[0] if scopes else ast.Constant(value="function")
                if not isinstance(scope, ast.Constant) or scope.value not in {"function", "class", "module", "package", "session"}:
                    errors.append((relative, node.lineno, "fixture scope must be a literal supported pytest scope"))
                    continue
                positional = [*node.args.posonlyargs, *node.args.args]
                required = positional[:len(positional) - len(node.args.defaults)]
                required.extend(argument for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults) if default is None)
                if scope.value != "function" and "governed_module_session" not in {argument.arg for argument in required}:
                    errors.append((relative, node.lineno, "broader fixture must request governed_module_session"))
        for node in definitions:
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if not _collection_factory(target, pytest_names, fixture_names, context_names):
                    errors.append((relative, decorator.lineno, "collection-time decorator requires a reviewed factory"))
                elif isinstance(decorator, ast.Call) and _syntax_name(target) in context_names:
                    errors.append((relative, decorator.lineno, "contextmanager must directly decorate a definition"))
                elif isinstance(decorator, ast.Call) and (any(not _decorator_argument(value) for value in decorator.args)
                        or any(keyword.arg is None or not _decorator_argument(keyword.value) for keyword in decorator.keywords)):
                    kind = _pytest_declaration_kind(target, pytest_names, fixture_names)
                    values = [keyword.value for keyword in decorator.keywords if keyword.arg == "ids"]
                    if kind == "parametrize" and len(decorator.args) >= 4:
                        values.append(decorator.args[3])
                    if kind == "parametrize" and (any(isinstance(value, ast.Starred) for value in decorator.args)
                            or any(keyword.arg is None for keyword in decorator.keywords)):
                        message = "parametrize arguments must make ids explicit"
                    elif any(not _decorator_argument(value) for value in values):
                        message = "ids must use the reviewed decorator grammar"
                    else:
                        message = "decorator arguments must use the reviewed grammar"
                    errors.append((relative, decorator.lineno, message))
        for node, parent in references:
            if (isinstance(node.ctx, ast.Load)
                    and _pytest_declaration_kind(node, pytest_names, fixture_names) == "fixture"
                    and node not in fixture_targets):
                errors.append((relative, node.lineno, "fixture registration must decorate a function definition"))
            if isinstance(node, ast.Attribute) and any(_syntax_name(node).startswith(prefix + ".mark.") for prefix in pytest_names):
                if not isinstance(parent, ast.Attribute) and node not in declaration_targets:
                    errors.append((relative, node.lineno, "pytest marks require a direct reviewed decorator"))
        for _, node in sorted(collection, key=lambda entry: entry[0]):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    if isinstance(node, ast.Import):
                        bound = alias.asname or alias.name.split(".")[0]
                        origin = alias.name if alias.asname else alias.name.split(".")[0]
                    else:
                        bound = alias.asname or alias.name
                        origin = node.module + "." + alias.name if node.module and not node.level else ""
                    if bound.startswith("pytest_"):
                        errors.append((relative, node.lineno, "pytest_* collection hooks are forbidden"))
                        continue
                    if bound in imports and origin != imports[bound]:
                        errors.append((relative, node.lineno, "collection factory import must keep its standard binding"))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id.startswith("pytest_"):
                errors.append((relative, node.lineno, "pytest_* collection hooks are forbidden"))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in reserved:
                errors.append((relative, node.lineno, "collection factory binding cannot be replaced"))
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                errors.append((relative, node.lineno, "collection-time attribute write"))
            elif isinstance(node, ast.Call):
                if (relative, ast.dump(node)) in expressions:
                    continue
                name = _syntax_name(node.func)
                if name.rsplit(".", 1)[-1] in {"setattr", "delattr"}:
                    errors.append((relative, node.lineno, "collection-time attribute write"))
                elif not (_decorator_argument(node) or node in marker_calls
                          or node.func in declaration_targets and _collection_factory(node.func, pytest_names, fixture_names, context_names)):
                    errors.append((relative, node.lineno, "collection-time call requires a reviewed helper shape"))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name.startswith("pytest_"):
                    errors.append((relative, node.lineno, "pytest_* collection hooks are forbidden"))
                if node.name in reserved:
                    errors.append((relative, node.lineno, "collection factory binding cannot be replaced"))
                if isinstance(node, ast.ClassDef) and (node.keywords or any(
                        _syntax_name(base) not in ({"object", "ast.NodeVisitor"} if helper else {"object"})
                        for base in node.bases)):
                    errors.append((relative, node.lineno, "collection class requires a standard base without a metaclass"))
                for decorator in node.decorator_list:
                    target = decorator.func if isinstance(decorator, ast.Call) else decorator
                    if not _collection_factory(target, pytest_names, fixture_names, context_names):
                        errors.append((relative, decorator.lineno, "collection-time decorator requires a reviewed factory"))
        if len(errors) == start:
            scopes = [tree, *(node for node in definitions if isinstance(node, ast.ClassDef))]
            for scope in scopes:
                methods = {node.name for node in scope.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))} if isinstance(scope, ast.ClassDef) else None
                for node in scope.body:
                    if not _closed_body_statement(node, methods=methods,
                            reviewed=reviewed if helper and scope is tree else set(),
                            platform=platform if scope is tree else None, pytest_names=pytest_names):
                        errors.append((relative, node.lineno, "collection body statement is outside the reviewed grammar"))
        if not helper and len(errors) == start:
            mark = _proof_suite_disabling_mark(tree, pytest_names)
            if mark is not None:
                errors.append((relative, mark.lineno, "pathlookup proof suite cannot use a disabling module mark"))
        errors[start:] = errors[start:start + 1]
    return errors


def _enforce_source_contract(root):
    sources = tuple(_pathlookup_source_trees(root))
    errors = _import_order_errors(sources) + _source_contract_errors(sources)
    assert not errors, "pathlookup source contract: " + repr(errors)


class _ImportBindings(ast.NodeVisitor):
    """Collect possible lexical bindings without entering child scopes."""

    def __init__(self):
        self.names = {}

    def bind(self, name, value):
        self.names.setdefault(name, set()).add(value)

    def visit_Import(self, node):
        for alias in node.names:
            self.bind(alias.asname or alias.name.split(".")[0],
                      alias.name if alias.asname else alias.name.split(".")[0])

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.bind(alias.asname or alias.name,
                      node.module + "." + alias.name if node.module and not node.level else None)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bind(node.id, None)

    def visit_Assign(self, node):
        if isinstance(node.value, (ast.Name, ast.Attribute)):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.bind(target.id, node.value)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.bind(node.name, None)

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef

    def visit_Lambda(self, node):
        pass


class _ModuleWrites(ast.NodeVisitor):
    """Resolve ordinary imports and simple aliases conservatively by scope."""

    def __init__(self, relative):
        self.relative = relative
        self.scopes = []
        self.writes = []

    def qualified(self, node, scopes, seen=frozenset()):
        if isinstance(node, ast.Attribute):
            return {name + "." + node.attr for name in self.qualified(node.value, scopes, seen)}
        if not isinstance(node, ast.Name):
            return set()
        for index in reversed(range(len(scopes))):
            bindings, _ = scopes[index]
            if node.id not in bindings:
                continue
            key = (index, node.id)
            if key in seen:
                return set()
            names = set()
            for value in bindings[node.id]:
                if isinstance(value, str):
                    names.add(value)
                elif isinstance(value, (ast.Name, ast.Attribute)):
                    names.update(self.qualified(value, scopes[:index + 1], seen | {key}))
            return names
        return {node.id}

    def scope(self, body, arguments=None, class_scope=False):
        imports = _ImportBindings()
        if arguments is not None:
            for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs,
                             arguments.vararg, arguments.kwarg):
                if argument is not None:
                    imports.bind(argument.arg, None)
        for statement in body:
            imports.visit(statement)
        previous = self.scopes
        # Methods close over enclosing functions and modules, not class locals.
        parents = [entry for entry in previous if not entry[1]] if arguments is not None else previous
        self.scopes = [*parents, (imports.names, class_scope)]
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self.scopes = previous

    def visit_Module(self, node):
        self.scope(node.body)

    def visit_FunctionDef(self, node):
        self.scope(node.body, node.args)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.scope(node.body, class_scope=True)

    def visit_Lambda(self, node):
        self.scope([node.body], node.args)

    def visit_Attribute(self, node):
        modules = {"aegis_core.pathlookup", "aegis_core.gitsafe", "aegis_core.primitives"}
        if isinstance(node.ctx, (ast.Store, ast.Del)) and self.qualified(node.value, self.scopes) & modules:
            self.writes.append((self.relative, node.lineno, ast.unparse(node)))
        self.generic_visit(node)


def pathlookup_patch_writes(root):
    """Check both tracked test sources; missing or malformed input fails loudly.

    Honest imports, qualified module references, and simple name aliases are
    resolved by lexical scope. Computed namespace mutation is outside this guard.
    Each invocation owns its visitor state, including on failure and retry.
    """
    writes = []
    for relative, tree in _pathlookup_source_trees(root):
        visitor = _ModuleWrites(relative)
        visitor.visit(tree)
        writes.extend(visitor.writes)
    return writes


def clean_host_os(root):
    """Copy the consumer's OS view, hiding only Git markers outside ``root``.

    Callers install the result with monkeypatch on pathlookup.os. Shared OS
    functions remain untouched, and capability probes retain their real names.
    """
    original = pathlookup.os
    base = os.path.normcase(os.path.realpath(root))

    def inside(path):
        key = os.path.normcase(os.path.realpath(path))
        return key == base or key.startswith(base.rstrip(os.sep) + os.sep)

    def lexists(path):
        if os.path.basename(path) == ".git" and not inside(os.path.dirname(path)):
            return False
        return original.path.lexists(path)

    def stat(path, *args, **kwargs):
        parent = kwargs.get("dir_fd")
        if path == ".git" and parent is not None:
            if not inside(pathlookup._fd_location(parent)):
                raise FileNotFoundError(2, "marker outside fixture model")
        elif os.path.basename(path) == ".git" and not inside(os.path.dirname(path)):
            raise FileNotFoundError(2, "marker outside fixture model")
        return original.stat(path, *args, **kwargs)

    return SimpleNamespace(**{**vars(original), "stat": stat,
        "path": SimpleNamespace(**{**vars(original.path), "lexists": lexists}),
        "supports_dir_fd": {stat if fn is original.stat else fn for fn in original.supports_dir_fd},
        "supports_follow_symlinks": {
            stat if fn is original.stat else fn for fn in original.supports_follow_symlinks}})


_enforce_source_contract(Path(__file__).resolve().parents[1])
