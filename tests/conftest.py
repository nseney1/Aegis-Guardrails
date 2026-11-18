"""Shared fixtures for the Soma regression suite.

The suite deliberately avoids requiring pyyaml: several invariants under test
exist precisely because `soma_mcp/` must work on a bare interpreter.

The temporary-directory guard refuses before initialization if any spelling it
can derive contains the path separator. This deliberately includes false refusals
when an alternative symlink interpretation is unsafe but pytest would use a safe
path. A path changing between the check and pytest's initialization is outside
this guard's scope; RF-88 covers the controller entry point.

Known Windows audit gaps, deferred by the owner to the end-of-build platform
pass: _winapi.CreateFile write/create dispositions, _winapi.CreateJunction,
winreg.SaveKey, and O_TEMPORARY delete-on-close opens. These families are not
claimed as covered by this census.

While a census session is active, implicit interpreter/pytest bytecode cache
creation is disabled. This avoids granting every importing product module write
authority for infrastructure artifacts. Explicit infrastructure writes remain
audited and owned by their innermost product caller. The prior cache policy is
restored when the outermost session ends.

The runtime patch guard is opt-in with AEGIS_PATCH_GUARD=on and defaults to off.
Merge-gating full runs enable it through COORD-PATCH-GUARD-FULL. Trusted import
baselines persist across items; every retained namespace is checked per test.
It governs ordinary test patches and shared namespace assignments. Limits deferred
to RF-11f: test threads racing import/initializer authentication; crafted callbacks
inside authenticated bulk operations; shared objects reachable only through
conftest/plugin graphs and never registered or imported before items (only patch
undo is checked); conftest/plugin hooks before the session baseline or during
collection. Those hooks are reviewed test infrastructure.
Container-held conftest helpers later aliased into sys.modules are deferred to RF-11f.
Registered framework-owned mutable bindings are not guarded, regardless
of their writer. RF-11f covers broader exceptions; callbacks grant no authority.
"""
import ast
import copy
import dis
import __future__ as _guard_future
from collections import Counter, namedtuple
from contextvars import ContextVar
from datetime import datetime as _guard_datetime
import hashlib
from functools import partial
from importlib import import_module
from importlib import metadata as _guard_metadata
from importlib.machinery import BuiltinImporter, FrozenImporter, PathFinder
from inspect import (CO_ASYNC_GENERATOR, CO_COROUTINE, CO_GENERATOR, Parameter,
                     getclosurevars, getattr_static, signature)
import mmap
import os
from operator import is_
from pathlib import Path
import pkgutil
import shutil
import socket
import subprocess
import sys
import sysconfig
import tempfile
from threading import RLock
from time import process_time_ns
from weakref import WeakKeyDictionary, ref
from types import (CodeType, FunctionType, GetSetDescriptorType, MappingProxyType,
                   MemberDescriptorType, ModuleType, MethodType, GeneratorType,
                   BuiltinMethodType)

import pytest

_PYTEST_API_ERROR = (
    "pytest runtime guard API is unsupported; install a compatible pytest/Python "
    "or update tests/conftest.py for the installed runtime"
)


def _patch_monkeypatch_defaults(monkeypatch_type):
    """Read public call defaults, preserving distinct setter/deleter sentinels."""
    setter = signature(getattr_static(monkeypatch_type, "setattr"))
    deleter = signature(getattr_static(monkeypatch_type, "delattr"))
    value_default = setter.parameters["value"].default
    name_default = deleter.parameters["name"].default
    if value_default is Parameter.empty or name_default is Parameter.empty:
        raise ValueError
    setter.bind(None, object(), "attribute", object(), True)
    setter.bind(None, "module.attribute", object(), raising=True)
    deleter.bind(None, object(), "attribute", True)
    deleter.bind(None, "module.attribute", raising=True)
    signature(getattr_static(monkeypatch_type, "setitem")).bind(None, {}, "key", object())
    signature(getattr_static(monkeypatch_type, "delitem")).bind(None, {}, "key", True)
    return value_default, name_default


def _patch_pytest_api():
    """Refuse unsupported private surfaces before pytest starts collection."""
    try:
        monkeypatch_api = import_module("_pytest.monkeypatch")
        mock_api = import_module("unittest.mock")
        derive = getattr(monkeypatch_api, "derive_importpath")
        annotated = getattr(monkeypatch_api, "annotated_getattr")
        _patch_monkeypatch_defaults(pytest.MonkeyPatch)
        fixture_value = signature(getattr_static(pytest.FixtureRequest, "getfixturevalue"))
        fixture_value.bind(None, "fixture")
        fixture_value.bind(None, argname="fixture")
        selected_fixture = signature(getattr_static(pytest.FixtureRequest, "_get_active_fixturedef"))
        selected_fixture.bind(None, "fixture")
        selected_fixture.bind(None, argname="fixture")
        signature(derive).bind("module.attribute", False)
        signature(annotated).bind(object(), "attribute", ann="module")
        # Other retained private surfaces belong to the Python runtime, not
        # pytest. Check their callable entry points before installing wrappers.
        entries = (sys._getframe, tempfile._get_candidate_names,
                   mock_api._patch.__init__, mock_api._patch.__enter__,
                   mock_api._patch.copy, mock_api._patch_dict.__init__,
                   mock_api._patch_dict.decorate_class, mock_api._patch_dict._patch_dict,
                   mock_api._get_target)
        if not all(callable(entry) for entry in entries):
            raise TypeError
        signature(mock_api._get_target).bind("module.attribute")
    except (ImportError, AttributeError, KeyError, TypeError, ValueError, RuntimeError):
        raise pytest.UsageError(_PYTEST_API_ERROR) from None
    return derive, annotated, mock_api


def _census_pytest_api():
    """Only the pre-existing writer census's imports are needed when OFF."""
    try:
        assertion_api = import_module("_pytest.assertion.rewrite")
        tmpdir_api = import_module("_pytest.tmpdir")
        hook = getattr(assertion_api, "AssertionRewritingHook")
        rewrite = getattr(assertion_api, "rewrite_asserts")
        user = getattr(tmpdir_api, "get_user")
        signature(hook).bind(object())
        signature(rewrite).bind(ast.Module(body=[], type_ignores=[]), b"",
                                module_path="module.py", config=None)
        signature(user).bind()
    except (ImportError, AttributeError, KeyError, TypeError, ValueError, RuntimeError):
        raise pytest.UsageError(_PYTEST_API_ERROR) from None
    return hook, rewrite, user


AssertionRewritingHook, rewrite_asserts, get_user = _census_pytest_api()

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_CENSUS_PACKAGES = ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk", "tools")
_CENSUS_NATIVE_QUALNAMES = hasattr((lambda: None).__code__, "co_qualname")
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

_PATCH_TESTS_PATH_CHANGE = None
try:
    import tests
    if hasattr(tests, "__path__") and TESTS_DIR not in tests.__path__:
        previous_tests_path = tests.__path__
        tests.__path__ = [TESTS_DIR, *previous_tests_path]
        _PATCH_TESTS_PATH_CHANGE = tests, previous_tests_path, tests.__path__
except ImportError:
    pass


@pytest.fixture(autouse=True)
def _no_real_gh(monkeypatch):
    """The trust tier (``aegis doctor``) reads GitHub through the user's own gh. No test reaches
    the network or the developer's gh: without a stand-in the answer is "gh is not installed"
    (tier C). A test of tier detection or ``doctor --github`` installs its own fake runner. The stub
    has the real runner's signature; the fixture's value is the real runner."""
    from aegis_core import ghcli

    real = ghcli.default_gh_runner
    monkeypatch.setattr(ghcli, "default_gh_runner", lambda argv, stdin=None, cwd=None, timeout=None: None)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    return real


@pytest.fixture
def real_gh_runner(monkeypatch, _no_real_gh):
    """The real gh runner, for a test that puts a fake gh on PATH (or leaves none there):
    ``_no_real_gh_on_path`` still finds only a gh under pytest's temporary root."""
    from aegis_core import ghcli

    monkeypatch.setattr(ghcli, "default_gh_runner", _no_real_gh)
    return _no_real_gh


@pytest.fixture(autouse=True)
def _no_real_gh_on_path(monkeypatch, tmp_path_factory):
    """``aegis doctor --release`` finds gh itself (``pathlookup.which``). Runner images put gh
    beside git (/usr/bin), so a PATH built from git's directory still holds the real gh. Only a
    gh that a test placed under pytest's temporary root is ever found."""
    from aegis_core import pathlookup

    real_which = pathlookup.which
    root = os.path.realpath(str(tmp_path_factory.getbasetemp()))

    def which(name, *args, **kwargs):
        found = real_which(name, *args, **kwargs)
        if found and os.path.splitext(os.path.basename(str(name)))[0].lower() == "gh":
            if not os.path.realpath(found).startswith(root + os.sep):
                return None
        return found

    monkeypatch.setattr(pathlookup, "which", which)


@pytest.fixture(scope="session")
def repo_root():
    return REPO_ROOT


def _ceiling_path_spellings(candidate, child=None):
    """Yield the union of supplied, absolute and physical interpretations."""
    def variants(path):
        yield path
        absolute = Path(os.path.abspath(str(path)))
        yield absolute
        yield path.resolve(strict=False)
        yield absolute.resolve(strict=False)

    supplied = Path(candidate)
    yield from variants(supplied if child is None else supplied / child)
    if child is not None:
        for root in variants(supplied):
            yield root
            joined = root / child
            yield joined
            yield joined.resolve(strict=False)


def _validate_ceiling_path(candidate, child=None):
    """Refuse any derived spelling that cannot form a Git ceiling."""
    try:
        for path in _ceiling_path_spellings(candidate, child):
            if os.pathsep not in str(path):
                continue
            from aegis_cli import sanitize_display
            from aegis_core.redaction import redact_command_secrets

            displayed = redact_command_secrets(sanitize_display(path, max_len=None))[:512]
            raise pytest.UsageError(
                "choose --basetemp outside paths containing the path separator "
                + repr(os.pathsep) + ": " + displayed
            )
    except (OSError, RuntimeError, ValueError):
        raise pytest.UsageError("cannot resolve pytest temporary directory") from None


def _configure_basetemp(config):
    """Refuse unsafe derived spellings before pytest initializes basetemp.

    Recursive collection from an enclosing directory may not load this conftest
    in the controller. From the checkout, use this launcher for that case::

        python tests/conftest.py /outer -n 2 --basetemp /safe/run

    It registers this check before pytest starts, then forwards all pytest
    arguments and its exit code. Workers still discover fixtures normally.
    Plain ``python -m pytest /outer`` does not provide this early check.
    """
    candidate = config.option.basetemp
    if candidate is None:
        # _pytest/tmpdir.py: 8.3.4 lines 156-167; 9.1.1 lines 161-172.
        # Numbered children use the fixed pytest- prefix and digits only.
        temproot = os.environ.get("PYTEST_DEBUG_TEMPROOT") or tempfile.gettempdir()
        # Check both the named user directory and pytest's OSError fallback.
        children = dict.fromkeys(("pytest-of-" + (get_user() or "unknown"), "pytest-of-unknown"))
        for child in children:
            _validate_ceiling_path(temproot, child=child)
    else:
        _validate_ceiling_path(candidate)


_PATCH_GUARD_DEFAULT = "off"
_PATCH_PATH_CASE_INSENSITIVE = os.name == "nt"


def _patch_guard_enabled(config):
    if not hasattr(config, "_patch_guard_enabled"):
        state = os.environ.get("AEGIS_PATCH_GUARD", _PATCH_GUARD_DEFAULT)
        if len(state) > 3 or state not in ("on", "off"):
            raise pytest.UsageError("AEGIS_PATCH_GUARD must be on or off")
        config._patch_guard_enabled = state == "on" and not config.getoption("--no-patch-guard")
    return config._patch_guard_enabled


def pytest_configure(config):
    _configure_basetemp(config)
    policy = os.path.join(TESTS_DIR, "contract", "test_monkeypatch_raising.py")
    if (_patch_guard_enabled(config)
            and getattr(config, "_patch_guard", None) is None):
        guard = _PatchGuard(config, policy)
        config._patch_guard = guard
        config.pluginmanager.register(guard, "runtime-patch-guard")
    # Multiple plugin registrations may dispatch this hook for the same config.
    # Each config owns one state; nested pytest.main calls have separate configs.
    if getattr(config, "_write_census", None) is not None:
        return
    # Some ceiling-guard tests copy this conftest alone into a source-free
    # checkout. There are no local product frames to census in those fixtures.
    if not config.getoption("--no-write-census") and any(
            os.path.isdir(os.path.join(REPO_ROOT, name)) for name in _CENSUS_PACKAGES):
        # conftest can also be imported as tests.conftest. Audit hooks cannot be
        # removed, so keep one callable per interpreter, including pytest.main
        # re-entry. A disabled benchmark process installs no hook at all.
        census = getattr(sys, "_aegis_write_census", None)
        if census is None:
            census = _WriteCensusObserver()
            sys.addaudithook(census)
            sys._aegis_write_census = census
        state = _WriteCensus()
        shared = getattr(config, "workerinput", {}).get("_aegis_census_source_index")
        state.start(REPO_ROOT, shared)
        census.push(state)
        config._write_census = state
        config._write_census_observer = census


@pytest.hookimpl(trylast=True)
def pytest_sessionstart(session):
    guard = getattr(session.config, "_patch_guard", None)
    if guard is not None and not guard.started:
        guard._start_baselines()


def pytest_addoption(parser):
    parser.addoption("--no-write-census", action="store_true", default=False,
                     help="disable runtime writer governance for overhead measurement")
    parser.addoption("--no-patch-guard", action="store_true", default=False,
                     help="disable runtime patch governance for overhead measurement")


def _patch_path_key(path):
    """Policy comparisons use platform case rules; display paths stay intact."""
    if type(path) is not str:
        raise pytest.UsageError("runtime patch guard policy cannot be read")
    if _PATCH_PATH_CASE_INSENSITIVE:
        return os.path.normcase(path).replace("\\", "/").lower()
    return path.replace(os.sep, "/")


def _patch_display(value):
    from aegis_cli import sanitize_display
    from aegis_core.redaction import redact_command_secrets

    return redact_command_secrets(sanitize_display(value, max_len=None))[:512]


# Only these framework bindings are outside namespace governance.
_PATCH_FRAMEWORK_BINDINGS = MappingProxyType({
    ("concurrent.futures", "ProcessPoolExecutor"):
        "stdlib lazy export cached on first access",
    ("concurrent.futures", "ThreadPoolExecutor"):
        "stdlib lazy export cached on first access",
    ("hypothesis.core", "_hypothesis_global_random"):
        "Hypothesis installs its session RNG when executing the first generated test.",
    ("hypothesis.core", "running_under_pytest"):
        "Hypothesis publishes its pytest runner context before each test item.",
    ("hypothesis.internal.conjecture.data", "global_test_counter"):
        "Hypothesis increments this identifier for every generated example.",
    ("hypothesis.internal.conjecture.providers", "_sys_modules_len"):
        "Hypothesis invalidates its constant pool when the imported module count changes.",
    ("hypothesis.internal.conjecture.providers", "_local_constants"):
        "Hypothesis refreshes constants from newly imported modules during generated examples.",
    ("hypothesis.internal.conjecture.junkdrawer", "_gc_start"):
        "Hypothesis records the current GC interval start from its interpreter callback.",
    ("hypothesis.internal.conjecture.junkdrawer", "_gc_cumulative_time"):
        "Hypothesis accumulates GC duration from its interpreter callback.",
    ("hypothesis.strategies._internal.lazy", "unwrap_depth"):
        "Hypothesis tracks nested strategy unwrapping while resolving generated values.",
})


# Approved cache initializers run before the trusted baseline, not on observation.
_PATCH_LAZY_CACHES = MappingProxyType({
    ("aegis_core.verification.import_guard", "_STDLIB_MODULES"):
        ("is_stdlib", ("sys",)),
    ("aegis_cli.registry", "_DEFAULT_REGISTRY"):
        ("get_default_registry", ()),
})


def _patch_is_instance(value, expected):
    """Inspect actual types without invoking a proxy's __class__ property."""
    return issubclass(type(value), expected)


def _patch_nonlocals(function):
    """Read captured bindings without inspecting arbitrary builtin providers."""
    if (function.__closure__ is None or len(function.__code__.co_names) > 4096
            or len(function.__code__.co_freevars) > 4096):
        return ()
    probe = FunctionType(function.__code__, {"__builtins__": {}}, closure=function.__closure__)
    try:
        return tuple(getclosurevars(probe).nonlocals.values())
    except ValueError:
        return ()  # unresolved captures provide no additional provenance


def _patch_snapshot(namespace):
    """Retain references and keys without rebuilding a namespace dictionary."""
    return tuple(namespace), tuple(namespace.values())


def _patch_same_bindings(namespace, keys, values):
    """Cheap whole-namespace check; no user-defined value equality is called."""
    if len(namespace) != len(keys):
        return False
    try:
        return all(map(is_, map(namespace.__getitem__, keys), values))
    except KeyError:
        # A removed key, including a None-valued one, needs the detailed check.
        return False


def _patch_runtime_site(frame, caller):
    """Keep generated/helper instructions distinct under their calling test."""
    code = frame.f_code
    digest = hashlib.sha256(code.co_code)
    for value in (code.co_filename, code.co_name):
        for offset in range(0, len(value), 512):
            digest.update(value[offset:offset + 512].encode("utf-8", "backslashreplace"))
        digest.update(b"\0")
    return "runtime:%s:%s:%s:%s" % (
        digest.hexdigest(), code.co_firstlineno, frame.f_lasti,
        caller.f_lasti if caller is not None else 0)


class _PatchHookCode(ast.NodeTransformer):
    """Observe framework namespace stores without granting callback authority.

    Recompiled functions keep their real globals, defaults and captured bindings.
    Ordinary local/object stores retain Python's evaluation order and effects.
    """
    def __init__(self, helper, globals_names, occupied, class_name=None, namespace=None):
        self.helper = helper
        self.globals_names = globals_names
        self.occupied = occupied
        self.serial = 0
        self.class_name = class_name
        self.namespace = namespace or {}

    def mangle(self, name):
        if self.class_name and name.startswith("__") and not name.endswith("__"):
            prefix = self.class_name.lstrip("_")
            if prefix:
                return "_" + prefix + name
        return name

    def temporary(self):
        while True:
            self.serial += 1
            name = "_aegis_hook_value_%s" % self.serial
            if name not in self.occupied:
                self.occupied.add(name)
                return name

    def invoke(self, operation, *args, keywords=()):
        return ast.Call(ast.Name(self.helper, ast.Load()), [ast.Constant(operation), *args], list(keywords))

    @staticmethod
    def resumable(node):
        if isinstance(node, ast.AsyncFunctionDef):
            return True
        pending = list(node.body)
        while pending:
            child = pending.pop()
            if isinstance(child, (ast.Yield, ast.YieldFrom)):
                return True
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                pending.extend(ast.iter_child_nodes(child))
        return False

    def visit_FunctionDef(self, node):
        nested = hasattr(self, "root_function")
        if not nested:
            self.root_function = node
        previous = self.globals_names
        pending, names = list(node.body), set()
        while pending:
            child = pending.pop()
            if isinstance(child, ast.Global):
                names.update(child.names)
            elif not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                pending.extend(ast.iter_child_nodes(child))
        self.globals_names = names
        result = self.generic_visit(node)
        self.globals_names = previous
        # A function created inside a framework call may run much later, after
        # its creator has returned to Test code. Give that function its own
        # entry decision rather than inheriting the creator's plain dispatcher.
        # The root receives its entry in _hook_compile.
        if nested:
            node.args.kwonlyargs.append(ast.arg(self.helper))
            node.args.kw_defaults.append(ast.Name(self.helper, ast.Load()))
            insertion = int(bool(node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and type(node.body[0].value.value) is str))
            statement = ast.Assign([ast.Name(self.helper, ast.Store())],
                                   self.invoke("enter", ast.Constant(self.resumable(node))))
            node.body.insert(insertion, ast.copy_location(statement, node))
            created = ast.Expr(self.invoke("created", ast.Name(node.name, ast.Load())))
            return [result, ast.copy_location(created, node)]
        return result

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        previous, names = self.class_name, self.globals_names
        self.class_name, self.globals_names = node.name, set()
        result = self.generic_visit(node)
        self.class_name, self.globals_names = previous, names
        registration = ast.Expr(self.invoke("class", ast.Name(node.name, ast.Load())))
        return [result, ast.copy_location(registration, node)]

    def visit_Call(self, node):
        node = self.generic_visit(node)
        # These builtins inspect the calling frame. Leave their call frame
        # intact; their returned capabilities are still witnessed on stores.
        if isinstance(node.func, ast.Name):
            if node.func.id in {"globals", "locals", "vars", "eval", "super"}:
                return node
            if node.func.id == "exec" and len(node.args) < 2:
                return node
        if isinstance(node.func, ast.Attribute) and node.func.attr not in {
                "setattr", "delattr", "update", "clear", "pop", "popitem", "setdefault",
                "__setitem__", "__delitem__"}:
            return node
        if isinstance(node.func, ast.Name):
            known = self.namespace.get(node.func.id)
            if known is not None and known is not setattr and known is not delattr:
                return node
            if node.func.id in {"len", "isinstance", "issubclass", "getattr", "hasattr", "next",
                                "type", "str", "repr", "bool", "int", "tuple", "list", "dict",
                                "set", "frozenset", "iter", "enumerate", "zip", "range", "all", "any"}:
                return node
        return ast.copy_location(self.invoke("call", node.func, *node.args, keywords=node.keywords), node)

    @staticmethod
    def index(node):
        if isinstance(node, ast.Slice):
            return ast.Call(ast.Name("slice", ast.Load()),
                            [node.lower or ast.Constant(None), node.upper or ast.Constant(None),
                             node.step or ast.Constant(None)], [])
        return node

    def target(self, target):
        if isinstance(target, ast.Attribute):
            return "set", target.value, ast.Constant(self.mangle(target.attr))
        if isinstance(target, ast.Subscript):
            return "itemset", target.value, self.index(target.slice)
        if isinstance(target, ast.Name) and target.id in self.globals_names:
            return "itemset", ast.Call(ast.Name("globals", ast.Load()), [], []), ast.Constant(self.mangle(target.id))
        return None

    def visit_Assign(self, node):
        node = self.generic_visit(node)
        if not any(self._has_store(target) for target in node.targets):
            return node
        value = self.temporary()
        result = [ast.Assign([ast.Name(value, ast.Store())], node.value)]
        for target in node.targets:
            result.extend(self._assign(target, ast.Name(value, ast.Load())))
        return [ast.copy_location(statement, node) for statement in result]

    def _has_store(self, target):
        if isinstance(target, (ast.Tuple, ast.List)):
            return any(self._has_store(child) for child in target.elts)
        if isinstance(target, ast.Starred):
            return self._has_store(target.value)
        return self.target(target) is not None

    def _assign(self, target, value):
        if isinstance(target, (ast.Tuple, ast.List)):
            names = [self.temporary() for _ in target.elts]
            unpacked = [ast.Starred(ast.Name(name, ast.Store()), ast.Store())
                        if isinstance(child, ast.Starred) else ast.Name(name, ast.Store())
                        for child, name in zip(target.elts, names)]
            result = [ast.Assign([ast.Tuple(unpacked, ast.Store())], value)]
            for child, name in zip(target.elts, names):
                if isinstance(child, ast.Starred):
                    child = child.value
                result.extend(self._assign(child, ast.Name(name, ast.Load())))
            return result
        entry = self.target(target)
        return ([ast.Expr(self.invoke(*entry, value))] if entry
                else [ast.Assign([target], value)])

    def visit_AnnAssign(self, node):
        if node.value is None or self.target(node.target) is None:
            return self.generic_visit(node)
        return self.visit_Assign(ast.copy_location(ast.Assign([node.target], node.value), node))

    def visit_AugAssign(self, node):
        node = self.generic_visit(node)
        entry = self.target(node.target)
        if entry is None:
            return node
        operation, owner, key = entry
        owner_name, key_name, value_name = self.temporary(), self.temporary(), self.temporary()
        owner_ref, key_ref = ast.Name(owner_name, ast.Load()), ast.Name(key_name, ast.Load())
        read = (ast.Attribute(owner_ref, node.target.attr, ast.Load()) if operation == "set"
                else ast.Subscript(owner_ref, key_ref, ast.Load()))
        statements = [ast.Assign([ast.Name(owner_name, ast.Store())], owner),
                      ast.Assign([ast.Name(key_name, ast.Store())], key),
                      ast.Assign([ast.Name(value_name, ast.Store())], read),
                      ast.AugAssign(ast.Name(value_name, ast.Store()), node.op, node.value),
                      ast.Expr(self.invoke(operation, owner_ref, key_ref, ast.Name(value_name, ast.Load())))]
        return [ast.copy_location(statement, node) for statement in statements]

    def visit_Delete(self, node):
        node = self.generic_visit(node)
        result = []
        for target in node.targets:
            entry = self.target(target)
            if entry:
                operation, owner, key = entry
                result.append(ast.Expr(self.invoke("del" if operation == "set" else "itemdel", owner, key)))
            else:
                result.append(ast.Delete([target]))
        return [ast.copy_location(statement, node) for statement in result]


class _PatchGuard:
    """Check actual owners and namespace identities, independently of spelling.

    Counts are unique executed call sites, not parameter/loop invocation counts.
    Workers send sites, rather than totals, so controller merging is idempotent.
    Namespace comparisons use identity only: test objects never get to execute
    equality methods during verification. The guard restores leaked bindings
    after reporting them, so a failed test cannot silently contaminate its retry.
    """
    def _hook_created(self, function):
        # Functions created by a rewritten parent need the same public
        # signature preservation as functions instrumented in place.
        if self.closing:
            return
        if self.created_inspecting.get():
            return
        token = self.created_inspecting.set(True)
        try:
            if type(function) in (classmethod, staticmethod):
                function = function.__func__
            if type(function) is not FunctionType:
                return
            helper = self.hook_private_names.get(id(function.__code__))
            if helper is None:
                return
            visible = signature(function)
            if helper in visible.parameters:
                function.__signature__ = visible.replace(parameters=[
                    parameter for name, parameter in visible.parameters.items() if name != helper])

        finally:
            self.created_inspecting.reset(token)


    def _pending_binding(self, identity, key, value):
        return any(value is binding[1] for binding in self.active_bindings.get((identity, key), ()))

    def _module_map(self, operation="trusted", name=None, value=None):
        """One authority map; live registries only transport or repair imports.

        Before items, reviewed infrastructure seeds the trusted record. A loader
        receipt publishes into that record and the retained interpreter registry,
        even when its import used a temporary copy of sys.modules. Observed
        bindings never grant a module allowance.
        """
        if operation == "seed":
            self.modules = sys.modules
            self.module_bindings = self.modules.copy()
        elif operation == "current":
            current = getattr(sys, "modules", self.modules)
            return current if _patch_is_instance(current, dict) else self.modules
        elif operation == "restore":
            current = getattr(sys, "modules", self.missing)
            if current is not self.modules:
                sys.modules = self.modules
            return current
        elif operation == "publish":
            if self.started and not self._publication_allowed(name, value):
                return False
            self.module_bindings[name] = value
            self.modules[name] = value
            if (self.import_parent is not None
                    and name not in self.import_parent._module_map()):
                self.import_parent._module_map("publish", name, value)
        elif operation == "withdraw":
            if value is self.missing:
                self.module_bindings.pop(name, None)
            else:
                self.module_bindings[name] = value
        elif operation == "remove":
            previous = self.module_bindings.get(name, self.missing)
            self.module_bindings.pop(name, None)
            self.modules.pop(name, None)
            if (self.import_parent is not None and previous is not self.missing
                    and self.import_parent._module_map().get(name, self.import_parent.missing) is previous):
                self.import_parent._module_map("remove", name)
        elif operation == "capture":
            # Capture admitted written aliases only from authenticated module
            # initialization. These receipts contain canonical names, never a
            # second module-identity map or a test frame's mutable bindings.
            if self.module_bindings.get(name, self.missing) is not value:
                return
            entry = self.snapshots.get(id(value))
            if entry is None:
                return
            namespace = dict(zip(entry[2], entry[3]))
            filename = namespace.get("__file__")
            if type(filename) is not str or len(filename) > _CENSUS_ADDRESS_LIMIT:
                return
            for (path, target) in self.policy["BUILTIN_GLOBALS"]:
                if _patch_path_key(os.path.abspath(filename)) != _patch_path_key(os.path.join(REPO_ROOT, path)):
                    continue
                written = target.rsplit(".", 1)[0]
                owner = namespace.get(written, self.missing)
                if not _patch_is_instance(owner, ModuleType):
                    continue
                for canonical, module in self.module_bindings.items():
                    if type(canonical) is str and module is owner:
                        self.consumer_spellings.setdefault((_patch_path_key(path), written), canonical)
                        break
                else:
                    self._module_map("consumer", (path, written), owner)
        elif operation == "binding":
            canonical = self.consumer_spellings.get((_patch_path_key(name[0]), name[1]))
            if canonical is None:
                return self.missing
            return self.module_bindings.get(canonical, self.missing)
        elif operation == "imported":
            module = self.module_bindings.get(name, self.missing)
            entry = self.snapshots.get(id(module))
            if entry is not None and dict(zip(entry[2], entry[3])).get("__spec__") is not None:
                return module
            return self.missing
        elif operation in {"consumer", "fixture"}:
            name = _patch_path_key(name[0]), name[1]
            # A scoped subject receipt grants no canonical import name. Only
            # an authenticated initializer or fixture result supplies it.
            if (not _patch_is_instance(value, ModuleType)
                    or any(module is value for module in self.module_bindings.values())
                    or not any((_patch_path_key(path), target.rsplit(".", 1)[0]) == name
                               for path, target in self.policy["BUILTIN_GLOBALS"])):
                return
            self._baseline_module(value, name[1])
            owners = self.consumer_owners if operation == "consumer" else self.fixture_owners
            owners.setdefault(name, set()).add(id(value))
        elif operation == "owned":
            name = _patch_path_key(name[0]), name[1]
            entry = self.module_owners.get(id(value))
            return (entry is not None and entry[0] is value
                    and (id(value) in self.consumer_owners.get(name, ())
                         or id(value) in self.fixture_owners.get(name, ())))
        elif operation == "initializer":
            entry = self.snapshots.get(id(name))
            owner = self.module_owners.get(id(name))
            if entry is None or owner is None:
                return self.missing
            if dict(zip(entry[2], entry[3])).get("__loader__", self.missing) is not value:
                return self.missing
            # module_from_spec also retains file-loader namespaces that were
            # never cached. Their loader and label come from that receipt.
            for canonical, module in self.module_bindings.items():
                if type(canonical) is str and module is name:
                    return canonical
            return owner[1]
        elif operation == "namespace":
            self.metrics["namespace_searches"] += 1
            self.metrics["namespace_search_modules"] += len(self.module_bindings)
            for canonical, module in self.module_bindings.items():
                if (_patch_is_instance(module, ModuleType)
                        and ModuleType.__getattribute__(module, "__dict__") is name):
                    return module, canonical, name
            # Physical dictionary ownership grants only the patch's undo
            # check. An uncached object gains no trusted import name or alias.
            for module in self.namespace_referrers(name):
                if (_patch_is_instance(module, ModuleType)
                        and ModuleType.__getattribute__(module, "__dict__") is name):
                    return module, "<unregistered module>", name
            return None
        return self.module_bindings


    def __init__(self, config, policy):
        started = process_time_ns()
        self.config = config
        self.missing = object()
        self._module_map("seed")
        required = {"PROCESS_MODULES", "PROCESS_PATCH_LIMITS", "PLATFORM_ABSENT",
                    "BUILTIN_GLOBALS", "LEASED_SITES"}
        self.policy = {}
        try:
            tree = _census_source(policy)
            for node in tree.body:
                if _patch_is_instance(node, ast.Assign):
                    for target in node.targets:
                        if _patch_is_instance(target, ast.Name) and target.id in required:
                            self.policy[target.id] = ast.literal_eval(node.value)
        except (OSError, SyntaxError, TypeError, ValueError, RecursionError):
            raise pytest.UsageError("runtime patch guard policy cannot be read") from None
        if self.policy.keys() != required:
            raise pytest.UsageError("runtime patch guard policy is incomplete")
        try:
            self.policy = MappingProxyType({
                name: frozenset(value) if name == "PROCESS_MODULES" else MappingProxyType(value)
                for name, value in self.policy.items()
            })
            self.platform_targets = tuple(tuple(name.rsplit(".", 1))
                                          for name in self.policy["PLATFORM_ABSENT"])
            if any(len(parts) != 2 or not all(parts) for parts in self.platform_targets):
                raise ValueError
            limits = {}
            for path, limit in self.policy["PROCESS_PATCH_LIMITS"].items():
                if type(limit) is not int or limit < 0:
                    raise ValueError
                key = _patch_path_key(path)
                limits[key] = min(limits.get(key, limit), limit)
            self.patch_limits = MappingProxyType(limits)
        except (AttributeError, TypeError, ValueError):
            raise pytest.UsageError("runtime patch guard policy cannot be read") from None
        self.derive_importpath, self.annotated_getattr, self.mock = _patch_pytest_api()
        try:
            self.collect_file_type = getattr_static(import_module("_pytest.nodes"), "File")
            if not _patch_is_instance(self.collect_file_type, type):
                raise TypeError
        except (ImportError, AttributeError, TypeError, ValueError, RuntimeError):
            raise pytest.UsageError(_PYTEST_API_ERROR) from None
        for (module_name, _), (initializer, arguments) in _PATCH_LAZY_CACHES.items():
            module = import_module(module_name)
            getattr(module, initializer)(*arguments)
        self.hypothesis_categories = None
        if "_hypothesis_pytestplugin" in self._module_map():
            # Loading the enabled plugin's library finishes its initialization
            # counter and resolves the storage path without creating storage.
            import_module("hypothesis.configuration").storage_directory(intent_to_write=False)
            import_module("hypothesis.internal.conjecture.junkdrawer").gc_cumulative_time()
            self.hypothesis_categories = import_module("hypothesis.internal.charmap").categories
        # tempfile is infrastructure shared by pytest and the test harnesses.
        # Initialize its lazy directory and name generator before baselines;
        # every binding is still compared exactly after each test.
        tempfile.gettempdir()
        tempfile._get_candidate_names()
        sysconfig.get_config_vars()
        # _strptime initializes time's timezone bindings on its first import.
        # Warm that stdlib state once; later rebinding remains a leak.
        _guard_datetime.strptime("2000-01-01", "%Y-%m-%d")
        # PEP 562 lazily publishes this class on concurrent.futures. Initialize
        # the ordinary import before snapshots, without creating any threads.
        getattr(import_module("concurrent.futures"), "ThreadPoolExecutor")
        # multiprocessing publishes the interpreter's main-module alias.
        # Establish its exact binding before any test can import this package.
        try:
            import_module("multiprocessing")
        except (ImportError, AttributeError, TypeError, ValueError, RuntimeError, OSError):
            raise pytest.UsageError("runtime patch guard import API is unsupported") from None
        resolve_name = getattr(pkgutil, "resolve_name", None)
        if resolve_name is not None:
            resolve_name("os")
        if os.path.isfile(os.path.join(REPO_ROOT, "aegis_core", "ghcli.py")):
            # These are unconditional autouse-fixture dependencies. Import
            # them before the baseline rather than exempting fixture imports.
            import_module("aegis_core.ghcli")
            import_module("aegis_core.pathlookup")
        try:
            creation_gc = import_module("gc")
            self.creation_api = (creation_gc.get_objects, creation_gc.freeze,
                                 creation_gc.unfreeze)
        except (ImportError, AttributeError, TypeError, ValueError, RuntimeError, OSError):
            self.creation_api = (None,) * 3
        self.creation_depth = 0
        self.creation_owned = False
        self.creation_canary = None
        self.creation_reason = None
        self.creation_checked = None
        self.creation_failures = {}
        self.creation_owner = self
        self.import_parent = None
        self.nested_tests_path = None
        self.import_exclusions = {}
        self.excluded_bindings = {}
        self.import_previous = {}
        self._module_map("seed")
        self.lock = RLock()
        self.creation_lock = RLock()
        self.metrics = Counter()
        self.sites = set()
        self.calls = set()
        self.owned_calls = set()
        self.owned_targets = {}
        self.test_owned = set()
        self.current_module = None
        self.namespace_owners = {}
        self.module_owners = {}
        self.conftest_owned = set()
        self.collection_adopted = False
        self.origins = WeakKeyDictionary()
        self.resolved_targets = WeakKeyDictionary()
        self.framework_owned = {}
        self.origin_context = ContextVar("runtime_patch_origin", default=None)
        self.target_context = ContextVar("runtime_patch_target", default=None)
        self.violations = set()
        self.active = None
        self.snapshots = {}
        self.touched = set()
        self.process_owners = set()
        self.originals = []
        self.hook_modules = set()
        self.hook_files = set()
        self.pytest_files = set()
        self.hook_distribution_index = None
        self.hook_codes = {}
        self.hook_attribution_codes = {}
        self.bookkeeping_codes = {}
        self.hook_callback_parents = set()
        self.hook_delegated = set()
        self.hook_private_names = {}
        self.hook_compiled = {}
        self.hook_instrumented = set()
        self.hook_indexed_modules = {}
        self.hook_sources = {}
        self.hook_wrapped = set()
        self.hook_entry_code = None
        self._pytest_main = import_module("_pytest.config").main
        self._pytest_main_codes = {self._pytest_main.__code__}
        self.hook_context = ContextVar("runtime_patch_hook", default=False)
        self.hook_inspecting = ContextVar("runtime_patch_inspecting", default=False)
        self.hook_setattr, self.hook_delattr = setattr, delattr
        self.hook_exec = exec
        self.import_writer_codes = {}
        self.framework_conflicts = {}
        self.active_bindings = {}
        self.store_versions = {}
        self.pending_differences = set()
        self.import_displacements = {}
        self.consumer_owners = {}
        self.fixture_owners = {}
        self.fixture_graph = {}
        self.fixture_selections = {}
        self.fixture_roots = {}
        self.pending_consumers = {}
        self.namespace_referrers = None
        self.consumer_spellings = {}
        self.import_context = ContextVar("runtime_patch_import", default=())
        self.loading_modules = {}
        self.unapproved_initializers = set()
        self.started = False
        self.closing = False
        self.created_inspecting = ContextVar("runtime_patch_created", default=False)
        self.readonly_hook_codes = set()
        self.guard_codes = set()
        pending_codes = [value.__code__ for value in _PatchGuard.__dict__.values()
                         if type(value) is FunctionType]
        while pending_codes:
            code = pending_codes.pop()
            self.guard_codes.add(code)
            pending_codes.extend(value for value in code.co_consts if type(value) is CodeType)
        # Register once per config, restoring the previous layer on unconfigure.
        # Nested pytest.main sessions therefore preserve the outer session.
        try:
            self._install_imports()
            if self.import_parent is not None:
                # A copied conftest reuses authenticated instrumentation, but
                # its dispatcher and expectations belong to its own config.
                parent = self.import_parent
                parent.guard_codes.update(self.guard_codes)
                self.hook_codes.update(parent.hook_codes)
                self.hook_attribution_codes.update(parent.hook_attribution_codes)
                self.hook_private_names.update(parent.hook_private_names)
                self.import_writer_codes.update(parent.import_writer_codes)
                self.hook_delegated.update(parent.hook_delegated)
                self.hook_callback_parents.update(parent.hook_callback_parents)
                self._pytest_main_codes = set(parent._pytest_main_codes)
                if _PATCH_TESTS_PATH_CHANGE is not None:
                    module, previous, installed = _PATCH_TESTS_PATH_CHANGE
                    entry = parent.snapshots.get(id(module))
                    if (entry is not None and entry[1].get("__path__") is installed
                            and dict(zip(entry[2], entry[3])).get("__path__") is previous):
                        self.nested_tests_path = module, previous, installed, entry[1]
                        parent._set_expected(id(module), "__path__", installed)
            self._install()
            self._install_bookkeeping_attribution()
        except BaseException:
            self.pytest_unconfigure(config)
            raise
        self.metrics["fixed_setup_ns"] = process_time_ns() - started

    def pytest_plugin_registered(self, plugin, manager):
        """Observe third-party stores; authenticate only pytest engine bookkeeping.

        Test/fixture/product source never gains authority merely by being called
        from a hook. Source-less/native functions receive no exemption.
        """
        warning_module = self._module_map().get("warnings")
        if type(warning_module) is ModuleType:
            namespace = ModuleType.__getattribute__(warning_module, "__dict__")
            filename = namespace.get("__file__")
            if type(filename) is str:
                filename = os.path.normcase(os.path.abspath(filename))
                self.hook_files.add(filename)
                self.pytest_files.add(filename)
                self._hook_instrument([namespace.get("catch_warnings")])
        for caller in manager.get_hookcallers(plugin) or ():
            for implementation in caller.get_hookimpls():
                if implementation.plugin is not plugin or id(implementation) in self.hook_wrapped:
                    continue
                function = implementation.function
                actual = function.__func__ if type(function) is MethodType else function
                if type(actual) is not FunctionType or getattr(function, "__self__", None) is self:
                    continue
                filename = os.path.normcase(os.path.abspath(actual.__code__.co_filename))
                if filename.startswith(os.path.normcase(TESTS_DIR) + os.sep):
                    continue
                if any(filename.startswith(os.path.normcase(os.path.join(REPO_ROOT, part)) + os.sep)
                       for part in _CENSUS_PACKAGES):
                    continue
                self.hook_modules.add(id(actual.__globals__))
                self.hook_files.add(filename)
                self._hook_distribution(actual.__globals__.get("__name__", ""))
                self._hook_instrument([actual])
                if filename not in self.pytest_files:
                    self.hook_wrapped.add(id(implementation))
                    continue
                def wrapped(*args, _function=function, **kwargs):
                    token = self.hook_context.set(True)
                    try:
                        result = _function(*args, **kwargs)
                    finally:
                        self.hook_context.reset(token)
                    return self._hook_generator(result) if type(result) is GeneratorType else result
                self.hook_entry_code = wrapped.__code__
                self.originals.append((implementation, "function", function))
                implementation.function = wrapped
                self.hook_wrapped.add(id(implementation))

    def _hook_distribution(self, module_name):
        # pytest11 metadata locates helpers for observation in the registered
        # plugin's distribution, including decorated test adapters. It grants
        # no authority to third-party framework writers.
        if self.hook_distribution_index is None:
            self.hook_distribution_index = {}
            for distribution in _guard_metadata.distributions():
                for entry in distribution.entry_points:
                    if entry.group == "pytest11":
                        self.hook_distribution_index.setdefault(entry.value.split(":", 1)[0], distribution)
            try:
                self.hook_distribution_index["_pytest"] = _guard_metadata.distribution("pytest")
            except _guard_metadata.PackageNotFoundError:
                pass  # no distribution metadata grants no additional source authority
        distribution = self.hook_distribution_index.pop(
            "_pytest" if module_name.startswith("_pytest.") else module_name, None)
        if distribution is not None:
            for path in distribution.files or ():
                if str(path).endswith(".py"):
                    filename = os.path.normcase(os.path.abspath(distribution.locate_file(path)))
                    self.hook_files.add(filename)
                    if module_name.startswith("_pytest."):
                        self.pytest_files.add(filename)

    def _hook_compile(self, function, *, entry=False):
        cached = self.hook_compiled.get(function)
        if cached is not None and not (entry and cached is function):
            return cached
        self.hook_compiled[function] = function  # recursion / unavailable source
        code = function.__code__
        filename = function.__globals__.get("__file__")
        if type(filename) is not str or os.path.normcase(os.path.abspath(filename)) not in self.hook_files:
            return function
        try:
            tree = self.hook_sources.get(filename)
            if tree is None:
                with open(filename, "rb") as stream:
                    source = stream.read(_CENSUS_SOURCE_LIMIT + 1)
                if len(source) > _CENSUS_SOURCE_LIMIT:
                    return function
                parsed = ast.parse(source, filename=filename)
                loader = function.__globals__.get("__loader__")
                if type(loader) is AssertionRewritingHook:
                    rewrite_asserts(parsed, source, module_path=filename,
                                    config=getattr(loader, "config", self.config))
                authentic = compile(parsed, filename, "exec", dont_inherit=True)
                source_codes, pending_codes = {}, [authentic]
                while pending_codes:
                    source_code = pending_codes.pop()
                    source_codes.setdefault((source_code.co_firstlineno, source_code.co_name), []).append(source_code)
                    pending_codes.extend(value for value in source_code.co_consts if type(value) is CodeType)
                tree = {}
                def index(node, class_name=None):
                    if isinstance(node, ast.ClassDef):
                        class_name = node.name
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        key = min([node.lineno] + [d.lineno for d in node.decorator_list]), node.name
                        tree.setdefault(key, []).append((node, class_name))
                    elif isinstance(node, ast.Lambda):
                        tree.setdefault((node.lineno, "<lambda>"), []).append((node, class_name))
                    for child in ast.iter_child_nodes(node):
                        index(child, class_name)
                index(parsed)
                self.hook_sources[filename] = tree, source_codes
            else:
                tree, source_codes = tree
            if not _TestCodeIndex._literal_code(code):
                return function
            matching = next((candidate for candidate in source_codes.get((code.co_firstlineno, code.co_name), ())
                             if candidate == code), None)
            if matching is None:
                # Decorators may preserve their implementation while changing
                # code-location metadata. Authenticate the complete executable
                # body, allowing only those non-executable metadata differences.
                for entries in source_codes.values():
                    for candidate in entries:
                        if candidate.co_code != code.co_code:
                            continue
                        fields = {"co_name": candidate.co_name, "co_firstlineno": candidate.co_firstlineno}
                        if hasattr(code, "co_qualname"):
                            fields["co_qualname"] = candidate.co_qualname
                        if code.replace(**fields) == candidate:
                            matching = candidate
                            break
                    if matching is not None:
                        break
            if matching is None:
                return function
            self._register_attribution_code(code)
            candidates = tree.get((matching.co_firstlineno, matching.co_name), ())
            if len(candidates) != 1:
                return function
            original_node, class_name = candidates[0]
            node = copy.deepcopy(original_node)
            if isinstance(node, ast.Lambda):
                node = ast.copy_location(ast.FunctionDef("_aegis_hook_lambda", node.args,
                    [ast.copy_location(ast.Return(node.body), node.body)], []), node)
            node.decorator_list = []
            # Defaults/annotations are already evaluated on the real function.
            node.args.defaults = []
            node.args.kw_defaults = [None for _ in node.args.kwonlyargs]
            for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
                argument.annotation = None
            if node.args.vararg:
                node.args.vararg.annotation = None
            if node.args.kwarg:
                node.args.kwarg.annotation = None
            node.returns = None
            globals_names = {name for child in ast.walk(node) if isinstance(child, ast.Global) for name in child.names}
            occupied = {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}
            occupied.update((*code.co_freevars, *code.co_varnames, *code.co_names))
            helper = "_aegis_hook_dispatch_%x" % id(self)
            while helper in occupied:
                helper += "_"
            node = _PatchHookCode(helper, globals_names, occupied, class_name, function.__globals__).visit(node)
            # A delegated exception can resume a generator without its original
            # caller chain (CPython 3.9). Keep an authenticated entry token even
            # in resumable helpers that have no stores of their own.
            resumable = code.co_flags & (CO_GENERATOR | CO_COROUTINE | CO_ASYNC_GENERATOR)
            if not entry and not resumable and not any(isinstance(child, ast.Name) and child.id == helper
                                         for child in ast.walk(node)):
                return function
            node.args.kwonlyargs.append(ast.arg(helper))
            node.args.kw_defaults.append(ast.Constant(None))
            # Keep every original captured binding, including those inherited from
            # an already-instrumented enclosing function.
            retained = ast.If(ast.Constant(False), [ast.Expr(ast.Tuple(
                [ast.Name(name, ast.Load()) for name in code.co_freevars], ast.Load()))], [])
            insertion = int(bool(node.body and isinstance(node.body[0], ast.Expr)
                                 and isinstance(node.body[0].value, ast.Constant)
                                 and type(node.body[0].value.value) is str))
            node.body.insert(insertion, ast.copy_location(retained, node))
            entry = ast.Assign([ast.Name(helper, ast.Store())], ast.Call(
                ast.Name(helper, ast.Load()), [ast.Constant("enter"), ast.Constant(bool(resumable))], []))
            node.body.insert(insertion + 1, ast.copy_location(entry, node))
            body = node
            if class_name:
                body = ast.copy_location(ast.ClassDef(class_name, [], [], [node], []), node)
            outer = ast.FunctionDef("_aegis_hook_closure", ast.arguments(
                posonlyargs=[], args=[ast.arg(name) for name in code.co_freevars],
                vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
                [body], decorator_list=[])
            # Nesting a recursive module function would otherwise capture its
            # own name from the synthetic enclosing function's local binding.
            if not class_name and node.name not in code.co_freevars:
                outer.body.insert(0, ast.copy_location(ast.Global([node.name]), node))
            ast.copy_location(outer, node)
            compiled = compile(ast.fix_missing_locations(ast.Module([outer], type_ignores=[])), filename, "exec",
                               flags=code.co_flags & _guard_future.annotations.compiler_flag, dont_inherit=True)
            outer_code = next(value for value in compiled.co_consts if type(value) is CodeType)
            inner = next(value for value in outer_code.co_consts if type(value) is CodeType)
            if class_name:
                inner = next(value for value in inner.co_consts if type(value) is CodeType and value.co_name == node.name)
            if inner.co_freevars != code.co_freevars:
                return function
            location = {"co_filename": code.co_filename, "co_name": code.co_name,
                        "co_firstlineno": code.co_firstlineno}
            if hasattr(code, "co_qualname"):
                location["co_qualname"] = code.co_qualname
            inner = inner.replace(**location)
            pending = [inner]
            while pending:
                child = pending.pop()
                self.hook_codes[id(child)] = child
                self._register_attribution_code(child)
                self.hook_private_names[id(child)] = helper
                children = [value for value in child.co_consts if type(value) is CodeType]
                if children:
                    self.hook_callback_parents.add(id(child))
                if child is not inner:
                    self.hook_delegated.add(id(child))
                pending.extend(children)
            result = inner, helper
            self.hook_compiled[function] = result
            if function is self._pytest_main:
                self._pytest_main_codes.add(inner)
            return result
        except (OSError, SyntaxError, TypeError, ValueError, StopIteration, RecursionError):
            return function  # unavailable provenance grants no write authority

    def _register_attribution_code(self, code):
        guard = self
        while guard is not None:
            guard.hook_attribution_codes[id(code)] = code
            guard = guard.import_parent

    def _install_bookkeeping_attribution(self):
        if self.creation_owner is not self:
            codes = getattr_static(self.creation_owner, "bookkeeping_codes", None)
            if type(codes) is not dict:
                raise pytest.UsageError(_PYTEST_API_ERROR)
            self.bookkeeping_codes.update(codes)
            return
        try:
            callers = import_module("pluggy._callers")
            manager = import_module("pluggy._manager")
            hooks = import_module("pluggy._hooks")
            functions = [callers._multicall, getattr_static(manager.PluginManager, "_hookexec"),
                         getattr_static(hooks.HookCaller, "__call__"),
                         getattr_static(hooks.HookCaller, "call_historic"),
                         getattr_static(hooks.HookCaller, "_maybe_apply_history")]
            legacy = getattr_static(callers, "run_old_style_hookwrapper", None)
            if legacy is not None:
                functions.append(legacy)
            for function in functions:
                if type(function) is not FunctionType:
                    raise TypeError
                self.bookkeeping_codes[id(function.__code__)] = function.__code__
            # Mock decorators execute their patch before entering the wrapped
            # callback. Retain the exact stdlib wrapper codes for attribution.
            for owner in (self.mock._patch, self.mock._patch_dict):
                dispatcher = getattr_static(owner, "__call__")
                if type(dispatcher) is not FunctionType:
                    raise TypeError
                # Python 3.9's dictionary wrapper lives in __call__; newer
                # runtimes delegate to the named sync/async helpers. Inspect
                # this runtime's dispatch rather than requiring newer APIs.
                decorators = [dispatcher]
                for name in ("decorate_callable", "decorate_async_callable"):
                    if name in dispatcher.__code__.co_names:
                        function = getattr_static(owner, name)
                        if type(function) is not FunctionType:
                            raise TypeError
                        decorators.append(function)
                wrapper_count = 0
                for function in decorators:
                    pending = [code for code in function.__code__.co_consts if type(code) is CodeType]
                    while pending:
                        code = pending.pop()
                        wrapper_count += 1
                        self.bookkeeping_codes[id(code)] = code
                        pending.extend(child for child in code.co_consts if type(child) is CodeType)
                if not wrapper_count:
                    raise TypeError
        except (ImportError, AttributeError, TypeError, ValueError):
            raise pytest.UsageError(_PYTEST_API_ERROR) from None

    def _hook_instrument(self, roots, *, entry=False):
        pending, seen = list(roots), set()
        while pending:
            value = pending.pop()
            if id(value) in seen:
                continue
            seen.add(id(value))
            if type(value) is MethodType:
                value = value.__func__
            if type(value) in (classmethod, staticmethod):
                pending.append(value.__func__)
                continue
            if type(value) is property:
                pending.extend(item for item in (value.fget, value.fset, value.fdel) if item is not None)
                continue
            if _patch_is_instance(value, type):
                namespace = type.__dict__["__dict__"].__get__(value)
                module_name = namespace.get("__module__")
                if type(module_name) is not str:
                    continue
                module = self._module_map().get(module_name)
                if type(module) is not ModuleType:
                    continue
                module_namespace = ModuleType.__getattribute__(module, "__dict__")
                filename = module_namespace.get("__file__")
                if type(filename) is str and os.path.normcase(os.path.abspath(filename)) in self.hook_files:
                    pending.extend(namespace.values())
                continue
            if type(value) is not FunctionType:
                continue
            wrapped = value.__dict__.get("__wrapped__")
            if wrapped is not None:
                pending.append(wrapped)
            pending.extend(_patch_nonlocals(value))
            if value in self.hook_instrumented and not entry:
                continue
            if self.hook_codes.get(id(value.__code__)) is value.__code__:
                helper = self.hook_private_names.get(id(value.__code__))
                dispatcher = (value.__kwdefaults__ or {}).get(helper)
                parent = self.import_parent
                if (parent is not None and type(dispatcher) is MethodType
                        and dispatcher.__self__ is parent
                        and dispatcher.__func__ in (parent._hook_dispatch.__func__, parent._hook_untrusted.__func__)):
                    self.originals.append((value, "__kwdefaults__", value.__kwdefaults__))
                    replacement = (self._hook_dispatch if dispatcher.__func__ is parent._hook_dispatch.__func__
                                   else self._hook_untrusted)
                    value.__kwdefaults__ = dict(value.__kwdefaults__, **{helper: replacement})
                self.hook_instrumented.add(value)
                continue
            namespace = value.__globals__
            module_name = namespace.get("__name__")
            module = self._module_map().get(module_name) if type(module_name) is str else None
            if type(module) is not ModuleType or ModuleType.__getattribute__(module, "__dict__") is not namespace:
                continue
            filename = namespace.get("__file__")
            if type(filename) is not str:
                continue
            filename = os.path.normcase(os.path.abspath(filename))
            if (filename not in self.hook_files or (hasattr(value, "_pytestfixturefunction") and filename not in self.pytest_files)
                    or id(value.__code__) in getattr(self, "untrusted_hook_codes", ())):
                continue
            self.hook_instrumented.add(value)
            result = self._hook_compile(value, entry=entry)
            if result is value:
                continue
            code, helper = result
            visible = signature(value)
            previous_signature = value.__dict__.get("__signature__", self.missing)
            self.originals.extend([(value, "__kwdefaults__", value.__kwdefaults__),
                                   (value, "__code__", value.__code__),
                                   (value, "__signature__", previous_signature)])
            value.__signature__ = visible
            dispatcher = self._hook_dispatch if filename in self.pytest_files else self._hook_untrusted
            value.__kwdefaults__ = dict(value.__kwdefaults__ or {}, **{helper: dispatcher})
            value.__code__ = code
            if (module_name == "_pytest.pathlib" and value.__name__ in {
                    "import_path", "_import_module_using_spec", "insert_missing_modules"}
                    or module_name == "_pytest.config" and value.__name__ == "_importconftest"):
                self.import_writer_codes[id(code)] = code

    def _hook_index_modules(self):
        for module in tuple(self._module_map().values()):
            if id(module) in self.hook_indexed_modules or type(module) is not ModuleType:
                continue
            namespace = ModuleType.__getattribute__(module, "__dict__")
            filename = namespace.get("__file__")
            if type(filename) is str and os.path.normcase(os.path.abspath(filename)) in self.hook_files:
                self.hook_indexed_modules[id(module)] = module
                self._hook_instrument(tuple(namespace.values()))

    def _hook_readonly_adapter(self, function):
        code = function.__code__
        if code.co_names or len(code.co_code) > 4096:
            return False
        allowed = {"COPY_FREE_VARS", "RESUME", "LOAD_DEREF", "LOAD_FAST", "LOAD_CONST",
                   "STORE_FAST", "DELETE_FAST", "BUILD_TUPLE", "BUILD_MAP", "BUILD_CONST_KEY_MAP",
                   "DICT_MERGE", "DICT_UPDATE", "BUILD_LIST", "LIST_EXTEND", "LIST_TO_TUPLE",
                   "KW_NAMES", "CALL_FUNCTION_EX", "CALL_FUNCTION_KW", "PRECALL",
                   "CALL", "CALL_FUNCTION", "RETURN_VALUE", "PUSH_NULL", "NOP"}
        if any(instruction.opname not in allowed for instruction in dis.get_instructions(code)):
            return False
        if sum(instruction.opname in {"CALL", "CALL_FUNCTION", "CALL_FUNCTION_EX", "CALL_FUNCTION_KW"}
               for instruction in dis.get_instructions(code)) != 1:
            return False
        for candidate in _patch_nonlocals(function):
            if (type(candidate) is FunctionType and os.path.normcase(os.path.abspath(
                    candidate.__code__.co_filename)) in self.hook_files):
                return True
        return False

    def _hook_generator(self, generator):
        value, error = None, None
        while True:
            token = self.hook_context.set(True)
            try:
                value = generator.throw(error) if error is not None else generator.send(value)
            except StopIteration as completed:
                return completed.value
            finally:
                self.hook_context.reset(token)
            try:
                value = yield value
                error = None
            except BaseException as caught:
                error = caught

    def _framework_target(self, owner, *, initializer=False):
        if _patch_is_instance(owner, ModuleType):
            identity = id(owner)
            if identity in self.test_owned and not initializer:
                return None
            entry = self.module_owners.get(identity)
        elif type(owner) is dict:
            entry = self.namespace_owners.get(id(owner))
            identity = id(entry[0]) if entry is not None else None
            if identity in self.test_owned and not initializer:
                return None
        else:
            return None
        baseline = self.snapshots.get(identity)
        # No observation made by a patch or a writer becomes a baseline.
        return (identity, baseline) if baseline is not None else None

    def _framework_change(self, owner, function, args, kwargs, attribute=None, *, _binding=()):
        if not self.started:
            if self.import_parent is not None and not self.closing:
                return self.import_parent._framework_change(
                    owner, function, args, kwargs, attribute, _binding=_binding)
            return function(*args, **kwargs)
        target = None
        if owner is not self.modules:
            target = self._framework_target(owner, initializer=function is self.hook_exec)
            if target is None:
                # Ordinary containers are not protected module namespaces.
                # Their stores need no provenance walk or baseline update.
                return function(*args, **kwargs)
        token = self.hook_inspecting.set(True)
        frame = None
        registry_writer = False
        try:
            frame = sys._getframe(1)
            while frame is not None and (frame.f_globals is globals() or frame.f_code in self.guard_codes):
                frame = frame.f_back
            if (frame is None or self.hook_codes.get(id(frame.f_code)) is not frame.f_code
                    or id(frame.f_code) in getattr(self, "untrusted_hook_codes", ())):
                return function(*args, **kwargs)
            # The patch fixture's undo belongs to the test that requested the
            # patch. Judge its final value against the unchanged baseline;
            # do not mistake explicit test cleanup for a framework overwrite.
            if frame is not None and frame.f_globals.get("__name__") == "_pytest.monkeypatch":
                return function(*args, **kwargs)
            if frame is not None and (id(frame.f_code) not in self.hook_delegated
                    and not self._hook_origin_allowed(frame.f_back)):
                return function(*args, **kwargs)
            if target is not None and (target[0] in self.test_owned or function is self.hook_exec):
                module = self.module_owners[target[0]][0]
                if function is self.hook_exec:
                    self._initialize_exec_builtins(module)
                    registry_before = self._import_registry_snapshot()
                name = self._module_map("initializer", module, frame.f_locals.get("self"))
                # Pytest's rewritten importlib loader executes modules without
                # importlib._bootstrap's load receipt. Authenticate its own
                # namespace before publishing this initializer's changes.
                if (frame.f_code.co_name != "exec_module"
                        or frame.f_locals.get("module") is not module
                        or name is self.missing or not self._initializer_allowed(module, name)):
                    if function is self.hook_exec:
                        self._exclude_import_value(module, refused=True)
                        try:
                            return function(*args, **kwargs)
                        finally:
                            self._finish_import_exclusions(module, registry_before)
                    return function(*args, **kwargs)
            registry_writer = frame is not None and self.import_writer_codes.get(id(frame.f_code)) is frame.f_code
        finally:
            del frame
            self.hook_inspecting.reset(token)
        if owner is self.modules:
            if not registry_writer:
                return function(*args, **kwargs)
            before = self.modules.copy()
            try:
                return function(*args, **kwargs)
            finally:
                for key in before.keys() | self.modules.keys():
                    value = self.modules.get(key, self.missing)
                    if value is before.get(key, self.missing):
                        continue
                    if (type(key) is not str or len(key) > _CENSUS_ADDRESS_LIMIT
                            or not self._initializer_allowed(value, key)
                            or id(value) in self.unapproved_initializers):
                        continue
                    if value is self.missing:
                        self._module_map("remove", key)
                    else:
                        self._module_map("publish", key, value)
                        self._baseline_module(value, key)
                    self.metrics["authenticated_imports"] += 1
        identity, (name, namespace, keys, values) = target
        while True:
            entry = self.snapshots.get(identity)
            if entry is None:
                return function(*args, **kwargs)
            previous = namespace.copy()
            expected = dict(zip(entry[2], entry[3]))
            if self.snapshots[identity] is entry:
                break
        examined = expected.keys() | previous.keys() if attribute is None else (attribute,)
        for key in examined:
            current = previous.get(key, self.missing)
            wanted = expected.get(key, self.missing)
            if current is not wanted and not self._pending_binding(identity, key, current):
                self._taint(identity, key, wanted, current)
        pair = identity, attribute
        version = self.store_versions.get(pair)
        token = None
        if _binding:
            token = object()
            self.active_bindings.setdefault(pair, []).append((token, _binding[0]))
        completed = False
        try:
            result = function(*args, **kwargs)
            completed = True
            return result
        finally:
            try:
                initializer_allowed = function is not self.hook_exec or self._initializer_allowed(
                    self.module_owners[identity][0], name)
                if not initializer_allowed:
                    self._exclude_import_value(self.module_owners[identity][0], refused=True)
                changes = ((previous.keys() | namespace.keys() if attribute is None else (attribute,))
                           if initializer_allowed else ())
                for key in changes:
                    if not self.started:
                        break
                    actual = current = namespace.get(key, self.missing)
                    if _binding:
                        if not completed and actual is previous.get(key, self.missing):
                            continue
                        desired = _binding[0] if completed else previous.get(key, self.missing)
                        latest = self.snapshots.get(identity)
                        if latest is None:
                            break
                        published = dict(zip(latest[2], latest[3])).get(key, self.missing)
                        newer = self.store_versions.get(pair) is not version
                        if (actual is not desired and not self._pending_binding(identity, key, actual)
                                and not (newer and actual is published)):
                            # The argument to this instruction is its receipt.
                            # A Test store after it returns is not that receipt.
                            self._taint(identity, key, desired, actual)
                            current = desired
                    if current is previous.get(key, self.missing) and not _binding:
                        continue
                    current = self._framework_expected(identity, key, current)
                    if (function is not self.hook_exec
                            and self._import_value_excluded(current, initializer=True)):
                        continue
                    self._set_expected(identity, key, current, _store=bool(_binding))
                    self.metrics["framework_writes"] += 1
                if function is self.hook_exec and initializer_allowed:
                    # Rewritten/importlib collection executes a manually
                    # published module without passing through loader wrappers.
                    self._module_map("capture", name, self.module_owners[identity][0])
                    self.unapproved_initializers.discard(identity)
                    self.import_previous.pop((name, identity), None)
            finally:
                if function is self.hook_exec:
                    self._finish_import_exclusions(self.module_owners[identity][0], registry_before)
                if token is not None:
                    pending = self.active_bindings.get(pair, ())
                    for index, binding in enumerate(pending):
                        if binding[0] is token:
                            pending.pop(index)
                            break
                    if not pending:
                        self.active_bindings.pop(pair, None)

    def _hook_origin_allowed(self, frame):
        delegated = []
        try:
            while frame is not None:
                identity = id(frame.f_code)
                if identity in getattr(self, "untrusted_hook_codes", ()):
                    return False
                if frame.f_code in self._pytest_main_codes:
                    return True
                if ((frame.f_code is self.hook_entry_code or frame.f_code is self._hook_generator.__func__.__code__)
                        and frame.f_locals.get("self") is self):
                    return True
                if (identity in self.hook_delegated or identity in self.hook_callback_parents
                        or self.hook_codes.get(identity) is frame.f_code):
                    # Reading f_locals materializes a dictionary that can keep
                    # deleted objects alive until their creator returns. First
                    # seek an entry frame without observing framework locals;
                    # only a shortened delegated unwind needs the saved token.
                    delegated.append(frame)
                filename = frame.f_code.co_filename
                if (type(filename) is str
                        and os.path.normcase(os.path.abspath(filename)) in self.hook_files
                        and os.path.normcase(os.path.abspath(filename)) not in self.pytest_files):
                    return False
                if (type(filename) is str and frame.f_code not in self.guard_codes
                        and identity not in self.readonly_hook_codes and frame.f_code.co_name != "<module>"
                        and os.path.normcase(os.path.abspath(filename)).startswith(os.path.normcase(REPO_ROOT) + os.sep)
                        and self.hook_codes.get(identity) is not frame.f_code):
                    return False
                frame = frame.f_back
            for candidate in delegated:
                witness = candidate.f_locals.get(self.hook_private_names.get(id(candidate.f_code)))
                if (type(witness) is MethodType and witness.__self__ is self
                        and witness.__func__ is self._hook_dispatch.__func__):
                    return True
            return False
        finally:
            delegated.clear()
            del frame

    def _hook_untrusted(self, operation, /, *args, **kwargs):
        if operation == "enter":
            return self._hook_untrusted
        if operation == "created":
            self._hook_created(*args)
            return None
        if operation == "class":
            if not self.closing:
                self._hook_instrument(args)
            return None
        # Final-state reconciliation is identical for direct and helper writes.
        # Authenticated engine stores retain separate displaced-value receipts.
        return self._hook_plain(operation, *args, **kwargs)

    def _hook_deferred(self, operation, /, *args, **kwargs):
        if self.closing:
            if self.import_parent is not None and self.import_parent.started:
                return self.import_parent._hook_deferred(operation, *args, **kwargs)
            return self._hook_plain(operation, *args, **kwargs)
        if operation in {"enter", "created", "class"}:
            return self._hook_dispatch(operation, *args, **kwargs)
        # Ignored audit events need no frame access. Effects delivered while
        # attribution itself emits an event remain ordinary, guarded writes.
        if self.hook_inspecting.get():
            return self._hook_plain(operation, *args, **kwargs)
        token = self.hook_inspecting.set(True)
        frame = None
        try:
            frame = sys._getframe(1)
            allowed = self._hook_origin_allowed(frame.f_back)
        except (AttributeError, TypeError, ValueError, RuntimeError):
            raise pytest.UsageError(_PYTEST_API_ERROR) from None
        finally:
            del frame
            self.hook_inspecting.reset(token)
        dispatcher = self._hook_dispatch if allowed else self._hook_plain
        return dispatcher(operation, *args, **kwargs)

    def _hook_dispatch(self, operation, /, *args, **kwargs):
        if self.closing:
            if self.import_parent is not None and self.import_parent.started:
                return self.import_parent._hook_deferred(operation, *args, **kwargs)
            if operation == "enter":
                return self._hook_plain
            if operation in {"class", "created"}:
                return None
            return self._hook_plain(operation, *args, **kwargs)
        if operation == "created":
            self._hook_created(*args)
            return None
        if operation == "class":
            self._hook_instrument(args)
            return None
        if operation == "enter":
            if not args or not args[0]:
                return self._hook_deferred
            if self.hook_inspecting.get():
                return self._hook_plain
            token = self.hook_inspecting.set(True)
            frame = None
            try:
                frame = sys._getframe(1)
                # Context alone also spans test/fixture callbacks. Validate the
                # caller before retaining authority in any authenticated frame.
                if not self._hook_origin_allowed(frame.f_back):
                    return self._hook_plain
                return self._hook_dispatch
            finally:
                del frame
                self.hook_inspecting.reset(token)
        if operation == "call":
            function, *arguments = args
            if function is self.hook_setattr and len(arguments) == 3 and not kwargs:
                return self._hook_dispatch("set", *arguments)
            if function is self.hook_delattr and len(arguments) == 2 and not kwargs:
                return self._hook_dispatch("del", *arguments)
            if function is self.hook_exec and len(arguments) >= 2 and type(arguments[1]) is dict:
                return self._framework_change(arguments[1], function, arguments, kwargs)
            if type(function) is BuiltinMethodType and type(function.__self__) is dict and function.__name__ in {
                    "update", "clear", "pop", "popitem", "setdefault", "__setitem__", "__delitem__"}:
                return self._framework_change(function.__self__, function, arguments, kwargs)
            if type(function) is BuiltinMethodType:
                return function(*arguments, **kwargs)
            return function(*arguments, **kwargs)
        owner, key, *value = args
        if operation in {"set", "del"}:
            function = self.hook_setattr if operation == "set" else self.hook_delattr
            if type(key) is not str:
                return function(owner, key, *value)
            if not _patch_is_instance(owner, ModuleType):
                return function(owner, key, *value)
            return self._framework_change(owner, function, (owner, key, *value), {}, key,
                                          _binding=(value[0] if operation == "set" else self.missing,))
        def store():
            if operation == "itemset":
                owner[key] = value[0]
            else:
                del owner[key]
        return self._framework_change(owner, store, (), {}, key,
                                      _binding=(value[0] if operation == "itemset" else self.missing,))

    def _hook_plain(self, operation, /, *args, **kwargs):
        if operation == "created":
            self._hook_created(*args)
            return None
        if operation == "enter":
            return self._hook_dispatch("enter", *args)
        if operation == "class":
            self._hook_instrument(args)
            return None
        if operation == "call":
            function, *arguments = args
            return function(*arguments, **kwargs)
        owner, key, *value = args
        if operation == "set":
            return self.hook_setattr(owner, key, value[0])
        if operation == "del":
            return self.hook_delattr(owner, key)
        if operation == "itemset":
            owner[key] = value[0]
        else:
            del owner[key]


    def _start_baselines(self):
        if self.hypothesis_categories is not None:
            # Hypothesis ends plugin initialization before this trylast hook.
            # Warm Unicode caches and its first post-init storage witness now;
            # later replacements remain guarded, including within a test.
            self.hypothesis_categories()
            self.hypothesis_categories = None
        self._module_map("seed")
        frame = None
        try:
            self._hook_index_modules()
            self._module_map("seed")
            self.started = True
            # Repeat the capability check with real attribution active. Audit
            # handlers that observe the identity operation used by the ledger
            # can otherwise recurse only after the first test begins.
            frame = sys._getframe()
            frame.f_code
            id(self)
        except Exception:
            self.pytest_unconfigure(self.config)
            raise pytest.UsageError("runtime patch guard audit callback API is unsupported") from None
        finally:
            del frame
        for name in self.policy["PROCESS_MODULES"]:
            module = import_module(name)
            namespace = ModuleType.__getattribute__(module, "__dict__")
            self.process_owners.update((id(module), id(namespace)))
        for name, module in self._module_map().items():
            self._baseline_module(module, name)
            self._module_map("capture", name, module)

    def _guarded_namespace(self, identity, namespace):
        ignored = self.framework_owned.get(identity)
        if not ignored:
            return namespace
        return {key: value for key, value in namespace.copy().items() if key not in ignored}

    @staticmethod
    def _initialize_module_metadata(namespace):
        # Interpreter-created dictionaries need stable baseline bindings.
        # Contents may change; replacement and deletion remain guarded.
        created = {}
        if "__warningregistry__" not in namespace:
            namespace["__warningregistry__"] = created["__warningregistry__"] = {}
        if _patch_is_instance(getattr_static(ModuleType, "__annotations__", None),
                              GetSetDescriptorType) and "__annotations__" not in namespace:
            namespace["__annotations__"] = created["__annotations__"] = {}
        return created

    def _baseline_module(self, module, name):
        if not _patch_is_instance(module, ModuleType):
            return
        identity = id(module)
        ignored = frozenset(attribute for (owner, attribute) in _PATCH_FRAMEWORK_BINDINGS
                            if self._module_map().get(owner, self.missing) is module)
        if ignored and ignored != self.framework_owned.get(identity):
            self.framework_owned[identity] = ignored
            previous = self.snapshots.get(identity)
            if previous is not None:
                label, namespace, keys, values = previous
                protected = {key: value for key, value in zip(keys, values) if key not in ignored}
                self.snapshots[identity] = label, namespace, *_patch_snapshot(protected)
        if identity in self.module_owners:
            return
        namespace = ModuleType.__getattribute__(module, "__dict__")
        self._initialize_module_metadata(namespace)
        label = name if type(name) is str else "<module>"
        entry = module, label, namespace
        self.module_owners[identity] = entry
        self.namespace_owners[id(namespace)] = entry
        if self._test_owned_module(module, namespace):
            self.conftest_owned.add(identity)
            self.test_owned.add(identity)
        self.snapshots[identity] = label, namespace, *_patch_snapshot(self._guarded_namespace(identity, namespace).copy())
        if self.import_parent is not None:
            parent = self.import_parent
            outer = parent.snapshots.get(identity)
            if outer is not None:
                previous = dict(zip(outer[2], outer[3]))
                observed = dict(zip(self.snapshots[identity][2], self.snapshots[identity][3]))
                for key in previous.keys() | observed.keys():
                    wanted = previous.get(key, parent.missing)
                    actual = observed.get(key, parent.missing)
                    if actual is not wanted and not parent._pending_binding(identity, key, actual):
                        parent._taint(identity, key, wanted, actual)
        if label in self.policy["PROCESS_MODULES"]:
            self.process_owners.update((identity, id(namespace)))
        self.metrics["metadata_namespaces"] += 1
        self.metrics["baseline_bindings"] += len(namespace)

    def _set_expected(self, identity, key, value, *, _store=False):
        if self.import_parent is not None and self.started:
            parent = self.import_parent
            forwarded = parent.missing if value is self.missing else value
            forwarded = parent._framework_expected(identity, key, forwarded)
            parent._set_expected(identity, key, forwarded, _store=_store)
        if key in self.framework_owned.get(identity, ()):
            return
        pair = identity, key
        version = self.store_versions.get(pair)
        # Build the candidate image outside the lock. GC can run here and its
        # callback may join another authenticated writer; that writer must be
        # able to publish its own receipt before the callback returns.
        while self.started:
            entry = self.snapshots.get(identity)
            if entry is None:
                return
            name, namespace, keys, values = entry
            expected = dict(zip(keys, values))
            if expected.get(key, self.missing) is value:
                with self.lock:
                    if self.snapshots.get(identity) is not entry:
                        continue
                    if _store:
                        self.store_versions[pair] = object()
                    return
            current = namespace.get(key, self.missing)
            newer = self.store_versions.get(pair) is not version
            if (not _store or newer) and current is not value and current is expected.get(key, self.missing):
                return  # a newer authenticated store already published it
            if value is self.missing:
                expected.pop(key, None)
            else:
                expected[key] = value
            replacement = name, namespace, tuple(expected), tuple(expected.values())
            receipt = object()
            with self.lock:
                if not self.started:
                    return
                if self.snapshots.get(identity) is entry:
                    self.snapshots[identity] = replacement
                    self.store_versions[pair] = receipt
                    return

    def _framework_expected(self, identity, key, current):
        for taint in reversed(self.framework_conflicts.get((identity, key), ())):
            # Saved unauthorized values retain the trusted binding displaced,
            # including when another configuration observes a framework store.
            taint[2] = current is taint[1]
            if taint[2]:
                current = taint[0]
        return current

    def _taint(self, identity, key, expected, actual):
        if key in self.framework_owned.get(identity, ()):
            return
        records = self.framework_conflicts.setdefault((identity, key), [])
        for record in records:
            if record[0] is expected and record[1] is actual:
                record[2] = False
                return
        records.append([expected, actual, False])

    def _initialize_exec_builtins(self, module):
        entry = self.snapshots.get(id(module))
        if entry is None:
            return
        _name, namespace, keys, _values = entry
        if "__builtins__" not in keys and "__builtins__" not in namespace:
            # exec supplies this binding even when the initializer is refused.
            # Python 3.9 resolves function builtins from this namespace binding.
            namespace["__builtins__"] = sys._getframe().f_builtins
            self._set_expected(id(module), "__builtins__", namespace["__builtins__"])

    def _approve_initializer(self, module, name, before):
        if not self._initializer_allowed(module, name):
            return
        self._baseline_module(module, name)
        identity = id(module)
        entry = self.snapshots.get(identity)
        if entry is None:
            return
        namespace = entry[1]
        for key in before.keys() | namespace.keys():
            value = namespace.get(key, self.missing)
            if value is not before.get(key, self.missing):
                self._set_expected(identity, key, value)
        self._module_map("capture", name, module)
        self.import_previous.pop((name, identity), None)

    def _import_registry_snapshot(self):
        current = self._module_map("current")
        snapshots = (dict.copy(self.modules),)
        return snapshots if current is self.modules else (*snapshots, dict.copy(current))

    def _import_value_excluded(self, module, *, initializer=False):
        if not _patch_is_instance(module, ModuleType):
            return False
        record = self.creation_owner.import_exclusions.get(id(module))
        return (record is not None and record[0] is module
                and (not initializer or record[1]))

    def _exclude_import_value(self, module, *, refused=False):
        if not _patch_is_instance(module, ModuleType):
            return
        owner, identity = self.creation_owner, id(module)
        while True:
            previous = owner.import_exclusions.get(identity)
            refused = refused or (previous is not None and previous[1])
            record = module, refused
            with owner.creation_lock:
                if owner.import_exclusions.get(identity) is previous:
                    owner.import_exclusions[identity] = record
                    break
        if refused:
            self.unapproved_initializers.add(identity)

    def _initializer_allowed(self, module, name):
        return (self._import_parents(name)
                and (not self._import_value_excluded(module, initializer=True)
                     or (self._module_map().get(name, self.missing) is module
                         and (name, id(module)) not in self.import_previous)))

    def _publication_allowed(self, name, module):
        allowed = self._initializer_allowed(module, name)
        expected = self._module_map().get(name, self.missing)
        if allowed and (expected is self.missing or expected is module):
            return True
        self._observe_import_displacement(name)
        self._exclude_import_value(module, refused=True)
        return False

    def _observe_import_displacement(self, name):
        if name in self.import_displacements:
            return
        site = ("collection", 0)
        frame = sys._getframe(1)
        try:
            while frame is not None:
                if frame.f_code not in self.guard_codes:
                    _filename, path = self._test_source(frame.f_code.co_filename)
                    if path is not None:
                        site = path, frame.f_lineno
                        break
                frame = frame.f_back
        finally:
            del frame
        # This is provenance, never a pending violation. A fully restored
        # binding remains clean even when its import could not be approved.
        self.import_displacements.setdefault(name, (self._module_map().get(name, self.missing), site))

    def _exclude_import_publications(self, before, *, refused):
        owner = self.creation_owner
        trusted = self._module_map()
        approved = {id(value) for value in dict.copy(trusted).values()}
        approved.update(id(value) for value in dict.copy(self.loading_modules).values()
                        if not self._import_value_excluded(value))
        if before is not None:
            for registry in self._import_registry_snapshot():
                for name, value in registry.items():
                    if (type(name) is not str or len(name) > _CENSUS_ADDRESS_LIMIT
                            or any(previous.get(name, self.missing) is value for previous in before)
                            or trusted.get(name, self.missing) is value):
                        continue
                    binding = name, id(value)
                    with owner.creation_lock:
                        owner.excluded_bindings[binding] = value
                    if id(value) not in approved:
                        self._exclude_import_value(value, refused=refused)
        return approved

    def _finish_import_exclusions(self, module, before=None):
        if not self.started or not self._import_value_excluded(module):
            return
        refused = self._import_value_excluded(module, initializer=True)
        approved = self._exclude_import_publications(before, refused=refused)
        # Negative observations grant no baseline. In particular, a fresh helper
        # held by this module cannot become an enclosing import's GC receipt.
        entry = self.module_owners.get(id(module))
        if entry is None or entry[0] is not module:
            return
        namespace = entry[2]
        for value in dict.copy(namespace).values():
            if id(value) not in approved:
                self._exclude_import_value(value, refused=refused)

    def _publication_excluded_spec(self, spec):
        filename, path = self._test_source(getattr(spec, "origin", None))
        return ((path is not None and path.rsplit("/", 1)[-1] == "conftest.py")
                or any(entry["kind"] == "collection" and entry["origin"] == filename
                       for entry in self.import_context.get()))

    def _validated_creation_owner(self, load, owner):
        if type(load) is not FunctionType:
            raise TypeError
        guard_type = load.__globals__.get("_PatchGuard")
        if type(guard_type) is not type:
            raise TypeError
        guard = next((value for value in _patch_nonlocals(load) if type(value) is guard_type), None)
        if guard is None or getattr_static(guard, "creation_owner") is not owner:
            raise TypeError
        depth = getattr_static(owner, "creation_depth", None)
        api = getattr_static(owner, "creation_api", None)
        if (getattr_static(owner, "creation_owner", None) is not owner
                or getattr_static(owner, "closing", None) is not False
                or type(depth) is not int or depth < 0
                or type(getattr_static(owner, "creation_owned", None)) is not bool
                or type(getattr_static(owner, "creation_lock", None)) is not type(self.creation_lock)
                or type(api) is not tuple or len(api) != 3
                or not all(value is None or callable(value) for value in api)
                or type(getattr_static(owner, "import_exclusions", None)) is not dict
                or type(getattr_static(owner, "excluded_bindings", None)) is not dict):
            raise TypeError
        for name in ("_creation_enter", "_creation_exit", "_creation_young_modules"):
            function = getattr_static(type(owner), name, None)
            if (getattr_static(owner, name, None) is not function
                    or type(function) is not FunctionType or function.__name__ != name
                    or function.__globals__.get("_PatchGuard") is not type(owner)):
                raise TypeError
            signature(function).bind(owner)
        for bound in (owner._creation_enter, owner._creation_exit, owner._creation_young_modules):
            if (type(bound) is not MethodType or bound.__self__ is not owner
                    or bound.__func__ is not getattr_static(type(owner), bound.__func__.__name__, None)):
                raise TypeError
        self.import_parent = guard
        return owner

    def _initializer_before(self, module, name):
        self._baseline_module(module, name)
        _label, namespace, keys, values = self.snapshots[id(module)]
        expected = dict(zip(keys, values))
        for key in self._guarded_namespace(id(module), namespace).keys() | expected.keys():
            actual = namespace.get(key, self.missing)
            wanted = expected.get(key, self.missing)
            if actual is not wanted:
                self._taint(id(module), key, wanted, actual)
        return namespace.copy()

    @staticmethod
    def _field_label(value):
        return value if type(value) is str else "<non-text key>"

    def _import_parents(self, name):
        if type(name) is not str or len(name) > _CENSUS_ADDRESS_LIMIT:
            raise pytest.UsageError("runtime patch guard import metadata is unsupported")
        current_modules = self._module_map("current")
        parts = name.split(".")
        for index in range(1, len(parts)):
            parent = ".".join(parts[:index])
            wanted = self._module_map().get(parent, self.missing)
            current = current_modules.get(parent, self.missing)
            initializing = self.loading_modules.get(parent, self.missing)
            if current is wanted or (initializing is not self.missing and current is initializing):
                continue
            return False
        return True

    def _install_imports(self):
        try:
            bootstrap = import_module("importlib._bootstrap")
            external = import_module("importlib._bootstrap_external")
            util = import_module("importlib.util")
            original_load = bootstrap._load_unlocked
            creation_owner = getattr(original_load, "_patch_creation_owner", None)
            if creation_owner is not None:
                self.creation_owner = self._validated_creation_owner(original_load, creation_owner)
            original_find = bootstrap._find_and_load_unlocked
            original_create = bootstrap.module_from_spec
            original_util_create = util.module_from_spec
            loader = external._LoaderBasics
            original_exec = loader.exec_module
            signature(original_load).bind(object())
            signature(original_find).bind("module", object())
            signature(original_create).bind(object())
            signature(original_util_create).bind(object())
            signature(original_exec).bind(object(), object())
        except (ImportError, AttributeError, TypeError, ValueError):
            raise pytest.UsageError("runtime patch guard import API is unsupported") from None

        def permitted(name):
            if not self._import_parents(name):
                return False
            return all(context.get("approved", True)
                       and (context.get("module") is None
                            or self._initializer_allowed(context["module"], name))
                       for context in self.import_context.get() if context.get("name") == name)

        def create(spec):
            # Every creation path authenticates its requested binding before
            # module_from_spec can replace a missing or substituted entry.
            previous = self._module_map().get(spec.name, self.missing)
            displaced = (self.started and previous is not self.missing
                         and self._module_map("current").get(spec.name, self.missing) is not previous)
            module = original_create(spec)
            if self.started:
                if previous is not module or displaced:
                    self.import_previous.setdefault((spec.name, id(module)), (module, previous))
                if displaced:
                    self._exclude_import_value(module, refused=True)
                self._baseline_module(module, spec.name)
                if self._publication_excluded_spec(spec):
                    self._exclude_import_value(module)
            for context in reversed(self.import_context.get()):
                if context["kind"] == "load" and context["spec"] is spec:
                    context["module"] = module
                    if not context["approved"] or self._import_value_excluded(module, initializer=True):
                        context["approved"] = False
                        self._exclude_import_value(module, refused=True)
                    if (self.started and context["approved"]
                            and _patch_is_instance(module, ModuleType)):
                        self._baseline_module(module, spec.name)
                        context["before"] = ModuleType.__getattribute__(module, "__dict__").copy()
                        self.loading_modules[spec.name] = module
                        receipt = context.get("receipt")
                        if (receipt is not None and receipt["active"]
                                and not self._import_value_excluded(module)):
                            receipt["created"].add(id(module))
                    break
            return module

        def execute(loader_self, module):
            if self.started:
                self._initialize_exec_builtins(module)
            name = self._module_map("initializer", module, loader_self) if self.started else self.missing
            if name is not self.missing and not permitted(name):
                self._exclude_import_value(module, refused=True)
            registry_before = (self._import_registry_snapshot()
                               if self.started and self._import_value_excluded(module) else None)
            before = (self._initializer_before(module, name)
                      if name is not self.missing and permitted(name) else None)
            if before is not None:
                for context in self.import_context.get():
                    receipt = context.get("receipt")
                    if (receipt is not None and receipt["active"]
                            and not self._import_value_excluded(module)):
                        receipt["created"].add(id(module))
            try:
                return original_exec(loader_self, module)
            finally:
                if name is not self.missing and not permitted(name):
                    self._exclude_import_value(module, refused=True)
                try:
                    if before is not None and permitted(name):
                        self._approve_initializer(module, name, before)
                finally:
                    self._finish_import_exclusions(module, registry_before)

        def load(spec):
            if not self.started:
                module = original_load(spec)
                self._module_map("publish", spec.name, module)
                return module
            context = {"kind": "load", "name": spec.name, "spec": spec, "module": None,
                       "approved": (permitted(spec.name) and self._publication_allowed(
                           spec.name, self._module_map("current").get(spec.name, self.missing)))}
            collected = self._publication_excluded_spec(spec)
            window = context["approved"] and not collected
            if window:
                self._creation_enter()
            try:
                registry_before = self._import_registry_snapshot()
                if context["approved"] and not collected:
                    # Both dictionaries transport imports; only module_bindings
                    # decides whether a name already has a trusted binding.
                    receipt = next((entry["receipt"] for entry in reversed(self.import_context.get())
                                    if entry.get("receipt") is not None and entry["receipt"]["active"]), None)
                    context["receipt_root"] = receipt is None
                    context["receipt"] = receipt if receipt is not None else self._import_receipt(registry_before)
                    context["package"] = (spec.name if getattr(spec, "submodule_search_locations", None) is not None
                                          else spec.name.rpartition(".")[0])
                token = self.import_context.set((*self.import_context.get(), context))
                try:
                    module = original_load(spec)
                    if context["module"] is None:
                        # Legacy load_module bypasses module_from_spec. Its
                        # returned namespace still needs refusal propagation.
                        context["module"] = module
                        self._baseline_module(module, spec.name)
                    if not permitted(spec.name) or not self._initializer_allowed(module, spec.name):
                        self._exclude_import_value(module, refused=True)
                        return module
                    created = context["module"]
                    origin = getattr(spec, "origin", None)
                    test_source = (type(origin) is str and os.path.normcase(os.path.abspath(origin)).startswith(
                        os.path.normcase(TESTS_DIR) + os.sep))
                    if test_source and created is not None and module is not created:
                        self._observe_import_displacement(spec.name)
                        module = created
                        self._module_map("current")[spec.name] = module
                    if self._module_map("publish", spec.name, module) is False:
                        context["approved"] = False
                        return module
                    if _patch_is_instance(module, ModuleType):
                        self._baseline_module(module, spec.name)
                        self._approve_initializer(module, spec.name, context.get("before", {}))
                        receipt = context.get("receipt")
                        if (receipt is not None and receipt["active"]
                                and not self._import_value_excluded(module)):
                            receipt["created"].add(id(module))
                    parent_name, _, child = spec.name.rpartition(".")
                    parent = self._module_map().get(parent_name)
                    before_parent = None
                    if _patch_is_instance(parent, ModuleType):
                        self._baseline_module(parent, parent_name)
                        parent_ns = ModuleType.__getattribute__(parent, "__dict__")
                        before_parent = parent_ns.get(child, self.missing)
                    for finding in reversed(self.import_context.get()):
                        if finding["kind"] == "find" and finding["name"] == spec.name:
                            finding["loaded"] = module, parent, child, before_parent
                            break
                    self.metrics["authenticated_imports"] += 1
                    return module
                finally:
                    try:
                        if not self._publication_allowed(spec.name, self._module_map("current").get(
                                spec.name, self.missing)):
                            context["approved"] = False
                        if window and permitted(spec.name):
                            self._approve_import_additions(registry_before, context["receipt"], context["package"])
                        if context["module"] is not None and permitted(spec.name):
                            self._approve_initializer(context["module"], spec.name, context.get("before", {}))
                    finally:
                        if context["module"] is not None:
                            if not permitted(spec.name):
                                self._exclude_import_value(context["module"], refused=True)
                            self._finish_import_exclusions(context["module"], registry_before)
                        elif not context["approved"]:
                            # A failing legacy loader may remove its canonical
                            # entry before returning control to importlib.
                            self._exclude_import_publications(registry_before, refused=True)
                        if context.get("receipt_root"):
                            receipt = context["receipt"]
                            receipt["active"] = False
                            receipt["keepalive"].clear()
                            receipt["existing"].clear()
                            receipt["created"].clear()
                        self.loading_modules.pop(spec.name, None)
                        self.import_context.reset(token)
            finally:
                if window:
                    self._creation_exit()


        def find(name, import_):
            if not self.started:
                return original_find(name, import_)
            context = {"kind": "find", "name": name, "approved": permitted(name)}
            token = self.import_context.set((*self.import_context.get(), context))
            try:
                result = original_find(name, import_)
                receipt = context.get("loaded")
                if receipt is not None and permitted(name):
                    module, parent, child, previous = receipt
                    if result is module and _patch_is_instance(parent, ModuleType):
                        entry = self.snapshots.get(id(parent))
                        namespace = ModuleType.__getattribute__(parent, "__dict__")
                        if entry is not None and namespace.get(child, self.missing) is module:
                            expected = dict(zip(entry[2], entry[3])).get(child, self.missing)
                            if previous is not expected:
                                self._taint(id(parent), child, expected, previous)
                            self._set_expected(id(parent), child, module)
                return result
            finally:
                self.import_context.reset(token)

        load._patch_creation_owner = self.creation_owner
        for owner, name, replacement in (
                (bootstrap, "module_from_spec", create),
                (util, "module_from_spec", create),
                (bootstrap, "_load_unlocked", load),
                (bootstrap, "_find_and_load_unlocked", find),
                (loader, "exec_module", execute)):
            self.originals.append((owner, name, getattr(owner, name)))
            setattr(owner, name, replacement)

    def _creation_self_check(self):
        objects, _freeze, _unfreeze = self.creation_api
        valid = False
        try:
            after = ModuleType("runtime_patch_after_window")
            young = {id(value) for value in objects() if _patch_is_instance(value, ModuleType)}
            valid = id(self.creation_canary) not in young and id(after) in young
        except (AttributeError, TypeError, ValueError, RuntimeError, OSError):
            pass
        self.metrics["creation_self_checks"] += 1
        return valid

    def _creation_enter(self):
        if self.creation_owner is not self:
            return self.creation_owner._creation_enter()
        self.creation_lock.acquire()
        try:
            self.creation_depth += 1
            if self.creation_depth != 1:
                return
            self.creation_reason = "creation window initializing"
            self.creation_owned = False
            try:
                if not all(callable(function) for function in self.creation_api):
                    self.creation_reason = "GC API unsupported"
                else:
                    # Keep this pre-freeze object alive until the window closes.
                    # Foreign frozen objects are also unfrozen at close (RF-11f).
                    self.creation_canary = ModuleType("runtime_patch_before_window")
                    self.creation_owned = True
                    self.creation_api[1]()
                    self.metrics["creation_window_freezes"] += 1
                    if self.creation_checked is None:
                        self.creation_checked = self._creation_self_check()
                    if not self.creation_checked:
                        self.creation_reason = "GC self-check failed"
                    else:
                        self.creation_reason = None
            except (AttributeError, TypeError, ValueError, RuntimeError, OSError):
                self.creation_reason = "GC API unsupported"
            except BaseException:
                self._creation_exit()
                raise
        finally:
            self.creation_lock.release()

    def _creation_exit(self):
        if self.creation_owner is not self:
            return self.creation_owner._creation_exit()
        with self.creation_lock:
            self.creation_depth -= 1
            if self.creation_depth == 0 and self.creation_owned:
                try:
                    self.creation_api[2]()
                except (AttributeError, TypeError, ValueError, RuntimeError, OSError):
                    self.pending_differences.add("creation window unavailable: GC cleanup failed")
                finally:
                    self.creation_owned = False
            if self.creation_depth == 0:
                self.creation_canary = None

    def _creation_young_modules(self):
        if self.creation_owner is not self:
            return self.creation_owner._creation_young_modules()
        with self.creation_lock:
            if self.creation_depth == 0:
                return set(), "no active window"
            if self.creation_reason is not None:
                return set(), self.creation_reason
            try:
                young = {id(value) for value in self.creation_api[0]()
                         if _patch_is_instance(value, ModuleType)}
                self.metrics["creation_censuses"] += 1
                if id(self.creation_canary) in young:
                    self.creation_reason = "canary became young"
                    return set(), self.creation_reason
                return young, None
            except (AttributeError, TypeError, ValueError, RuntimeError, OSError):
                self.creation_reason = "GC census failed"
                return set(), self.creation_reason

    def _import_receipt(self, before):
        """Retain prior module values from the guard's existing namespace records."""
        existing = set(self.module_owners)
        modules = []
        for _module, _name, namespace in dict.copy(self.module_owners).values():
            modules.extend(value for value in dict.copy(namespace).values()
                           if _patch_is_instance(value, ModuleType))
        existing.update(map(id, modules))
        existing.update(map(id, dict.copy(self._module_map()).values()))
        existing.update(id(value) for registry in before for value in registry.values())
        return {"existing": existing, "keepalive": modules, "created": set(), "active": True}

    def _approve_import_additions(self, before, receipt, package):
        """Admit import-created module values and package failure placeholders."""
        trusted = self._module_map()
        current = self._module_map("current")
        registries = (self.modules,) if current is self.modules else (self.modules, current)
        young, unavailable = None, None
        for registry in registries:
            for name, value in dict.copy(registry).items():
                if not receipt["active"]:
                    return
                if (type(name) is not str or len(name) > _CENSUS_ADDRESS_LIMIT
                        or any(name in registry_before for registry_before in before) or name in trusted
                        or not self._import_parents(name) or self._import_value_excluded(value)
                        or (name, id(value)) in self.creation_owner.excluded_bindings):
                    continue
                imported = (_patch_is_instance(value, ModuleType)
                            and id(value) in receipt["created"])
                if _patch_is_instance(value, ModuleType) and not imported:
                    if young is None:
                        young, unavailable = self._creation_young_modules()
                    imported = id(value) in young
                    if not imported and unavailable is not None:
                        self.creation_failures[name] = unavailable
                placeholder = (value is None and package and len(package) < _CENSUS_ADDRESS_LIMIT
                               and name.startswith(package + "."))
                if not (imported or placeholder):
                    continue
                if any(dict.get(other, name, self.missing) is not self.missing
                       and dict.get(other, name, self.missing) is not value
                       for other in registries if other is not registry):
                    self._observe_import_displacement(name)
                    continue
                self._module_map("publish", name, value)
                self._baseline_module(value, name)
                if imported:
                    receipt["created"].add(id(value))
                self.metrics["authenticated_import_additions"] += 1

    def _verify_baselines(self):
        self._check_consumer_uses()
        differences = set(self.pending_differences)
        self.pending_differences.clear()
        observed_registry = self._module_map("restore")
        if observed_registry is not self.modules:
            differences.add("sys.modules")
        trusted = self._module_map()
        for name in self.modules.keys() | trusted.keys():
            current = self.modules.get(name, self.missing)
            expected = trusted.get(name, self.missing)
            previous = self.import_previous.get((name, id(expected)))
            if (previous is not None and previous[0] is expected
                    and self._import_value_excluded(expected, initializer=True)):
                # An early framework cache store is provisional until exec is
                # approved. Refusal withdraws it without disrupting live exec.
                expected = previous[1]
                self._module_map("withdraw", name, expected)
            if current is not expected:
                differences.add("sys.modules[" + self._field_label(name) + "]")
                if expected is self.missing:
                    self.modules.pop(name, None)
                else:
                    self.modules[name] = expected
        if observed_registry is not self.modules and _patch_is_instance(observed_registry, dict):
            for name in dict.keys(observed_registry) | trusted.keys():
                if dict.get(observed_registry, name, self.missing) is not trusted.get(name, self.missing):
                    differences.add("sys.modules[" + self._field_label(name) + "]")
        for name, reason in self.creation_failures.copy().items():
            if ("sys.modules[" + name + "]" in differences
                    or ("sys.modules" in differences and type(observed_registry) is dict
                        and name in observed_registry)):
                path, line = ("collection", "0") if self.active is None else self._item_site(self.active)
                self.violations.add((path, str(line), "creation window unavailable",
                                     reason + ": sys.modules[" + name + "]"))
        self.creation_failures.clear()
        self.metrics["registry_bindings"] += len(trusted)
        # Every retained namespace is compared after every test. Baseline
        # tuples are reused until an authenticated operation changes them.
        for identity in tuple(self.snapshots):
            name, namespace, keys, values = self.snapshots[identity]
            while True:
                entry = self.snapshots[identity]
                name, namespace, keys, values = entry
                self.metrics["whole_checks"] += 1
                if self.active_bindings:
                    expected_now = dict(zip(keys, values))
                    for (owner, key), pending in self.active_bindings.copy().items():
                        actual = namespace.get(key, self.missing) if owner == identity else self.missing
                        if (owner == identity and actual is not expected_now.get(key, self.missing)
                                and self._pending_binding(identity, key, actual)):
                            self._set_expected(identity, key, actual, _store=True)
                    if self.snapshots[identity] is not entry:
                        continue
                self.metrics["whole_bindings"] += len(keys)
                protected = self._guarded_namespace(identity, namespace)
                same = _patch_same_bindings(protected, keys, values)
                if self.snapshots[identity] is not entry:
                    continue  # an asynchronous writer changed the expected image
                expected = dict(zip(keys, values))
                conflicts = [(key, taint)
                             for (owner, key), records in tuple(self.framework_conflicts.items())
                             if owner == identity for taint in records]
                local = {name + "." + self._field_label(key)
                         for key, taint in conflicts
                         if namespace.get(key, self.missing) is not expected.get(key, self.missing)}
                repairs = [] if same else [(key, expected.get(key, self.missing))
                    for key in protected.keys() | expected.keys()
                    if namespace.get(key, self.missing) is not expected.get(key, self.missing)]
                if self.snapshots[identity] is not entry:
                    continue
                for key, wanted in repairs:
                    local.add(name + "." + self._field_label(key))
                    if wanted is self.missing:
                        namespace.pop(key, None)
                    else:
                        namespace[key] = wanted
                if self.snapshots[identity] is not entry:
                    continue
                differences.update(local)
                if repairs:
                    self.metrics["detailed_checks"] += 1
                    self.metrics["detailed_bindings"] += len(namespace) + len(keys)
                elif identity in self.touched:
                    self.metrics["restored_touched"] += 1
                break
        self.framework_conflicts.clear()
        for name, namespace, attribute, expected in self.owned_targets.values():
            if namespace.get(attribute, self.missing) is not expected:
                differences.add(str(name) + "." + self._field_label(attribute))
                if expected is self.missing:
                    namespace.pop(attribute, None)
                else:
                    namespace[attribute] = expected
        self.owned_targets.clear()
        for name, (expected, site) in self.import_displacements.items():
            binding = "sys.modules[" + self._field_label(name) + "]"
            if binding in differences:
                expectation = "absent" if expected is self.missing else "original"
                differences.remove(binding)
                differences.add(binding + " (expected " + expectation + " binding " + binding
                                + "; first observed displaced at " + site[0] + ":" + str(site[1]) + ")")
        self.import_displacements.clear()
        return differences

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_make_collect_report(self, collector):
        token = None
        if self.started and _patch_is_instance(collector, self.collect_file_type):
            try:
                filename, _path = self._test_source(os.fspath(collector.path))
                if filename is None:
                    raise ValueError
            except (AttributeError, TypeError, ValueError, OSError, RuntimeError):
                raise pytest.UsageError(_PYTEST_API_ERROR) from None
            # Pytest collecting this file is not an import made by its code.
            # Nested imports of other modules keep their own loader receipts.
            context = {"kind": "collection", "origin": filename}
            token = self.import_context.set((*self.import_context.get(), context))
        try:
            yield
        finally:
            if token is not None:
                self.import_context.reset(token)

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_collection_finish(self, session):
        yield
        if not self.collection_adopted:
            self.collection_adopted = True
            owned = set(self.conftest_owned)
            for item in session.items:
                try:
                    module = item.module
                except AttributeError:
                    continue
                if _patch_is_instance(module, ModuleType):
                    self._baseline_module(module, item.nodeid.split("::", 1)[0])
                    owned.add(id(module))
            for identity in owned:
                _name, namespace, keys, _values = self.snapshots[identity]
                created = self._initialize_module_metadata(namespace)
                for key, value in created.items():
                    # Preserve evidence of a deleted or replaced trusted binding.
                    # Only a newly created, previously absent metadata key is ours.
                    if key not in keys:
                        self._set_expected(identity, key, value)
        for name in self._verify_baselines():
            self.violations.add(("collection", "0", "unrestored namespace", name))

    def _remember_mock_target(self, patcher, kind):
        """One construction receipt, also recovered for pre-install patchers."""
        target = None
        if kind == "mock.dict":
            candidate = getattr(patcher, "in_dict", None)
            if _patch_is_instance(candidate, str):
                target = candidate
        else:
            getter = getattr(patcher, "getter", None)
            model = self.mock_getter
            prefix = None
            if (type(getter) is partial and type(model) is partial
                    and getter.func is model.func and len(getter.args) == 1
                    and not getter.keywords):
                prefix = getter.args[0]
            elif (type(getter) is FunctionType and type(model) is FunctionType
                    and getter.__code__ is model.__code__ and getter.__globals__ is model.__globals__):
                # Python 3.9's stdlib factory closes over the module string;
                # later runtimes return partial(resolve_name, module) instead.
                actual_values = _patch_nonlocals(getter)
                expected_values = _patch_nonlocals(model)
                if len(actual_values) != len(expected_values):
                    return
                for actual, expected in zip(actual_values, expected_values):
                    if type(expected) is str and expected == "os":
                        prefix = actual
                    elif actual is not expected:
                        return
            attribute = getattr(patcher, "attribute", None)
            if _patch_is_instance(prefix, str) and _patch_is_instance(attribute, str):
                if len(prefix) + len(attribute) + 1 > _CENSUS_ADDRESS_LIMIT:
                    raise pytest.UsageError("runtime patch guard mock target metadata is unsupported")
                target = prefix + "." + attribute
        if target is None:
            target = self.target_context.get()
        if target is not None:
            if len(target) > _CENSUS_ADDRESS_LIMIT:
                raise pytest.UsageError("runtime patch guard mock target metadata is unsupported")
            self.resolved_targets[patcher] = target

    def _install(self):
        MonkeyPatch = pytest.MonkeyPatch
        FixtureRequest = pytest.FixtureRequest
        old_active_fixturedef = getattr_static(FixtureRequest, "_get_active_fixturedef")
        activate_fixture = self._activate_consumer_fixture
        _guard_mock = self.mock
        guard = self
        try:
            fixture_api = import_module("_pytest.fixtures")
            definition_types = (getattr_static(fixture_api, "FixtureDef"),)
            legacy_definition = getattr(fixture_api, "PseudoFixtureDef", None)
            if legacy_definition is not None:
                definition_types += (legacy_definition,)
            if not all(type(kind) is type for kind in definition_types):
                raise TypeError
            refuse_runtime = pytest.exit
            signature(refuse_runtime).bind(_PYTEST_API_ERROR, returncode=4)
            value_default, name_default = _patch_monkeypatch_defaults(MonkeyPatch)
        except (ImportError, AttributeError, KeyError, TypeError, ValueError, RuntimeError):
            raise pytest.UsageError(_PYTEST_API_ERROR) from None
        self.fixture_refuse = refuse_runtime

        def active_fixturedef_wrapper(self, argname):
            definition = old_active_fixturedef(self, argname)
            if guard.started and not _patch_is_instance(definition, definition_types):
                refuse_runtime(_PYTEST_API_ERROR, returncode=4)
            activate_fixture(self, definition)
            return definition

        def capture_init(original, kind):
            def initialize(patcher, *args, **kwargs):
                self.metrics["mock_constructions"] += 1
                target = args[0] if args else kwargs.get("in_dict")
                if kind == "mock.dict" and _patch_is_instance(target, str) and len(target) > _CENSUS_ADDRESS_LIMIT:
                    raise pytest.UsageError("runtime patch guard mock target metadata is unsupported")
                original(patcher, *args, **kwargs)
                self._remember_mock_target(patcher, kind)
                origin = self.origin_context.get() or self._site(sys._getframe(1), kind)
                if origin is not None:
                    with self.lock:
                        self.origins[patcher] = origin
            return initialize

        def inherit_origin(original):
            def inherited(patcher, *args, **kwargs):
                self.metrics["mock_copies"] += 1
                with self.lock:
                    origin = self.origins.get(patcher)
                token = self.origin_context.set(origin)
                target_token = self.target_context.set(self.resolved_targets.get(patcher))
                try:
                    return original(patcher, *args, **kwargs)
                finally:
                    self.target_context.reset(target_token)
                    self.origin_context.reset(token)
            return inherited

        # Keep string-form handling explicit; value/name positions differ from
        # the object form, and resolving a target twice can invoke user code.
        def resolve_owner(path, raising, method, caller):
            try:
                name, owner = self.derive_importpath(path, False)
            except BaseException:
                self.record(None, path, method, not raising, caller)
                raise
            self.record(owner, name, method, not raising, caller, resolved_target=path)
            if raising:
                # Preserve pytest's annotated AttributeError after recording
                # the resolved owner, including when that attribute is absent.
                self.annotated_getattr(owner, name, ann=path.rsplit(".", 1)[0])
            return name, owner

        def setattr_wrapper(patcher, target, name, value=value_default, raising=True):
            if value is value_default and _patch_is_instance(target, str):
                value = name
                name, target = resolve_owner(target, raising, "setattr", sys._getframe(1))
            else:
                self.record(target, name, "setattr", not raising, sys._getframe(1))
            return old_setattr(patcher, target, name, value, raising)

        def delattr_wrapper(patcher, target, name=name_default, raising=True):
            if name is name_default and _patch_is_instance(target, str):
                name, target = resolve_owner(target, raising, "delattr", sys._getframe(1))
            else:
                self.record(target, name, "delattr", not raising, sys._getframe(1))
            return old_delattr(patcher, target, name, raising)

        def setitem_wrapper(patcher, dic, name, value):
            caller = sys._getframe(1)
            if caller.f_code.co_name != "setenv" or caller.f_globals.get("__name__") != "_pytest.monkeypatch":
                self.record(dic, name, "setitem", False, caller)
            else:
                self.metrics["delegated_env"] += 1
            return old_setitem(patcher, dic, name, value)

        def delitem_wrapper(patcher, dic, name, raising=True):
            caller = sys._getframe(1)
            if caller.f_code.co_name != "delenv" or caller.f_globals.get("__name__") != "_pytest.monkeypatch":
                self.record(dic, name, "delitem", not raising, caller)
            else:
                self.metrics["delegated_env"] += 1
            return old_delitem(patcher, dic, name, raising)

        def target_wrapper(target):
            if _patch_is_instance(target, str) and len(target) > _CENSUS_ADDRESS_LIMIT:
                raise pytest.UsageError("runtime patch guard mock target metadata is unsupported")
            getter, attribute = old_target(target)
            if _patch_is_instance(target, str):
                if type(getter) not in (FunctionType, partial):
                    raise pytest.UsageError("runtime patch guard mock target API is unsupported")
            return getter, attribute

        def enter_wrapper(patcher):
            getter = patcher.getter
            try:
                owner = getter()
            except BaseException:
                self.record(None, patcher.attribute, "mock", patcher.create, sys._getframe(1),
                            self.origins.get(patcher))
                raise
            resolved_target = self.resolved_targets.get(patcher)
            self.record(owner, patcher.attribute, "mock", patcher.create, sys._getframe(1),
                        self.origins.get(patcher), resolved_target=resolved_target)
            patcher.getter = lambda: owner
            try:
                return old_enter(patcher)
            finally:
                patcher.getter = getter

        def dict_patch_wrapper(patcher):
            try:
                return old_dict_patch(patcher)
            finally:
                # Context managers, start() and decorators all use this entry.
                # Let mock resolve strings with its interpreter-specific logic.
                prior = patcher._original
                keys = (set(prior) | set(patcher.in_dict) if prior is not None and patcher.clear
                        else patcher.values)
                self.record(patcher.in_dict, "<item>", "mock.dict", False, sys._getframe(1),
                            self.origins.get(patcher), prior=prior, keys=keys,
                            resolved_target=self.resolved_targets.get(patcher))

        old_setattr = getattr_static(MonkeyPatch, "setattr")
        old_delattr = getattr_static(MonkeyPatch, "delattr")
        old_setitem = getattr_static(MonkeyPatch, "setitem")
        old_delitem = getattr_static(MonkeyPatch, "delitem")
        old_target = _guard_mock._get_target
        try:
            model = old_target("os.path")
            if type(model) is not tuple or len(model) != 2 or type(model[1]) is not str or model[1] != "path":
                raise ValueError
            getter = model[0]
            if type(getter) is partial:
                if (len(getter.args) != 1 or type(getter.args[0]) is not str
                        or getter.args[0] != "os" or getter.keywords):
                    raise ValueError
            elif type(getter) is FunctionType:
                if len(getter.__closure__ or ()) > 16:
                    raise ValueError
                if not any(type(value) is str and value == "os" for value in _patch_nonlocals(getter)):
                    raise ValueError
            else:
                raise ValueError
            self.mock_getter = getter
        except (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
            raise pytest.UsageError(_PYTEST_API_ERROR) from None
        # Recover standard factory receipts before any test can activate an
        # existing context manager or a patcher held by a decorator closure.
        gc_api = import_module("gc")
        get_objects = getattr(gc_api, "get_objects", None)
        get_referrers = getattr(gc_api, "get_referrers", None)
        if not callable(get_objects) or not callable(get_referrers):
            raise pytest.UsageError(_PYTEST_API_ERROR)
        self.namespace_referrers = get_referrers
        for candidate in get_objects():
            if type(candidate) is _guard_mock._patch:
                self._remember_mock_target(candidate, "mock")
            elif type(candidate) is _guard_mock._patch_dict:
                self._remember_mock_target(candidate, "mock.dict")
        old_enter = _guard_mock._patch.__enter__
        old_dict_patch = _guard_mock._patch_dict._patch_dict
        for owner, name, replacement in (
                (FixtureRequest, "_get_active_fixturedef", active_fixturedef_wrapper),
                (_guard_mock, "_get_target", target_wrapper),
                (_guard_mock._patch, "__init__", capture_init(_guard_mock._patch.__init__, "mock")),
                (_guard_mock._patch, "copy", inherit_origin(_guard_mock._patch.copy)),
                (_guard_mock._patch_dict, "__init__", capture_init(_guard_mock._patch_dict.__init__, "mock.dict")),
                (_guard_mock._patch_dict, "decorate_class", inherit_origin(_guard_mock._patch_dict.decorate_class)),
                (MonkeyPatch, "setattr", setattr_wrapper),
                (MonkeyPatch, "delattr", delattr_wrapper),
                (MonkeyPatch, "setitem", setitem_wrapper),
                (MonkeyPatch, "delitem", delitem_wrapper),
                (_guard_mock._patch, "__enter__", enter_wrapper),
                (_guard_mock._patch_dict, "_patch_dict", dict_patch_wrapper)):
            self.originals.append((owner, name, getattr(owner, name)))
            setattr(owner, name, replacement)

    @staticmethod
    def _item_site(item):
        path = os.path.relpath(os.path.abspath(str(item.path)), REPO_ROOT).replace(os.sep, "/")
        line = item.location[1]
        return path, 0 if line is None else line + 1

    @staticmethod
    def _test_source(filename):
        """Normalize code metadata without reading source files."""
        if (type(filename) is not str or len(filename) > _CENSUS_ADDRESS_LIMIT
                or filename.startswith("<")):
            return None, None
        try:
            absolute = os.path.abspath(filename)
            normalized = _patch_path_key(absolute)
            prefix = _patch_path_key(os.path.abspath(TESTS_DIR)) + "/"
            path = (os.path.relpath(absolute, REPO_ROOT).replace(os.sep, "/")
                    if normalized.startswith(prefix) else None)
            return normalized, path
        except (OSError, ValueError):
            return None, None

    @staticmethod
    def _source_site_path(filename):
        try:
            path = os.path.relpath(filename, REPO_ROOT)
        except ValueError:
            path = filename  # Windows has no relative path across drives.
        return path.replace(os.sep, "/")

    def _callback_site(self, first, caller, field, origin):
        function = caller.f_locals.get(field)
        if field == "item":
            function = getattr_static(function, "_obj", None)
        if type(function) is MethodType:
            function = function.__func__
        if type(function) is not FunctionType:
            return None
        candidate = first
        try:
            while candidate is not None and candidate is not caller:
                if candidate.f_code is function.__code__:
                    # Only an authenticated stdlib decorator can supply a
                    # callback source before that callback has an active frame.
                    namespace = ModuleType.__getattribute__(self.mock, "__dict__")
                    seen = set()
                    for _ in range(32):
                        if function.__globals__ is not namespace:
                            break
                        if (id(function) in seen
                                or self.bookkeeping_codes.get(id(function.__code__)) is not function.__code__):
                            self.fixture_refuse(_PYTEST_API_ERROR, returncode=4)
                        seen.add(id(function))
                        wrapped = getattr_static(function, "__wrapped__", self.missing)
                        if not any(value is wrapped for value in _patch_nonlocals(function)):
                            self.fixture_refuse(_PYTEST_API_ERROR, returncode=4)
                        function = wrapped.__func__ if type(wrapped) is MethodType else wrapped
                        if type(function) is not FunctionType:
                            self.fixture_refuse(_PYTEST_API_ERROR, returncode=4)
                    else:
                        self.fixture_refuse(_PYTEST_API_ERROR, returncode=4)
                    filename, _path = self._test_source(function.__code__.co_filename)
                    if filename is None:
                        self.fixture_refuse(_PYTEST_API_ERROR, returncode=4)
                    if filename == _patch_path_key(os.path.abspath(__file__)):
                        return None  # preserve the guard file's per-item fixture attribution
                    path = self._source_site_path(filename)
                    source = origin if origin is not None else candidate
                    return path, source.f_lineno, _patch_runtime_site(source, candidate)
                candidate = candidate.f_back
            return None
        finally:
            del candidate

    def _recorded_by_child(self, frame):
        if frame is None or frame.f_code not in self.guard_codes:
            return False
        if frame.f_code.co_name not in {
                "setattr_wrapper", "delattr_wrapper", "setitem_wrapper", "delitem_wrapper",
                "enter_wrapper", "dict_patch_wrapper"}:
            return False
        child = frame.f_locals.get("self")
        return (child is not self and type(child) is frame.f_globals.get("_PatchGuard")
                and child.import_parent is self and child.started and not child.closing)

    def _site(self, frame, attribute):
        origin = None
        first = frame
        test_frame = False
        guard_filename = _patch_path_key(os.path.abspath(__file__))
        while frame is not None:
            if frame.f_code in self.guard_codes:
                frame = frame.f_back
                continue
            test_frame = test_frame or id(frame.f_code) in getattr(self, "untrusted_hook_codes", ())
            owner = self.namespace_owners.get(id(frame.f_globals))
            module_name = owner[1] if owner is not None and owner[2] is frame.f_globals else None
            engine = (type(module_name) is str and module_name.startswith("_pytest.")
                      and (self.hook_attribution_codes.get(id(frame.f_code)) is frame.f_code
                           or self.hook_codes.get(id(frame.f_code)) is frame.f_code))
            dispatcher = (type(module_name) is str and module_name.startswith("pluggy.")
                          and self.bookkeeping_codes.get(id(frame.f_code)) is frame.f_code)
            field = None
            if engine:
                if module_name == "_pytest.python" and frame.f_code.co_name == "pytest_pyfunc_call":
                    field = "testfunction"
                elif module_name == "_pytest.fixtures" and frame.f_code.co_name in {
                        "call_fixture_func", "_teardown_yield_fixture"}:
                    field = "fixturefunc"
                elif module_name == "_pytest.runner" and frame.f_code.co_name == "pytest_runtest_call":
                    field = "item"
            if field is not None:
                site = self._callback_site(first, frame, field, origin)
                if site is not None:
                    return site
            if frame.f_code in self._pytest_main_codes and not test_frame:
                enclosing = frame.f_back
                while enclosing is not None:
                    if enclosing.f_code in self._pytest_main_codes:
                        if origin is None:
                            return None  # only authenticated bookkeeping precedes this entry
                        filename, _path = self._test_source(origin.f_code.co_filename)
                        if filename is None:
                            self.fixture_refuse(_PYTEST_API_ERROR, returncode=4)
                        path = self._source_site_path(filename)
                        return path, origin.f_lineno, _patch_runtime_site(origin, None)
                    enclosing = enclosing.f_back
            filename, path = self._test_source(frame.f_code.co_filename)
            if path is not None and filename != guard_filename:
                if origin is None:
                    return path, frame.f_lineno, frame.f_lasti
                return path, origin.f_lineno, _patch_runtime_site(origin, frame)
            if origin is None and filename != guard_filename:
                mock_frame = owner is not None and owner[0] is self.mock
                if (not engine and not dispatcher and not mock_frame
                        and frame.f_code not in self._pytest_main_codes):
                    origin = frame
            frame = frame.f_back
        if self.active is not None:
            path, line = self._item_site(self.active)
            if origin is not None:
                return path, origin.f_lineno, _patch_runtime_site(origin, None)
            return path, line, str(attribute)
        return None

    def record(self, owner, attribute, method, permissive, frame, site=None, *, prior=None, keys=None,
               resolved_target=None):
        if not self.started:
            return
        if self._recorded_by_child(frame):
            return
        site = site or self._site(frame, attribute)
        if site is None:
            return
        with self.lock:
            self.metrics["guard_" + method] += 1
            module_name = None
            module = None
            if _patch_is_instance(owner, ModuleType):
                module = owner
                namespace = ModuleType.__getattribute__(owner, "__dict__")
                module_name = namespace.get("__name__", "<module>")
            elif _patch_is_instance(owner, dict):
                entry = self.namespace_owners.get(id(owner))
                if entry is None and owner is not self.modules:
                    entry = self._module_map("namespace", owner)
                    if entry is not None:
                        self.namespace_owners[id(owner)] = entry
                if entry is not None:
                    module, module_name, namespace = entry
            if module is not None:
                original = namespace if prior is None else prior
                if prior is not None:
                    module_name = prior.get("__name__", module_name)
                if (id(module) in self.test_owned
                        or (prior is not None and id(module) not in self.snapshots)
                        or self._test_owned_module(module, original, fresh=True)):
                    for key in ((attribute,) if keys is None else keys):
                        if id(module) not in self.snapshots:
                            self.owned_targets.setdefault((id(namespace), key),
                                (module_name, namespace, key, original.get(key, self.missing)))
                        self.owned_calls.add((site[0], str(site[1]), str(module_name) + "." + str(key)))
                elif id(module) in self.snapshots:
                    self.touched.add(id(module))
                else:
                    # Uncached module objects can still become shared patch
                    # owners (for example overlapping thread contexts).
                    self._baseline_module(module, module_name)
                    self.touched.add(id(module))
            shared = owner is not None and (
                id(owner) in self.process_owners or owner is self.modules
                or owner is getattr(os, "environ", self.missing)
                or owner is self._module_map("current"))
            if module_name is not None or shared or permissive:
                self.calls.add((*site, method, str(module_name), str(attribute), bool(permissive)))
            if shared:
                self.sites.add(site)
            # RF-11b explicitly permits non-creating capability deletions.
            # Environment helpers delegate to delitem/setitem and are not
            # attribute creation; their static registrations remain authoritative.
            if permissive and method in {"setattr", "mock"}:
                field = str(attribute)
                target = str(module_name) + "." + field
                platform_allowed = module is not None and any(
                    module is self._module_map().get(owner_name, self.missing) and field == owner_field
                    for owner_name, owner_field in self.platform_targets)
                allowed = (platform_allowed
                           or (not shared and self._written_builtin(owner, field, site, resolved_target)))
                if not allowed:
                    if (not shared and _patch_is_instance(owner, ModuleType)
                            and not any(module is owner for module in self._module_map().values())):
                        self.pending_consumers[id(owner), field, site, id(resolved_target)] = owner, target, resolved_target
                    else:
                        self.violations.add((site[0], str(site[1]), "permits a missing target", target))

    def _check_consumer_uses(self):
        uses, self.pending_consumers = self.pending_consumers, {}
        for (_identity, field, site, _target_identity), (owner, target, resolved_target) in uses.items():
            if not self._written_builtin(owner, field, site, resolved_target):
                self.violations.add((site[0], str(site[1]), "permits a missing target", target))

    def _written_builtin(self, owner, field, site, resolved_target=None):
        """Match observed consumer subjects or canonical construction receipts."""
        if not _patch_is_instance(owner, ModuleType):
            return False
        path, _line, _ = site
        path = _patch_path_key(path)
        targets = [target for (filename, target) in self.policy["BUILTIN_GLOBALS"]
                   if _patch_path_key(filename) == path and target.rsplit(".", 1)[-1] == field]
        if not targets:
            return False
        trusted = self._module_map()
        if not any(module is owner for module in trusted.values()):
            return any(self._module_map("owned", (path, target.rsplit(".", 1)[0]), owner)
                       for target in targets)
        names = [target.rsplit(".", 1)[0] for target in targets
                 if resolved_target is None or target == resolved_target]
        if any((trusted.get(name, self.missing) if resolved_target is not None
                else self._module_map("imported", name)) is owner for name in names):
            return True
        if any(self._module_map("binding", (path, name)) is owner for name in names):
            return True
        return False

    def _start_fixture_execution(self, definition, request):
        """Only an actual setup invocation creates an execution token."""
        if self._fixture_graph_node(definition) is not None:
            self.fixture_refuse(_PYTEST_API_ERROR, returncode=4)
        node = {"definition": definition, "token": object(), "ready": False,
                "recording": True, "module": None, "edges": {}}
        self.fixture_graph[id(definition)] = node
        selected = self._fixture_view(self._fixture_request_chain(request))
        if selected is not None:
            for name, child in selected.items():
                self._record_fixture_dependency(node, name, self._fixture_graph_node(child))
        return node

    def _end_fixture_execution(self, node):
        """Finalization and failed setup share the sole edge-removal rule."""
        identity = id(node["definition"])
        if self.fixture_graph.get(identity) is node:
            self.fixture_graph.pop(identity)
            for context, selected in tuple(self.fixture_selections.items()):
                if context[0] == identity or any(value is node["definition"] for value in selected.values()):
                    self.fixture_selections.pop(context)
        node["recording"] = False
        node["ready"] = False
        node["module"] = None
        node["edges"].clear()

    def _record_fixture_dependency(self, node, name, child):
        if (node["recording"] and child is not None
                and self._fixture_graph_node(node["definition"]) is node
                and self._fixture_graph_node(child["definition"]) is child):
            node["edges"].setdefault(child["token"], (name, child))

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_fixture_setup(self, fixturedef, request):
        item = getattr(request, "_pyfuncitem", None)
        node = None
        if (self.started and item is self.active
                and getattr(request, "_fixturedef", None) is fixturedef):
            node = self._start_fixture_execution(fixturedef, request)
        outcome = yield
        if node is None:
            return
        if outcome.excinfo is not None or not self.started or item is not self.active:
            self._end_fixture_execution(node)
            return
        if self._fixture_graph_node(fixturedef) is not node:
            return
        result = outcome.get_result()
        cached = getattr(fixturedef, "cached_result", None)
        if (type(cached) is not tuple or len(cached) != 3
                or cached[0] is not result or cached[2] is not None):
            self._end_fixture_execution(node)
            return
        # Publishing a cache value promotes this execution in place. Its
        # token and all body/post-yield dependency edges remain unchanged.
        node["module"] = ref(result) if _patch_is_instance(result, ModuleType) else None
        node["ready"] = True

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_fixture_post_finalizer(self, fixturedef, request):
        node = self._fixture_graph_node(fixturedef)
        try:
            yield
        finally:
            if node is not None:
                self._end_fixture_execution(node)

    def _fixture_graph_node(self, definition):
        node = self.fixture_graph.get(id(definition))
        return node if node is not None and node["definition"] is definition else None

    @staticmethod
    def _fixture_request_chain(request):
        """Keep the selected caller chain without retaining request objects."""
        chain, seen = [], set()
        try:
            while getattr(request, "_fixturedef", None) is not None:
                if id(request) in seen:
                    return None
                seen.add(id(request))
                definition = request._fixturedef
                if not _patch_is_instance(getattr(definition, "argname", None), str):
                    return None
                chain.append(definition)
                request = getattr(request, "_parent_request", None)
                if request is None:
                    return None
        except (AttributeError, LookupError, TypeError, ValueError, RuntimeError):
            return None
        return tuple(reversed(chain))

    def _fixture_context(self, chain):
        """Retain only ancestor counts that can affect remaining dependencies."""
        if chain is None:
            return None
        if not chain:
            return None, ()
        parent = chain[-1]
        try:
            names = set(parent.argnames)
            node = self._fixture_graph_node(parent)
            pending, seen = ([node] if node is not None else []), set()
            while pending:
                node = pending.pop()
                if node["token"] in seen:
                    continue
                seen.add(node["token"])
                names.update(node["definition"].argnames)
                for name, child in node["edges"].values():
                    names.add(name)
                    pending.append(child)
            counts = Counter(ancestor.argname for ancestor in chain if ancestor.argname in names)
        except (AttributeError, TypeError, ValueError):
            return None
        return id(parent), tuple(sorted(counts.items()))

    def _fixture_view(self, chain):
        context = self._fixture_context(chain)
        if context is None:
            return None
        return self.fixture_selections.setdefault(context, {})

    def _resolve_fixture_definition(self, name, chain):
        """Resolve metadata as pytest does, without executing fixture values."""
        selected = self._fixture_view(chain)
        if selected is None:
            return None
        if name in selected:
            return selected[name]
        definition = None
        try:
            request = self.active._request
            # Collection includes direct parametrization definitions here.
            definitions = request._arg2fixturedefs.get(name)
            if definitions is None:
                definitions = request._fixturemanager.getfixturedefs(name, self.active)
            if _patch_is_instance(definitions, (tuple, list)) and definitions:
                # As in pytest's definition-selection branch, a fixture asking
                # for its own name consumes one override level per caller.
                index = -1 - sum(ancestor.argname == name for ancestor in chain)
                if -index <= len(definitions):
                    definition = definitions[index]
        except (AttributeError, LookupError, TypeError, ValueError, RuntimeError):
            definition = None
        selected[name] = definition
        return definition

    def _activate_consumer_fixture(self, request, definition):
        """An observed cached view never changes the execution's setup edges."""
        item = getattr(request, "_pyfuncitem", None)
        if not self.started or item is not self.active:
            return
        name = getattr(definition, "argname", None)
        if not _patch_is_instance(name, str) or name == "request":
            return
        node = self._fixture_graph_node(definition)
        if node is not None:
            # This return closes the actual setup, including wrappers outside
            # our hook. Cache population alone does not close that interval.
            node["recording"] = False
        chain = self._fixture_request_chain(request)
        selected = self._fixture_view(chain)
        if selected is None:
            return
        selected[name] = definition
        parent = getattr(request, "_fixturedef", None)
        if parent is not None and parent is not definition:
            execution = self._fixture_graph_node(parent)
            if execution is not None:
                self._record_fixture_dependency(execution, name, node)
        elif node is not None:
            context = self._fixture_context(chain)
            self.fixture_roots[node["token"], context] = node, chain
        if node is not None:
            self._activate_fixture_graph(((node, chain),))

    def _fixture_sources(self, callback):
        """Validate at most 32 function links before publishing any source."""
        seen, sources = set(), set()
        for _ in range(32):
            if type(callback) is MethodType:
                callback = callback.__func__
            if type(callback) is not FunctionType or id(callback) in seen:
                return ()
            seen.add(id(callback))
            source = self._test_source(callback.__code__.co_filename)[1]
            if source is not None:
                sources.add(source)
            wrapped = getattr_static(callback, "__wrapped__", self.missing)
            if wrapped is self.missing:
                return tuple(sorted(sources))
            callback = wrapped
        return ()

    def _activate_fixture_graph(self, roots):
        """Every edge must match the current item's selected definition."""
        if not self.started or self.active is None:
            return
        pending, seen = list(roots), set()
        while pending:
            node, chain = pending.pop()
            definition = node["definition"]
            if any(ancestor is definition for ancestor in chain):
                continue
            if self._fixture_graph_node(definition) is not node or not node["ready"]:
                continue
            context = self._fixture_context(chain + (definition,))
            if context is None:
                continue
            key = node["token"], context
            if key in seen:
                continue
            seen.add(key)
            cached = getattr(definition, "cached_result", None)
            if type(cached) is not tuple or len(cached) != 3 or cached[2] is not None:
                continue
            child_chain = chain + (definition,)
            for name, child in tuple(node["edges"].values()):
                selected = self._resolve_fixture_definition(name, child_chain)
                if selected is child["definition"]:
                    pending.append((child, child_chain))
            module = node["module"]
            if module is not None and cached[0] is module():
                path, _ = self._item_site(self.active)
                self._module_map("fixture", (path, definition.argname), cached[0])
                for source in self._fixture_sources(definition.func):
                    self._module_map("fixture", (source, definition.argname), cached[0])

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_runtest_setup(self, item):
        self.active = item
        self.fixture_owners.clear()
        self.fixture_selections.clear()
        self.fixture_roots.clear()
        self.current_module = getattr(item, "module", None)
        self.test_owned = self.conftest_owned | {id(self.current_module)}
        self.untrusted_hook_codes = set()
        self.readonly_hook_codes = set()
        callbacks = [(getattr(item, "obj", None), False)]
        fixture_info = getattr(item, "_fixtureinfo", None)
        for definitions in getattr(fixture_info, "name2fixturedefs", {}).values():
            callbacks.extend((definition.func, True) for definition in definitions)
        for callback, fixture in callbacks:
            actual = callback.__func__ if type(callback) is MethodType else callback
            seen = set()
            while type(actual) is FunctionType and id(actual) not in seen:
                seen.add(id(actual))
                filename = os.path.normcase(os.path.abspath(actual.__code__.co_filename))
                if not fixture and self._hook_readonly_adapter(actual):
                    self.readonly_hook_codes.add(id(actual.__code__))
                if ((fixture and filename not in self.pytest_files)
                        or (not fixture and filename not in self.hook_files and not self._hook_readonly_adapter(actual))):
                    self.untrusted_hook_codes.add(id(actual.__code__))
                actual = actual.__dict__.get("__wrapped__")
        self._hook_index_modules()
        self._hook_instrument([getattr(item, "obj", None)])
        self.touched = set()
        self.owned_targets = {}
        self.process_owners.update((id(os.environ), id(self.modules)))
        self.metrics["tests"] += 1
        yield
        self._activate_fixture_graph(tuple(self.fixture_roots.values()))

    def _test_owned_module(self, module, namespace, *, fresh=False):
        if module is self.current_module:
            return True
        filename = namespace.get("__file__")
        if (_patch_is_instance(filename, str) and filename.endswith("conftest.py")
                and os.path.basename(filename) == "conftest.py"
                and os.path.normcase(os.path.abspath(filename)).startswith(
                    os.path.normcase(TESTS_DIR) + os.sep)):
            return True
        if not fresh:
            return False
        return self._fresh_module_owned(module)

    def _fresh_module_owned(self, module):
        # Ownership follows the actual registry entry, never mutable metadata.
        # Recheck uniqueness on every call: a later alias revokes ownership.
        if id(module) in self.snapshots:
            return False
        candidates = self._module_map("current").copy()
        trusted = self._module_map()
        self.metrics.update(fresh_owner_checks=1,
                            fresh_owner_registry_bindings=len(candidates) + len(trusted))
        names = [name for name, candidate in candidates.items() if candidate is module]
        if len(names) != 1 or not _patch_is_instance(names[0], str):
            return False
        name = names[0]
        if name in trusted or any(candidate is module for candidate in trusted.values()):
            return False
        path = None
        parts = name.split(".")
        try:
            for index in range(len(parts)):
                prefix = ".".join(parts[:index + 1])
                spec = (BuiltinImporter.find_spec(prefix)
                        or FrozenImporter.find_spec(prefix)
                        or PathFinder.find_spec(prefix, path))
                if index == len(parts) - 1:
                    return spec is None
                parent = trusted.get(prefix)
                parent_namespace = (ModuleType.__getattribute__(parent, "__dict__")
                                    if _patch_is_instance(parent, ModuleType) else {})
                if "__path__" in parent_namespace:
                    path = parent_namespace["__path__"]
                elif spec is None:
                    return True
                else:
                    path = spec.submodule_search_locations
                if path is None:
                    return True
        except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
            # An indeterminate import probe cannot grant an exemption.
            return False
        return False

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_runtest_teardown(self, item, nextitem):
        outcome = yield
        differences = self._verify_baselines()
        self.active = None
        if differences:
            outcome.force_exception(pytest.fail.Exception(
                "unrestored namespace: " + ", ".join(_patch_display(value) for value in sorted(differences)),
                pytrace=False))

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_runtest_protocol(self, item, nextitem):
        yield
        # Reporting callbacks run after pytest_runtest_teardown. Their test
        # callbacks receive no framework authority and must also be repaired
        # before another item can consume the changed namespace.
        differences = self._verify_baselines()
        if differences:
            message = "unrestored namespace: " + ", ".join(
                _patch_display(value) for value in sorted(differences))
            report = pytest.TestReport(item.nodeid, item.location, dict.fromkeys(item.keywords),
                                       "failed", message, "teardown")
            item.ihook.pytest_runtest_logreport(report=report)
            for name in self._verify_baselines():
                path, line = self._item_site(item)
                self.violations.add((path, str(line), "unrestored namespace", name))

    @pytest.hookimpl(optionalhook=True)
    def pytest_testnodedown(self, node, error):
        output = getattr(node, "workeroutput", {})
        self.sites.update(tuple(site) for site in output.get("patch_guard_sites", ()))
        self.calls.update(tuple(row) for row in output.get("patch_guard_calls", ()))
        self.owned_calls.update(tuple(row) for row in output.get("patch_guard_owned_calls", ()))
        self.violations.update(tuple(row) for row in output.get("patch_guard_violations", ()))
        worker_metrics = dict(output.get("patch_guard_metrics", {}))
        maximum = worker_metrics.pop("maximum_namespace", 0)
        self.metrics.update(worker_metrics)
        self.metrics["maximum_namespace"] = max(self.metrics["maximum_namespace"], maximum)

    def pytest_sessionfinish(self, session, exitstatus):
        self._check_consumer_uses()
        if hasattr(self.config, "workeroutput"):
            self.config.workeroutput["patch_guard_sites"] = sorted(self.sites, key=repr)
            self.config.workeroutput["patch_guard_calls"] = sorted(self.calls, key=repr)
            self.config.workeroutput["patch_guard_owned_calls"] = sorted(self.owned_calls)
            self.config.workeroutput["patch_guard_violations"] = sorted(self.violations)
            self.config.workeroutput["patch_guard_metrics"] = dict(self.metrics)
        paths = {}
        for site in sorted(self.sites, key=repr):
            paths.setdefault(_patch_path_key(site[0]), site[0])
        for key, path in paths.items():
            count = len({site[1:] for site in self.sites if _patch_path_key(site[0]) == key})
            limit = self.patch_limits.get(key, 0)
            if count > limit:
                self.violations.add((path, "0", "shared module patch count %s exceeds %s" % (count, limit), ""))
        if self.violations and session.exitstatus == 0:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED

    def pytest_terminal_summary(self, terminalreporter):
        permissive = len({row[:3] for row in self.calls if row[3] in {"setattr", "mock"} and row[6]})
        terminalreporter.write_line("runtime patch guard observed %s shared site(s), %s permissive attribute site(s)" %
                                   (len(self.sites), permissive))
        terminalreporter.write_line("runtime patch guard metrics: " + repr(dict(sorted(self.metrics.items()))))
        for row in sorted(self.owned_calls):
            terminalreporter.write_line("runtime patch guard attribution: " + ":".join(
                _patch_display(value) for value in row))
        if self.violations:
            terminalreporter.section("runtime patch guard", red=True)
            for row in sorted(self.violations):
                terminalreporter.write_line(":".join(_patch_display(value) for value in row), red=True)

    def pytest_unconfigure(self, config):
        if self.nested_tests_path is not None:
            module, previous, installed, namespace = self.nested_tests_path
            if namespace.get("__path__") is installed:
                namespace["__path__"] = previous
                self.import_parent._set_expected(id(module), "__path__", previous)
            self.nested_tests_path = None
        with self.lock:
            self.closing = True
            self.started = False
        for owner, name, original in reversed(self.originals):
            if type(owner) is dict:
                if original is self.missing:
                    owner.pop(name, None)
                else:
                    owner[name] = original
            else:
                if original is self.missing:
                    delattr(owner, name)
                else:
                    setattr(owner, name, original)
        self.originals.clear()
        # Escaped plugin callbacks retain their dispatcher closure. After the
        # session it performs plain stores and holds no namespace/code cache.
        for mapping in (self.module_owners, self.namespace_owners, self.snapshots,
                        self.hook_compiled, self.hook_sources, self.hook_codes,
                        self.hook_attribution_codes, self.bookkeeping_codes,
                        self.hook_indexed_modules, self.import_writer_codes,
                        self.loading_modules, self.framework_conflicts):
            mapping.clear()
        self._module_map().clear()
        self.unapproved_initializers.clear()
        self.creation_failures.clear()
        self.import_exclusions.clear()
        self.excluded_bindings.clear()
        self.import_previous.clear()
        self.modules = None
        self.import_context.set(())
        self.pending_differences.clear()
        self.import_displacements.clear()
        self.consumer_owners.clear()
        self.fixture_owners.clear()
        for node in tuple(self.fixture_graph.values()):
            self._end_fixture_execution(node)
        self.fixture_selections.clear()
        self.fixture_roots.clear()
        self.fixture_refuse = None
        self.pending_consumers.clear()
        self.namespace_referrers = None
        self.consumer_spellings.clear()
        self.resolved_targets.clear()
        self.mock_getter = None
        self.target_context.set(None)
        self.framework_owned.clear()
        self.hook_instrumented.clear()
        self.hook_callback_parents.clear()
        self.hook_delegated.clear()
        self.hook_private_names.clear()
        self.active_bindings.clear()
        self.store_versions.clear()
        self.readonly_hook_codes.clear()
        self.guard_codes.clear()


# Filesystem mutation events in CPython's documented audit table (3.9/3.12):
# https://docs.python.org/3.12/library/audit_events.html
# File writes themselves are covered at write-capable open time. This is a
# regression census of exercised Python code, not a sandbox for hostile code,
# native extensions, subprocesses or descriptors opened before hook startup.
_WRITE_EVENTS = frozenset({
    "os.rename", "os.link", "os.symlink", "os.truncate", "os.mkdir", "os.remove",
    "os.rmdir", "os.chmod", "os.chown", "os.chflags", "os.utime",
    "os.setxattr", "os.removexattr", "shutil.move", "shutil.copyfile",
    "shutil.copymode", "shutil.copystat", "shutil.copytree", "shutil.rmtree",
    "shutil.chown", "shutil.make_archive", "shutil.unpack_archive",
    "tempfile.mkstemp", "tempfile.mkdtemp", "sqlite3.connect",
})
_WRITE_FLAGS = os.O_CREAT | os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_TRUNC
_READ_ONLY_MMAP_ACCESS = frozenset({mmap.ACCESS_READ, mmap.ACCESS_COPY})
_CENSUS_EVENTS = _WRITE_EVENTS | frozenset({
    "open", "mmap.__new__", "msvcrt.open_osfhandle", "socket.bind", "exec",
})
_CensusCode = namedtuple("_CensusCode", "code site owned forwards callbacks key declared")
_TestModuleCodes = namedtuple("_TestModuleCodes", "module spec codes compiled")
_TestImportCodes = namedtuple("_TestImportCodes", "module spec body codes executor namespace")
_CENSUS_SOURCE_LIMIT = 1024 * 1024
_CENSUS_ADDRESS_LIMIT = 4096
_ANONYMOUS_SCOPES = {
    ast.Lambda: "<lambda>", ast.ListComp: "<listcomp>", ast.SetComp: "<setcomp>",
    ast.DictComp: "<dictcomp>", ast.GeneratorExp: "<genexpr>",
}
_SCOPE_BRANCHES = (ast.stmt, ast.ExceptHandler)
if hasattr(ast, "match_case"):
    _SCOPE_BRANCHES += (ast.match_case,)


def _census_source(filename):
    with open(filename, encoding="utf-8") as stream:
        source = stream.read(_CENSUS_SOURCE_LIMIT + 1)
    if len(source) > _CENSUS_SOURCE_LIMIT:
        raise ValueError("census source limit")
    return ast.parse(source, filename=filename)


class _TestCodeIndex:
    """Trust whole import trees, never filenames or namespace reachability."""
    def __init__(self):
        self.modules = {}
        self.imports = {}
        self.dict_slots = {}
        self.lock = RLock()

    @staticmethod
    def _namespace(module):
        return ModuleType.__dict__["__dict__"].__get__(module)

    @staticmethod
    def _class_namespace(owner):
        return type.__dict__["__dict__"].__get__(owner)

    @classmethod
    def _class_member(cls, owner, name):
        for base in type.__dict__["__mro__"].__get__(owner):
            members = cls._class_namespace(base)
            if name in members:
                return members[name]
        return None

    def _instance_namespace(self, value):
        kind = type(value)
        record = self.dict_slots.get(id(kind))
        if record is None:
            slot = None
            for base in type.__dict__["__mro__"].__get__(kind):
                candidate = self._class_namespace(base).get("__dict__")
                if type(candidate) is GetSetDescriptorType or type(candidate) is MemberDescriptorType:
                    slot = candidate
                    break
            record = (kind, slot)
            self.dict_slots[id(kind)] = record
        data = record[1].__get__(value, kind) if record[1] is not None else None
        return data if type(data) is dict else {}

    @staticmethod
    def _add_code(code, codes):
        pending = [code]
        while pending:
            item = pending.pop()
            identity = id(item)
            if identity in codes:
                continue
            codes[identity] = item
            pending.extend(child for child in item.co_consts if type(child) is CodeType)

    def _module_codes(self, module):
        namespace = self._namespace(module)
        spec = namespace.get("__spec__")
        loader = self._instance_namespace(spec).get("loader")
        if loader is None or loader is not namespace.get("__loader__"):
            return {}
        try:
            method = self._class_member(type(loader), "get_code")
            if type(method) in (FunctionType, classmethod, staticmethod):
                code = method.__get__(loader, type(loader))(namespace["__name__"])
            elif type(loader) is AssertionRewritingHook:
                # Pytest's loader has no get_code. Recreate its compilation
                # without executing the module or writing a bytecode cache.
                origin = namespace["__file__"]
                with open(origin, "rb") as stream:
                    source = stream.read(_CENSUS_SOURCE_LIMIT + 1)
                if len(source) > _CENSUS_SOURCE_LIMIT:
                    return {}
                tree = ast.parse(source, filename=origin)
                rewrite_asserts(tree, source, module_path=origin,
                                config=self._instance_namespace(loader).get("config"))
                code = compile(tree, origin, "exec", dont_inherit=True)
            else:
                return {}
        except (ImportError, OSError, SyntaxError, ValueError):
            return {}  # unavailable provenance grants nothing
        if type(code) is not CodeType:
            return {}
        codes, compiled = {}, {}
        self._add_code(code, codes)
        codes.pop(id(code), None)  # module-body replay never gains authority
        for child in codes.values():
            compiled.setdefault((child.co_filename, child.co_firstlineno), []).append(child)
        return compiled

    def preload(self, state):
        # Each start closes any unobserved interval for this root. Recompile
        # before fault injection; the write hook performs no source I/O.
        seen = set()
        for module in tuple(sys.modules.values()):
            if not issubclass(type(module), ModuleType):
                continue
            namespace = self._namespace(module)
            origin = namespace.get("__file__")
            name = namespace.get("__name__")
            if (type(origin) is not str or len(origin) > _CENSUS_SOURCE_LIMIT
                    or type(name) is not str or sys.modules.get(name) is not module
                    or os.path.normcase(os.path.abspath(origin)) not in state.test_files):
                continue
            if id(module) in seen:
                continue
            seen.add(id(module))
            compiled = self._module_codes(module)
            with self.lock:
                previous = self.modules.get(id(module))
                codes = {}
                if previous is not None and previous.module is module:
                    codes.update(previous.codes)
                    # Old callbacks may outlive a source change or have never
                    # run yet. Retain their earlier authenticated trees too.
                    for key, items in previous.compiled.items():
                        entries = compiled.setdefault(key, [])
                        entries.extend(item for item in items if item not in entries)
                spec = self._namespace(module).get("__spec__")
                self.modules[id(module)] = _TestModuleCodes(module, spec, codes, compiled)

    @staticmethod
    def _literal_code(code):
        # Code equality/hash can call hooks on arbitrary co_consts inserted by
        # CodeType.replace. Compiler-produced constants have only these types.
        filename, pending, remaining = code.co_filename, [code], _CENSUS_SOURCE_LIMIT
        while pending:
            remaining -= 1
            if remaining < 0:
                return False
            item = pending.pop()
            kind = type(item)
            if kind is CodeType:
                if type(item.co_filename) is not str or item.co_filename != filename:
                    return False
                pending.extend((item.co_name, item.co_names, item.co_varnames,
                                item.co_freevars, item.co_cellvars, item.co_consts,
                                item.co_code,
                                item.co_linetable if hasattr(item, "co_linetable") else item.co_lnotab,
                                getattr(item, "co_exceptiontable", None)))
            elif kind is tuple or kind is frozenset:
                if len(item) > remaining - len(pending):
                    return False
                pending.extend(item)
            elif kind not in (str, bytes, int, float, complex, bool, type(None), type(Ellipsis)):
                return False
        return True

    @classmethod
    def _import_module(cls, code, frame):
        # The real loader must hold this exact executable code object and the
        # module it is executing. A product exec with matching globals has no
        # such loader/code identity, even during another module's import.
        try:
            while frame is not None:
                values = tuple(frame.f_locals.values())
                if any(value is code for value in values):
                    for module in values:
                        if not issubclass(type(module), ModuleType):
                            continue
                        namespace = cls._namespace(module)
                        name, origin = namespace.get("__name__"), namespace.get("__file__")
                        if (type(name) is not str or sys.modules.get(name) is not module
                                or type(origin) is not str or len(origin) > _CENSUS_SOURCE_LIMIT
                                or os.path.normcase(os.path.abspath(origin)) !=
                                os.path.normcase(os.path.abspath(code.co_filename))):
                            continue
                        loader = namespace.get("__loader__")
                        method = cls._class_member(type(loader), "exec_module")
                        if (type(method) is FunctionType and method.__code__ is frame.f_code
                                and any(value is loader for value in values)):
                            return module
                frame = frame.f_back
            return None
        finally:
            del frame

    def executing(self, code, frame, sessions):
        try:
            if type(code.co_filename) is not str or len(code.co_filename) > _CENSUS_SOURCE_LIMIT:
                return
            filename = os.path.normcase(os.path.abspath(code.co_filename))
            if not any(filename in state.test_files for state in sessions):
                return
            module = self._import_module(code, frame)
            if module is None:
                return
            codes = {}
            self._add_code(code, codes)
            codes.pop(id(code), None)
            spec = self._namespace(module).get("__spec__")
            with self.lock:
                previous = self.modules.get(id(module))
                compiled = {}
                if previous is not None and previous.module is module:
                    codes.update(previous.codes)
                    compiled = previous.compiled
                record = _TestImportCodes(module, spec, code, codes, frame.f_code, frame.f_locals)
                self.imports[id(module)] = record
                # Publish each new trusted execution even with the same spec;
                # retained callbacks from earlier executions remain genuine.
                self.modules[id(module)] = _TestModuleCodes(module, spec, codes, compiled)
        finally:
            del frame

    def owns(self, frame):
        namespace, code = frame.f_globals, frame.f_code
        if type(namespace) is not dict:
            return False
        name, origin = namespace.get("__name__"), namespace.get("__file__")
        if type(name) is not str or type(origin) is not str:
            return False
        module = sys.modules.get(name)
        if not issubclass(type(module), ModuleType) or self._namespace(module) is not namespace:
            return False
        spec = namespace.get("__spec__")
        imported = self.imports.get(id(module))
        if imported is not None and imported.module is module and imported.spec is spec:
            if code is imported.body:
                caller = frame.f_back
                try:
                    return (caller is not None and caller.f_code is imported.executor
                            and caller.f_locals is imported.namespace)
                finally:
                    del caller
        record = self.modules.get(id(module))
        if record is None or record.module is not module or record.spec is not spec:
            return False
        if record.codes.get(id(code)) is code:
            return True
        # CPython equality omits co_filename: require it explicitly. Equality
        # is only a fallback for imports completed before observer startup.
        if type(code.co_filename) is not str:
            return False
        candidates = record.compiled.get((code.co_filename, code.co_firstlineno), ())
        if candidates and self._literal_code(code) and any(code == item for item in candidates):
            with self.lock:
                record.codes[id(code)] = code
            return True
        return False


class _WriteCensus:
    def start(self, root, shared=None):
        self.root = os.path.normcase(os.path.abspath(root))
        self.prefix = self.root + os.sep
        self.packages = tuple(self.prefix + name + os.sep for name in _CENSUS_PACKAGES)
        self.tests_prefix = self.prefix + "tests" + os.sep
        self.codes = {}
        self.last_entry = None
        self.scopes = {}
        self.declarations = {}
        self.violations = set()
        # Read only literal registry assignments; importing the test module here
        # would import test helpers and their collection-time side effects.
        self.forwarders = {}
        self.callback_forwarders = {}
        path = os.path.join(root, "tests", "unit", "core", "test_storage_ratchets.py")
        try:
            self._registry(_census_source(path))
            # Establish trusted test sources before product I/O budgets and
            # fault injection begin. No source reads/stat calls in the hook.
            self.test_files = frozenset(
                os.path.normcase(os.path.abspath(str(path)))
                for path in Path(self.tests_prefix).rglob("*.py") if path.is_file()
            )
            if not self._load_index(shared):
                self._index_sources()
            # Detach transport dictionaries before exposing a read-only view.
            self.scopes = MappingProxyType({
                filename: MappingProxyType(dict(scopes))
                for filename, scopes in self.scopes.items()
            })
        except (OSError, SyntaxError, UnicodeError, ValueError, KeyError, TypeError, RecursionError):
            raise pytest.UsageError("cannot load storage writer registry") from None

    def _registry(self, tree):
        registry = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                name = getattr(node.targets[0], "id", None)
                if name in ("NON_AEGIS_WRITERS", "AUDIT_WRITERS", "AUDIT_STORAGE_MODULES"):
                    registry[name] = ast.literal_eval(node.value)
                elif name == "AUDIT_FORWARDER_OPERATIONS":
                    for key, (event, reason) in ast.literal_eval(node.value).items():
                        self.forwarders.setdefault(key[:2], set()).add(event)
                elif name == "CALLBACK_EXCEPTIONS":
                    events = {"os.open": "open", "os.rename": "os.rename",
                              "os.replace": "os.rename", "os.link": "os.link",
                              "os.unlink": "os.remove"}
                    for file, caller, operation, wrapper in ast.literal_eval(node.value):
                        contexts = self.callback_forwarders.setdefault((file, wrapper), {})
                        contexts.setdefault((file, caller), set()).add(events[operation])
        self.registered = set(registry["NON_AEGIS_WRITERS"])
        # A descriptor review can authorize reads only. Runtime write authority
        # is explicit in the writer registries, never inferred from that review.
        self.registered.update(registry["AUDIT_WRITERS"])
        self.storage = set(registry.get("AUDIT_STORAGE_MODULES", ()))

    def _index_keys(self):
        keys = self.registered | self.forwarders.keys() | self.callback_forwarders.keys()
        for contexts in self.callback_forwarders.values():
            keys.update(contexts)
        return keys

    def _load_index(self, shared):
        # This is a local xdist controller message, never a persisted cache.
        # Mismatched/invalid messages fall back to independent source parsing.
        if type(shared) is not dict or type(shared.get("version")) is not int or shared["version"] != 1:
            return False
        if (type(shared.get("root")) is not str or shared["root"] != self.root
                or type(shared.get("native_qualnames")) is not bool
                or shared["native_qualnames"] != _CENSUS_NATIVE_QUALNAMES):
            return False
        scopes = shared.get("scopes")
        if type(scopes) is not dict or len(scopes) > _CENSUS_SOURCE_LIMIT:
            return False
        needed = {self.prefix + file.replace("/", os.sep) for file, scope in self._index_keys()}
        needed.update(self.prefix + file.replace("/", os.sep) for file in self.storage)
        if not needed.issubset(scopes):
            return False
        for filename, entries in scopes.items():
            if (type(filename) is not str or len(filename) > _CENSUS_SOURCE_LIMIT
                    or not filename.startswith(self.packages)
                    or type(entries) is not dict or len(entries) > _CENSUS_SOURCE_LIMIT):
                return False
            for location, qualified in entries.items():
                if type(location) is not tuple or len(location) != 2:
                    return False
                name, line = location
                if (type(name) is not str or len(name) > _CENSUS_SOURCE_LIMIT
                        or type(line) is not int or not 1 <= line <= _CENSUS_SOURCE_LIMIT + 1
                        or type(qualified) is not str or len(qualified) > _CENSUS_SOURCE_LIMIT
                        or qualified.rsplit(".", 1)[-1] != name):
                    return False
        self.scopes = scopes
        return True

    def index_payload(self):
        return {"version": 1, "root": self.root, "native_qualnames": _CENSUS_NATIVE_QUALNAMES,
                "scopes": {filename: dict(entries) for filename, entries in self.scopes.items()}}

    def _index_sources(self):
        # Resolve authority before test I/O budgets/fault-injection counters
        # start. The observer must not open source files inside a product call.
        files = {}
        for file, scope in self._index_keys():
            files.setdefault(self.prefix + file.replace("/", os.sep), set()).add(scope)
        storage_files = {self.prefix + file.replace("/", os.sep) for file in self.storage}
        for filename in storage_files:
            files.setdefault(filename, set())
        if not _CENSUS_NATIVE_QUALNAMES:
            # 3.9 lacks co_qualname. Index unregistered scopes too, so they can
            # be diagnosed precisely without runtime reads or name-only grants.
            for package in self.packages:
                for path in Path(package).rglob("*.py"):
                    files.setdefault(os.path.normcase(os.path.abspath(str(path))), set())
        for filename, scopes in sorted(files.items()):
            # Native qualified names already identify unregistered code. Only
            # declarations that could grant authority need validation. Storage
            # and legacy name resolution retain the complete lexical index.
            required = (scopes if _CENSUS_NATIVE_QUALNAMES and filename not in storage_files
                        and not any("<" in scope and scope != "<module>" for scope in scopes) else None)
            self.scopes[filename] = self._source_scopes(filename, required)

    def _code_entry(self, code):
        """Resolve source identity and authority once, on a code-cache miss."""
        filename = os.path.normcase(os.path.abspath(code.co_filename))
        site = None
        if filename in self.test_files:
            site = ()  # loaded-module provenance is checked against the actual frame
        elif filename.startswith(self.packages):
            rel = filename[len(self.prefix):].replace(os.sep, "/")
            # co_qualname was added in 3.11. The AST fallback uses lexical
            # scopes, never self.__class__, so inherited methods retain the
            # actual defining class on 3.9 as well.
            scope = getattr(code, "co_qualname", None)
            if scope is None:
                scope = self.scopes.get(filename, {}).get(
                    (code.co_name, code.co_firstlineno), "<unresolved>")
            site = (rel, scope.replace(".<locals>", ""), code.co_firstlineno)
        key = site[:2] if site else None
        declared = self._declared(site) if site else False
        # Event-specific forwarding and callback context stay dynamic. Only
        # immutable per-session authority is cached with the exact source site.
        forwards = self.forwarders.get(key, ()) if declared else ()
        callbacks = self.callback_forwarders.get(key) if declared else None
        storage = (site and site[0] in self.storage and key not in self.forwarders
                   and key not in self.callback_forwarders)
        owned = declared and (storage or key in self.registered)
        entry = _CensusCode(code, site, owned, forwards, callbacks, key, declared)
        # Code equality ignores filenames. Retain the object alongside its id
        # so equal code cannot poison attribution and ids cannot be reused.
        self.codes[id(code)] = entry
        return entry

    def _cached_code(self, code):
        # id() itself emits an audit event. Consecutive direct writers can use
        # object identity without that recursive hook call or a dict lookup.
        last = self.last_entry
        if last is not None and code is last.code:
            return last
        entry = self.codes.get(id(code))
        if entry is None:
            entry = self._code_entry(code)
        # Publish one immutable entry, never separate code/authority fields.
        # Readers keep a local snapshot across a possible thread switch.
        self.last_entry = entry
        return entry

    @staticmethod
    def _source_scopes(filename, required=None):
        try:
            tree = _census_source(filename)
        except (OSError, SyntaxError, UnicodeError, ValueError, RecursionError):
            # No name-only authority for dynamically compiled/removed source.
            return {}
        scopes = {("<module>", 1): "<module>"}
        ancestors = set()
        for scope in required or ():
            parts = scope.split(".")
            ancestors.update(".".join(parts[:index]) for index in range(1, len(parts)))

        def visit(node, parents):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                nested = parents + [node.name]
                first = (node.lineno if isinstance(node, ast.ClassDef) else
                         min([node.lineno] + [d.lineno for d in node.decorator_list]))
                qualified = ".".join(nested)
                if required is not None:
                    if qualified in required:
                        scopes[(node.name, first)] = qualified
                    if qualified in ancestors:
                        for child in node.body:
                            visit(child, nested)
                    return
                scopes[(node.name, first)] = qualified
                # Defaults, annotations, decorators and class bases execute in
                # the outer scope; only the body enters the new named scope.
                for field, value in ast.iter_fields(node):
                    children = value if isinstance(value, list) else [value]
                    for child in children:
                        if isinstance(child, ast.AST):
                            visit(child, nested if field == "body" else parents)
                return
            if required is not None:
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, _SCOPE_BRANCHES):
                        visit(child, parents)
                return
            anonymous = _ANONYMOUS_SCOPES.get(type(node))
            if anonymous:
                parents = parents + [anonymous]
                scopes[(anonymous, node.lineno)] = ".".join(parents)
            for child in ast.iter_child_nodes(node):
                visit(child, parents)

        try:
            visit(tree, [])
        except RecursionError:
            return {}
        return scopes

    def _declared(self, site):
        if site in self.declarations:
            return self.declarations[site]
        file, scope, line = site
        filename = self.prefix + file.replace("/", os.sep)
        resolved = (scope != "<unresolved>" and
                    self.scopes.get(filename, {}).get((scope.rsplit(".", 1)[-1], line)) == scope)
        self.declarations[site] = resolved
        return resolved

    def observe(self, event, frame):
        self.observer._observe_sessions(event, frame, (self,))


class _WriteCensusObserver:
    """One process hook; each nested pytest session owns independent state."""
    def __init__(self):
        self.sessions = []
        self.current = None
        self.bytecode_policy = None
        self.test_codes = _TestCodeIndex()

    def push(self, state):
        state.observer = self
        if not self.sessions:
            self.bytecode_policy = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        self.test_codes.preload(state)
        self.sessions = [*self.sessions, state]
        self.current = state

    def finish(self, state):
        if state not in self.sessions:
            return
        self.sessions = [active for active in self.sessions if active is not state]
        self.current = self.sessions[-1] if self.sessions else None
        if not self.sessions:
            sys.dont_write_bytecode = self.bytecode_policy

    def __call__(self, event, args):
        # Most events, including audit events from frame/code access itself,
        # need one set lookup and no state lookup, allocation or stack work.
        if event not in _CENSUS_EVENTS:
            return
        sessions = self.sessions
        if not sessions:
            return
        if event == "exec":
            # Import execution supplies provenance metadata, never a write.
            if len(args) == 1 and type(args[0]) is CodeType:
                self.test_codes.executing(args[0], sys._getframe(1), sessions)
            return
        if event == "open":
            # Hot path: no Path objects, normalization, stack walk or cache
            # allocation for read-only opens (including imports).
            mode, flags = args[1], args[2]
            if not (flags & _WRITE_FLAGS or
                    (mode is not None and ("w" in mode or "a" in mode or "x" in mode or "+" in mode))):
                return
        elif event == "mmap.__new__":
            if args[0] == -1 or args[2] in _READ_ONLY_MMAP_ACCESS:
                return
        elif event == "msvcrt.open_osfhandle":
            if not args[1] & _WRITE_FLAGS:
                return
        elif event == "socket.bind":
            family = getattr(socket, "AF_UNIX", None)
            address = args[1]
            if family is None or getattr(args[0], "family", None) != family:
                return
            if not self._filesystem_address(address):
                return
        if len(sessions) == 1:
            sessions[0].observe(event, sys._getframe(1))
        else:
            self._observe_sessions(event, sys._getframe(1), sessions)

    def _frame_entries(self, frame, sessions):
        owners, fixture = [], False
        code = frame.f_code
        for state in sessions:
            last = state.last_entry
            entry = last if last is not None and code is last.code else state._cached_code(code)
            if entry.site:
                owners.append((state, entry))
            elif entry.site == () and self.test_codes.owns(frame):
                fixture = True
        return owners, fixture

    @staticmethod
    def _deliver(owners, event, *, unresolved=False):
        for state, entry in owners:
            if unresolved or not entry.owned:
                state.violations.add((*entry.site, event))

    @staticmethod
    def _denied_callbacks(pending, owners, event):
        callers = dict(owners)
        denied = []
        for state, entry in pending:
            caller = callers.get(state)
            if (caller is None or not caller.declared
                    or event not in entry.callbacks.get(caller.key, ())):
                denied.append((state, entry))
        return denied

    def _observe_sessions(self, event, frame, sessions):
        # One walk resolves ownership for both single and nested sessions.
        # Forwarding follows each frame's own root before selecting an owner.
        forwarded, pending, fixture_seen = {}, [], False
        try:
            while frame is not None:
                owners, fixture = self._frame_entries(frame, sessions)
                if owners:
                    denied = self._denied_callbacks(pending, owners, event)
                    if denied:
                        self._deliver(denied, event)
                        return
                    pending, direct = [], []
                    for state, entry in owners:
                        if event in entry.forwards or entry.callbacks:
                            forwarded.setdefault(state, entry)
                            if event not in entry.forwards:
                                pending.append((state, entry))
                        else:
                            direct.append((state, entry))
                    if direct:
                        self._deliver(direct, event)
                        return
                elif fixture:
                    if not forwarded:
                        return  # genuine fixture/fault injection before product code
                    # A fixture caller can resolve a direct API exercise, but
                    # cannot hide a later product owner after a forwarder.
                    fixture_seen = True
                frame = frame.f_back
            if pending:
                self._deliver(pending, event)
            elif not fixture_seen:
                self._deliver(forwarded.items(), event, unresolved=True)
        finally:
            del frame

    @staticmethod
    def _filesystem_address(address):
        try:
            if isinstance(address, str):
                if str.__len__(address) > _CENSUS_ADDRESS_LIMIT:
                    return True
                # Bypass subclass __len__/__str__/encode overrides. The base
                # string's bounded contents are what the socket API consumes.
                raw = os.fsencode(str.__str__(address))
            else:
                with memoryview(address) as view:
                    if view.nbytes > _CENSUS_ADDRESS_LIMIT:
                        return True
                    raw = bytes(view)
        except Exception:
            # An unreadable buffer/path object still denotes a potential
            # filesystem write. Refusal to normalize must retain attribution.
            return True
        return bool(raw) and not raw.startswith(b"\x00")


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node):
    census = getattr(node.config, "_write_census", None)
    if census is not None:
        node.workerinput["_aegis_census_source_index"] = census.index_payload()


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node, error):
    census = getattr(node.config, "_write_census", None)
    if census is not None:
        output = getattr(node, "workeroutput", {})
        census.violations.update(tuple(row) for row in output.get("write_census", ()))


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    census = getattr(session.config, "_write_census", None)
    if census is not None:
        session.config._write_census_observer.finish(census)
        if hasattr(session.config, "workeroutput"):
            session.config.workeroutput["write_census"] = sorted(census.violations)
        if census.violations and session.exitstatus == 0:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_unconfigure(config):
    census = getattr(config, "_write_census", None)
    if census is not None:
        config._write_census_observer.finish(census)


def pytest_terminal_summary(terminalreporter):
    census = getattr(terminalreporter.config, "_write_census", None)
    if census is not None and census.violations:
        from aegis_cli import sanitize_display
        from aegis_core.redaction import redact_command_secrets

        terminalreporter.section("unregistered storage writer", red=True)
        for row in sorted(census.violations):
            fields = [redact_command_secrets(sanitize_display(value, max_len=None))[:512]
                      for value in row]
            terminalreporter.write_line("%s:%s %s (first line %s)" %
                                       (fields[0], fields[1], fields[3], fields[2]), red=True)


class _BasetempControllerGuard:
    pytest_configure = staticmethod(_configure_basetemp)


if __name__ == "__main__":
    # Prefer this checkout over an editable install pointing at another tree.
    sys.path.insert(0, REPO_ROOT)
    raise SystemExit(pytest.main(sys.argv[1:], plugins=[_BasetempControllerGuard()]))


@pytest.fixture(scope="session", autouse=True)
def _tmp_path_git_ceiling(tmp_path_factory):
    """Stop Git discovery above temporary workspaces before per-test env snapshots."""
    basetemp = tmp_path_factory.getbasetemp().resolve()
    _validate_ceiling_path(basetemp)
    # A ceiling inside the source tree would also hide Git from sibling directories.
    ceiling_path = basetemp if Path(REPO_ROOT).resolve() in basetemp.parents else basetemp.parent
    ceiling = str(ceiling_path)
    previous = os.environ.get("GIT_CEILING_DIRECTORIES")
    os.environ["GIT_CEILING_DIRECTORIES"] = (
        ceiling + os.pathsep + previous if previous else ceiling
    )
    yield
    if previous is None:
        os.environ.pop("GIT_CEILING_DIRECTORIES", None)
    else:
        os.environ["GIT_CEILING_DIRECTORIES"] = previous


def require_bash():
    """Path to bash, or skip. Prefers /bin/bash: on macOS that is 3.2, the
    oldest supported shell and the one that surfaced SOMA-C03. Windows has
    no /bin/bash for native processes; Git Bash is found on PATH or Git installation."""
    if os.name == "nt":
        for git_bash in (r"C:\Program Files\Git\usr\bin\bash.exe", r"C:\Program Files (x86)\Git\usr\bin\bash.exe"):
            if os.path.exists(git_bash):
                return git_bash
    path = "/bin/bash" if os.path.exists("/bin/bash") else shutil.which("bash")
    if not path:
        pytest.skip("bash is not available")
    return path


@pytest.fixture(scope="session")
def bash():
    return require_bash()


def symlink_or_skip(target, link, target_is_directory: bool = False):
    """Create a symlink, or skip: Windows needs Developer Mode or admin
    rights (WinError 1314)."""
    try:
        os.symlink(str(target), str(link), target_is_directory=target_is_directory)
    except (OSError, NotImplementedError):
        # On POSIX a failure here is a test bug; don't let it hide the
        # symlink-escape security tests behind a skip.
        if os.name != "nt":
            raise
        pytest.skip("symlinks are unavailable")


@pytest.fixture
def fake_home(tmp_path):
    """An isolated HOME so installer tests never touch the real one."""
    home = tmp_path / "home"
    home.mkdir()
    return home


def run(cmd, cwd=REPO_ROOT, env=None, stdin=subprocess.DEVNULL, timeout=120):
    """Run a command and return CompletedProcess with text output."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
        # Under Git Bash resolve_home() prefers USERPROFILE, so a HOME-only
        # override would still point the installer at the real profile (BUG-010).
        if "HOME" in env and "USERPROFILE" not in env:
            full_env["USERPROFILE"] = env["HOME"]
    return subprocess.run(
        cmd, cwd=cwd, env=full_env, stdin=stdin,
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
    )


def read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def iter_source_files(root, extensions):
    """Yield absolute paths under root matching extensions, skipping caches."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in {"__pycache__", ".git", "node_modules", ".pytest_cache"}
        ]
        for fn in filenames:
            if any(fn.endswith(ext) for ext in extensions):
                yield os.path.join(dirpath, fn)


# Variables the shell that launched pytest may export: AEGIS_WORKSPACE would aim
# CLI and MCP calls at the developer's real workspace, the others change host
# identity, the Layer-2 backend and scan budgets. Tests that need one set it.
_DEVELOPER_ENV = ("AEGIS_WORKSPACE", "AEGIS_CLIENT", "AEGIS_LLM_CMD", "AEGIS_MAX_JIT_TOKENS")


@pytest.fixture(autouse=True)
def _no_developer_aegis_env(monkeypatch):
    for key in _DEVELOPER_ENV:
        monkeypatch.delenv(key, raising=False)


# pytest sets PYTEST_CURRENT_TEST to "<node id> (teardown)" (NUL shown as "(null)"), and
# CPython on Windows refuses the whole "NAME=value" string beyond 32767 UTF-16 units
# (_MAX_ENV in win32_putenv), so a longer id errors only on Windows. A bytes parameter
# without ids= once put 64 KiB in an id. Checking at collection reports it on every platform,
# including for tests that a mark skips before any fixture runs.
_WINDOWS_ENVIRONMENT_LIMIT = 32767


def _windows_environment_units(nodeid):
    entry = "PYTEST_CURRENT_TEST=%s (teardown)" % nodeid.replace("\x00", "(null)")
    return len(entry.encode("utf-16-le", "surrogatepass")) // 2


def pytest_collection_modifyitems(config, items):
    too_long = [(item.nodeid[:120], units) for item in items
                for units in (_windows_environment_units(item.nodeid),)
                if units > _WINDOWS_ENVIRONMENT_LIMIT]
    if too_long:
        raise pytest.UsageError(
            "test ids too long for PYTEST_CURRENT_TEST on Windows (name long parameters with ids=): "
            + "; ".join("%s... (%d units)" % row for row in too_long))


@pytest.fixture(autouse=True)
def hermetic_environment_and_mcp_isolation():
    """Restore os.environ and reset loaded MCP singletons and credit caches between tests."""
    old_env = dict(os.environ)
    yield
    # Restore os.environ
    os.environ.clear()
    os.environ.update(old_env)

    credit = sys.modules.get("aegis_core.credit")
    if credit is not None:
        for name in ("_EXPOSED", "_VERIFIED_CI",
                     "_UNAVAILABLE_CI", "_SIGNERS_CHANGED", "_DEFAULT_BRANCH"):
            getattr(credit, name).clear()
    memo = sys.modules.get("aegis_core.credit_memo")
    if memo is not None:
        memo.reset()
    scan_handler = sys.modules.get("aegis_mcp.handlers.core")
    if scan_handler is not None:
        scan_handler._RECORDED.clear()

    # Reset MCP server singletons if aegis_mcp.server is loaded
    for mod_name in ("aegis_mcp.server", "aegis_mcp.server"):
        if mod_name in sys.modules:
            mcp_server = sys.modules[mod_name]
            if hasattr(mcp_server, "_session_tokens") and isinstance(mcp_server._session_tokens, set):
                mcp_server._session_tokens.clear()
            if hasattr(mcp_server, "_tool_call_times") and hasattr(mcp_server._tool_call_times, "clear"):
                mcp_server._tool_call_times.clear()
            if hasattr(mcp_server, "_session_token"):
                mcp_server._session_token = None


