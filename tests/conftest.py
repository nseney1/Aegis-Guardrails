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
"""
import ast
from collections import namedtuple
import mmap
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
from threading import RLock
from types import (CodeType, FunctionType, GetSetDescriptorType, MappingProxyType,
                   MemberDescriptorType, ModuleType)

import pytest
from _pytest.assertion.rewrite import AssertionRewritingHook, rewrite_asserts
from _pytest.tmpdir import get_user

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_CENSUS_PACKAGES = ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk", "tools")
_CENSUS_NATIVE_QUALNAMES = hasattr((lambda: None).__code__, "co_qualname")
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

try:
    import tests
    if hasattr(tests, "__path__") and TESTS_DIR not in tests.__path__:
        tests.__path__ = [TESTS_DIR, *tests.__path__]
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


def pytest_configure(config):
    _configure_basetemp(config)
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


def pytest_addoption(parser):
    parser.addoption("--no-write-census", action="store_true", default=False,
                     help="disable runtime writer governance for overhead measurement")


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


