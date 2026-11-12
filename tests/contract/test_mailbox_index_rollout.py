"""Tripwire against ordinary MailboxIndex adoption before the owner's phase-0 exit.

Unadmitted tracked runtime files may not mention either index needle, even in
comments. Deliberately obfuscated code (exec, computed import names, getattr with
strings) is out of scope; code review covers it. MB-MODE-1 now enforces existing
instance mode immutability through a captured member descriptor and a read-only
dictionary snapshot. Deliberate introspection can still reach the descriptor via
type(idx).mode.fget.__self__ or MailboxIndex.__init__.__closure__; this is outside
the honest-code model. Reinitialization refuses at runtime. The exact guard is
pinned below; ordinary construction/default/hook escapes refuse here.
Fresh explicit construction remains legitimate outside this rollout contract.
RECEIVER_ATTR_ALLOW pins classmethod receiver attribute reads; MB lanes must
extend it deliberately. Allowed reads never expose mode or construction/state
dunders, and attribute stores/deletes still refuse.

These are the repository's own tracked files: use plain, bounded, cross-platform
reads and refuse tracked symlinks/reparse points. Checkout ancestors and concurrent
filesystem replacement are outside this test's threat model. No product path
opening or descriptor-relative filesystem enforcement is introduced here.

RF24_MENTION/MODE/REFERENCE/MODE_WRITE/SIZE/PARSE/READ/PATH/GIT/SIGNATURE
are stable refusal codes with fixed next actions. Diagnostics never echo source
or exception text. RF24_GIT includes Git's bounded failure line when available;
only missing Git skips, with a reason. Git runs inside tests, never at collection.
"""
import ast
import os
from pathlib import Path
import shutil
import stat
import subprocess
import symtable
import tempfile

import pytest

from tests.contract.test_process_ratchets import ScopedNames


REPO = Path(__file__).resolve().parents[2]
INDEX = "tools/hierarchy_mailbox_index.py"
# Owner approved Phase 1 for the read-only doctor (MB-5 round 1b, Addendum A).
ADMITTED_IMPORTERS = frozenset({"tools/hierarchy_mailbox_doctor.py"})
RECEIVER_ATTR_ALLOW = frozenset({"_path_key"})
RECEIVER_ATTR_DENY = frozenset({"mode", "__init__", "__new__", "__dict__", "__class__"})
NEEDLES = (b"MailboxIndex", b"hierarchy_mailbox_index")
RUNTIME_DIRS = ("tools", "rules", "skills")
MAX_SOURCE = 1024 * 1024
MAX_LIST = 1024 * 1024
MAX_FILES = 10000
MAX_TOTAL = 32 * 1024 * 1024
MAX_ERRORS = 16384
ACTIONS = {
    "RF24_MENTION": ("MailboxIndex adoption is phase 1 (ADR mailbox-structure ~:226-227): "
                     "add the file to ADMITTED_IMPORTERS in an owner-approved change and keep mode='shadow'"),
    "RF24_MODE": "pass literal mode='shadow'",
    "RF24_REFERENCE": "use a direct shadow construction; re-review constructor references",
    "RF24_MODE_WRITE": "remove mode writes; the index initializer may only store the unmodified mode parameter",
    "RF24_SIZE": "reduce tracked input below the RF24 byte and file-count limits; rerun",
    "RF24_PARSE": "fix the tracked Python syntax and re-review shadow-mode handling",
    "RF24_READ": "restore the tracked regular file; remove symlinks or reparse points; rerun",
    "RF24_PATH": "restore safe checkout-relative tracked paths; rerun",
    "RF24_GIT": "run from a git checkout; check git safe.directory",
    "RF24_SIGNATURE": "restore the reviewed index shape; MB-MODE-1 must change this contract deliberately",
}


def _message(name=None, line=None, code="RF24_MODE", *, action=None):
    location = f"{name}:{line}: " if line is not None else f"{name}: " if name else ""
    return f"{location}{code}: {ACTIONS[code] if action is None else action}"


def _require(condition, name, code):
    if not condition:
        raise AssertionError(_message(name, code=code))


def _parse(raw, name):
    _require(len(raw) <= MAX_SOURCE, name, "RF24_SIZE")
    try:
        return ast.parse(raw, filename=name)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        raise AssertionError(_message(name, code="RF24_PARSE")) from None


def _mode_signature(tree):
    classes = [node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == "MailboxIndex"]
    _require(len(classes) == 1, INDEX, "RF24_SIGNATURE")
    constructors = [node for node in classes[0].body
                    if isinstance(node, ast.FunctionDef) and node.name == "__init__"]
    _require(len(constructors) == 1, INDEX, "RF24_SIGNATURE")
    args = constructors[0].args
    positional = args.posonlyargs + args.args
    _require(positional and positional[0].arg == "self", INDEX, "RF24_SIGNATURE")
    defaults = dict(zip([arg.arg for arg in positional[-len(args.defaults):]], args.defaults))
    defaults.update(zip([arg.arg for arg in args.kwonlyargs], args.kw_defaults))
    names = [arg.arg for arg in positional[1:]]
    _require("mode" in names + [arg.arg for arg in args.kwonlyargs]
             and _literal(defaults.get("mode"), "shadow"), INDEX, "RF24_SIGNATURE")
    return (names.index("mode") if "mode" in names else None, len(names))


def _literal(node, value):
    return isinstance(node, ast.Constant) and node.value == value


def _name(node, value):
    return isinstance(node, ast.Name) and node.id == value


def _shadow_call(call, signature, *, allow_default=False):
    position, positional_count = signature
    if (any(isinstance(arg, ast.Starred) for arg in call.args)
            or any(keyword.arg is None for keyword in call.keywords)
            or len(call.args) > positional_count):
        return False
    values = [keyword.value for keyword in call.keywords if keyword.arg == "mode"]
    if position is not None and len(call.args) > position:
        values.append(call.args[position])
    return (not values and allow_default) or len(values) == 1 and _literal(values[0], "shadow")


def _reference(node, names):
    return ((isinstance(node, ast.Name) and node.id == "MailboxIndex")
            or (isinstance(node, ast.Attribute) and node.attr == "MailboxIndex")
            or (isinstance(node, (ast.Name, ast.Attribute))
                and any(target.endswith(".MailboxIndex") for target in names.resolve(node))))


def _mode_write(node, names):
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return node.attr in {"mode", "__mode", "_MailboxIndex__mode"}
    if (isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del))
            and _literal(node.slice, "mode") and isinstance(node.value, ast.Attribute)
            and node.value.attr == "__dict__"):
        return True
    if not isinstance(node, ast.Call):
        return False
    setter = (_name(node.func, "setattr") or _name(node.func, "delattr")
              or names.resolve(node.func).intersection({"builtins.setattr", "builtins.delattr"})
              or isinstance(node.func, ast.Attribute) and node.func.attr in {"__setattr__", "__delattr__"})
    if not setter:
        return False
    bound = (isinstance(node.func, ast.Attribute)
             and (node.func.attr == "__setattr__" and len(node.args) == 2
                  or node.func.attr == "__delattr__" and len(node.args) == 1))
    offset = 0 if bound else 1
    return len(node.args) <= offset or not (
        isinstance(node.args[offset], ast.Constant)
        and node.args[offset].value not in {"mode", "__mode", "_MailboxIndex__mode"}
    )


def _binds_name(node, protected, parameter=None):
    return (
        isinstance(node, ast.Name) and node.id in protected and isinstance(node.ctx, (ast.Store, ast.Del))
        or isinstance(node, ast.arg) and node.arg in protected and node is not parameter
        or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler))
        and node.name in protected
        or isinstance(node, ast.alias) and (node.asname or node.name.split(".")[0]) in protected
        or isinstance(node, (ast.Global, ast.Nonlocal)) and bool(protected.intersection(node.names))
        or type(node).__name__ in ("MatchAs", "MatchStar") and node.name in protected
        or type(node).__name__ == "MatchMapping" and node.rest in protected
    )


def _class_body_nodes(cls):
    """Visit bindings in a class's scope, without entering method bodies."""
    pending = list(cls.body)
    while pending:
        node = pending.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            pending.extend(node.args.defaults)
            pending.extend(value for value in node.args.kw_defaults if value is not None)
            pending.extend(getattr(node, "decorator_list", ()))
        elif isinstance(node, ast.ClassDef):
            pending.extend(node.bases)
            pending.extend(node.keywords)
            pending.extend(node.decorator_list)
        else:
            pending.extend(ast.iter_child_nodes(node))


def _receiver_attribute_read(node, parents):
    current = parents.get(node)
    if (not isinstance(current, ast.Attribute) or current.value is not node
            or current.attr not in RECEIVER_ATTR_ALLOW):
        return False
    while True:
        if (isinstance(current, (ast.Attribute, ast.Subscript)) and not isinstance(current.ctx, ast.Load)
                or isinstance(current, ast.Attribute) and current.attr in RECEIVER_ATTR_DENY):
            return False
        parent = parents.get(current)
        if (isinstance(parent, (ast.Attribute, ast.Subscript)) and parent.value is current
                or isinstance(parent, ast.Call) and parent.func is current):
            current = parent
        else:
            return True


def _classmethod_shape(method, signature, names, parents):
    if not any(_name(decorator, "classmethod") or "builtins.classmethod" in names.resolve(decorator)
               for decorator in method.decorator_list):
        return set()
    positional = method.args.posonlyargs + method.args.args
    if not positional:
        return {method.lineno}
    receiver = positional[0].arg
    found = set()
    for statement in method.body:
        for node in ast.walk(statement):
            if _name(node, receiver):
                parent = parents.get(node)
                call = (isinstance(parent, ast.Call) and parent.func is node
                        and _shadow_call(parent, signature, allow_default=True))
                if (not isinstance(node.ctx, ast.Load)
                        or not (call or _receiver_attribute_read(node, parents))):
                    found.add(node.lineno)
    return found


_MODE_GUARD_SOURCE = '''\
_MODE_READ_ONLY = "mailbox index mode is read-only; changing mode requires the ADR phase-0 exit"

class _ModeSnapshot(dict):
    def _refuse(*args, **kwargs):
        raise AttributeError(_MODE_READ_ONLY)
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _refuse

class _IndexStorage:
    """Keep native instance state and the doctor's bound method overrides."""

def _guard_mode(cls):
    slot, state, original, missing = cls.__dict__["_MailboxIndex__mode"], _IndexStorage.__dict__["__dict__"], cls.__init__, object()
    del cls._MailboxIndex__mode
    def initialize(self, mailbox, *, mode="shadow"):
        if getattr(self, "mode", missing) is not missing:
            _ModeSnapshot._refuse()
        hm.require(mode in ("shadow", "indexed"), "unknown mailbox index mode; valid modes: shadow, indexed")
        slot.__set__(self, mode)
        return original(self, mailbox, mode=mode)
    def clone(self):
        other = cls(self.mailbox, mode=self.mode)
        state.__get__(other).update(state.__get__(self))
        return other
    cls.__init__, cls.__copy__ = initialize, clone
    cls.mode = cls._MailboxIndex__mode = property(slot.__get__, _ModeSnapshot._refuse, _ModeSnapshot._refuse)
    return cls

@_guard_mode
class MailboxIndex(_IndexStorage):
    __slots__ = ("__mode",)
    __dict__ = property(lambda self: _ModeSnapshot(_IndexStorage.__dict__["__dict__"].__get__(self)), _ModeSnapshot._refuse, _ModeSnapshot._refuse)

    def __init__(self, mailbox, *, mode="shadow"):
        self.mailbox = mailbox
'''
_MODE_GUARD_TREE = ast.parse(_MODE_GUARD_SOURCE)
_GUARD_SUPPORT = frozenset({"_MODE_READ_ONLY", "_ModeSnapshot", "_IndexStorage", "_guard_mode"})
# The sentinel is still used elsewhere in the reader. Pin its sole definition,
# along with the guard's existing module import, without forbidding normal reads.
_GUARD_CONTEXT_SOURCE = '''\
if __package__:
    from . import hierarchy_mailbox as hm
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import hierarchy_mailbox as hm
_MISSING = object()
'''
_GUARD_CONTEXT_TREE = ast.parse(_GUARD_CONTEXT_SOURCE)


def _guard_free_names(tree):
    """Use Python's scope analysis on the pinned AST, including nested scopes."""
    pending = [symtable.symtable(ast.unparse(tree), INDEX, "exec")]
    free = set()
    while pending:
        scope = pending.pop()
        free.update(symbol.get_name() for symbol in scope.get_symbols()
                    if symbol.is_referenced() and symbol.is_global())
        pending.extend(scope.get_children())
    return frozenset(free)


_GUARD_NAMES = _GUARD_SUPPORT | _guard_free_names(_MODE_GUARD_TREE) | frozenset({"_MISSING"})


def _mode_guard_shape(tree, cls, init):
    """Exempt only exact reviewed guard nodes from the existing token checks."""
    expected = _MODE_GUARD_TREE
    reviewed = expected.body[-1]
    members = [node for node in cls.body if (
        isinstance(node, ast.FunctionDef) and node.name in {"mode", "__dict__"}
        or isinstance(node, (ast.Assign, ast.AnnAssign)) and any(isinstance(target, ast.Name)
            and target.id in {"__slots__", "__dict__"}
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])))]
    pinned = reviewed.body[:-1]
    support = [node for node in tree.body
               if any(_binds_name(binding, _GUARD_SUPPORT) for binding in ast.walk(node))]
    context = [node for node in tree.body if (
        isinstance(node, ast.If) and _name(node.test, "__package__")
        or isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(_binds_name(binding, {"_MISSING"}) for binding in ast.walk(node)))]
    if ([ast.dump(node) for node in context] != [ast.dump(node) for node in _GUARD_CONTEXT_TREE.body]
            or ast.dump(ast.Module(body=support, type_ignores=[]))
            != ast.dump(ast.Module(body=expected.body[:-1], type_ignores=[]))
            or [ast.dump(node) for node in members] != [ast.dump(node) for node in pinned]
            or [ast.dump(node) for node in cls.bases] != [ast.dump(node) for node in reviewed.bases]
            or cls.keywords
            or [ast.dump(node) for node in cls.decorator_list]
            != [ast.dump(node) for node in reviewed.decorator_list]):
        return set(), {init.lineno}
    prefix = reviewed.body[-1].body
    found = ({init.lineno} if [ast.dump(node) for node in init.body[:len(prefix)]]
             != [ast.dump(node) for node in prefix] else set())
    return {node for member in [*context, *support, *members, *cls.bases, *cls.decorator_list]
            for node in ast.walk(member)}, found


def _index_shape(tree, names, parents):
    # Signature validation precedes extraction, so missing/duplicate definitions refuse.
    signature = _mode_signature(tree)
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "MailboxIndex")
    init = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "__init__")
    args = init.args.posonlyargs + init.args.args + init.args.kwonlyargs
    parameter = next(arg for arg in args if arg.arg == "mode")
    guard_nodes, found = _mode_guard_shape(tree, cls, init)
    if init.decorator_list:
        found.add(init.lineno)
    for node in ast.walk(init):
        if _binds_name(node, {"mode"}, parameter):
            found.add(getattr(node, "lineno", init.lineno))
    decorators = {decorator for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                  for decorator in node.decorator_list}
    for node in ast.walk(cls):
        if _binds_name(node, {"__getattribute__", "__getattr__"}):
            found.add(getattr(node, "lineno", getattr(parents.get(node), "lineno", init.lineno)))
    for node in ast.walk(tree):
        if node in guard_nodes:
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found.update(_classmethod_shape(node, signature, names, parents))
        if isinstance(node, ast.ClassDef):
            for binding in _class_body_nodes(node):
                if _binds_name(binding, {"mode"}) and binding not in guard_nodes:
                    found.add(getattr(binding, "lineno", node.lineno))
        identifier = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None
        if identifier in _GUARD_SUPPORT or _binds_name(node, _GUARD_NAMES):
            found.add(getattr(node, "lineno", getattr(parents.get(node), "lineno", init.lineno)))
        if identifier in {"__kwdefaults__", "__defaults__", "partialmethod", "__init__"}:
            found.add(node.lineno)
        if (isinstance(node, ast.alias) and node.name in {"type", "classmethod", "partialmethod"}
                and isinstance(parents.get(node), ast.ImportFrom)):
            found.add(getattr(node, "lineno", parents[node].lineno))
        if (_name(node, "type") or "builtins.type" in names.resolve(node)):
            call = parents.get(node)
            outer = parents.get(call)
            if (not isinstance(call, ast.Call) or call.func is not node
                    or len(call.args) == 1 and not (not call.keywords
                        and isinstance(outer, ast.Attribute) and outer.value is call
                        and isinstance(outer.ctx, ast.Load)
                        and outer.attr in {"__name__", "__qualname__", "__module__"})):
                found.add(node.lineno)
        if ((_name(node, "classmethod") or "builtins.classmethod" in names.resolve(node))
                and node not in decorators):
            found.add(node.lineno)
        if identifier in ("__dict__", "__class__") and node not in guard_nodes:
            found.add(node.lineno)
        if (isinstance(node, ast.Attribute) and node.attr in {"__mode", "_MailboxIndex__mode"}
                and isinstance(node.ctx, (ast.Store, ast.Del))
                or _literal(node, "_MailboxIndex__mode")):
            found.add(node.lineno)
        if isinstance(node, ast.Call):
            func = node.func
            callee = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
            if (callee in ("vars", "setattr", "delattr")
                    or isinstance(func, ast.Attribute) and func.attr == "__init__"):
                found.add(node.lineno)
        if _mode_write(node, names):
            found.add(node.lineno)
        if _reference(node, names):
            parent = parents.get(node)
            if (not isinstance(parent, ast.Call) or parent.func is not node
                    or not _shadow_call(parent, signature, allow_default=True)):
                found.add(node.lineno)
    return [(line, "RF24_SIGNATURE") for line in sorted(found)]


def _importer_state_access(node):
    if isinstance(node, ast.Attribute):
        if (isinstance(node.ctx, (ast.Store, ast.Del))
                and node.attr in {"__class__", "__getattribute__", "__getattr__", "__init__", "__new__"}):
            return True
        if node.attr == "__init__":
            call = node.value
            return not (isinstance(call, ast.Call) and _name(call.func, "super")
                        and not call.args and not call.keywords)
    if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
        target = node.value
        while isinstance(target, ast.Subscript):
            target = target.value
        if isinstance(target, ast.Attribute) and target.attr in {"__kwdefaults__", "__defaults__"}:
            return True
    return _literal(node, "_MailboxIndex__mode")


def _violations(tree, name, signature):
    try:
        names = ScopedNames(tree, name)
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        if name == INDEX:
            found = set(_index_shape(tree, names, parents))
        else:
            found = set()
            for node in ast.walk(tree):
                if (isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names)
                        and (node.module or "").endswith("hierarchy_mailbox_index")):
                    found.add((node.lineno, "RF24_REFERENCE"))
                if _reference(node, names):
                    parent = parents.get(node)
                    callee = isinstance(parent, ast.Call) and parent.func is node
                    if not callee or not _shadow_call(parent, signature):
                        found.add((node.lineno, "RF24_MODE" if callee else "RF24_REFERENCE"))
                if _mode_write(node, names) or _importer_state_access(node):
                    found.add((node.lineno, "RF24_MODE_WRITE"))
        return [_message(name, line, code) for line, code in sorted(found)]
    except (RecursionError, MemoryError):
        raise AssertionError(_message(name, code="RF24_PARSE")) from None


def _parts(name):
    # Invalid path bytes are never echoed. A valid, bounded tracked path is a location.
    _require(0 < len(name) <= 4096 and name.isprintable()
             and not any(char in name for char in "\\\0:"), None, "RF24_PATH")
    parts = name.split("/")
    _require(len(parts) <= 64 and all(part not in ("", ".", "..") for part in parts), None, "RF24_PATH")
    return parts


def _read_source(root, name, limit=MAX_SOURCE):
    parts = _parts(name)
    path = root
    try:
        for index, part in enumerate(parts):
            path = path / part
            info = path.lstat()
            reparse = getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            _require(not stat.S_ISLNK(info.st_mode) and not reparse, name, "RF24_READ")
            _require(stat.S_ISDIR(info.st_mode) if index < len(parts) - 1 else stat.S_ISREG(info.st_mode),
                     name, "RF24_READ")
        _require(info.st_size <= limit, name, "RF24_SIZE")
        with path.open("rb") as stream:
            raw = stream.read(info.st_size + 1)
        _require(len(raw) <= limit, name, "RF24_SIZE")
        _require(len(raw) == info.st_size, name, "RF24_READ")
        return raw
    except OSError:
        raise AssertionError(_message(name, code="RF24_READ")) from None


def _git_environment():
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    env["LC_ALL"] = "C"
    return env


def _tracked_names(root):
    try:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            try:
                result = subprocess.run(
                    ["git", "-c", "core.fsmonitor=false", "ls-files", "--stage", "-z", "--",
                     "tools", "aegis_*", "rules", "skills"],
                    cwd=root, env=_git_environment(), stdout=output, stderr=errors, timeout=5, check=False,
                )
            except FileNotFoundError as error:
                if error.filename not in (None, "git") or not root.is_dir():
                    raise AssertionError(_message(code="RF24_GIT")) from None
                pytest.skip("RF24_GIT: git is unavailable; install git and rerun")
            _require(os.fstat(errors.fileno()).st_size <= MAX_ERRORS, None, "RF24_SIZE")
            _require(os.fstat(output.fileno()).st_size <= MAX_LIST, None, "RF24_SIZE")
            if result.returncode:
                errors.seek(0)
                lines = errors.read(MAX_ERRORS + 1).decode("utf-8", errors="replace").splitlines()
                line = next((line for line in lines if line.startswith(("fatal:", "error:"))), "")
                line = "".join(char if char.isprintable() else "?" for char in line)
                raise AssertionError(_message(code="RF24_GIT") + ("\n" + line if line else ""))
            output.seek(0)
            raw = output.read(MAX_LIST + 1)
        _require(len(raw) <= MAX_LIST and raw.count(b"\0") <= MAX_FILES, None, "RF24_SIZE")
        _require(not raw or raw.endswith(b"\0"), None, "RF24_GIT")
        names = []
        for entry in raw.split(b"\0")[:-1]:
            fields = entry.split(b"\t", 1)
            _require(len(fields) == 2, None, "RF24_GIT")
            name = os.fsdecode(fields[1])
            parts = _parts(name)
            if not (parts[0] in RUNTIME_DIRS or parts[0].startswith("aegis_")):
                continue
            metadata = fields[0].split()
            _require(len(metadata) == 3 and metadata[2] == b"0", None, "RF24_GIT")
            _require(metadata[0] != b"120000", name, "RF24_READ")
            _require(metadata[0] in (b"100644", b"100755"), None, "RF24_GIT")
            names.append(name)
        return sorted(set(names))
    except (OSError, subprocess.TimeoutExpired):
        raise AssertionError(_message(code="RF24_GIT")) from None


def _importer_violations(raw, name, signature):
    _require(len(raw) <= MAX_SOURCE, name, "RF24_SIZE")
    offsets = [offset for needle in NEEDLES for offset in [raw.find(needle)] if offset >= 0]
    if not offsets:
        return []
    line = raw.count(b"\n", 0, min(offsets)) + 1
    python = name.endswith(".py")
    if not python or name not in ADMITTED_IMPORTERS:
        action = None if python else "remove the mention; only Python importers can be admitted"
        return [_message(name, line, "RF24_MENTION", action=action)]
    return _violations(_parse(raw, name), name, signature)


def _runtime_violations(root):
    try:
        root = root.resolve()
    except (OSError, RuntimeError):
        raise AssertionError(_message("<checkout>", code="RF24_READ")) from None
    names = _tracked_names(root)  # Exactly one inventory, only during the test.
    _require(INDEX in names, INDEX, "RF24_SIGNATURE")
    candidates, used = {}, 0
    for name in names:
        raw = _read_source(root, name, min(MAX_SOURCE, MAX_TOTAL - used))
        used += len(raw)
        if name == INDEX or any(needle in raw for needle in NEEDLES):
            candidates[name] = raw
    tree = _parse(candidates.pop(INDEX), INDEX)
    signature = _mode_signature(tree)
    return (_violations(tree, INDEX, signature)
            + [message for name, raw in sorted(candidates.items())
               for message in _importer_violations(raw, name, signature)])


@pytest.fixture
def shadow_signature():
    return _mode_signature(ast.parse(
        'class MailboxIndex:\n    def __init__(self, mailbox, *, mode="shadow"): pass\n'
    ))


@pytest.fixture
def pipeline_repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("RF24_GIT: git is unavailable; install git and rerun")
    (tmp_path / "tools").mkdir()
    shutil.copyfile(REPO / INDEX, tmp_path / INDEX)
    (tmp_path / "tools/probe.py").write_text("# tracked probe\n", encoding="utf-8")
    (tmp_path / "tools/irrelevant.py").write_text("invalid syntax (", encoding="utf-8")
    for args in [("init", "--quiet"), ("add", "--", "tools")]:
        subprocess.run(["git", *args], cwd=tmp_path, env=_git_environment(),
                       check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (tmp_path / "tools/untracked.py").write_text("MailboxIndex(", encoding="utf-8")
    return tmp_path


def test_round3_planted_shadow_adoption_refuses(pipeline_repo):
    (pipeline_repo / "tools/probe.py").write_text(
        'from tools.hierarchy_mailbox_index import MailboxIndex\n'
        'MailboxIndex(mailbox, mode="shadow")\n', encoding="utf-8",
    )
    findings = _runtime_violations(pipeline_repo)
    assert len(findings) == 1 and "tools/probe.py:1: RF24_MENTION:" in findings[0]


def test_tip_prefilters_once_with_clean_git_environment(monkeypatch):
    real_run, real_parse = subprocess.run, ast.parse
    calls, parsed, tracked = [], [], []
    real_tracked_names = _tracked_names
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_CONFIG_COUNT", "gIt_DIR"):
        monkeypatch.setenv(key, "RF24-untrusted-environment")

    def observed_run(*args, **kwargs):
        calls.append(args[0])
        assert not any(key.upper().startswith("GIT_") for key in kwargs["env"])
        return real_run(*args, **kwargs)

    def observed_parse(*args, **kwargs):
        parsed.append(kwargs.get("filename"))
        return real_parse(*args, **kwargs)

    def observed_tracked_names(root):
        names = real_tracked_names(root)
        tracked.extend(names)
        return names

    monkeypatch.setattr(subprocess, "run", observed_run)
    monkeypatch.setattr(ast, "parse", observed_parse)
    monkeypatch.setitem(globals(), "_tracked_names", observed_tracked_names)
    assert _runtime_violations(REPO) == []
    assert len(calls) == 1 and "ls-files" in calls[0]
    assert all(path in calls[0] for path in ("tools", "aegis_*", "rules", "skills"))
    assert parsed == [INDEX] + sorted(ADMITTED_IMPORTERS.intersection(tracked))


def test_owner_admits_only_doctor_and_refuses_a_second_importer(shadow_signature):
    doctor = "tools/hierarchy_mailbox_doctor.py"
    assert ADMITTED_IMPORTERS == frozenset({doctor})
    raw = b'from tools.hierarchy_mailbox_index import MailboxIndex\nMailboxIndex(mailbox, mode="shadow")\n'
    assert _importer_violations(raw, doctor, shadow_signature) == []
    second = "tools/second_reader.py"
    assert _importer_violations(raw, second, shadow_signature) == [_message(second, 1, "RF24_MENTION")]
    # New files may be untracked in a writer handoff. Check the admitted source
    # directly too; this remains a plain bounded read of our own repository.
    assert _importer_violations(_read_source(REPO, doctor, MAX_SOURCE), doctor, shadow_signature) == []


def _symlink(target, link, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except NotImplementedError:
        pytest.skip("symlink creation is unavailable")
    except OSError as error:
        if os.name == "nt" and getattr(error, "winerror", None) in (50, 1314):
            pytest.skip("symlink creation needs Windows privileges or filesystem support")
        raise


@pytest.mark.parametrize("winerror", [None, 50, 1314], ids=["no-symlinks", "windows-filesystem", "windows-privileges"])
def test_unsupported_symlinks_skip(tmp_path, monkeypatch, winerror):
    target, link = tmp_path / "target", tmp_path / "link"

    def unsupported(*args, **kwargs):
        if winerror is None:
            raise NotImplementedError("untrusted detail")
        error = OSError("untrusted detail")
        error.winerror = winerror
        raise error

    with pytest.raises(pytest.skip.Exception) as error:
        with monkeypatch.context() as patch:
            patch.setattr(Path, "symlink_to", unsupported)
            if winerror is not None:
                patch.setattr(os, "name", "nt")
            _symlink(target, link)
    expected = ("symlink creation is unavailable" if winerror is None else
                "symlink creation needs Windows privileges or filesystem support")
    assert str(error.value) == expected


def test_tracked_symlink_refuses_through_pipeline(pipeline_repo):
    probe = pipeline_repo / "tools/probe.py"
    outside = pipeline_repo.parent / "outside.py"
    outside.write_text("MailboxIndex", encoding="utf-8")
    probe.unlink()
    _symlink(outside, probe)
    subprocess.run(["git", "add", "--", "tools/probe.py"], cwd=pipeline_repo,
                   env=_git_environment(), check=True, timeout=5,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with pytest.raises(AssertionError) as error:
        _runtime_violations(pipeline_repo)
    assert str(error.value) == _message("tools/probe.py", code="RF24_READ")


@pytest.mark.parametrize("source,line", [
    pytest.param('class Factory:\n    from tools.hierarchy_mailbox_index import MailboxIndex as Build\nFactory.Build(mb)', 2, id='class-alias'),
    pytest.param('import tools.hierarchy_mailbox_index as idx\ndef build(mb):\n    return idx.MailboxIndex(mb)', 1, id='factory'),
    pytest.param('from hierarchy_mailbox_index import MailboxIndex as Export', 1, id='script-reexport'),
    pytest.param('from tools.hierarchy_mailbox_index import MailboxIndex\nBuild = MailboxIndex', 1, id='assignment-alias'),
    pytest.param('from tools.hierarchy_mailbox_index import MailboxIndex\npartial(MailboxIndex, mode="indexed")', 1, id='partial'),
    pytest.param('consume(MailboxIndex)', 1, id='callback'),
    pytest.param('class Derived(MailboxIndex): pass', 1, id='subclass'),
    pytest.param('idx = MailboxIndex(mb, mode="shadow"); idx.mode = config["mode"]', 1, id='mode-write'),
    pytest.param('# hierarchy_mailbox_index', 1, id='module-needle-comment'),
    pytest.param('MailboxIndex(', 1, id='malformed-mention'),
])
def test_unadmitted_mention_classes_refuse(source, line, shadow_signature):
    assert _importer_violations(source.encode(), "tools/probe.py", shadow_signature) == [
        _message("tools/probe.py", line, "RF24_MENTION")
    ]


@pytest.mark.parametrize("sources,refused", [
    ({"tools/probe.py": 'idx = MailboxIndex(mailbox); idx.__init__(mailbox, mode="indexed")'},
     "tools/probe.py"),
    ({"tools/hierarchy_mailbox_pager.py": 'from hierarchy_mailbox_index import MailboxIndex as Index',
      "tools/consumer.py": 'from hierarchy_mailbox_pager import Index\nIndex(mailbox, mode="indexed")'},
     "tools/hierarchy_mailbox_pager.py"),
    ({"tools/probe.py": 'idx = MailboxIndex(mailbox); idx.__dict__.update(mode="indexed")'},
     "tools/probe.py"),
    ({"tools/probe.py": 'from tools.hierarchy_mailbox_index import MailboxIndex as Index\n'
                        'class Holder: Index = Index(mailbox, mode="indexed")'}, "tools/probe.py"),
], ids=["argon1-reinitialization", "argon2-bare-reexport-pair", "argon3-dict-update", "argon4-class-body"])
def test_argon0708_inputs_refuse_unadmitted(sources, refused, shadow_signature):
    assert ADMITTED_IMPORTERS.isdisjoint(sources)
    findings = [message for name, source in sources.items()
                for message in _importer_violations(source.encode(), name, shadow_signature)]
    assert findings == [_message(refused, 1, "RF24_MENTION")]


def test_mentions_in_every_runtime_location_refuse(shadow_signature):
    for name in ("tools/probe.py", "aegis_core/probe.py", "aegis_cli/probe.py", "aegis_mcp/probe.py",
                 "aegis_sdk/probe.py", "rules/probe.py", "skills/probe.py", "skills/probe/SKILL.md"):
        assert _importer_violations(b"MailboxIndex", name, shadow_signature) == [
            _message(name, 1, "RF24_MENTION", action=None if name.endswith(".py") else
                     "remove the mention; only Python importers can be admitted")
        ]


def test_irrelevant_bytes_are_not_parsed(shadow_signature):
    assert _importer_violations(b"invalid syntax without an index mention (", "tools/probe.py",
                                shadow_signature) == []


@pytest.mark.parametrize("prefix,callee", [
    ("", "MailboxIndex"),
    ("from tools.hierarchy_mailbox_index import MailboxIndex as X\n", "X"),
    ("from .hierarchy_mailbox_index import MailboxIndex as X\n", "X"),
    ("import tools.hierarchy_mailbox_index as idx\n", "idx.MailboxIndex"),
    ("from tools import hierarchy_mailbox_index as idx\n", "idx.MailboxIndex"),
    ("import tools.hierarchy_mailbox_index\n", "tools.hierarchy_mailbox_index.MailboxIndex"),
])
def test_admitted_import_spellings_remain_checked(prefix, callee, shadow_signature):
    for mode, allowed in [("'shadow'", True), ("'indexed'", False)]:
        tree = ast.parse(f"{prefix}{callee}(mailbox, mode={mode})")
        line = 2 if prefix else 1
        assert _violations(tree, "tools/probe.py", shadow_signature) == (
            [] if allowed else [_message("tools/probe.py", line)]
        )


@pytest.mark.parametrize("arguments,allowed", [
    ("mailbox, mode='shadow'", True), ("mailbox", False),
    ("mailbox, mode=choice", False), ("mailbox, mode=self.mode", False),
    ("*args, mode='shadow'", False), ("mailbox, **options", False),
    ("mailbox, 'shadow'", False),
    ("mailbox, mode='shadow', mode='shadow'", False),
])
def test_admitted_constructions_require_explicit_literal_shadow(arguments, allowed, shadow_signature):
    findings = _violations(ast.parse(f"MailboxIndex({arguments})"), "tools/probe.py", shadow_signature)
    assert findings == ([] if allowed else [_message("tools/probe.py", 1)])


def test_admitted_importer_routes_through_ast(monkeypatch, shadow_signature):
    monkeypatch.setitem(globals(), "ADMITTED_IMPORTERS", frozenset({"tools/probe.py"}))
    assert _importer_violations(b'MailboxIndex(mb, mode="shadow")', "tools/probe.py", shadow_signature) == []
    assert _importer_violations(b'MailboxIndex(mb, mode="indexed")', "tools/probe.py", shadow_signature) == [
        _message("tools/probe.py", 1)
    ]
    assert _importer_violations(b"MailboxIndex(", "tools/unadmitted.py", shadow_signature) == [
        _message("tools/unadmitted.py", 1, "RF24_MENTION")
    ]


@pytest.mark.parametrize("source,code", [
    ('Build = MailboxIndex', "RF24_REFERENCE"),
    ('from hierarchy_mailbox_index import *', "RF24_REFERENCE"),
    ('idx.mode = "shadow"', "RF24_MODE_WRITE"),
    ('del idx.mode', "RF24_MODE_WRITE"),
    ('setattr(idx, "mode", "shadow")', "RF24_MODE_WRITE"),
    ('from builtins import setattr as put\nput(idx, "mode", choice)', "RF24_MODE_WRITE"),
    ('idx.__setattr__("mode", choice)', "RF24_MODE_WRITE"),
    ('setattr(idx, attribute, choice)', "RF24_MODE_WRITE"),
    ('idx.__dict__["mode"] = choice', "RF24_MODE_WRITE"),
])
def test_admitted_references_and_mode_mutations_refuse(source, code, shadow_signature):
    findings = _violations(ast.parse(source), "tools/probe.py", shadow_signature)
    assert findings == [_message("tools/probe.py", source.count("\n") + 1, code)]


def test_admitted_imports_reads_and_unrelated_attributes_are_allowed(shadow_signature):
    tree = ast.parse('from tools.hierarchy_mailbox_index import MailboxIndex\n'
                     'idx = MailboxIndex(mb, mode="shadow")\n'
                     'print(idx.mode)\nsetattr(idx, "other", "indexed")')
    assert _violations(tree, "tools/probe.py", shadow_signature) == []


@pytest.mark.parametrize("source", [
    "pass", "class Other: pass",
    'class MailboxIndex:\n    def __init__(self, mailbox): pass',
    'class MailboxIndex:\n    def __init__(self, mailbox, *, mode="indexed"): pass',
    'class MailboxIndex:\n    def __init__(self, mailbox, *, mode=CONFIG): pass',
    'class MailboxIndex:\n    def __init__(self, mailbox, *, mode): pass',
    'class MailboxIndex:\n    def __init__(self, mailbox, *, mode="shadow"): pass\n'
    '    def __init__(self, mailbox, *, mode="shadow"): pass',
])
def test_changed_signature_refuses(source):
    with pytest.raises(AssertionError) as error:
        _mode_signature(ast.parse(source))
    assert str(error.value) == _message(INDEX, code="RF24_SIGNATURE")


def test_positional_mode_is_checked_against_the_signature():
    signature = _mode_signature(ast.parse(
        'class MailboxIndex:\n    def __init__(self, mailbox, mode="shadow"): pass'
    ))
    assert _violations(ast.parse('MailboxIndex(mb, "shadow")'), "tools/probe.py", signature) == []
    assert _violations(ast.parse('MailboxIndex(mb, "indexed")'), "tools/probe.py", signature) == [
        _message("tools/probe.py", 1)
    ]


@pytest.mark.parametrize("body", [
    "self.mode = mode", "self.mailbox, self.mode = mailbox, mode",
    ])
def test_index_old_mutable_parameter_stores_refuse(body, shadow_signature):
    tree = ast.parse('class MailboxIndex:\n    def __init__(self, mailbox, *, mode="shadow"):\n        ' + body)
    findings = _violations(tree, INDEX, shadow_signature)
    assert findings and all("RF24_SIGNATURE:" in message for message in findings)


@pytest.mark.parametrize("locationless", [False, True], ids=["native-alias", "locationless-alias"])
def test_initializer_alias_without_location_refuses(shadow_signature, monkeypatch, locationless):
    if locationless:
        real_parse = ast.parse

        def parse_without_alias_locations(*args, **kwargs):
            parsed = real_parse(*args, **kwargs)
            for node in ast.walk(parsed):
                if isinstance(node, ast.alias) and hasattr(node, "lineno"):
                    del node.lineno
            return parsed

        monkeypatch.setattr(ast, "parse", parse_without_alias_locations)
    tree = ast.parse(_index_source(initializer='import settings as mode\nself.mailbox = mailbox'))
    init = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "__init__")
    alias = next(node for node in ast.walk(init) if isinstance(node, ast.alias))
    if hasattr(alias, "lineno"):
        del alias.lineno  # Python 3.9 aliases already lack this attribute.
    assert _violations(tree, INDEX, shadow_signature) == [_message(INDEX, init.lineno, "RF24_SIGNATURE")]


@pytest.mark.parametrize("raw,code", [
    (b"MailboxIndex(", "RF24_PARSE"),
    (b"\xff", "RF24_PARSE"),
    (b"x" * (MAX_SOURCE + 1), "RF24_SIZE"),
], ids=["syntax", "encoding", "size"])
def test_parse_refusals_have_fixed_actions(raw, code):
    with pytest.raises(AssertionError) as error:
        _parse(raw, "tools/probe.py")
    assert str(error.value) == _message("tools/probe.py", code=code)


@pytest.mark.parametrize("kind", ["missing", "size", "budget", "directory"])
def test_read_refusals_have_fixed_actions(tmp_path, kind):
    probe = tmp_path / "probe.py"
    if kind in ("size", "budget"):
        probe.write_bytes(b"x" * (MAX_SOURCE + 1) if kind == "size" else b"four")
    elif kind == "directory":
        probe.mkdir()
    with pytest.raises(AssertionError) as error:
        _read_source(tmp_path, "probe.py", limit=3 if kind == "budget" else MAX_SOURCE)
    code = "RF24_SIZE" if kind in ("size", "budget") else "RF24_READ"
    assert str(error.value) == _message("probe.py", code=code)


def test_read_refuses_directory_symlink(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "probe.py").write_text("pass", encoding="utf-8")
    _symlink(actual, tmp_path / "linked", directory=True)
    with pytest.raises(AssertionError) as error:
        _read_source(tmp_path, "linked/probe.py")
    assert str(error.value) == _message("linked/probe.py", code="RF24_READ")


@pytest.mark.parametrize("name", ["", "../secret", "/absolute", "a//b", "a/./b", "a\\b",
                                "C:secret", "secret\nsource", "a" * 4097, "/".join(["a"] * 65)],
                         ids=["empty", "parent", "absolute", "empty-part", "dot", "backslash",
                              "drive", "control", "length", "depth"])
def test_invalid_paths_do_not_echo_input(name):
    with pytest.raises(AssertionError) as error:
        _parts(name)
    assert str(error.value) == _message(code="RF24_PATH")


@pytest.mark.parametrize("kind,code", [
    ("timeout", "RF24_GIT"), ("os-error", "RF24_GIT"),
    ("non-checkout", "RF24_GIT"), ("dubious", "RF24_GIT"),
    ("exit", "RF24_GIT"), ("list-size", "RF24_SIZE"), ("stderr-size", "RF24_SIZE"),
    ("count", "RF24_SIZE"), ("no-terminator", "RF24_GIT"), ("no-tab", "RF24_GIT"),
    ("bad-stage", "RF24_GIT"), ("bad-mode", "RF24_GIT"), ("symlink", "RF24_READ"),
    ("bad-path", "RF24_PATH"),
])
def test_git_refusals_have_fixed_actions_and_no_path_guess(tmp_path, monkeypatch, kind, code):
    line = {
        "non-checkout": b"fatal: not a git repository (or any parent)\n",
        "dubious": b"fatal: detected dubious ownership in repository at 'fixture'\n",
    }.get(kind, b"")
    record = b"100644 " + b"a" * 40 + b" 0\ttools/probe.py\0"

    def run(*args, **kwargs):
        if kind == "timeout":
            raise subprocess.TimeoutExpired("untrusted detail", 5)
        if kind == "os-error":
            raise OSError("untrusted detail")
        if kind == "list-size":
            kwargs["stdout"].truncate(MAX_LIST + 1)
        elif kind == "stderr-size":
            kwargs["stderr"].truncate(MAX_ERRORS + 1)
        else:
            raw = {
                "count": b"x\0" * (MAX_FILES + 1),
                "no-terminator": record[:-1],
                "no-tab": b"missing-fields\0",
                "bad-stage": record.replace(b" 0\t", b" 1\t"),
                "bad-mode": record.replace(b"100644", b"160000"),
                "symlink": record.replace(b"100644", b"120000"),
                "bad-path": record.replace(b"tools/probe.py", b"tools/../untrusted"),
            }.get(kind, record)
            kwargs["stdout"].write(raw)
        kwargs["stderr"].write(line)
        return subprocess.CompletedProcess(args[0], 128 if kind in ("non-checkout", "dubious", "exit") else 0)

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(AssertionError) as error:
        _tracked_names(tmp_path)
    expected = _message("tools/probe.py" if kind == "symlink" else None, code=code)
    assert str(error.value) == expected + ("\n" + line.decode().rstrip("\n") if line else "")


def test_missing_git_skips_with_reason(tmp_path, monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("untrusted detail")

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(pytest.skip.Exception) as error:
        _tracked_names(tmp_path)
    assert str(error.value) == "RF24_GIT: git is unavailable; install git and rerun"


def test_git_inventory_includes_shipped_rules_skills_and_non_python_files(tmp_path, monkeypatch):
    names = ["tools/probe.py", INDEX, "aegis_core/probe.py", "rules/probe.py",
             "skills/probe.py", "skills/probe/SKILL.md"]
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        for name in names:
            kwargs["stdout"].write(b"100644 " + b"a" * 40 + b" 0\t" + name.encode() + b"\0")
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(subprocess, "run", run)
    assert _tracked_names(tmp_path) == sorted(names)
    assert len(calls) == 1 and calls[0][-4:] == ["tools", "aegis_*", "rules", "skills"]

def _index_source(body="", initializer="self.mailbox = mailbox", decorator=""):
    source = _GUARD_CONTEXT_SOURCE + _MODE_GUARD_SOURCE.replace(
        "        self.mailbox = mailbox\n",
        "\n".join("        " + line for line in initializer.splitlines()) + "\n")
    if decorator:
        source = source.replace("    def __init__", "    " + decorator + "\n    def __init__")
    return source + body


def test_index_reviewed_runtime_guard_is_allowed(shadow_signature):
    assert _violations(ast.parse(_index_source()), INDEX, shadow_signature) == []


@pytest.mark.parametrize("hook", ["__getattribute__", "__getattr__"])
@pytest.mark.parametrize("renamed", [False, True], ids=["unrenamed", "renamed"])
@pytest.mark.parametrize("locationless", [False, True], ids=["native-alias", "py39-alias"])
def test_imported_lookup_hooks_refuse(hook, renamed, locationless, shadow_signature):
    binding = "lookup as " + hook if renamed else hook
    source = _index_source("    from helper import " + binding + "\n")
    tree = ast.parse(source)
    if locationless:
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "helper":
                node.names[:] = [ast.alias(name=alias.name, asname=alias.asname) for alias in node.names]
    findings = _violations(tree, INDEX, shadow_signature)
    assert findings and all("RF24_SIGNATURE:" in message for message in findings)


def test_imported_delegating_getter_refuses(shadow_signature):
    source = _index_source("    from helper import lookup as __getattribute__\n") + '''
def lookup(self, name):
    value = object.__getattribute__(self, name)
    return "indexed" if name == "mode" else value
'''
    findings = _violations(ast.parse(source), INDEX, shadow_signature)
    assert findings and all("RF24_SIGNATURE:" in message for message in findings)


@pytest.mark.parametrize("identifier", ["__getattribute__", "__getattr__", "_ModeSnapshot"])
@pytest.mark.parametrize("statement", [
    "NAME = replacement", "del NAME", "from helper import NAME",
    "from helper import lookup as NAME", "import helper as NAME",
    "def NAME(): pass", "async def NAME(): pass", "class NAME: pass",
    "try:\n    pass\nexcept E as NAME:\n    pass",
    "global NAME", "nonlocal NAME", "def other(NAME): pass",
])
def test_protected_binding_forms_refuse(identifier, statement, shadow_signature):
    body = "\n".join("    " + line for line in statement.replace("NAME", identifier).splitlines()) + "\n"
    findings = _violations(ast.parse(_index_source(body)), INDEX, shadow_signature)
    assert findings and all("RF24_SIGNATURE:" in message for message in findings)


@pytest.mark.parametrize("statement", [
    '_MISSING = "shadow"', 'getattr = lambda *args: "shadow"',
    'property = lambda *args: "indexed"', 'dict = replacement',
    'object = replacement', 'AttributeError = replacement', 'hm = replacement',
    'from helper import lookup as getattr', 'from helper import property',
])
def test_guard_global_rebindings_refuse(statement, shadow_signature):
    source = _index_source() + "\n" + statement + "\n"
    findings = _violations(ast.parse(source), INDEX, shadow_signature)
    assert findings and all("RF24_SIGNATURE:" in message for message in findings)


@pytest.mark.parametrize("statement", [
    'idx.__init__.__kwdefaults__["mode"] = "indexed"',
    'type(idx).__getattribute__ = lambda s, n: "indexed" if n == "mode" else object.__getattribute__(s, n)',
    'class Swap(index_module._IndexStorage):\n    __slots__ = ("_MailboxIndex__mode",)\n    mode = "indexed"\nidx.__class__ = Swap',
    'idx.__init__(mailbox, mode="indexed")', 'initialize = idx.__init__',
    'super(other).__init__()', 'idx.__defaults__[0] = "indexed"',
    'del idx.__kwdefaults__["mode"]', 'name = "_MailboxIndex__mode"',
])
def test_importer_construction_escapes_refuse(statement, shadow_signature):
    source = 'from tools import hierarchy_mailbox_index as index_module\n' + statement + "\n"
    findings = _importer_violations(source.encode(), "tools/hierarchy_mailbox_doctor.py", shadow_signature)
    assert findings and all("RF24_MODE_WRITE:" in message for message in findings)


@pytest.mark.parametrize("attribute", ["__class__", "__getattribute__", "__getattr__", "__init__", "__new__"])
@pytest.mark.parametrize("operation", ["store", "delete"])
@pytest.mark.parametrize("receiver", ["idx", "type(idx)", "other"])
def test_importer_class_attribute_mutations_refuse(attribute, operation, receiver, shadow_signature):
    target = receiver + "." + attribute
    statement = target + " = replacement" if operation == "store" else "del " + target
    findings = _violations(ast.parse(statement), "tools/hierarchy_mailbox_doctor.py", shadow_signature)
    assert findings and all("RF24_MODE_WRITE:" in message for message in findings)


@pytest.mark.parametrize("statement", [
    'class Refusal(Exception):\n    def __init__(self, code):\n        super().__init__(code)',
    'clone.__kwdefaults__ = function.__kwdefaults__',
    'clone.__defaults__ = function.__defaults__',
])
def test_doctor_initializer_and_whole_defaults_remain_allowed(statement, shadow_signature):
    assert _violations(ast.parse(statement), "tools/hierarchy_mailbox_doctor.py", shadow_signature) == []
    doctor = "tools/hierarchy_mailbox_doctor.py"
    assert _importer_violations(_read_source(REPO, doctor), doctor, shadow_signature) == []


@pytest.mark.parametrize("body", [
    '    def promote(self): self._MailboxIndex__mode = "indexed"\n',
    '    def promote(self, other): other.__mode = "indexed"\n',
    '\ndef promote(index): index._MailboxIndex__mode = "indexed"\n',
    '    def promote(self): del self._MailboxIndex__mode\n',
    '    def promote(self, other): del other.__mode\n',
    '\ndef promote(index): del index._MailboxIndex__mode\n',
    '    def promote(self): object.__setattr__(self, "_MailboxIndex__mode", "indexed")\n',
    '    def promote(self): object.__delattr__(self, "_MailboxIndex__mode")\n',
    '    def inspect(self): return "_MailboxIndex__mode"\n',
])
def test_backing_slot_spellings_refuse_on_every_receiver(body, shadow_signature):
    findings = _violations(ast.parse(_index_source(body)), INDEX, shadow_signature)
    assert findings and all("RF24_SIGNATURE:" in message for message in findings)


@pytest.mark.parametrize("body", [
    '    __init__ = functools.partialmethod(__init__, mode="indexed")\n',
    '    def promote(self): self.__init__.__kwdefaults__["mode"] = "indexed"\n',
    '    def promote(self): return self.__init__.__defaults__\n',
    '\ndef promote(index): return type(index)(index.mailbox, mode="indexed")\n',
    '    def promote(self, other): return type(other)(self.mailbox, mode="indexed")\n',
    '    def promote(self):\n        me = self\n        return type(me)(self.mailbox, mode="indexed")\n',
    '    def promote(self):\n        build = type\n        return build(self)(self.mailbox, mode="indexed")\n',
    '    def promote(self):\n        from builtins import type as build\n        return build(self)(self.mailbox, mode="indexed")\n',
    '    def promote(cls, mailbox): return cls(mailbox, mode="indexed")\n    promote = classmethod(promote)\n',
    '    wrap = classmethod\n    def promote(cls, mailbox): return cls(mailbox, mode="indexed")\n    promote = wrap(promote)\n',
    '    def __getattribute__(self, name): return "indexed" if name == "mode" else object.__getattribute__(self, name)\n',
    '    def __getattr__(self, name): return "indexed"\n',
])
def test_construction_escape_idioms_refuse(body, shadow_signature):
    findings = _violations(ast.parse(_index_source(body)), INDEX, shadow_signature)
    assert findings and all("RF24_SIGNATURE:" in message for message in findings)


@pytest.mark.parametrize("attribute", ["__name__", "__qualname__", "__module__"])
def test_type_metadata_reads_remain_allowed(attribute, shadow_signature):
    body = "    def inspect(self, error): return type(error)." + attribute + "\n"
    assert _violations(ast.parse(_index_source(body)), INDEX, shadow_signature) == []


@pytest.mark.parametrize("statement", [
    '_MODE_READ_ONLY: str = "x"',
    '_ModeSnapshot: object = replacement',
    '_IndexStorage: object = replacement',
    '_guard_mode: object = replacement',
    '_ModeSnapshot._refuse = replacement',
    'snapshot = _ModeSnapshot',
    'from config import value as _MODE_READ_ONLY',
    'def replace(_MODE_READ_ONLY): return _MODE_READ_ONLY',
    '_MODE_READ_ONLY += "x"',
])
def test_guard_support_rebindings_refuse(statement, shadow_signature):
    source = _index_source() + "\n" + statement + "\n"
    findings = _violations(ast.parse(source), INDEX, shadow_signature)
    assert findings and all("RF24_SIGNATURE:" in message for message in findings)


def test_guard_member_annotation_refuses(shadow_signature):
    source = _index_source('    __slots__: tuple = ()\n')
    findings = _violations(ast.parse(source), INDEX, shadow_signature)
    assert findings and all("RF24_SIGNATURE:" in message for message in findings)


def test_unrelated_slot_annotation_is_allowed(shadow_signature):
    source = _index_source() + '\nclass Other:\n    __slots__: tuple = ()\n'
    assert _violations(ast.parse(source), INDEX, shadow_signature) == []


@pytest.mark.parametrize("statement", [
    'delattr(idx, "mode")',
    'idx.__delattr__("mode")',
    'object.__delattr__(idx, "_MailboxIndex__mode")',
    'from builtins import delattr as remove\nremove(idx, "mode")',
])
def test_admitted_deletion_spelling_refuses(statement, shadow_signature):
    findings = _violations(ast.parse(statement), "tools/probe.py", shadow_signature)
    assert findings and all("RF24_MODE_WRITE:" in message for message in findings)


def test_admitted_unrelated_deletion_remains_allowed(shadow_signature):
    assert _violations(ast.parse('delattr(idx, "other")'), "tools/probe.py", shadow_signature) == []


@pytest.mark.parametrize("before,after", [
    ('slot.__set__(self, mode)', 'slot.__set__(self, "indexed")'),
    ('slot.__get__', 'lambda self: "indexed"'),
    ('raise AttributeError(_MODE_READ_ONLY)', 'pass'),
    ('del cls._MailboxIndex__mode', 'pass'),
    ('__slots__ = ("__mode",)', '__slots__ = ()'),
    ('class MailboxIndex(_IndexStorage)', 'class MailboxIndex'),
    ('if getattr(self, "mode", missing) is not missing:', 'if False:'),
])
def test_index_runtime_guard_mutations_refuse(before, after, shadow_signature):
    assert before in _index_source()
    findings = _violations(ast.parse(_index_source().replace(before, after)), INDEX, shadow_signature)
    assert findings and all("RF24_SIGNATURE:" in message for message in findings)


@pytest.mark.parametrize("source", [
    _index_source(initializer="pass"),
    _index_source(initializer='if mode != "shadow":\n    self.mode = mode'),
    _index_source(decorator="@decorate"),
    _index_source(initializer="self.mode = mode\nself.mode = mode"),
    _index_source(initializer='self.mode = os.environ.get("AEGIS_INDEX_MODE", mode)'),
    _index_source(initializer='mode = "indexed"\nself.mode = mode'),
    _index_source(initializer="del mode\nself.mode = mode"),
    _index_source('    @property\n    def mode(self): return config["mode"]\n'),
    _index_source('    mode = config["mode"]\n'),
    _index_source('    def promote(self): self.mode = "indexed"\n'),
    _index_source('    def promote(self): self.mode += "indexed"\n'),
    _index_source('    def promote(self): del self.mode\n'),
    _index_source() + '\nclass Other:\n    mode = config["mode"]\n',
], ids=["missing-store", "conditional-store", "decorated-init", "duplicate-store",
        "environment-value", "parameter-rebind", "parameter-delete", "property",
        "class-attribute", "other-store", "augassign", "attribute-delete", "other-class-binding"])
def test_index_shape_refuses(source, shadow_signature):
    findings = _violations(ast.parse(source), INDEX, shadow_signature)
    assert findings, "index accepted a forbidden mode shape"
    assert all("RF24_SIGNATURE:" in message for message in findings)


@pytest.mark.parametrize("statement", [
    'self.__dict__.update(mode=config["mode"])',
    'self.__dict__ = {"mode": "indexed"}',
    'vars(self).update(mode="indexed")',
    'setattr(self, "other", 1)',
    'delattr(self, "other")',
    'build = type(self)\nreturn build(self.mailbox, mode="indexed")',
    'build = self.__class__\nreturn build(self.mailbox, mode="indexed")',
    'self.__init__(self.mailbox, mode="indexed")',
], ids=["dict-update", "dict-replacement", "vars-write", "setattr", "delattr",
        "captured-type", "captured-class", "reinitialization"])
def test_index_state_and_constructor_tokens_refuse(statement, shadow_signature):
    body = "    def promote(self):\n" + "\n".join("        " + line for line in statement.splitlines())
    findings = _violations(ast.parse(_index_source(body)), INDEX, shadow_signature)
    assert findings, "index accepted a denied state or constructor token"
    assert all("RF24_SIGNATURE:" in message for message in findings)


@pytest.mark.parametrize("raw,line", [
    (b"# heading\n# another\nMailboxIndex(", 3),
    (b"# hierarchy_mailbox_index\nMailboxIndex(", 1),
    (b"# heading\nMailboxIndex\nhierarchy_mailbox_index", 2),
])
def test_mention_reports_first_line(raw, line, shadow_signature):
    assert _importer_violations(raw, "tools/probe.py", shadow_signature) == [
        _message("tools/probe.py", line, "RF24_MENTION")
    ]


def test_non_python_mentions_cannot_be_admitted(monkeypatch, shadow_signature):
    name = "skills/probe/SKILL.md"
    for admitted in (frozenset(), frozenset({name})):
        monkeypatch.setitem(globals(), "ADMITTED_IMPORTERS", admitted)
        assert _importer_violations(b"# heading\nMailboxIndex(", name, shadow_signature) == [
            name + ":2: RF24_MENTION: remove the mention; only Python importers can be admitted"
        ]



@pytest.mark.parametrize("statement", [
    'build = Receiver\nreturn build(mailbox, mode="indexed")',
    'return consume(Receiver)',
    'return Receiver.promote(mailbox)',
    'return Receiver(mailbox, mode="indexed")',
    'return Receiver(mailbox, mode=choice)',
    'Receiver = alternate\nreturn Receiver(mailbox)',
], ids=["receiver-alias", "receiver-argument", "receiver-attribute", "indexed-call", "dynamic-call", "receiver-rebind"])
def test_index_classmethod_receiver_refuses(statement, shadow_signature):
    body = ("    @classmethod\n    def clone(Receiver, mailbox):\n"
            + "\n".join("        " + line for line in statement.splitlines()))
    findings = _violations(ast.parse(_index_source(body)), INDEX, shadow_signature)
    assert findings, "index accepted a classmethod receiver outside a direct shadow call"
    assert all("RF24_SIGNATURE:" in message for message in findings)


def test_index_classmethod_direct_shadow_calls_are_allowed(shadow_signature):
    for arguments in ('mailbox', 'mailbox, mode="shadow"'):
        body = f"    @classmethod\n    def clone(Receiver, mailbox):\n        return Receiver({arguments})"
        assert _violations(ast.parse(_index_source(body)), INDEX, shadow_signature) == []


def test_receiver_pinned_attribute_read_is_allowed(shadow_signature):
    for expression in ("Receiver._path_key", "Receiver._path_key(path)"):
        body = ("    @classmethod\n    def inspect(Receiver, path):\n"
                "        return " + expression)
        assert _violations(ast.parse(_index_source(body)), INDEX, shadow_signature) == []


@pytest.mark.parametrize("statement", [
    "return Receiver._Other(path)",
    "return Receiver._Evidence.path_sample(path)",
    "Receiver._path_key = replacement",
    "del Receiver._path_key",
    "return Receiver._path_key.mode",
    "return Receiver._path_key.__init__",
    "return Receiver._path_key.__new__",
    "return Receiver._path_key.__dict__",
    "return Receiver._path_key.__class__",
    "return Receiver._path_key(path).mode",
    'Receiver._path_key["mode"] = "indexed"',
    'del Receiver._path_key["mode"]',
    'return Receiver._path_key["item"].mode',
], ids=["other-name", "removed-namespace", "store", "delete", "mode", "init", "new", "dict", "class", "mode-after-call",
        "subscript-store", "subscript-delete", "mode-after-subscript"])
def test_receiver_pinned_attribute_refusals(statement, shadow_signature):
    body = "    @classmethod\n    def inspect(Receiver, path):\n        " + statement
    findings = _violations(ast.parse(_index_source(body)), INDEX, shadow_signature)
    assert findings and all("RF24_SIGNATURE:" in message for message in findings)
