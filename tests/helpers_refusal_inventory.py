"""Source-derived refusal inventory for the opt-in mailbox record tools.

Call-protocol table (the executable CALL_PROTOCOLS table is authoritative):

Protocol          Handling       Dispatch
explicit          MODELLED       functions, instances, constructors and metaclasses
 decorator        MODELLED       decorator invocation and returned callable bindings
 descriptor       MODELLED       get/set/delete, staticmethod/classmethod wrappers
 operator         MODELLED       arithmetic/reflected/in-place/conversion protocols
 comparison       MODELLED       comparison hooks and both operands' capabilities
 containment      MODELLED       contains, iteration and equality fallbacks
 bool             MODELLED       boolean contexts, bool and len fallbacks
 len              MODELLED       resolved builtin len and its user hook
 iteration        MODELLED       iter/next/subscript, yield-from, loops/comprehensions
 context_manager  MODELLED       enter/exit including async context managers
 attribute_hook   MODELLED       getattribute/getattr/setattr/delattr
 registration     MODELLED       transported arguments or UNKNOWN parameter values
 defaults         MODELLED       incoming alternatives including callable instances
 storage_attribute MODELLED      class/module attribute candidates; UNKNOWN aliases
 storage_subscript MODELLED      local container/native method candidates; UNKNOWN module fallback
 storage_slice    MODELLED       slice contents join every visible container read
 suspension       ESCAPE-GATED   await with refusal-capable operands
 other_protocol   ESCAPE-GATED   unlisted dunders, metaclass forms, dynamic code

EXACT is issued only by the closed PROVEN_PATTERNS allowlist in resolve().
All other identities, layouts and states are UNKNOWN; joins retain every
candidate. Unenumerable code/detail values use the reserved ANY whole-field
sentinel. Closed escape-form guards still refuse unsupported constructs.
Unknown values never acquire a convenient primitive default. The closed
MODELLED_WRAPPERS and MODELLED_STORES tables prove the effects they support;
other consumers get unknown_environment() and other binding effects widen to
the module pool. Scalar values without enumerated evidence stay ANY. Summaries,
AST evaluation and control-flow steps all share INVENTORY_WORK_BUDGET.
BINDING_TARGET_FIELDS recognizes stores/captures; PRECISE_BINDING_FORMS and
PRECISE_BINDING_EXPRESSIONS are the only precision proofs. Every other bound
name stays UNKNOWN in both reference and scalar evaluation. CALL_TARGET_KINDS
admits modelled kinds only; constructors, callable objects and unproved wrapper
inputs retain concrete candidates plus the symbolic UNKNOWN_CALL_TARGET summary.
Already-bound methods retain their original receiver through re-exports.
Mutation owners use lexical identity evidence only: parameters, decorated
bindings and unmodelled storage shapes have wildcard owners. No parameter name
or default supplies an owner proof. Wildcard entries always invalidate reads,
including when a wildcard is the only census entry for a newly stored hook.
An unproved local declaration stops lexical lookup; it never borrows an outer
binding. Unproved argument layouts cannot supply a precise mutation field name.
Every recognized or unproved binder registers its names before declarations
are resolved, so nonlocal lookup cannot skip a nearer unproved binding scope.
Obfuscated namespace mutation remains outside the honest-source threat model.
"""
import ast
from collections import deque
from dataclasses import dataclass
from pathlib import Path
import re
from types import SimpleNamespace
from time import monotonic


# Bounds apply to the abstract value graph, independently of Python's stack.
INVENTORY_CANDIDATE_BOUND = 64
INVENTORY_DEPTH_BOUND = 64
INVENTORY_WORK_BUDGET = 100000

_REPO = Path(__file__).resolve().parents[1]

# Reserved whole-field sentinel in inventory results, never a substring glob.
# (code, ANY) includes every detail for that code; (ANY, ANY) includes every
# refusal. It is source-analysis metadata, never a product refusal code/detail.
ANY = "<ANY>"
# Abstract summary target with a non-identifier component, so it cannot alias
# any concrete source callable identity.
UNKNOWN_CALL_TARGET = "widened.<call_target>"


def covers_refusal(rows, pair):
    """Whether a union of symbolic rows contains the entire requested row."""
    return any((code == ANY or code == pair[0]) and (detail == ANY or detail == pair[1])
               for code, detail in rows)


def _refusal_rows(codes, details, model, node):
    if not codes or ANY in codes or any(type(code) is not str for code in codes):
        rows = RefusalRows({(ANY, ANY)})
    else:
        details = ({ANY} if details is None or any(detail is not None and type(detail) is not str for detail in details)
                   else {"" if detail is None else detail for detail in details})
        rows = RefusalRows((code, detail) for code in codes for detail in details)
    if any(ANY in row for row in rows):
        model.scalar_widened.add((getattr(node, "_inventory_file", "inventory.py"), getattr(node, "lineno", 1)))
    return rows


def _pinned_rows(statement):
    """The closed literal-table model; every unproved field/shape is ANY."""
    if not isinstance(statement, ast.Assign) or not any(
            isinstance(target, ast.Name) and target.id == "PINNED_REFUSALS" for target in statement.targets):
        return
    if not isinstance(statement.value, (ast.Tuple, ast.List)):
        yield ANY, ANY, ANY
        return
    for row in statement.value.elts:
        if not isinstance(row, (ast.Tuple, ast.List)) or len(row.elts) != 3:
            yield ANY, ANY, ANY
            continue
        message, code, detail = (part.value if isinstance(part, ast.Constant) and type(part.value) is str else ANY
                                 for part in row.elts)
        if isinstance(row.elts[2], ast.Constant) and row.elts[2].value is None:
            detail = ""
        if code == ANY:
            detail = ANY
        yield message, code, detail


class RefusalRows(set):
    """Finite symbolic rows with coverage-aware set comparisons and deltas.

    Iteration/JSON retain the sentinel so uncertainty is never serialized as a
    convenient literal. A difference retains a whole symbolic row when its
    remainder cannot be represented precisely (a conservative superset).
    """

    def __contains__(self, pair):
        return isinstance(pair, (tuple, list)) and len(pair) == 2 and covers_refusal(self, pair)

    def __le__(self, other):
        return all(covers_refusal(other, row) for row in self)

    def __ge__(self, other):
        return all(covers_refusal(self, row) for row in other)

    def __lt__(self, other):
        return self <= other and not self >= other

    def __gt__(self, other):
        return self >= other and not self <= other

    def __eq__(self, other):
        if not isinstance(other, (set, frozenset)):
            return NotImplemented
        return self <= other and self >= other

    def __ne__(self, other):
        result = self.__eq__(other)
        return NotImplemented if result is NotImplemented else not result

    def __sub__(self, other):
        return RefusalRows(row for row in self if not covers_refusal(other, row))

    def __rsub__(self, other):
        return RefusalRows(row for row in other if not covers_refusal(self, row))

    def __or__(self, other):
        return RefusalRows(set(self).union(other))

    __ror__ = __or__

    def __and__(self, other):
        result = RefusalRows()
        for left in self:
            for right in other:
                if all(a == b or a == ANY or b == ANY for a, b in zip(left, right)):
                    result.add(tuple(b if a == ANY else a for a, b in zip(left, right)))
        return result

    __rand__ = __and__

    def copy(self):
        return RefusalRows(self)

    def issubset(self, other):
        return self <= other

    def issuperset(self, other):
        return self >= other

    def difference(self, *others):
        result = self.copy()
        for other in others:
            result = result - other
        return result

    def union(self, *others):
        result = self.copy()
        for other in others:
            result.update(other)
        return result

    def intersection(self, *others):
        result = self.copy()
        for other in others:
            result = result & other
        return result

    def isdisjoint(self, other):
        return not self & other

    def __ior__(self, other):
        self.update(other)
        return self

    def __iand__(self, other):
        result = self & other
        self.clear()
        self.update(result)
        return self

    def __isub__(self, other):
        result = self - other
        self.clear()
        self.update(result)
        return self


class HistoryRows(set):
    """History messages use the same exact sentinel for unknown messages."""

    def __contains__(self, message):
        return set.__contains__(self, ANY) or set.__contains__(self, message)

    def __le__(self, other):
        return all(message in HistoryRows(other) for message in self)

    def __ge__(self, other):
        return all(message in self for message in other)

    def __eq__(self, other):
        if not isinstance(other, (set, frozenset)):
            return NotImplemented
        return self <= other and self >= other

    def __ne__(self, other):
        result = self.__eq__(other)
        return NotImplemented if result is NotImplemented else not result

    def __sub__(self, other):
        return HistoryRows(message for message in self if message not in HistoryRows(other))

    def __rsub__(self, other):
        return HistoryRows(message for message in other if message not in self)

    def copy(self):
        return HistoryRows(self)

    def __or__(self, other):
        return HistoryRows(set(self).union(other))

    __ror__ = __or__

    def __and__(self, other):
        return HistoryRows(message for message in self | other if message in self and message in HistoryRows(other))

    __rand__ = __and__

    def issubset(self, other):
        return self <= other

    def issuperset(self, other):
        return self >= other

    def difference(self, *others):
        result = self.copy()
        for other in others:
            result = result - other
        return result


def history_has_prefix(messages, prefix):
    return ANY in set(messages) or any(message.startswith(prefix) for message in messages)


class RefusalInventoryError(AssertionError):
    """A stable first refusal plus the complete, deterministic site census."""

    def __init__(self, sites):
        self.sites = tuple(dict.fromkeys(sites))
        super().__init__(self.sites[0])


def _owned_nodes(node):
    """Walk one callable's body without borrowing nested callable bindings."""
    yield node
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            yield child
            # A definition evaluates its headers in the enclosing environment.
            headers = ([child.args, *child.decorator_list,
                        *([child.returns] if child.returns is not None else [])]
                       if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else
                       [*child.bases, *child.keywords, *child.decorator_list] if isinstance(child, ast.ClassDef) else [child.args])
            for header in headers:
                yield from _owned_nodes(header)
        else:
            yield from _owned_nodes(child)


@dataclass(frozen=True)
class _Invocation:
    target: str
    arguments: tuple = ()

    def sort_key(self):
        return self.target, tuple((name, owner, expression if isinstance(expression, str) else
                                   ast.dump(expression, include_attributes=True))
                                  for name, expression, owner in self.arguments)


@dataclass(frozen=True)
class _Resolution:
    status: str
    candidates: frozenset
    invocations: tuple = ()
    callbacks: tuple = ()
    bindings: tuple = ()
    values: tuple = ()


class _CallableModel:
    """One binding graph and resolution authority shared by both inventories.

    Evidence is monotone and retains every possible definition. Only resolve()
    issues EXACT/UNKNOWN records and invocation environments; domain walkers
    attribute all candidate summaries without making independent guesses.
    """

    MODULES = {
        "records": ("tools/hierarchy_mailbox_records.py", "hierarchy_mailbox_records"),
        "guidance": ("tools/hierarchy_mailbox_records_guidance.py", "hierarchy_mailbox_records_guidance"),
        "codec": ("aegis_core/message_codec.py", "aegis_core.message_codec"),
        "format": ("aegis_core/message_codec_format.py", "aegis_core.message_codec_format"),
        "store": ("aegis_core/message_codec_store.py", "aegis_core.message_codec_store"),
        "views": ("aegis_core/message_codec_views.py", "aegis_core.message_codec_views"),
        "mailbox": ("tools/hierarchy_mailbox.py", "hierarchy_mailbox"),
        "mcp": ("tools/hierarchy_mailbox_mcp.py", "hierarchy_mailbox_mcp"),
        "pager": ("tools/hierarchy_mailbox_pager.py", "hierarchy_mailbox_pager"),
    }

    BUILTINS = frozenset({"isinstance", "issubclass", "type", "callable", "hasattr", "getattr", "super",
                          "dict", "list", "tuple", "set", "frozenset", "str", "int", "bool", "bytes", "len",
                          "all", "any", "ord", "range", "sorted", "zip", "enumerate", "min", "max",
                          "iter", "next", "repr", "divmod", "object", "float", "id", "sum", "abs", "hash", "format", "round", "pow", "complex", "reversed", "setattr", "delattr", "staticmethod", "classmethod", "property", "eval", "exec", "compile"})
    EXTERNAL_DATA = frozenset({"argparse", "contextlib", "dataclasses", "datetime", "hashlib", "importlib", "json", "os",
                               "pathlib", "re", "stat", "subprocess", "sys", "threading", "time", "types",
                               "unicodedata", "uuid", "weakref", "typing", "math", "errno", "copy"})
    DATA_BUILTINS = frozenset({"dict", "list", "tuple", "set", "frozenset", "str", "int", "bool", "bytes",
                                "len", "all", "any", "ord", "range", "sorted", "zip", "enumerate", "min", "max"})
    BUILTIN_PROTOCOLS = {
        "len": ("__len__",), "bool": ("__bool__", "__len__"),
        "str": ("__str__", "__repr__"), "repr": ("__repr__",), "bytes": ("__bytes__",),
        "int": ("__int__", "__index__"), "range": ("__index__",),
        "iter": ("__iter__", "__getitem__"), "next": ("__next__",),
        "enumerate": ("__iter__", "__next__", "__getitem__"),
        "min": ("__iter__", "__next__", "__lt__", "__gt__"),
        "max": ("__iter__", "__next__", "__lt__", "__gt__"),
        "divmod": ("__divmod__", "__rdivmod__"),
        "float": ("__float__", "__index__"), "complex": ("__complex__", "__float__", "__index__"),
        "abs": ("__abs__",), "hash": ("__hash__",), "format": ("__format__",), "round": ("__round__",),
        "pow": ("__pow__", "__rpow__"), "reversed": ("__reversed__", "__len__", "__getitem__"),
        "all": ("__iter__", "__next__", "__getitem__", "__bool__", "__len__"),
        "any": ("__iter__", "__next__", "__getitem__", "__bool__", "__len__"),
        "sorted": ("__iter__", "__next__", "__getitem__", "__lt__", "__gt__"),
        "zip": ("__iter__", "__next__", "__getitem__"),
        "sum": ("__iter__", "__next__", "__getitem__", "__add__", "__radd__"),
        "list": ("__iter__", "__next__", "__getitem__"), "tuple": ("__iter__", "__next__", "__getitem__"),
        "dict": ("keys", "__iter__", "__next__", "__getitem__", "__hash__", "__eq__"),
        "set": ("__iter__", "__next__", "__getitem__", "__hash__", "__eq__"),
        "frozenset": ("__iter__", "__next__", "__getitem__", "__hash__", "__eq__"),
        "getattr": ("__getattribute__", "__getattr__"), "hasattr": ("__getattribute__", "__getattr__"),
        "setattr": ("__setattr__",), "delattr": ("__delattr__",),
    }
    NATIVE_ARGUMENTS = {"format": (1,), "round": (1,), "getattr": (1,), "hasattr": (1,),
                        "setattr": (1, 2), "delattr": (1,)}
    META_HOOKS = frozenset({"__call__", "__instancecheck__", "__subclasscheck__"})
    NATIVE_STORAGE_METHODS = frozenset({"__getitem__", "get", "pop", "setdefault", "values", "items", "copy",
                                        "__iter__", "__next__", "__setitem__", "append", "extend", "insert", "update"})
    CONTAINER_STORES = frozenset({"append", "extend", "insert", "add", "update", "setdefault"})
    CONTAINER_READS = frozenset({"get", "pop", "items", "values", "keys", "copy", "fromkeys"})
    # Operand hooks still receive their full summaries. These resolved APIs
    # cannot invoke an operand *as a callback* (including a stored primitive).
    DATA_CONSUMERS = frozenset({"ext:re.fullmatch", "ext:re.compile", "ext:pathlib.Path",
                               "ext:os.open", "ext:os.close", "ext:os.read", "ext:os.write",
                               "ext:os.fstat", "ext:os.stat", "ext:os.rename", "ext:os.unlink",
                               "ext:hashlib.sha256", "ext:math.isfinite",
                               "ext:re.compile.fullmatch", "ext:re.compile.finditer"})
    CALLBACK_KEYWORDS = {
        "ext:json.dumps": frozenset({"default", "cls"}),
        "ext:json.loads": frozenset({"cls", "object_hook", "parse_float", "parse_int", "parse_constant", "object_pairs_hook"}),
        "builtin:sorted": frozenset({"key"}), "builtin:min": frozenset({"key"}), "builtin:max": frozenset({"key"}),
    }

    PROVEN_PATTERNS = (ast.Name, ast.Attribute, ast.Lambda, str)
    # A native wrapper is modelled only if its result preserves a callable's
    # descriptor kind. All other consumers use UNKNOWN argument environments.
    MODELLED_WRAPPERS = {"builtin:staticmethod": "static:", "builtin:classmethod": "classmeth:"}
    MODELLED_STORES = (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.For, ast.AsyncFor)
    # Recognition is separate from proof. New binding forms default to UNKNOWN;
    # only the precise forms below may retain a value in the declaring scope.
    BINDING_TARGET_FIELDS = {
        "Assign": ("targets",), "AnnAssign": ("target",),
        "For": ("target",), "AsyncFor": ("target",), "comprehension": ("target",),
        "NamedExpr": ("target",), "AugAssign": ("target",), "withitem": ("optional_vars",),
        "ExceptHandler": ("name",), "Delete": ("targets",),
        "Global": ("names",), "Nonlocal": ("names",),
        "Import": ("names",), "ImportFrom": ("names",),
        "MatchAs": ("name",), "MatchStar": ("name",), "MatchMapping": ("rest",),
    }
    PRECISE_BINDING_FORMS = frozenset({"Assign", "AnnAssign", "For", "AsyncFor", "Import", "ImportFrom"})
    PRECISE_PARAMETER_ROLES = frozenset({"posonlyargs", "args", "kwonlyargs"})
    PRECISE_BINDING_EXPRESSIONS = (ast.Constant, ast.Name, ast.Attribute, ast.Lambda, ast.Call,
                                   ast.List, ast.Tuple, ast.Set, ast.Dict, ast.Subscript, ast.IfExp)
    CALL_TARGET_KINDS = {
        "fn": "MODELLED", "rawfn": "MODELLED", "bound": "MODELLED",
        "member": "MODELLED", "member_static": "MODELLED", "member_class": "MODELLED",
        "static": "MODELLED", "classmeth": "MODELLED",
        "builtin": "MODELLED", "ext": "MODELLED", "extdata": "MODELLED", "container": "MODELLED",
        "class": "UNKNOWN", "inst": "UNKNOWN", "data": "UNKNOWN", "opaque": "UNKNOWN",
        "unknown": "UNKNOWN", "native": "UNKNOWN", "mod": "UNKNOWN",
    }
    CALL_PROTOCOLS = {
        "explicit": ("MODELLED", (ast.Call,), ("__call__", "__new__", "__init__", "__instancecheck__", "__subclasscheck__")),
        "decorator": ("MODELLED", (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef), ()),
        "descriptor": ("MODELLED", (ast.Attribute,), ("__get__", "__set__", "__delete__")),
        "operator": ("MODELLED", (ast.BinOp, ast.UnaryOp, ast.AugAssign, ast.FormattedValue, ast.Dict, ast.Set),
                     tuple("__" + name + "__" for name in
                           "add radd iadd sub rsub isub mul rmul imul matmul rmatmul imatmul truediv rtruediv itruediv floordiv rfloordiv ifloordiv mod rmod imod pow rpow ipow lshift rlshift ilshift rshift rrshift irshift and rand iand xor rxor ixor or ror ior neg pos abs invert index int float complex hash format str repr bytes".split())),
        "comparison": ("MODELLED", (ast.Compare,), ("__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__")),
        "containment": ("MODELLED", (ast.Compare,), ("__contains__", "__iter__", "__next__", "__getitem__", "__eq__")),
        "bool": ("MODELLED", (ast.If, ast.While, ast.IfExp, ast.BoolOp, ast.Assert, ast.comprehension), ("__bool__", "__len__")),
        "len": ("MODELLED", (), ("__len__",)),
        "iteration": ("MODELLED", (ast.For, ast.AsyncFor, ast.comprehension, ast.Subscript, ast.YieldFrom),
                      ("__iter__", "__next__", "__getitem__", "__setitem__", "__delitem__", "__aiter__", "__anext__", "send", "throw", "close")),
        "context_manager": ("MODELLED", (ast.With, ast.AsyncWith), ("__enter__", "__exit__", "__aenter__", "__aexit__")),
        "attribute_hook": ("MODELLED", (ast.Attribute,), ("__getattribute__", "__getattr__", "__setattr__", "__delattr__")),
        "registration": ("MODELLED", (ast.Call,), ()),
        "defaults": ("MODELLED", (ast.arguments,), ("__call__",)),
        "storage_attribute": ("MODELLED", (), ()),
        "storage_subscript": ("MODELLED", (), ()),
        "storage_slice": ("MODELLED", (), ()),
        "suspension": ("ESCAPE-GATED", (ast.Await,), ("__await__",)),
        "other_protocol": ("ESCAPE-GATED", (), ()),
    }

    # Resolved stdlib identity -> target position/name, args position, kwargs position.
    # None args/kwargs positions mean the remaining call arguments are forwarded.
    REGISTERED_CONSUMERS = {
        "ext:contextlib.ExitStack.callback": (0, None, None, None),
        "ext:functools.partial": (0, None, None, None),
        "ext:threading.Thread": (1, "target", 3, 4),
        "ext:atexit.register": (0, None, None, None),
    }

    def __init__(self, sources):
        self.sources = dict(sources)
        self.trees = {name: ast.parse(source) for name, source in sources.items()}
        self.functions, self.classes, self.lambdas = {}, {}, {}
        self.scope, self.parent, self.outer, self.method_class = {}, {}, {}, {}
        self.events, self.parameters, self.defaults, self.fields = {}, {}, {}, {}
        self.declarations, self.definition_keys, self.local_names = {}, {}, {}
        self.locations, self.tail = {}, {}
        self.arguments, self.overrides = {}, {}
        self.unknown_bindings, self._unknown_binding_values = {}, {}
        self.storage_attributes, self.storage_containers = {}, {}
        self.native_methods = {}
        self._mutation_raw, self._mutation_calls = [], []
        self._mutation_overflow = False
        self._mutation_attribute_names = set()
        self.mutation_census, self.mutation_sites = {}, []
        self._mutation_presence = {}
        self._storage_roots_cache, self._storage_values_cache = {}, {}
        self._projection_cache = {}
        self._layout_cache, self._layout_active = {}, set()
        self._protocol_arguments, self._protocol_changed = {}, False
        self.invocation_sites = []
        for name, tree in self.trees.items():
            self.outer[name] = None
            self._walk(tree, name)
        self.carriers = set()
        self.refusing = {"format.CodecError", "format.require", "_builtin.ValueError", UNKNOWN_CALL_TARGET}
        self._cache, self._resolution_cache, self._capability_cache = {}, {}, {}
        self.work_used, self.budget_exhausted = 0, False
        self.widened = {}
        self.known_contributors = {}
        self.scalar_widened = set()
        self._reset_graph()
        self._uncertain = []
        self.generated_fields = {}
        self._build_mutation_census()
        if self.widened:
            self._finish_widened()
            return
        for key, node in self.classes.items():
            generated = not node.bases and len(node.decorator_list) == 1 and all(
                self.refs(item.func if isinstance(item, ast.Call) else item, self.scope[node]) == {"ext:dataclasses.dataclass"}
                and (not isinstance(item, ast.Call) or not item.args and all(
                    keyword.arg == "frozen" and isinstance(keyword.value, ast.Constant) and type(keyword.value.value) is bool
                    for keyword in item.keywords)) for item in node.decorator_list)
            generated &= all(not isinstance(item, ast.AnnAssign) or isinstance(item.annotation, ast.Name)
                             for item in node.body)
            if generated and not self.members(key, "__init__"):
                names = [item.target.id for item in node.body if isinstance(item, ast.AnnAssign)
                         and isinstance(item.target, ast.Name)]
                self.generated_fields[key] = names
                self.parameters[key] = set(names)
                for name in names:
                    parameter = ast.copy_location(ast.Name(id=name, ctx=ast.Load()), node)
                    self.fields.setdefault((key, name), []).append((node, parameter, key))
        if self.widened:
            self._finish_widened()
            return
        # Monotone constraints over finite source expressions, not runtime
        # retries. Every successful step adds a binding or a relevance edge.
        while True:
            self._cache.clear()
            self._reset_graph()
            self._projection_cache.clear()
            self._storage_roots_cache.clear()
            self._storage_values_cache.clear()
            self._layout_cache.clear()
            self._resolution_cache.clear()
            self._capability_cache.clear()
            changed = False
            self._protocol_changed = False
            for call in self.invocation_sites:
                context = self.scope[call]
                resolution = self.resolve(call, context, invocation=True)
                if self.widened:
                    self._finish_widened()
                    return
                for invocation in resolution.bindings:
                    for name, expression, owner in invocation.arguments:
                        slot = self.arguments.setdefault((invocation.target, name), set())
                        if len(slot) >= INVENTORY_CANDIDATE_BOUND and (expression, owner) not in slot:
                            self._widen(("arguments", call, context, name), "candidates")
                            self._finish_widened()
                            return
                        if (expression, owner) not in slot:
                            slot.add((expression, owner))
                            changed = True
                owner = context
                if owner in self.functions and any(self.key(ref) in self.refusing
                                                    for ref in self.invocations(call, context)):
                    if owner not in self.refusing:
                        self.refusing.add(owner)
                        changed = True
            for name in self.classes:
                inherited = any(self.key(ref) in self.refusing for base in self.classes[name].bases
                                for ref in self.refs(base, self.scope[self.classes[name]]))
                if (inherited or any(target in self.refusing for target in self.constructors(name))) and name not in self.refusing:
                    self.refusing.add(name)
                    changed = True
            if self.widened:
                self._finish_widened()
                return
            changed |= self._protocol_changed
            if not changed:
                break
        self._cache.clear()
        self._reset_graph()
        self._projection_cache.clear()
        self._storage_roots_cache.clear()
        self._storage_values_cache.clear()
        self._layout_cache.clear()
        self._resolution_cache.clear()
        # Objects and namespaces carrying a refusing reference cannot launder
        # it through an otherwise ordinary alias. This is the same finite
        # binding closure as the callable graph, not a list of escape forms.
        self.carriers = set()
        while True:
            self._resolution_cache.clear()
            self._capability_cache.clear()
            previous = set(self.carriers)
            previous_refusing = set(self.refusing)
            for key, defaults in self.defaults.items():
                returns = [(item.value, key) for item in _owned_nodes(self.functions[key])
                           if isinstance(item, (ast.Return, ast.Yield))]
                if any(self.potential(self.refs(value, owner)) for value, owner in [*defaults.values(), *returns]):
                    self.carriers.update(("fn:" + key, "bound:" + key))
            for key in self.classes:
                values = [(value, owner) for _site, value, owner in self.class_values(key)]
                stored = any(self.potential(self.refs(value, owner)) for value, owner in values)
                if stored:
                    self.carriers.update(("class:" + key, "inst:" + key))
            for namespace in self.trees:
                values = [(value, owner) for (scope, _name), events in self.events.items() if scope == namespace
                          for _site, value, owner in events]
                if (any(name.startswith(namespace + ".") for name in self.refusing) or
                        any(self.potential(self.refs(value, owner)) for value, owner in values)):
                    self.carriers.add("mod:" + namespace)
            for node in self.invocation_sites:
                owner = self.scope[node]
                if owner in self.functions and any(self.key(ref) in self.refusing for ref in self.invocations(node, owner)):
                    self.refusing.add(owner)
            if self.widened:
                self._finish_widened()
                return
            if previous == self.carriers and previous_refusing == self.refusing:
                break
        self._resolution_cache.clear()
        # Mailbox/MCP are boundary sources, not additional public tool roots.
        # Index their definitions for qualified lookup, but audit only the
        # boundary functions reached by the adapter/codec source graph.
        self.active = {key for key in self.functions if key.split(".")[0] not in ("mailbox", "mcp", "pager")}
        edges = {}
        for call in self.invocation_sites:
            for ref in self.invocations(call, self.scope[call]):
                targets = self.constructors(self.key(ref)) if ref.startswith("class:") else [self.key(ref)]
                edges.setdefault(self.scope[call], set()).update(targets)
        self.edges = edges
        self._bound_call_paths()
        if self.widened:
            self._finish_widened()
            return
        self.callback_sites, self.callback_summaries = {}, {}
        pending = list(self.active)
        while pending:
            for child in edges.get(pending.pop(), ()):
                if child not in self.active:
                    self.active.add(child)
                    pending.append(child)
        self.escapes = []
        self.audit()

    @classmethod
    def module(cls, name):
        for key, (_path, absolute) in cls.MODULES.items():
            if name in (key, absolute, absolute.rsplit(".", 1)[-1]):
                return key
        return None

    def _reset_graph(self):
        self._graph_slots, self._graph_users = {}, {}
        self._graph_queue, self._graph_queued = deque(), set()
        self._graph_current, self._graph_busy = None, False
        self._graph_symbols = {}

    def _finish_widened(self):
        # The pool covers the remaining graph, so further precise evaluation
        # cannot add a refusal outside it. This is a sound early fixpoint.
        self.active, self.edges = set(self.functions), {}
        self.callback_sites = getattr(self, "callback_sites", {})
        self.callback_summaries = getattr(self, "callback_summaries", {})
        self.escapes = []

    def _bound_call_paths(self):
        # Domain summaries consume these edges after the value fixpoint. Bound
        # their longest path too, before a domain can follow an open call path.
        children = {key: set(self.edges.get(key, ())) & self.functions.keys() for key in self.functions}
        users, height = {}, dict.fromkeys(children, 0)
        pending = deque(key for key in sorted(children) if not children[key])
        remaining = {key: len(values) for key, values in children.items()}
        for key, values in children.items():
            for child in values:
                users.setdefault(child, set()).add(key)
        finished = set()
        while pending:
            key = pending.popleft()
            if not self._spend(self.functions[key], key):
                return
            finished.add(key)
            for parent in sorted(users.get(key, ())):
                height[parent] = max(height[parent], height[key] + 1)
                if height[parent] > INVENTORY_DEPTH_BOUND:
                    self._widen(("call_path", self.functions[parent], parent, None), "depth")
                    return
                remaining[parent] -= 1
                if not remaining[parent]:
                    pending.append(parent)
        if len(finished) != len(children):
            key = min(set(children) - finished)
            self._widen(("call_path", self.functions[key], key, None), "cycle")

    def _widen(self, marker, reason):
        self.widened.setdefault(marker, reason)

    def _spend(self, node, context):
        if self.budget_exhausted or self.widened:
            return False
        if self.work_used >= INVENTORY_WORK_BUDGET:
            self.budget_exhausted = True
            self._widen(("work", node, context, None), "budget")
            return False
        self.work_used += 1
        return True

    def unknown_environment(self, target, node, context):
        """Absent argument evidence means UNKNOWN, never an omitted argument.

        Every unmodelled protocol/consumer uses this one environment builder;
        only resolve's proven call layouts may apply Python defaults.
        """
        names = set(self.parameters.get(target, ()))
        if target in ("format.require", "format.CodecError"):
            names.update(("code", "detail"))
            if target == "format.require":
                names.add("condition")
        elif target == "_builtin.ValueError":
            names.add("message")
        slot = (node, ("unknown_environment", target))
        argument = self._protocol_arguments.setdefault(slot, (ast.copy_location(
            ast.Name(id="_unknown_environment", ctx=ast.Load()), node) if isinstance(node, ast.AST)
            else ast.Name(id="_unknown_environment", ctx=ast.Load()),))[0]
        argument._inventory_file = getattr(node, "_inventory_file", "inventory.py")
        argument._inventory_refs = frozenset({"unknown:"})
        argument._inventory_values_unknown = True
        return tuple((name, argument, context) for name in sorted(names))

    ATTRIBUTE_VALUE_KINDS = {
        "fn": "function", "rawfn": "function", "static": "staticmethod",
        "classmeth": "classmethod", "member": "bound", "member_class": "bound",
        "class": "constructor", "native": "plain", "builtin": "plain",
        "mod": "plain", "code": "plain",
    }
    ATTRIBUTE_READ_FORMS = {"namespace", "instance_storage", "descriptor", "metaclass"}

    def _mutation_refs(self, expression, context):
        """Bounded lexical evidence for census owners, never a resolution proof.

        No call/value graph is evaluated while collecting mutations. An owner
        or callee outside this closed structural model is a wildcard candidate.
        """
        result, seen, pending = set(), set(), [(expression, context, (), 0)]
        while pending:
            node, scope, suffix, depth = pending.pop()
            if not self._spend(node, scope) or depth > INVENTORY_DEPTH_BOUND:
                return {"unknown:"}
            marker = (node, scope, suffix)
            if marker in seen:
                result.add("unknown:")
                continue
            seen.add(marker)
            if isinstance(node, str):
                definition = self.functions.get(self.key(node), self.classes.get(self.key(node)))
                if definition is not None and definition.decorator_list:
                    # A declaration is not the identity returned by its
                    # decorators. The census does not evaluate call results.
                    result.add("unknown:")
                    continue
                if node.startswith("import:"):
                    module, _, name = self.key(node).partition(".")
                    values = self.events.get((module, name), ())
                    if (len(values) != 1 or any(not self._census_unconditional(site, module)
                                              for site, _value, _owner in values)
                            or name in self._mutation_attribute_names or "*" in self._mutation_attribute_names):
                        result.add("unknown:")
                    if len(pending) + len(values) > INVENTORY_CANDIDATE_BOUND:
                        return {"unknown:"}
                    pending.extend((value, owner, suffix, depth + 1) for _site, value, owner in values)
                elif suffix:
                    name, rest = suffix[0], suffix[1:]
                    if node.startswith(("class:", "mod:")):
                        values = self.events.get((self.key(node), name), ())
                        if (len(values) != 1 or any(not self._census_unconditional(site, self.key(node))
                                                  for site, _value, _owner in values)
                                or name in self._mutation_attribute_names or "*" in self._mutation_attribute_names):
                            result.add("unknown:")
                        if len(pending) + len(values) > INVENTORY_CANDIDATE_BOUND:
                            return {"unknown:"}
                        pending.extend((value, owner, rest, depth + 1) for _site, value, owner in values)
                    elif node == "ext:builtins":
                        if rest:
                            result.add("unknown:")
                        else:
                            result.add("builtin:" + name)
                    elif node.startswith("ext:"):
                        if name in self._mutation_attribute_names or "*" in self._mutation_attribute_names:
                            result.add("unknown:")
                        pending.append((node + "." + name, scope, rest, depth + 1))
                    elif node.startswith("object:") and len(suffix) == 1 and name in (
                            self.NATIVE_STORAGE_METHODS | self.CONTAINER_READS | self.CONTAINER_STORES):
                        result.add("native_method:" + node + "." + name)
                    else:
                        result.add("unknown:")
                else:
                    result.add(node)
            elif isinstance(node, ast.Name):
                current = self.declarations.get((scope, node.id), scope)
                while current is not None:
                    values = self.events.get((current, node.id), ())
                    if ((current, node.id) in self.unknown_bindings
                            or node.id in self.local_names.get(current, ()) and not values):
                        # A local declaration shadows enclosing bindings even
                        # when its binding form supplies no modeled event.
                        result.add("unknown:")
                        break
                    if node.id in self.parameters.get(current, ()):
                        # The lexical census precedes argument transport. A
                        # parameter can denote any owner, whatever its spelling
                        # or default, even if a local assignment also exists.
                        result.add("unknown:")
                        break
                    if values:
                        if (len(values) != 1 or any(not self._census_unconditional(site, current)
                                                  for site, _value, _owner in values)
                                or current in self.trees and (
                                node.id in self._mutation_attribute_names or "*" in self._mutation_attribute_names)):
                            result.add("unknown:")
                        if len(pending) + len(values) > INVENTORY_CANDIDATE_BOUND:
                            return {"unknown:"}
                        pending.extend((value, owner, suffix, depth + 1) for _site, value, owner in values)
                        break
                    current = self.outer.get(current)
                else:
                    primitives = {"CodecError": "class:format.CodecError", "ValueError": "class:_builtin.ValueError",
                                  "require": "fn:format.require", "need": "fn:format.require"}
                    if node.id in self.BUILTINS:
                        pending.append(("builtin:" + node.id, scope, suffix, depth + 1))
                        if node.id in self._mutation_attribute_names or "*" in self._mutation_attribute_names:
                            result.add("unknown:")
                    else:
                        pending.append((primitives.get(node.id, "unknown:"), scope, suffix, depth + 1))
            elif isinstance(node, ast.Attribute):
                if len(suffix) >= INVENTORY_DEPTH_BOUND:
                    return {"unknown:"}
                pending.append((node.value, scope, (node.attr, *suffix), depth + 1))
            elif isinstance(node, (ast.List, ast.Tuple, ast.Dict, ast.Set)):
                ref = "object:" + scope + ":" + str(node.lineno) + ":" + str(node.col_offset)
                if suffix:
                    pending.append((ref, scope, suffix, depth + 1))
                else:
                    result.add(ref)
            else:
                result.add("unknown:")
            if len(pending) > INVENTORY_CANDIDATE_BOUND or len(result) > INVENTORY_CANDIDATE_BOUND:
                return {"unknown:"}
        return result or {"unknown:"}

    def _mutation_record(self, kind, target, name, site, context):
        if len(self._mutation_raw) >= INVENTORY_WORK_BUDGET:
            self._mutation_overflow = True
            return
        self._mutation_raw.append((kind, target, name, site, context))
        if kind not in ("name", "parameter", "delete_name", "augment_name"):
            self._mutation_attribute_names.add(name)

    def _census_owner(self, scope):
        return ("mod:" if scope in self.trees else "class:" if scope in self.classes else "local:") + scope

    def _census_add(self, owner, name, site, context, kind, unconditional):
        key = (owner, name)
        entry = self.mutation_census.setdefault(key, {"count": 0, "site": site, "context": context,
                                                     "unconditional": True, "binding": True})
        entry["count"] += 1
        entry["unconditional"] &= unconditional
        entry["binding"] &= kind in ("name", "parameter", "attribute", "slot")
        self.mutation_sites.append((owner, name, site._inventory_file, site.lineno, kind, unconditional))

    def _census_unconditional(self, site, context):
        root = self.trees.get(context, self.classes.get(context, self.functions.get(context)))
        if root is None or self.parent.get(site) is not root or not isinstance(
                site, (ast.Assign, ast.AnnAssign, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
            return False
        if context not in self._mutation_presence:
            present, exited = set(), False
            for statement in root.body:
                if not self._spend(statement, context):
                    break
                if not exited:
                    present.add(statement)
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                for part in _owned_nodes(statement):
                    if not self._spend(part, context):
                        break
                    exited |= isinstance(part, (ast.Raise, ast.Return, ast.Break, ast.Continue))
            self._mutation_presence[context] = present
        return site in self._mutation_presence[context]

    def _build_mutation_census(self):
        """Index the one source walk's mutations before any runtime resolution."""
        if self._mutation_overflow:
            self.work_used = INVENTORY_WORK_BUDGET
            self.budget_exhausted = True
            self._widen(("mutation", None, "records", None), "budget")
            return
        for kind, target, name, site, context in self._mutation_raw:
            if kind in ("name", "parameter", "delete_name", "augment_name"):
                if not self._spend(site, context):
                    return
                self._census_add(self._census_owner(target), name, site, context, kind,
                                 kind == "parameter" or self._census_unconditional(site, target))
        for (scope, name), site in self.unknown_bindings.items():
            if not self._spend(site, scope):
                return
            owner = self._census_owner(scope)
            if (owner, name) in self.mutation_census:
                self.mutation_census[(owner, name)]["binding"] = False
            else:
                self._census_add(owner, name, site, scope, "unmodelled", False)
        # Unknown calls with a setattr/delattr-compatible layout are possible
        # mutators too. Proven other identities never qualify by their spelling.
        attributes = [event for event in self._mutation_raw if event[0] not in ("name", "parameter", "delete_name", "augment_name")]
        for call, context in self._mutation_calls:
            if not self._spend(call, context):
                return
            spread = any(isinstance(arg, ast.Starred) for arg in call.args) or any(k.arg is None for k in call.keywords)
            if not spread and (call.keywords or len(call.args) not in (2, 3)):
                continue
            refs = self._mutation_refs(call.func, context)
            mutators = {"builtin:setattr", "builtin:delattr"}
            unknown = any(not ref.startswith(("fn:", "rawfn:", "class:", "builtin:", "native_method:")) and not (
                ref.startswith("ext:") and self.key(ref).split(".")[0] in self.EXTERNAL_DATA) for ref in refs)
            if not refs & mutators and not unknown:
                continue
            direct = (isinstance(call.func, ast.Name) and refs == {"builtin:" + call.func.id}
                      and call.func.id in ("setattr", "delattr") and not spread)
            target = call.args[0] if direct else None
            name = (call.args[1].value if not spread and len(call.args) > 1
                    and isinstance(call.args[1], ast.Constant) and isinstance(call.args[1].value, str) else "*")
            attributes.append(("mutator", target, name, call, context))
            self._mutation_attribute_names.add(name)
        for kind, target, name, site, context in attributes:
            if not self._spend(site, context):
                return
            refs = self._mutation_refs(target, context)
            owner = next(iter(refs)) if len(refs) == 1 else "*"
            if not owner.startswith(("mod:", "class:", "inst:", "fn:", "object:", "ext:")):
                owner = "*"
            if kind.endswith("slot"):
                owner = "slot:" + owner
            self._census_add(owner, name, site, context, kind, self._census_unconditional(site, context))

    def _census_entries(self, owner, name):
        keys = {(owner, name), (owner, "*")}
        if not owner.startswith("local:"):
            keys.update((("*", name), ("*", "*")))
        if owner.startswith("slot:"):
            keys.update((("slot:*", name), ("slot:*", "*")))
        return [self.mutation_census[key] for key in keys if key in self.mutation_census]

    def single_binding(self, owner, name):
        entries = self._census_entries(owner, name)
        # A wildcard is uncertainty, even when no original binding exists.
        return ("*" not in (owner, name) and owner != "slot:*"
                and (owner, name) in self.mutation_census and len(entries) == 1
                and entries[0] is self.mutation_census[(owner, name)]
                and entries[0]["count"] == 1 and entries[0]["unconditional"]
                and entries[0]["binding"])

    def mutation_value(self, owner, name, *, implicit=False):
        entries = self._census_entries(owner, name)
        if not entries or not implicit and self.single_binding(owner, name):
            return None
        site = entries[0]["site"]
        value = self.unknown_binding_value(name, owner, site)
        value._inventory_refs |= {"fn:" + UNKNOWN_CALL_TARGET}
        return value

    def _read_mutation_value(self, node, context):
        """The shared census gate for explicit names, attributes and slots."""
        if isinstance(node, ast.Name) and node in self.scope:
            current = self.declarations.get((context, node.id), context)
            while current is not None:
                if (self.events.get((current, node.id)) or node.id in self.parameters.get(current, ())
                        or (current, node.id) in self.unknown_bindings):
                    return self.mutation_value(self._census_owner(current), node.id)
                if node.id in self.local_names.get(current, ()):
                    value = self.unknown_binding_value(node.id, self._census_owner(current), node)
                    value._inventory_refs |= {"fn:" + UNKNOWN_CALL_TARGET}
                    return value
                current = self.outer.get(current)
            return self.mutation_value("ext:builtins", node.id, implicit=True) if node.id in self.BUILTINS else None
        if isinstance(node, ast.Attribute):
            for receiver in self.refs(node.value, context):
                receiver = receiver.partition("|")[2] if receiver.startswith("super:") else receiver
                owners = {receiver}
                if receiver.startswith("inst:"):
                    owners.add("class:" + self.key(receiver))
                if receiver.startswith(("class:", "inst:")):
                    for base in self.mro(self.key(receiver)):
                        if base != "unknown:":
                            owners.add("class:" + base)
                for owner in owners:
                    value = self.mutation_value(owner, node.attr, implicit=owner.startswith(
                        ("ext:", "fn:", "rawfn:", "builtin:", "native:", "code:")))
                    if value is not None:
                        return value
        elif isinstance(node, ast.Subscript):
            refs = self._mutation_refs(node.value, context)
            name = self._slot_name(node.slice)
            for owner in refs:
                value = self.mutation_value("slot:" + owner, name)
                if value is not None:
                    return value
        return None

    @staticmethod
    def _slot_name(node):
        return type(node.value).__name__ + ":" + str(node.value) if isinstance(node, ast.Constant) and type(node.value) in (str, int) else "*"

    def read_attribute(self, stored, receiver, *, form="descriptor"):
        """Apply descriptor binding exactly once, to the stored value's kind.

        rawfn is the plain function value after a descriptor read; unlike fn,
        looking it up again must not reapply the defining decorators. A bound
        value carries its actual receiver, regardless of later holder classes.
        Namespace and instance-dictionary reads do not invoke descriptors.
        Unknown descriptor kinds retain their candidate and symbolic top.
        """
        kind = self.ATTRIBUTE_VALUE_KINDS.get(stored.partition(":")[0])
        unknown = {stored, "unknown:" + self.key(receiver).split(".")[0]}
        if self.key(stored) == UNKNOWN_CALL_TARGET:
            return unknown
        if form not in self.ATTRIBUTE_READ_FORMS:
            return unknown
        if form in ("namespace", "instance_storage"):
            return {stored}
        if kind in ("constructor", "plain"):
            return {stored}
        if kind == "bound":
            return {stored} if stored.partition("|")[2].startswith(("inst:", "class:")) else unknown
        if kind == "staticmethod":
            return {"rawfn:" + self.key(stored)}
        if kind == "classmethod":
            if receiver.startswith(("inst:", "class:")):
                return {"member_class:" + self.key(stored) + "|class:" + self.key(receiver)}
            return unknown
        if kind == "function":
            getter = self.functions.get(self.key(stored)) if stored.startswith("fn:") else None
            if getter is not None and any(self.refs(item, self.scope[getter]) == {"builtin:property"}
                                          for item in getter.decorator_list):
                # Custom/data descriptors are not in the closed kind table.
                # Retain returned candidates and the getter, but never guess
                # their binding or claim the read's result is exact.
                for item in _owned_nodes(getter):
                    if isinstance(item, ast.Return):
                        candidates = self.refs(item.value, self.key(stored))
                        if len(unknown) + len(candidates) > INVENTORY_CANDIDATE_BOUND:
                            self._widen(("refs", getter, self.key(stored), None), "candidates")
                            return unknown
                        unknown.update(candidates)
                return unknown
            if receiver.startswith("inst:") or form == "metaclass" and receiver.startswith("class:"):
                return {"member:" + self.key(stored) + "|" + receiver}
            if receiver.startswith("class:"):
                return {"rawfn:" + self.key(stored)}
        return unknown

    def mro(self, key):
        return self._query("mro", key, key)

    def _collect_mro(self, key):
        """Bounded C3 lookup order; an unproved hierarchy stays UNKNOWN."""
        if key == "_builtin.object":
            return [key]
        cls = self.classes.get(key)
        if cls is None:
            return [key, "unknown:"]
        if len(cls.bases) > INVENTORY_CANDIDATE_BOUND:
            self._widen(("mro", key, key, None), "candidates")
            return [key, "unknown:"]
        bases = []
        for base in cls.bases:
            identities = self.refs(base, self.scope[cls])
            if len(identities) != 1:
                return [key, "unknown:"] if identities else []
            identity = next(iter(identities))
            if identity == "builtin:object":
                bases.append("_builtin.object")
            elif identity.startswith("class:"):
                bases.append(self.key(identity))
            else:
                return [key, "unknown:"]
        sequences = [list(self.mro(base)) for base in bases]
        if any(not sequence for sequence in sequences):
            return []
        if any("unknown:" in sequence for sequence in sequences) or len(set(bases)) != len(bases):
            return [key, "unknown:"]
        sequences.append(bases[:])
        result = [key]
        while any(sequences):
            if not self._spend(cls, key) or len(result) >= INVENTORY_DEPTH_BOUND:
                return [key, "unknown:"]
            candidate = next((sequence[0] for sequence in sequences if sequence and
                              all(sequence[0] not in other[1:] for other in sequences)), None)
            if candidate is None:
                return [key, "unknown:"]
            result.append(candidate)
            for sequence in sequences:
                if sequence and sequence[0] == candidate:
                    sequence.pop(0)
        return result

    def super_members(self, current, receiver, name):
        order = self.mro(self.key(receiver)) if receiver.startswith(("inst:", "class:")) else []
        if order and "unknown:" not in order and current in order:
            result = []
            for owner in order[order.index(current) + 1:]:
                events = self.events.get((owner, name), ())
                if len(events) + int((owner, name) in self.unknown_bindings) > INVENTORY_CANDIDATE_BOUND:
                    self._widen(("members", current, current, name), "candidates")
                    return result, True
                values = list(events)
                if (owner, name) in self.unknown_bindings:
                    site = self.unknown_bindings[(owner, name)]
                    values.append((site, self.unknown_binding_value(name, owner, site), owner))
                if len(result) + len(values) > INVENTORY_CANDIDATE_BOUND:
                    self._widen(("members", current, current, name), "candidates")
                    return result, True
                result.extend(values)
                mutation = self.mutation_value("class:" + owner, name)
                if mutation is not None:
                    if len(result) >= INVENTORY_CANDIDATE_BOUND:
                        self._widen(("members", current, current, name), "candidates")
                        return result, True
                    site = self.mutation_census.get(("class:" + owner, name), {}).get("site")
                    site = site if site is not None else self.classes.get(owner, self.classes[current])
                    result.append((site, mutation, owner))
                if self.single_binding("class:" + owner, name) and (owner, name) not in self.unknown_bindings and any(
                        self.member_is_unconditional(owner, site) for site, _value, _scope in values):
                    return result, False
            return result, bool(result)
        # Keep every inherited candidate when C3/receiver identity is unproved.
        values = []
        cls = self.classes.get(current)
        for base in cls.bases if cls is not None else ():
            if not self._spend(base, current):
                return values, True
            for identity in self.refs(base, self.scope[cls]):
                if identity.startswith("class:"):
                    candidates = self.members(self.key(identity), name)
                    if len(values) + len(candidates) > INVENTORY_CANDIDATE_BOUND:
                        self._widen(("members", current, current, name), "candidates")
                        return values, True
                    values.extend(candidates)
        return values, True

    def member_is_unconditional(self, owner, site):
        """Only an executed class-top-level binding can stop MRO lookup."""
        cls = self.classes.get(owner)
        if cls is None or self.parent.get(site) is not cls:
            return False
        for statement in cls.body:
            if statement is site:
                return True
            if not self._spend(statement, owner):
                return False
            # Definition bodies execute later. Other preceding statements can
            # leave the class body before this binding is reached.
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for part in _owned_nodes(statement):
                if not self._spend(part, owner):
                    return False
                if isinstance(part, (ast.Raise, ast.Return, ast.Break, ast.Continue)):
                    return False
        return False

    def binding_effect(self, node, context):
        """One allowlist for all recognized Python name-binding constructs."""
        kind = type(node).__name__
        fields = self.BINDING_TARGET_FIELDS.get(kind, ())
        field_values = dict(ast.iter_fields(node))
        pending = [field_values.get(field) for field in fields]
        if kind not in self.BINDING_TARGET_FIELDS:
            # Future AST binders cannot silently inherit precise state. Store
            # targets and name-bearing captures are recognized structurally;
            # definition names/import aliases have their existing full models.
            for _field, value in ast.iter_fields(node):
                children = value if isinstance(value, list) else [value]
                pending.extend(child for child in children if isinstance(child, ast.Name) and
                               isinstance(child.ctx, (ast.Store, ast.Del)))
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.alias)):
                name = getattr(node, "name", None)
                if isinstance(name, str):
                    pending.append(name)
        names = set()
        while pending:
            target = pending.pop()
            if isinstance(target, str):
                names.add(target)
            elif isinstance(target, ast.Name):
                names.add(target.id)
            elif isinstance(target, ast.alias):
                names.add(target.asname or target.name.split(".")[0])
            elif isinstance(target, (ast.Tuple, ast.List)):
                pending.extend(target.elts)
            elif isinstance(target, ast.Starred):
                pending.append(target.value)
            elif isinstance(target, (tuple, list)):
                pending.extend(target)
        precise = kind in self.PRECISE_BINDING_FORMS
        if kind in ("Assign", "AnnAssign"):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            precise &= all(isinstance(target, (ast.Name, ast.Attribute, ast.Subscript)) for target in targets)
            precise &= getattr(node, "value", None) is None or isinstance(node.value, self.PRECISE_BINDING_EXPRESSIONS)
        elif kind in ("For", "AsyncFor"):
            precise &= isinstance(node.target, ast.Name)
        elif kind in ("Import", "ImportFrom"):
            precise &= context not in self.functions
        return names, precise

    def binding_is_unknown(self, name, context):
        seen = set()
        while context is not None and context not in seen:
            seen.add(context)
            if (context, name) in self.unknown_bindings:
                return True
            declared = self.declarations.get((context, name))
            if declared is not None:
                context = declared
            elif name in self.local_names.get(context, ()):
                return False
            else:
                context = self.outer.get(context)
        return False

    @staticmethod
    def _graph_bottom(kind):
        if kind in ("refs", "roots", "projection", "metaclasses"):
            return frozenset()
        if kind in ("layout", "literals"):
            return None
        if kind == "unstable":
            return False
        return []

    def _graph_unknown(self, marker):
        kind, _node, context, _extra = marker
        if kind in ("refs", "projection"):
            return frozenset({"unknown:" + context.split(".")[0]})
        if kind == "roots":
            return frozenset({None})
        if kind in ("layout", "literals"):
            return None
        if kind == "unstable":
            return True
        return self._graph_bottom(kind)

    def _queue(self, marker):
        if marker not in self._graph_queued:
            self._graph_queue.append(marker)
            self._graph_queued.add(marker)

    def _query(self, kind, node, context, extra=None):
        # Synthetic names used for import/member proofs have stable identities.
        # Re-evaluation must not allocate a fresh slot for the same source fact.
        if isinstance(node, ast.Name) and node not in self.scope:
            identity = (context, node.id, tuple(sorted(getattr(node, "_inventory_refs", ()))),
                        getattr(node, "_inventory_symbol", None),
                        getattr(node, "_inventory_attribute_source", None))
            node = self._graph_symbols.setdefault(identity, node)
        marker = (kind, node, context, extra)
        if self.widened:
            return self._graph_unknown(marker)
        parent = self._graph_current
        if marker not in self._graph_slots:
            path = self._graph_slots[parent]["path"] + (parent,) if parent is not None else ()
            self._graph_slots[marker] = {"value": self._graph_bottom(kind), "path": path,
                                         "dependencies": set(), "updates": 0}
            if len(path) > INVENTORY_DEPTH_BOUND:
                self._widen(marker, "depth")
            self._queue(marker)
        if parent is not None:
            self._graph_slots[parent]["dependencies"].add(marker)
            self._graph_users.setdefault(marker, set()).add(parent)
            if marker == parent or marker in self._graph_slots[parent]["path"]:
                self._widen(marker, "cycle")
        if self._graph_busy:
            return self._graph_slots[marker]["value"]
        self._graph_busy = True
        try:
            while self._graph_queue and not self.widened:
                current = self._graph_queue.popleft()
                self._graph_queued.remove(current)
                if not self._spend(current[1], current[2]):
                    break
                slot = self._graph_slots[current]
                for dependency in slot["dependencies"]:
                    self._graph_users[dependency].discard(current)
                slot["dependencies"] = set()
                self._graph_current = current
                value = self._evaluate_query(*current)
                size = len(value) if isinstance(value, (tuple, list, set, frozenset, dict)) else 0
                if size > INVENTORY_CANDIDATE_BOUND:
                    self._widen(current, "candidates")
                    break
                if value != slot["value"]:
                    slot["value"] = value
                    self._resolution_cache.clear()
                    self._capability_cache.clear()
                    slot["updates"] += 1
                    if slot["updates"] > INVENTORY_CANDIDATE_BOUND:
                        self._widen(current, "updates")
                        break
                    for user in sorted(self._graph_users.get(current, ()), key=self._graph_order):
                        self._queue(user)
            if self.widened:
                # Budget and local widening both saturate to the pool. Every
                # still-open slot is UNKNOWN; no partially solved result leaks.
                reason = "budget" if self.budget_exhausted else "module_pool"
                for current, slot in self._graph_slots.items():
                    self._widen(current, reason)
                    slot["value"] = self._graph_unknown(current)
                self._graph_queue.clear()
                self._graph_queued.clear()
            return self._graph_slots[marker]["value"]
        finally:
            self._graph_current, self._graph_busy = None, False

    @staticmethod
    def _graph_order(marker):
        kind, node, context, extra = marker
        return (context, getattr(node, "lineno", 0), getattr(node, "col_offset", 0), kind,
                node if isinstance(node, str) else type(node).__name__, str(extra))

    def _evaluate_query(self, kind, node, context, extra):
        if kind == "refs":
            return self._reference_evidence(node, context)
        if kind == "roots":
            return self._collect_storage_roots(node, context)
        if kind == "storage":
            return self._collect_storage_values(node, context, container=extra)
        if kind == "callees":
            return self._collect_storage_callee_bindings(node, context)
        if kind == "members":
            return self._collect_members(node, extra)
        if kind == "mro":
            return self._collect_mro(node)
        if kind == "fields":
            return self._collect_inherited_fields(node, extra)
        if kind == "class_values":
            return self._collect_class_values(node)
        if kind == "metaclasses":
            return self._collect_metaclasses(node)
        if kind == "layout":
            return self._collect_layout(node, context, extra)
        if kind == "projection":
            return self._collect_project_refs(node, extra, context, set())
        if kind == "literals":
            return self._collect_literal_values(node, context)
        if kind == "unstable":
            return self._collect_unstable(node, context)
        raise AssertionError("unknown inventory query kind")

    @staticmethod
    def key(ref):
        return ref.partition(":")[2].partition("|")[0]

    @staticmethod
    def callable(ref):
        return ref.startswith(("fn:", "rawfn:", "bound:", "member:", "member_static:", "member_class:", "static:", "classmeth:", "class:"))

    def potential(self, refs):
        result = {self.key(ref) for ref in refs
                if self.callable(ref) and (self.key(ref) in self.refusing or "fn:" + self.key(ref) in self.carriers)
                or ref in self.carriers}
        if any(ref.startswith("unknown:") for ref in refs):
            result.add(UNKNOWN_CALL_TARGET)
        return result

    @staticmethod
    def unsupported(node, construct=None):
        raise RefusalInventoryError([_CallableModel.diagnostic(node, construct)])

    @staticmethod
    def diagnostic(node, construct=None):
        # Only fixed AST type names, trusted source identities and integers are
        # printed. Supplied source text and identifiers never enter a refusal.
        return ("unsupported form " + (construct or type(node).__name__) + " at " +
                getattr(node, "_inventory_file", "inventory.py") + ":" + str(getattr(node, "lineno", 1)))

    def _event(self, context, name, site, value, owner):
        context = self.declarations.get((context, name), context)
        self.events.setdefault((context, name), []).append((site, value, owner))
        self._mutation_record("name", context, name, site, owner)
        if context in self.classes or context in self.trees:
            self.tail.setdefault(name, set()).add(context)

    def _store(self, target, value, context, site):
        module = context.split(".")[0]
        if isinstance(target, ast.Attribute):
            self.storage_attributes.setdefault((module, target.attr), []).append((target, site, value, context))
        elif isinstance(target, ast.Subscript):
            self.storage_containers.setdefault(module, []).append((target.value, site, value, context))
        if isinstance(target, ast.Name):
            destination = self.declarations.get((context, target.id), context)
            self._event(destination, target.id, site, value, context)
        elif (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
              and context in self.method_class
              and target.value.id == next(iter([arg.arg for arg in [*self.functions[context].args.posonlyargs,
                                                                   *self.functions[context].args.args]]), None)):
            self.fields.setdefault((self.method_class[context], target.attr), []).append((site, value, context))
            self.tail.setdefault(target.attr, set()).add(self.method_class[context])
        elif isinstance(target, ast.Starred):
            # The remainder's shape and owner are not proven. Keep storage
            # candidates, but never let destructuring preserve old precision.
            unknown = self.unknown_binding_value("*", context, site)
            self._store(target.value, unknown, context, site)
        elif isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts):
                for left, right in zip(target.elts, value.elts):
                    self._store(left, right, context, site)
            else:
                for index, item in enumerate(target.elts):
                    projected = ast.copy_location(ast.Subscript(value=value, slice=ast.Constant(index), ctx=ast.Load()), site)
                    self._store(item, projected, context, site)

    def _storage_roots(self, node, context, seen=None):
        return self._query("roots", node, context)

    def _storage_bindings(self, node, context):
        """Binding evidence without re-entering reference/call resolution."""
        current = self.declarations.get((context, node.id), context)
        while current is not None:
            events = self._visible(self.events.get((current, node.id), ()), current, node, context)
            values = [(value, owner) for _site, value, owner in events]
            if node.id in self.parameters.get(current, ()):
                values.extend(self.arguments.get((current, node.id), ()))
                default = self.defaults.get(current, {}).get(node.id)
                if default is not None:
                    values.append(default)
                if current in self.method_class:
                    args = [*self.functions[current].args.posonlyargs, *self.functions[current].args.args]
                    if args and node.id == args[0].arg:
                        values.extend((prefix + self.method_class[current], current) for prefix in ("inst:", "class:"))
                return values
            if values:
                return values
            current = self.outer.get(current)
        return []

    def _storage_callee_bindings(self, node, context, seen=None):
        return self._query("callees", node, context)

    def _collect_storage_callee_bindings(self, node, context, seen=None):
        seen = set() if seen is None else seen
        marker = (node, context)
        if marker in seen:
            return [("unknown:", context)]
        seen = seen | {marker}
        if isinstance(node, ast.Name):
            return self._storage_bindings(node, context)
        if isinstance(node, ast.Attribute):
            values = []
            for value, owner in self._storage_callee_bindings(node.value, context, seen):
                if isinstance(value, str) and value.startswith("ext:"):
                    values.append((value + "." + node.attr, owner))
                elif isinstance(value, str) and value.startswith("mod:"):
                    member = ast.Name(id=node.attr, ctx=ast.Load())
                    values.extend(self._storage_bindings(member, self.key(value)))
                else:
                    values.append(("unknown:", owner))
            return values
        return [("unknown:", context)]

    def _collect_storage_roots(self, node, context, seen=None):
        """Finite alias worklist; paths beyond local identity stay UNKNOWN.

        These identities connect storage evidence, never prove a callable's
        identity. Atomic attribute/slot paths deliberately join aliases rather
        than recursively expanding an object graph.
        """
        visited, pending, roots = set() if seen is None else set(seen), [(node, context, 0)], set()
        while pending:
            value, owner, depth = pending.pop()
            if depth > INVENTORY_DEPTH_BOUND or not self._spend(node, context):
                self._widen(("roots", node, context, None), "depth" if depth > INVENTORY_DEPTH_BOUND else "budget")
                return {None}
            marker = (value, owner)
            if marker in visited:
                continue
            visited.add(marker)
            if isinstance(value, str):
                if value.startswith("import:"):
                    module, _separator, name = self.key(value).partition(".")
                    events = self.events.get((module, name), ())
                    pending.extend((expression, scope, depth + 1) for _site, expression, scope in events)
                    if not events:
                        roots.add(None)
                elif value.startswith(("inst:", "class:", "mod:")):
                    roots.add(value)
                else:
                    roots.add(None)
            elif isinstance(value, ast.Name):
                bindings = self._storage_bindings(value, owner)
                pending.extend((item, scope, depth + 1) for item, scope in bindings)
                if not bindings:
                    roots.add(None)
            elif isinstance(value, ast.IfExp):
                pending.extend(((value.body, owner, depth + 1), (value.orelse, owner, depth + 1)))
            elif isinstance(value, ast.Attribute):
                roots.add(("attribute", owner.split(".")[0], value.attr))
            elif isinstance(value, ast.Subscript):
                roots.add(("slot", owner, ast.dump(value)))
                roots.add(None)
            elif isinstance(value, ast.Call):
                bindings = self._storage_callee_bindings(value.func, owner)
                instances = {"inst:" + self.key(item) for item, _scope in bindings
                             if isinstance(item, str) and item.startswith("class:")}
                returned = [(item.value, self.key(ref)) for ref, _scope in bindings
                            if isinstance(ref, str) and ref.startswith("fn:") and self.key(ref) in self.functions
                            for item in _owned_nodes(self.functions[self.key(ref)])
                            if isinstance(item, (ast.Return, ast.Yield)) and item.value is not None]
                data_consumers = self.DATA_CONSUMERS | {"ext:json.loads", "ext:json.dumps"}
                callback_keywords = {"cls", "object_hook", "parse_float", "parse_int", "parse_constant", "object_pairs_hook"}
                data = bool(bindings) and all(isinstance(ref, str) and ref in data_consumers for ref, _scope in bindings)
                data &= all(item.arg is not None and item.arg not in callback_keywords for item in value.keywords)
                if instances:
                    roots.update(instances)
                    for ref, _scope in bindings:
                        cls = self.classes.get(self.key(ref)) if isinstance(ref, str) else None
                        if cls is not None and (cls.bases or cls.keywords or cls.decorator_list or any(
                                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "__new__"
                                for item in cls.body)):
                            roots.add(None)
                if returned:
                    pending.extend((item, scope, depth + 1) for item, scope in returned)
                if data:
                    roots.add(("fresh", value, owner))
                if not instances and not returned and not data:
                    roots.add((value, owner))
                for ref, _scope in bindings:
                    known = isinstance(ref, str) and (ref.startswith("class:") or data and ref in data_consumers)
                    if isinstance(ref, str) and ref.startswith("fn:") and self.key(ref) in self.functions:
                        function = self.functions[self.key(ref)]
                        known = all(isinstance(decorator, ast.Name) and
                                    all(item == "ext:contextlib.contextmanager" for item, _scope in
                                        self._storage_bindings(decorator, self.scope[function])) and
                                    self._storage_bindings(decorator, self.scope[function])
                                    for decorator in function.decorator_list)
                    if not known:
                        roots.add((value, owner))
            elif isinstance(value, (ast.List, ast.Tuple, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)):
                roots.add((value, owner))
        return roots or {None}

    def _attribute_storage(self, node, context, seen=None):
        roots = self._storage_roots(node.value, context, seen)
        if not roots:
            return []  # Worklist bottom is not evidence of an opaque owner.
        known = {root for root in roots if isinstance(root, str)}
        module = context.split(".")[0]
        result = []
        for (namespace, name), events in self.storage_attributes.items():
            if name != node.attr:
                continue
            for event in events:
                target, _site, _value, owner = event
                if not self._spend(target, context):
                    return result
                targets = self._storage_roots(target.value, owner, seen)
                if not targets:
                    continue
                identities = {root for root in targets if isinstance(root, str)}
                modules = {root for root in known if root.startswith("mod:")}
                target_modules = {root for root in identities if root.startswith("mod:")}
                typed = bool(roots and targets) and all(isinstance(root, str) and root.startswith(
                    ("inst:", "class:", "mod:")) for root in roots | targets)
                # Proven distinct owners are not module-pool aliases. In
                # particular, writing B.method cannot modify A.method's RHS.
                related = bool((roots - {None}) & (targets - {None})) or namespace == module and (
                    not typed and (not known or not identities or not modules and not target_modules))
                if not related:
                    receiver_refs = self.refs(node.value, context)
                    related |= namespace == module and any(not ref.startswith(("inst:", "class:", "mod:"))
                                                          for ref in receiver_refs)
                    receivers = {ref.partition("|")[2] if ref.startswith("super:") else ref for ref in receiver_refs}
                    receivers = {ref for ref in receivers if ref.startswith(("inst:", "class:"))}
                    origins = self.refs(target.value, owner) if receivers else ()
                    related |= namespace == module and any(not ref.startswith(("inst:", "class:", "mod:"))
                                                          for ref in origins)
                    for origin in origins:
                        for receiver in receivers:
                            if not self._spend(target, context):
                                return result
                            if not origin.startswith(("inst:", "class:")):
                                continue
                            if self.key(origin) == self.key(receiver):
                                related = True
                            else:
                                order = self.mro(self.key(receiver))
                                related |= "unknown:" in order or self.key(origin) in order
                if related:
                    if len(result) >= INVENTORY_CANDIDATE_BOUND:
                        self._widen(("storage", node, context, False), "candidates")
                        return result
                    result.append(event)
        return result

    def storage_values(self, node, context, *, container=False):
        return self._query("storage", node, context, container)

    def attribute_projection(self, node, context, event):
        """Retain write provenance until every consumer requests the read.

        The synthetic value is a graph node, not a snapshot of provisional
        bindings. Its reference evaluation goes through read_attribute; scalar
        consumers retain the original source expression and its environment.
        """
        target, site, value, owner = event
        slot = (node, ("attribute_read", context, target, site, owner))
        projected = self._protocol_arguments.setdefault(slot, (ast.copy_location(
            ast.Name(id="_stored_attribute", ctx=ast.Load()), node),))[0]
        projected._inventory_file = getattr(node, "_inventory_file", "inventory.py")
        projected._inventory_attribute_source = (node, context, target, value, owner)
        projected._inventory_values = ((value, owner),)
        return projected, context

    def stored_attribute_refs(self, projection):
        node, context, target, value, owner = projection._inventory_attribute_source
        origins = self.refs(target.value, owner)
        reads = self.refs(node.value, context)
        receivers = {ref.partition("|")[2] if ref.startswith("super:") else ref for ref in reads}
        stored = self.refs(value, owner)
        if not origins or not receivers or not stored:
            return set()  # Worklist dependencies have not supplied evidence yet.
        unknown = len(origins) != 1 or len(receivers) != 1
        result = set()
        for origin in sorted(origins):
            for receiver in sorted(receivers):
                if not self._spend(projection, context):
                    return {"unknown:" + context.split(".")[0]}
                form = "unproven"
                if origin.startswith("mod:") and origin == receiver:
                    form = "namespace"
                elif origin.startswith(("class:", "inst:")) and receiver.startswith(("class:", "inst:")):
                    compatible = self.key(origin) == self.key(receiver)
                    if not compatible:
                        order = self.mro(self.key(receiver))
                        if not order:
                            continue
                        compatible = "unknown:" not in order and self.key(origin) in order
                    if compatible and origin.startswith("class:"):
                        form = "descriptor"
                    elif compatible and origin.startswith("inst:") and receiver.startswith("inst:"):
                        form = "instance_storage"
                unknown |= form == "unproven"
                for member in sorted(stored):
                    candidates = self.read_attribute(member, receiver, form=form)
                    if len(result) + len(candidates) > INVENTORY_CANDIDATE_BOUND:
                        self._widen(("refs", projection, context, None), "candidates")
                        return {"unknown:" + context.split(".")[0]}
                    result.update(candidates)
        if unknown:
            result.add("unknown:" + context.split(".")[0])
        return result

    def field_refs(self, node, context, event, receiver):
        """Field indexing and store projection consume the same provenance."""
        site, value, owner = event
        result, found = set(), False
        for source in self.storage_attributes.get((owner.split(".")[0], node.attr), ()):
            target, source_site, source_value, source_owner = source
            if not self._spend(target, context):
                return {"unknown:" + context.split(".")[0]}
            if source_site is site and source_value is value and source_owner == owner:
                found = True
                projected, scope = self.attribute_projection(node, context, source)
                candidates = self.refs(projected, scope)
                if len(result) + len(candidates) > INVENTORY_CANDIDATE_BOUND:
                    self._widen(("refs", node, context, None), "candidates")
                    return {"unknown:" + context.split(".")[0]}
                result.update(candidates)
        if not found:
            # Generated dataclass fields have an instance dictionary but no
            # source assignment event. Their constructor remains UNKNOWN.
            for member in self.refs(value, owner):
                result.update(self.read_attribute(member, receiver, form="instance_storage"))
        return result

    def _collect_storage_values(self, node, context, *, container=False):
        """UNKNOWN storage projection, retaining values rather than defaults.

        Locals join writes through source aliases in their function. A read
        with no tied object uses all container writes in its module. Attributes
        use the module's same-name pool, including writes in other methods.
        Slot keys and execution order are deliberately over-approximated.
        """
        module = context.split(".")[0]
        attributes = ([self.attribute_projection(node, context, event) for event in self._attribute_storage(node, context)]
                      if isinstance(node, ast.Attribute) and not container else [])
        expression = node.value if isinstance(node, ast.Subscript) and not container else node
        forced = container or isinstance(node, ast.Subscript) or getattr(node, "_inventory_container_read", False)
        if not forced and not isinstance(node, (ast.Name, ast.Attribute)):
            return []
        roots = self._storage_roots(expression, context)
        events = self.storage_containers.get(module, ())
        matched = [(value, owner) for target, _site, value, owner in events
                   if (roots - {None}) & (self._storage_roots(target, owner) - {None})]
        if forced:
            for target, _site, value, owner in events:
                targets = self._storage_roots(target, owner)
                if None in targets or any(isinstance(root, tuple) and isinstance(root[0], ast.Call) for root in targets):
                    matched.append((value, owner))
        opaque = None in roots or any(isinstance(root, tuple) and isinstance(root[0], ast.Call) for root in roots)
        if forced and (not matched or opaque):
            # An attribute container has a module-wide name pool. Do not
            # confuse an unrelated attribute such as path.parts with every
            # mutable local container in that module.
            label = expression.id if isinstance(expression, ast.Name) else expression.attr if isinstance(expression, ast.Attribute) else None
            if label is not None and not opaque:
                events = [event for event in events if isinstance(event[0], (ast.Name, ast.Attribute)) and
                          (event[0].id if isinstance(event[0], ast.Name) else event[0].attr) == label]
            matched.extend((value, owner) for _target, _site, value, owner in events)
        return attributes + matched

    def _walk(self, node, context, parent=None):
        self.scope[node] = context
        if not hasattr(node, "lineno") and parent is not None and hasattr(parent, "lineno"):
            node.lineno, node.col_offset = parent.lineno, getattr(parent, "col_offset", 0)
        node._inventory_file = self.MODULES.get(context.split(".")[0], ("inventory.py", ""))[0]
        if parent is not None:
            self.parent[node] = parent
        if isinstance(node, ast.Call):
            if len(self._mutation_calls) >= INVENTORY_WORK_BUDGET:
                self._mutation_overflow = True
            else:
                self._mutation_calls.append((node, context))
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Del):
            destination = self.declarations.get((context, node.id), context)
            self._mutation_record("delete_name", destination, node.id, node, context)
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Del):
            self._mutation_record("delete", node.value, node.attr, node, context)
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Del):
            self._mutation_record("delete_slot", None, self._slot_name(node.slice), node, context)
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
            # Census the AST target itself, independently of value projection.
            # This also sees targets in comprehensions and under Starred. Only
            # the closed direct-assignment form can establish a precise owner.
            direct = isinstance(parent, (ast.Assign, ast.AnnAssign))
            kind = "augment" if isinstance(parent, ast.AugAssign) else "attribute"
            self._mutation_record(kind, node.value if direct else None, node.attr, parent or node, context)
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store):
            kind = "augment_slot" if isinstance(parent, ast.AugAssign) else "slot"
            self._mutation_record(kind, None, self._slot_name(node.slice), parent or node, context)
        elif isinstance(node, ast.AugAssign):
            target = node.target
            if isinstance(target, ast.Name):
                self._mutation_record("augment_name", self.declarations.get((context, target.id), context), target.id, node, context)
        names, precise = self.binding_effect(node, context)
        if not precise:
            for name in names:
                destination = self.declarations.get((context, name), context)
                self.unknown_bindings.setdefault((destination, name), node)
                if type(node).__name__ not in self.BINDING_TARGET_FIELDS:
                    # An unmodelled scope (for example a future type-parameter
                    # binder) cannot prove that outer references are untouched.
                    self.unknown_bindings.setdefault((context.split(".")[0], name), node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            is_class = isinstance(node, ast.ClassDef)
            name = (node.name if not isinstance(node, ast.Lambda) else
                    "_inventory_lambda_" + context.split(".")[0] + "_" + str(node.lineno) + "_" + str(node.col_offset))
            key = context + "." + name
            if key in self.functions or key in self.classes:
                key += "@" + str(node.lineno) + "_" + str(node.col_offset)
            self.definition_keys[node] = key
            self.outer[key] = context
            if is_class:
                self.classes[key] = node
                symbol = "class:" + key
            else:
                function = node
                if isinstance(node, ast.Lambda):
                    statement = ast.copy_location(ast.Return(value=node.body), node)
                    function = ast.copy_location(ast.FunctionDef(
                        name=name, args=node.args, body=[statement], decorator_list=[],
                        returns=None, type_comment=None), node)
                    self.lambdas[key] = function
                    self.scope[function] = key
                self.functions[key] = function
                self.parameters[key] = {arg.arg for arg in
                                        [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                                         *([node.args.vararg] if node.args.vararg else []),
                                         *([node.args.kwarg] if node.args.kwarg else [])]}
                for parameter in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                                  *([node.args.vararg] if node.args.vararg else []),
                                  *([node.args.kwarg] if node.args.kwarg else [])]:
                    self._mutation_record("parameter", key, parameter.arg, parameter, key)
                for role, parameters in ast.iter_fields(node.args):
                    if role in self.PRECISE_PARAMETER_ROLES:
                        continue
                    for parameter in parameters if isinstance(parameters, list) else [parameters]:
                        if isinstance(parameter, ast.arg):
                            self.unknown_bindings.setdefault((key, parameter.arg), parameter)
                if context in self.classes:
                    self.method_class[key] = context
                    self.outer[key] = self.outer[context]
                defaults = dict(zip([arg.arg for arg in [*node.args.posonlyargs, *node.args.args]][-len(node.args.defaults):],
                                    node.args.defaults)) if node.args.defaults else {}
                defaults.update((arg.arg, value) for arg, value in zip(node.args.kwonlyargs, node.args.kw_defaults)
                                if value is not None)
                self.defaults[key] = {name: (value, context) for name, value in defaults.items()}
                symbol = "fn:" + key
            # The shared scope-aware walk includes nested definition headers
            # evaluated here, while excluding their separately scoped bodies.
            body = ast.Module(body=node.body if not isinstance(node, ast.Lambda) else [node.body], type_ignores=[])
            owned = list(_owned_nodes(body))
            self.local_names[key] = set(self.parameters.get(key, ()))
            for item in owned:
                # Scope membership is independent of value precision. Index
                # every binder before resolving any nested nonlocal, including
                # binders that occur after the nested definition in the source.
                names, _precise = self.binding_effect(item, key)
                self.local_names[key].update(names)
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    self.local_names[key].add(item.name)
            for item in owned:
                if isinstance(item, (ast.Global, ast.Nonlocal)):
                    for declared in item.names:
                        destination = context.split(".")[0] if isinstance(item, ast.Global) else context
                        if isinstance(item, ast.Nonlocal):
                            while destination is not None and (destination in self.classes or
                                    declared not in self.local_names.get(destination, ())):
                                destination = self.outer.get(destination)
                            if destination is None:
                                self.unsupported(item)
                        self.declarations[(key, declared)] = destination
                        self.local_names[key].discard(declared)
            self.locations[(context.split(".")[0], node.lineno, node.col_offset, name)] = key
            if not isinstance(node, ast.Lambda):
                self._event(context, name, node, symbol, context)
            # Defaults are evaluated where the definition is made.
            if not is_class:
                self._walk(node.args, context, node)
            else:
                for child in [*node.bases, *node.keywords]:
                    self._walk(child, context, node)
            for decorator in getattr(node, "decorator_list", []):
                self._walk(decorator, context, node)
            for parameter in getattr(node, "type_params", ()):
                self._walk(parameter, key, node)
            if getattr(node, "returns", None) is not None:
                self._walk(node.returns, context, node)
            body = node.body if not isinstance(node, ast.Lambda) else [node.body]
            for child in body:
                self._walk(child, key, node)
            if not isinstance(node, ast.Lambda) and node.decorator_list:
                self.invocation_sites.append(node)
            return
        if isinstance(node, ast.Assign):
            for target in node.targets:
                self._store(target, node.value, context, node)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            self._store(node.target, node.value, context, node)
        elif isinstance(node, ast.NamedExpr):
            self._store(node.target, node.value, context, node)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            node.iter._inventory_container_read = True
            self._store(node.target, node.iter, context, node)
        elif isinstance(node, (ast.comprehension, ast.YieldFrom)):
            (node.iter if isinstance(node, ast.comprehension) else node.value)._inventory_container_read = True
        elif isinstance(node, ast.ExceptHandler) and node.name and node.type is not None:
            # A caught exception is an instance, not an unbound external
            # receiver. Preserve each declared alternative without executing it.
            types = node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
            for exception in types:
                instance = ast.copy_location(ast.Call(func=exception, args=[], keywords=[]), node)
                self._event(context, node.name, node, instance, context)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    self._store(item.optional_vars, item.context_expr, context, node)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                module = self.module(alias.name)
                if not alias.asname and "." in alias.name:
                    module = None
                self._event(context, alias.asname or alias.name.split(".")[0], node,
                            ("mod:" + module) if module else ("ext:" + (alias.name if alias.asname else alias.name.split(".")[0])), context)
        elif isinstance(node, ast.ImportFrom):
            module = self.module(node.module or "")
            for alias in node.names:
                if alias.name == "*" and module:
                    # Export membership and __all__ are not modeled. Preserve
                    # every candidate for relevance, then refuse this import.
                    self._event(context, "*", node, "mod:" + module, context)
                    continue
                imported_module = self.module(alias.name) if module is None else None
                value = ("import:" + module + "." + alias.name if module else
                         "mod:" + imported_module if imported_module else
                         "ext:" + (node.module or "") + "." + alias.name)
                self._event(context, alias.asname or alias.name, node, value, context)
        if isinstance(node, tuple({kind for _mode, kinds, _hooks in self.CALL_PROTOCOLS.values() for kind in kinds})):
            self.invocation_sites.append(node)
        for child in ast.iter_child_nodes(node):
            self._walk(child, context, node)

    def _visible(self, events, context, expression, origin):
        # A local RHS captures the binding at that source point. Globals read
        # by a function use the defining module's final binding.
        if context == origin:
            def flow(site):
                while site is not None and self.scope.get(site) == context:
                    if isinstance(site, (ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.NamedExpr)):
                        return True
                    site = self.parent.get(site)
                return False
            def evaluating(site):
                child = expression
                while child is not None:
                    parent = self.parent.get(child)
                    if parent is site:
                        if isinstance(site, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                            return child is site.value
                        if isinstance(site, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                            return child not in site.body
                        if isinstance(site, (ast.For, ast.AsyncFor)):
                            return child is site.iter
                        if isinstance(site, (ast.With, ast.AsyncWith)):
                            return child in site.items
                        if isinstance(site, ast.ExceptHandler):
                            return child is site.type
                        return False
                    child = parent
                return False
            events = [event for event in events if not evaluating(event[0]) and (flow(event[0]) or
                      event[0].lineno <= getattr(expression, "lineno", float("inf")))]
        if not events:
            return []
        # Keep all alternatives until the admission gate has proved that the
        # declaring scope binds the name exactly once. Never select a later
        # syntactic event as though conditional execution were established.
        return events

    def bindings(self, name, context, expression):
        values = self._precise_bindings(name, context, expression)
        if not self.binding_is_unknown(name, context):
            return values
        return [(self.unknown_binding_value(name, context, expression), context), *values]

    def unknown_binding_value(self, name, context, expression):
        marker = (context, name)
        if marker not in self._unknown_binding_values:
            unknown = ast.copy_location(ast.Name(id="_unknown_binding", ctx=ast.Load()), expression)
            unknown._inventory_file = getattr(expression, "_inventory_file", "inventory.py")
            unknown._inventory_refs = frozenset({"unknown:" + context.split(".")[0]})
            unknown._inventory_values_unknown = True
            self._unknown_binding_values[marker] = unknown
        return self._unknown_binding_values[marker]

    def _precise_bindings(self, name, context, expression):
        current = self.declarations.get((context, name), context)
        while current is not None:
            events = self.events.get((current, name), [])
            visible = self._visible(events, current, expression, context)
            if visible and name not in self.parameters.get(current, ()):
                return [(value, owner) for _site, value, owner in visible]
            if events and current in self.functions and name not in self.parameters.get(current, ()):
                # Python treats a local binding anywhere in the scope as a
                # shadow, including before its first assignment. Such a name
                # cannot prove the identity of a process builtin.
                return [("data:", current)]
            if name in self.parameters.get(current, ()):
                values = set(self.arguments.get((current, name), set()))
                values.update((value, owner) for _site, value, owner in visible)
                default = self.defaults.get(current, {}).get(name)
                if default is not None and (not values or any(self.callable(ref) or ref.startswith("inst:") for ref in self.refs(*default))):
                    # Callable defaults remain alternatives at every call. Scalar
                    # defaults follow Python's omitted-argument semantics.
                    values.add(default)
                if values:
                    return sorted(values, key=lambda item: (
                        item[1], getattr(item[0], "lineno", 0), getattr(item[0], "col_offset", 0),
                        item[0] if isinstance(item[0], str) else type(item[0]).__name__))
                if name in self.defaults.get(current, {}):
                    return [self.defaults[current][name]]
                if current in self.method_class:
                    function = self.functions[current]
                    positional = [*function.args.posonlyargs, *function.args.args]
                    decorators = [self.refs(item, self.scope[function]) for item in function.decorator_list]
                    if positional and name == positional[0].arg and {"builtin:staticmethod"} not in decorators:
                        prefix = "class:" if {"builtin:classmethod"} in decorators else "inst:"
                        return [(prefix + self.method_class[current], current)]
                if name == "codec":
                    return [("mod:codec", current)]
                if name in ("mailbox", "store", "access", "_access"):
                    key = {"mailbox": "mailbox.Mailbox", "store": "store.Store",
                           "access": "records._RecordAccess", "_access": "records._RecordAccess"}[name]
                    return [("inst:" + key, current)]
                return [("data:", current)]
            if current in self.overrides and name in self.overrides[current]:
                return list(self.overrides[current][name])
            for _site, module, _owner in self.events.get((current, "*"), ()):
                values = self._global(self.key(module), name, set())
                if values:
                    return [(value, current) for value in values]
            current = self.outer.get(current)
        primitive = {"CodecError": "class:format.CodecError", "require": "fn:format.require",
                     "need": "fn:format.require", "ValueError": "class:_builtin.ValueError"}
        if name in primitive:
            return [(primitive[name], context)] if name == "ValueError" else [(primitive[name], context), ("unresolved:", context)]
        if name in self.BUILTINS:
            return [("builtin:" + name, context)]
        # An otherwise unbound direct callee is external to these sources.
        # Do not acquire the process-wide builtins namespace to classify it.
        parent = self.parent.get(expression)
        if isinstance(parent, ast.Call) and parent.func is expression:
            return [("ext:_external." + name, context)]
        return []

    def refs(self, node, context, seen=None):
        return self._query("refs", node, context)

    def _reference_evidence(self, node, context, seen=None):
        if isinstance(node, str):
            if node.startswith("fn:") and self.key(node) in self.functions:
                fn = self.functions[self.key(node)]
                result = {node}
                for decorator in fn.decorator_list:
                    identities = self.refs(decorator, self.scope[fn], seen)
                    if identities == {"builtin:staticmethod"}:
                        result = {"static:" + self.key(item) for item in result}
                    elif identities == {"builtin:classmethod"}:
                        result = {"classmeth:" + self.key(item) for item in result}
                    elif identities not in ({"ext:contextlib.contextmanager"}, {"builtin:property"}):
                        for identity in identities:
                            target = self.functions.get(self.key(identity))
                            if target is not None:
                                for item in _owned_nodes(target):
                                    if isinstance(item, ast.Return):
                                        result.update(self.refs(item.value, self.key(identity), seen))
                return frozenset(result)
            if node.startswith("import:"):
                module, _, name = self.key(node).partition(".")
                return self._global(module, name, seen)
            return frozenset({node})
        if node is None:
            return frozenset()
        marker = (node, context)
        seen = set()
        self._uncertain.append(False)
        found = self._refs(node, context, seen | {marker})
        mutation = self._read_mutation_value(node, context)
        if mutation is not None:
            found = set(found) | self.refs(mutation, context)
        dependency = node.value if isinstance(node, (ast.Attribute, ast.Subscript)) else node.func if isinstance(node, ast.Call) else None
        if dependency is not None:
            found = set(found) | {ref for ref in self.refs(dependency, context)
                                  if ref.startswith("unknown:")}
        if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) or getattr(node, "_inventory_container_read", False):
            found = set(found)
            for value, owner in self.storage_values(node, context):
                for ref in self.refs(value, owner, seen | {marker}):
                    found.update(self.read_attribute(ref, context, form="namespace"))
        uncertain = self._uncertain.pop()
        identities = {ref for ref in found if ref != "unresolved:"}
        scalar = isinstance(node, (ast.Constant, ast.Compare, ast.BinOp, ast.UnaryOp, ast.JoinedStr, ast.FormattedValue))
        if scalar:
            found = identities
        elif uncertain:
            found = set(found) | {"unresolved:"}
        result = frozenset(found)
        # A cycle cut remains explicit through callers and cache hits. It must
        # not acquire a false concrete receiver identity during escape checks.
        if "unresolved:" in result and self._uncertain:
            self._uncertain[-1] = True
        return result

    def _global(self, module, name, seen):
        events = self.events.get((module, name), [])
        mutation = self.mutation_value("mod:" + module, name)
        entries = self._census_entries("mod:" + module, name)
        if not events and (module, name) not in self.unknown_bindings and not entries:
            return frozenset()
        seen = set() if seen is None else seen
        marker = ("import", module, name)
        if marker in seen:
            return frozenset({"unresolved:"})
        result = frozenset().union(*(self.read_attribute(ref, "mod:" + module, form="namespace")
                                    for _site, value, owner in events for ref in self.refs(value, owner, seen | {marker})))
        if (module, name) in self.unknown_bindings:
            result |= {"unknown:" + module.split(".")[0]}
        if mutation is None and not events and entries:
            mutation = self.unknown_binding_value(name, "mod:" + module, entries[0]["site"])
            mutation._inventory_refs |= {"fn:" + UNKNOWN_CALL_TARGET}
        if mutation is not None:
            result |= self.refs(mutation, module)
        return result

    def members(self, key, name, seen=None):
        return self._query("members", key, key, name)

    def _collect_members(self, key, name, seen=None):
        seen = set() if seen is None else seen
        if key in seen:
            self.unsupported(self.classes[key])
        values = self.events.get((key, name), [])
        result = list(values)
        owner_ref = ("mod:" if key in self.trees else "class:") + key
        mutation = self.mutation_value(owner_ref, name)
        entries = self._census_entries(owner_ref, name)
        if mutation is None and not values and entries:
            mutation = self.unknown_binding_value(name, owner_ref, entries[0]["site"])
            mutation._inventory_refs |= {"fn:" + UNKNOWN_CALL_TARGET}
        if mutation is not None:
            result.append((entries[0]["site"], mutation, key))
        if (key, name) in self.unknown_bindings:
            site = self.unknown_bindings[(key, name)]
            result.append((site, self.unknown_binding_value(name, key, site), key))
        owner = self.classes.get(key)
        if owner is not None:
            for base in owner.bases:
                for ref in sorted(self.refs(base, self.scope[owner])):
                    if ref.startswith("class:"):
                        result.extend(self.members(self.key(ref), name, seen | {key}))
        return list(dict.fromkeys(result))

    def inherited_fields(self, key, name=None, seen=None):
        return self._query("fields", key, key, name)

    def _collect_inherited_fields(self, key, name=None, seen=None):
        seen = set() if seen is None else seen
        if key in seen:
            return []
        values = [item for (owner, field), items in self.fields.items() if owner == key and (name is None or field == name) for item in items]
        cls = self.classes.get(key)
        if cls is not None:
            for base in cls.bases:
                for ref in self.refs(base, self.scope[cls]):
                    if ref.startswith("class:"):
                        values.extend(self.inherited_fields(self.key(ref), name, seen | {key}))
        return list(dict.fromkeys(values))

    def class_values(self, key, seen=None):
        return self._query("class_values", key, key)

    def _collect_class_values(self, key, seen=None):
        seen = set() if seen is None else seen
        if key in seen:
            return []
        result = [item for (scope, _name), items in self.events.items() if scope == key for item in items]
        result.extend(item for (scope, _name), items in self.fields.items() if scope == key for item in items)
        identities = {"inst:" + key, "class:" + key}
        for (_module, _name), events in self.storage_attributes.items():
            for target, site, value, owner in events:
                receivers = self.refs(target.value, owner)
                if receivers & identities:
                    result.append((site, value, owner))
        cls = self.classes.get(key)
        if cls is not None:
            for base in cls.bases:
                for ref in self.refs(base, self.scope[cls]):
                    if ref.startswith("class:"):
                        result.extend(self.class_values(self.key(ref), seen | {key}))
        return list(dict.fromkeys(result))

    def constructors(self, key):
        result = set()
        for name in ("__new__", "__init__"):
            for _site, value, owner in self.members(key, name):
                result.update(self.key(bound) for ref in self.refs(value, owner)
                              for bound in self.read_attribute(ref, "class:" + key if name == "__new__" else "inst:" + key)
                              if self.callable(bound))
        return sorted(result)

    def layout(self, node, context, kind, seen=None):
        return self._query("layout", node, context, kind)

    def _collect_layout(self, node, context, kind, seen=None):
        seen = set() if seen is None else seen
        marker = (node, context, kind)
        if isinstance(node, str) or marker in seen:
            return None
        seen = seen | {marker}
        if isinstance(node, ast.Name):
            values = [*self.bindings(node.id, context, node), *self.storage_values(node, context, container=True)]
            pieces = [self.layout(value, owner, kind, seen) for value, owner in values]
        elif isinstance(node, ast.IfExp):
            pieces = [self.layout(value, context, kind, seen) for value in (node.body, node.orelse)]
        elif isinstance(node, ast.Call):
            targets = self.refs(node.func, context)
            if targets == {"ext:contextlib.ExitStack.enter_context"} and node.args:
                return self.layout(node.args[0], context, kind, seen)
            values = [(item.value, self.key(ref)) for ref in targets if self.key(ref) in self.functions
                      for item in _owned_nodes(self.functions[self.key(ref)])
                      if isinstance(item, (ast.Return, ast.Yield)) and item.value is not None]
            pieces = [self.layout(value, owner, kind, seen) for value, owner in values]
        elif kind == "sequence" and isinstance(node, (ast.Tuple, ast.List)):
            rows = [()]
            for value in node.elts:
                choices = self.layout(value.value, context, kind, seen) if isinstance(value, ast.Starred) else [((value, context),)]
                if choices is None or len(rows) * len(choices) > 64:
                    return None
                rows = [row + tail for row in rows for tail in choices]
            return rows
        elif kind == "keywords" and isinstance(node, ast.Dict):
            rows = [()]
            for key, value in zip(node.keys, node.values):
                if key is None:
                    choices = self.layout(value, context, kind, seen)
                elif isinstance(key, ast.Constant) and type(key.value) is str:
                    choices = [((key.value, value, context),)]
                else:
                    return None
                if choices is None or len(rows) * len(choices) > 64:
                    return None
                rows = [row + tail for row in rows for tail in choices]
            return rows
        else:
            return None
        if not pieces or any(piece is None for piece in pieces):
            return None
        result = list(dict.fromkeys(row for piece in pieces for row in piece))
        return result if len(result) <= 64 else None

    def metaclasses(self, key, seen=None):
        return self._query("metaclasses", key, key)

    def _collect_metaclasses(self, key, seen=None):
        seen = set() if seen is None else seen
        if key in seen or key not in self.classes:
            return set()
        cls = self.classes[key]
        result = set().union(*(self.refs(item.value, self.scope[cls]) for item in cls.keywords if item.arg == "metaclass"))
        for base in cls.bases:
            for ref in self.refs(base, self.scope[cls]):
                if ref.startswith("class:"):
                    result.update(self.metaclasses(self.key(ref), seen | {key}))
        return result

    def _unstable(self, value, owner):
        return self._query("unstable", value, owner)

    def _collect_unstable(self, value, owner):
        visited = set()
        marker = (value, owner)
        if marker in visited:
            return False
        visited.add(marker)
        if isinstance(value, str):
            if value.startswith("import:"):
                module, _, name = self.key(value).partition(".")
                return self._unstable(ast.Name(id=name, ctx=ast.Load()), module)
            return False
        if isinstance(value, ast.Name):
            current = self.declarations.get((owner, value.id), owner)
            while current is not None:
                events = self.events.get((current, value.id), ())
                if events:
                    if len(events) != 1:
                        return True
                    site = events[0][0]
                    if self.scope.get(site) != current:
                        return True
                    parent = self.parent.get(site)
                    while parent is not None and self.scope.get(parent) == current:
                        if isinstance(parent, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try)):
                            return True
                        parent = self.parent.get(parent)
                    return any(self._unstable(item, scope) for _site, item, scope in events)
                if value.id in self.parameters.get(current, ()):
                    default = self.defaults.get(current, {}).get(value.id)
                    if default and any(self.callable(ref) or ref.startswith("inst:") for ref in self.refs(*default)):
                        return True
                    return len(self.arguments.get((current, value.id), ())) != 1
                if self.events.get((current, "*")):
                    return True
                current = self.outer.get(current)
        if isinstance(value, ast.Attribute):
            return self._unstable(value.value, owner)
        return isinstance(value, (ast.IfExp, ast.BoolOp, ast.NamedExpr))

    def resolve(self, node, context, *, invocation=False):
        """The sole issuer of identity proofs and Python argument environments.

        refs/bindings collect monotone evidence; no evidence prefix constitutes
        a proof. UNKNOWN retains all candidates, including descriptor targets,
        registered callbacks and capability carriers. Walkers consume these
        records and never guess a target or zip a second argument mapping.
        """
        if not self._spend(node, context):
            return _Resolution("UNKNOWN", frozenset({"unknown:" + context.split(".")[0]}))
        marker = (node, context, invocation)
        if marker in self._resolution_cache:
            return self._resolution_cache[marker]
        call = node if invocation and isinstance(node, ast.Call) else None
        expression = call.func if call is not None else node
        refs = set(self.refs(expression, context))
        # A missing-proof marker is not itself a target identity. An unknown
        # binding/kind, however, always contributes symbolic top alongside all
        # concrete candidates already known at this site.
        candidates = refs - {"unresolved:"}
        unknown_target = call is not None and (not candidates or any(
            self.key(ref) not in ("format.CodecError", "format.require", "_builtin.ValueError") and
            self.CALL_TARGET_KINDS.get(ref.partition(":")[0], "UNKNOWN") == "UNKNOWN"
            for ref in candidates))
        if call is not None and refs & self.MODELLED_WRAPPERS.keys():
            wrapped = self.refs(call.args[0], context) if call.args else set()
            unknown_target |= not wrapped or any(not ref.startswith(("fn:", "rawfn:")) for ref in wrapped)
        native_methods = [self.native_methods[ref] for ref in sorted(refs) if ref in self.native_methods]
        if call is not None:
            for receiver, owner, method in native_methods:
                if method not in self.CONTAINER_STORES:
                    continue
                # The projection deliberately joins every supplied value. It
                # includes unpacked layouts and keys as an UNKNOWN superset.
                receiver_roots = self._storage_roots(receiver, owner) - {None}
                if any(receiver_roots & (self._storage_roots(value, context) - {None}) for value in call.args):
                    self._widen(("storage", receiver, owner, True), "cycle")
                events = self.storage_containers.setdefault(owner.split(".")[0], [])
                for index, value in enumerate([*call.args, *(item.value for item in call.keywords)]):
                    # Materialize the finite candidate set at the write. Reads
                    # must not recursively re-interpret the whole module's
                    # value-producing graph through an UNKNOWN alias pool.
                    slot = (call, ("native_store", index))
                    projected = self._protocol_arguments.setdefault(slot, (ast.copy_location(
                        ast.Name(id="_stored_candidates", ctx=ast.Load()), value),))[0]
                    projected._inventory_file = getattr(value, "_inventory_file", "inventory.py")
                    joined = getattr(projected, "_inventory_refs", frozenset()) | self.refs(value, context)
                    if getattr(projected, "_inventory_refs", None) != joined:
                        projected._inventory_refs = joined
                        self._protocol_changed = True
                    projected._inventory_values = ((value, context),)
                    event = (receiver, call, projected, context)
                    if event not in events:
                        events.append(event)
                        self._protocol_changed = True
        def project(projected):
            resolution = self.resolve(projected, context, invocation=True)
            return (*resolution.invocations, *resolution.callbacks)
        if hasattr(expression, "_inventory_symbol"):
            refs = {"fn:" + expression._inventory_symbol}
        # No proof is the default. Only a closed syntactic identity pattern can
        # become EXACT, after every binding/layout/protocol condition succeeds.
        proven = isinstance(expression, self.PROVEN_PATTERNS)
        uncertain = not proven or len(refs) != 1 or any(ref.startswith(("data:", "opaque:", "unresolved:", "unknown:")) for ref in refs)
        uncertain |= self._unstable(expression, context)
        receiver_refs = set()
        literal_bindings = list(self.bindings(expression.id, context, expression)) if isinstance(expression, ast.Name) else []
        stored = self.storage_values(expression, context) if isinstance(expression, (ast.Name, ast.Attribute, ast.Subscript)) else []
        literal_bindings.extend(stored)
        uncertain |= bool(stored)
        if isinstance(expression, ast.Attribute):
            receiver_refs = set(self.refs(expression.value, context))
            for receiver in receiver_refs:
                if receiver.startswith(("mod:", "class:", "inst:")):
                    key = self.key(receiver)
                    member = ast.Name(id=expression.attr, ctx=ast.Load())
                    uncertain |= self._unstable(member, key)
                    uncertain |= bool(self.fields.get((key, expression.attr), ()))
                    events = [*(self.inherited_fields(key, expression.attr) if receiver.startswith("inst:") else ()), *self.members(key, expression.attr)]
                    literal_bindings.extend((value, owner) for _site, value, owner in events)
            if not receiver_refs or any(ref.startswith(("data:", "opaque:", "unresolved:")) for ref in receiver_refs):
                uncertain = True
                for candidate in sorted(self.tail.get(expression.attr, ())):
                    form = "descriptor" if candidate in self.classes else "namespace"
                    for _site, value, owner in self.members(candidate, expression.attr):
                        for member in self.refs(value, owner):
                            refs.update(self.read_attribute(member, "inst:" + candidate, form=form))
                        literal_bindings.append((value, owner))
                    for event in self.fields.get((candidate, expression.attr), ()):
                        refs.update(self.field_refs(expression, context, event, "inst:" + candidate))
                        literal_bindings.append((event[1], event[2]))
        specifications = []
        for instance in tuple(refs):
            if instance.startswith("inst:"):
                for _site, value, owner in self.members(self.key(instance), "__call__"):
                    for item in self.refs(value, owner):
                        refs.update(self.read_attribute(item, instance))
        if call is not None and refs & {"builtin:eval", "builtin:exec", "builtin:compile"}:
            self.unsupported(node)
        if call is not None:
            for instance in tuple(refs):
                if not instance.startswith("class:"):
                    continue
                metas = self.metaclasses(self.key(instance))
                candidates = {self.key(meta) for meta in metas if meta.startswith("class:")}
                if any(not meta.startswith(("class:", "builtin:")) for meta in metas):
                    uncertain = True
                    candidates.update(self.classes)
                for candidate in candidates:
                    for _site, value, owner in self.members(candidate, "__call__"):
                        for member in self.refs(value, owner):
                            refs.update(self.read_attribute(member, instance, form="metaclass"))
        positional = [()]
        keywords = [()]
        if call is not None:
            for argument in call.args:
                tail = self.layout(argument.value, context, "sequence") if isinstance(argument, ast.Starred) else [((argument, context),)]
                positional = None if positional is None or tail is None or len(positional) * len(tail) > 64 else [row + part for row in positional for part in tail]
            if getattr(call, "_inventory_unknown_layout", False):
                positional = None
            for keyword in call.keywords:
                tail = self.layout(keyword.value, context, "keywords") if keyword.arg is None else [((keyword.arg, keyword.value, context),)]
                keywords = None if keywords is None or tail is None or len(keywords) * len(tail) > 64 else [row + part for row in keywords for part in tail]
        layouts = [(args, kw) for args in (positional or [None]) for kw in (keywords or [None])]
        for ref in sorted(refs):
            key = self.key(ref)
            targets = self.constructors(key) if ref.startswith("class:") and key not in (
                "format.CodecError", "_builtin.ValueError") else [key] if self.callable(ref) else []
            if ref.startswith("class:") and key in self.generated_fields:
                targets.append(key)
            if ref.startswith("class:"):
                if "format.CodecError.__init__" in targets:
                    targets = ["format.CodecError" if item == "format.CodecError.__init__" else item for item in targets]
                if not targets and key in self.classes:
                    pending, visited_bases = [key], set()
                    while pending:
                        base_key = pending.pop()
                        if base_key in visited_bases:
                            continue
                        visited_bases.add(base_key)
                        for base in self.classes[base_key].bases:
                            for identity in self.refs(base, self.scope[self.classes[base_key]]):
                                ancestor = self.key(identity)
                                if ancestor in ("_builtin.ValueError", "format.CodecError"):
                                    targets.append(ancestor)
                                elif ancestor in self.classes:
                                    pending.append(ancestor)
            for target in targets:
                fn = self.functions.get(target)
                supplied, implicit = {}, None
                member_receiver = ref.partition("|")[2] if ref.startswith(("member:", "member_static:", "member_class:")) else ""
                if member_receiver and not ref.startswith("member_static:"):
                    # read_attribute already applied the descriptor. Source
                    # decorators cannot bind a plain function a second time.
                    implicit = member_receiver
                elif fn is not None and ref.startswith("class:") and target in self.method_class:
                    decorators = [self.refs(item, self.scope[fn]) for item in fn.decorator_list]
                    static = any(items == {"builtin:staticmethod"} for items in decorators)
                    classmethod = any(items == {"builtin:classmethod"} for items in decorators)
                    if any(items not in ({"builtin:staticmethod"}, {"builtin:classmethod"}) for items in decorators):
                        uncertain = True
                    actual = key
                    if classmethod:
                        implicit = "class:" + actual
                    elif target.rsplit(".", 1)[-1].startswith("__new__"):
                        implicit = "class:" + actual
                    elif not static:
                        implicit = "inst:" + actual
                if fn is not None:
                    names = [arg.arg for arg in [*fn.args.posonlyargs, *fn.args.args]]
                    uncertain |= fn.args.vararg is not None or fn.args.kwarg is not None
                elif target in ("format.require", "format.CodecError", "_builtin.ValueError"):
                    names = (["condition", "code"] if target == "format.require" else
                             ["code"] if target == "format.CodecError" else ["message"])
                else:
                    names = self.generated_fields.get(target, [])
                if implicit is not None and names:
                    supplied[names[0]] = (implicit, context)
                    names = names[1:]
                for args, kw in layouts:
                    environment = dict(supplied)
                    allowed = set(names) | set(self.parameters.get(target, ())) | {"detail"}
                    if args is None or kw is None:
                        uncertain = True
                        sources = []
                        after_star = False
                        if args is None:
                            for argument in call.args:
                                after_star |= isinstance(argument, ast.Starred)
                                if after_star:
                                    sources.append(argument.value if isinstance(argument, ast.Starred) else argument)
                            if not after_star:
                                sources.extend(call.args)
                        if kw is None:
                            sources.extend(item.value for item in call.keywords if item.arg is None)
                        identities = frozenset().union(*(self.refs(value, context) for value in sources)) | {"unknown:"}
                        for name in allowed - environment.keys():
                            slot = ((context, getattr(node, "_inventory_file", "inventory.py"),
                                     getattr(node, "lineno", 0), getattr(node, "col_offset", 0)),
                                    ("unknown_arguments", target, name))
                            unknown_argument = self._protocol_arguments.setdefault(
                                slot, (ast.copy_location(ast.Name(id="_unknown_arguments", ctx=ast.Load()), node),))[0]
                            unknown_argument._inventory_file = getattr(node, "_inventory_file", "inventory.py")
                            joined = identities | getattr(unknown_argument, "_inventory_refs", frozenset())
                            if getattr(unknown_argument, "_inventory_refs", None) != joined:
                                unknown_argument._inventory_refs = joined
                                self._protocol_changed = True
                            values = {(owner, ast.dump(value)): (value, owner)
                                      for value, owner in getattr(unknown_argument, "_inventory_values", ())}
                            for value in sources:
                                if len(values) >= 64:
                                    unknown_argument._inventory_values_unknown = True
                                    break
                                values[(context, ast.dump(value))] = (value, context)
                            unknown_argument._inventory_values = tuple(values.values())
                            environment[name] = (unknown_argument, context)
                    if args is not None:
                        environment.update(zip(names, args))
                    elif call is not None:
                        prefix = []
                        for argument in call.args:
                            if isinstance(argument, ast.Starred):
                                break
                            prefix.append((argument, context))
                        environment.update(zip(names, prefix))
                    if kw is not None:
                        environment.update((name, (value, owner)) for name, value, owner in kw if name in allowed)
                    elif call is not None:
                        environment.update((item.arg, (item.value, context)) for item in call.keywords
                                           if item.arg is not None and item.arg in allowed)
                    if args is not None and kw is not None:
                        for name, binding in self.defaults.get(target, {}).items():
                            environment.setdefault(name, binding)
                    specifications.append(_Invocation(target, tuple((name, value, owner) for name, (value, owner) in sorted(environment.items()))))
        if invocation and call is None:
            # Reading a callable attribute/default does not invoke that value.
            # Only the protocols below can supply an implicit call environment.
            specifications = []
        if isinstance(node, ast.Compare) and any(not isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops):
            operands = set().union(*(self.refs(item, context) for item in [node.left, *node.comparators]))
            candidates = self._capability_callables(operands)
            if candidates:
                uncertain = True
                specifications.extend(_Invocation(key, self.unknown_environment(key, node, context)) for key in sorted(candidates))
                refs.update("fn:" + key for key in candidates)
        if call is not None and refs & {"builtin:isinstance", "builtin:issubclass"}:
            hook = "__instancecheck__" if "builtin:isinstance" in refs else "__subclasscheck__"
            operands = set().union(*(self.refs(item, context) for item in call.args))
            hooks = [(value, owner, item) for item in operands if item.startswith("class:")
                     for meta in self.metaclasses(self.key(item)) if meta.startswith("class:")
                     for _site, value, owner in self.members(self.key(meta), hook)]
            opaque_meta = (any(item.startswith(("data:", "opaque:", "unresolved:", "unknown:")) for item in operands) or
                           any(not meta.startswith(("class:", "builtin:")) for item in operands if item.startswith("class:")
                               for meta in self.metaclasses(self.key(item))))
            if opaque_meta:
                uncertain = True
                actual_classes = {item for item in operands if item.startswith("class:")} or {"class:" + key for key in self.classes}
                hooks.extend((value, owner, actual) for key in self.classes
                             for _site, value, owner in self.members(key, hook) for actual in sorted(actual_classes))
            carriers = self._capability_callables(operands)
            if hooks or carriers:
                uncertain = True
                specifications.extend(_Invocation(key, self.unknown_environment(key, node, context)) for key in sorted(carriers))
                for value, owner, actual_class in hooks:
                    for ref in sorted(self.refs(value, owner)):
                        function = ast.copy_location(ast.Name(id="_metaclass_hook", ctx=ast.Load()), node)
                        function._inventory_refs = frozenset(self.read_attribute(ref, actual_class, form="metaclass"))
                        projected = ast.copy_location(ast.Call(func=function, args=call.args[:1], keywords=[]), node)
                        projected._inventory_file = getattr(node, "_inventory_file", "inventory.py")
                        specifications.extend(project(projected))
        # Native protocol consumers and decoder hooks may invoke arguments.
        native_records = []
        if call is not None:
            for ref in tuple(refs):
                if ref.startswith("builtin:"):
                    for argument in [*call.args, *(item.value for item in call.keywords)]:
                        if isinstance(argument, ast.Constant):
                            continue
                        identities = self.refs(argument, context)
                        hooks = self.BUILTIN_PROTOCOLS.get(self.key(ref), ())
                        owners = {self.key(item) for item in identities if item.startswith("inst:")}
                        if not identities or any(item.startswith(("data:", "opaque:", "unresolved:", "unknown:")) for item in identities):
                            owners.update(key for key in self.classes if any(self.members(key, hook) for hook in hooks))
                        for owner in sorted(owners):
                            for hook in hooks:
                                for _site, value, scope in self.members(owner, hook):
                                    for method in sorted(self.refs(value, scope)):
                                        if not self.callable(method):
                                            continue
                                        members = self.read_attribute(method, "inst:" + owner)
                                        function = ast.copy_location(ast.Name(id="_native_protocol", ctx=ast.Load()), node)
                                        function._inventory_refs = frozenset(members)
                                        arguments = [call.args[index] for index in self.NATIVE_ARGUMENTS.get(self.key(ref), ()) if index < len(call.args)]
                                        if self.key(ref) == "format" and not arguments:
                                            arguments = [ast.copy_location(ast.Constant(""), node)]
                                        arguments = list(self._protocol_arguments.setdefault((node, ("native", method, owner)), tuple(arguments)))
                                        projected = ast.copy_location(ast.Call(func=function, args=arguments, keywords=[]), node)
                                        projected._inventory_file = getattr(node, "_inventory_file", "inventory.py")
                                        projected._inventory_unknown_layout = hook in {"__getitem__", "__eq__", "__lt__", "__gt__", "__add__", "__radd__", "__pow__", "__rpow__", "__divmod__", "__rdivmod__"}
                                        native_records.extend(project(projected))
                if ref == "ext:json.loads":
                    for item in call.keywords:
                        if item.arg in ("object_pairs_hook", "parse_constant"):
                            specifications.extend(_Invocation(key, self.unknown_environment(key, node, context)) for key in sorted(self._capability_callables(self.refs(item.value, context))))
        registered = []
        if call is not None:
            for consumer in sorted(refs & self.REGISTERED_CONSUMERS.keys()):
                uncertain = True
                position, keyword, args_position, kwargs_position = self.REGISTERED_CONSUMERS[consumer]
                options = {item.arg: item.value for item in call.keywords if item.arg is not None}
                callback = options.get(keyword, call.args[position] if len(call.args) > position else None)
                if callback is None:
                    continue
                if args_position is None:
                    arguments, keywords = call.args[position + 1:], call.keywords
                else:
                    arguments = options.get("args", call.args[args_position] if len(call.args) > args_position else ast.Tuple(elts=[], ctx=ast.Load()))
                    kwargs = options.get("kwargs", call.args[kwargs_position] if len(call.args) > kwargs_position else ast.Dict(keys=[], values=[]))
                    if isinstance(kwargs, ast.Constant) and kwargs.value is None:
                        kwargs = ast.Dict(keys=[], values=[])
                    arguments, keywords = [ast.Starred(value=arguments, ctx=ast.Load())], [ast.keyword(arg=None, value=kwargs)]
                projected = ast.copy_location(ast.Call(func=callback, args=arguments, keywords=keywords), node)
                projected._inventory_file = getattr(node, "_inventory_file", "inventory.py")
                registered.extend(project(projected))
        protocol_records = list(native_records)
        # Every implicit call comes from the closed table; no dunder is selected
        # by a domain walker. Unknown operands retain source-wide hook candidates.
        for protocol, (handling, kinds, hooks) in self.CALL_PROTOCOLS.items():
            if not isinstance(node, kinds) or protocol in ("explicit", "registration", "defaults", "suspension"):
                continue
            operands = []
            if protocol == "attribute_hook":
                hooks = ("__setattr__",) if isinstance(node.ctx, ast.Store) else ("__delattr__",) if isinstance(node.ctx, ast.Del) else ("__getattribute__", "__getattr__")
            elif protocol == "descriptor":
                hooks = ("__set__",) if isinstance(node.ctx, ast.Store) else ("__delete__",) if isinstance(node.ctx, ast.Del) else ("__get__",)
            elif protocol == "iteration" and isinstance(node, ast.Subscript):
                hooks = ("__setitem__",) if isinstance(node.ctx, ast.Store) else ("__delitem__",) if isinstance(node.ctx, ast.Del) else ("__getitem__",)
            if protocol == "decorator":
                for index, decorator in enumerate(reversed(node.decorator_list)):
                    argument = self._protocol_arguments.setdefault(
                        (node, ("decorator", index)), (ast.copy_location(ast.Name(id="_definition", ctx=ast.Load()), node),))[0]
                    argument._inventory_refs = frozenset({("class:" if isinstance(node, ast.ClassDef) else "rawfn:") + self.definition_keys[node]})
                    projected = ast.copy_location(ast.Call(func=decorator, args=[argument], keywords=[]), node)
                    projected._inventory_file = getattr(node, "_inventory_file", "inventory.py")
                    protocol_records.extend(project(projected))
                continue
            if protocol in ("comparison", "containment"):
                identity = all(isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops)
                contains = any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops)
                if identity or contains != (protocol == "containment"):
                    continue
                operands = [node.left, *node.comparators]
            elif protocol == "bool":
                operands = node.values if isinstance(node, ast.BoolOp) else node.ifs if isinstance(node, ast.comprehension) else [node.test]
            elif protocol == "iteration":
                operands = [node.value if isinstance(node, (ast.Subscript, ast.YieldFrom)) else node.iter]
            elif protocol == "context_manager":
                operands = [item.context_expr for item in node.items]
            elif protocol in ("descriptor", "attribute_hook"):
                operands = [node.value]
                if protocol == "descriptor":
                    descriptor_refs = set()
                    for receiver in self.refs(node.value, context):
                        if receiver.startswith(("inst:", "class:")):
                            for _site, value, owner in self.members(self.key(receiver), node.attr):
                                members = self.refs(value, owner)
                                descriptor_refs.update(members)
                                for member in members:
                                    fn = self.functions.get(self.key(member))
                                    if fn is not None and any(self.refs(d, self.scope[fn]) == {"builtin:property"} for d in fn.decorator_list):
                                        protocol_records.append(_Invocation(self.key(member), self.unknown_environment(self.key(member), node, context)))
                    operands = []
                    hook_refs = descriptor_refs
            elif protocol == "operator":
                operands = [item for item in ast.iter_child_nodes(node) if isinstance(item, ast.expr)]
            hook_refs = hook_refs if protocol == "descriptor" else set().union(*(self.refs(item, context) for item in operands)) if operands else set()
            if any(ref.startswith("unknown:") for ref in hook_refs):
                unknown_target = True
            found = []
            unknown_receiver = any(ref.startswith(("data:", "opaque:", "unresolved:", "unknown:")) for ref in hook_refs)
            owners = {self.key(ref) for ref in hook_refs if ref.startswith(("inst:", "class:", "mod:"))}
            if unknown_receiver:
                owners.update(key for key in self.classes if any(self.members(key, hook) for hook in hooks))
            for owner in sorted(owners):
                for hook in hooks:
                    for _site, value, scope in self.members(owner, hook):
                        for method in self.refs(value, scope):
                            found.extend(self.read_attribute(method, "mod:" + owner if owner in self.trees else "inst:" + owner,
                                                             form="namespace" if owner in self.trees else "descriptor"))
            for member in sorted(set(found)):
                if self.key(member) not in self.functions:
                    unknown_target = True
                    continue
                function = ast.copy_location(ast.Name(id="_protocol", ctx=ast.Load()), node)
                function._inventory_refs = frozenset({member})
                hook = self.functions[self.key(member)].name
                zero = {"__bool__", "__len__", "__iter__", "__next__", "__aiter__", "__anext__", "__enter__", "__aenter__", "__neg__", "__pos__", "__abs__", "__invert__", "__int__", "__float__", "__index__", "__hash__", "__repr__", "__str__", "__bytes__"}
                arguments, unknown_layout = [], False
                if hook in zero:
                    pass
                elif protocol == "attribute_hook" and hook in ("__getattr__", "__getattribute__", "__delattr__"):
                    arguments = [ast.copy_location(ast.Constant(node.attr), node)]
                elif protocol == "iteration" and isinstance(node, ast.Subscript) and hook == "__getitem__":
                    arguments = [node.slice]
                elif protocol in ("comparison", "containment"):
                    receiver = member.partition("|")[2]
                    positions = [index for index, operand in enumerate(operands)
                                 if receiver in self.refs(operand, context)]
                    # The whole chain is not one binary invocation. Until its
                    # per-operator environment is proven, no operand is guessed.
                    if len(operands) == 2 and len(positions) == 1 and (
                            protocol != "containment" or positions[0] == 1):
                        arguments = [operands[1 - positions[0]]]
                    else:
                        unknown_layout = True
                elif protocol == "operator" and len(operands) > 1:
                    arguments = [operands[0] if hook.startswith("__r") else operands[-1]]
                elif hook in ("__set__", "__setattr__", "__setitem__"):
                    parent = self.parent.get(node)
                    assigned = parent.value if isinstance(parent, (ast.Assign, ast.AnnAssign)) else None
                    first = node.value if hook == "__set__" else ast.copy_location(ast.Constant(node.attr), node) if isinstance(node, ast.Attribute) else node.slice
                    if assigned is None:
                        unknown_layout = True
                    else:
                        arguments = [first, assigned]
                elif protocol == "descriptor" and hook == "__delete__":
                    arguments = [node.value]
                elif protocol == "descriptor" and hook == "__get__":
                    arguments = [node.value]
                    owner = ast.copy_location(ast.Name(id="_descriptor_owner", ctx=ast.Load()), node)
                    owner._inventory_refs = frozenset("class:" + self.key(ref) for ref in self.refs(node.value, context) if ref.startswith(("inst:", "class:")))
                    arguments.append(owner)
                else:
                    unknown_layout = True
                saved = self._protocol_arguments.setdefault((node, member), tuple(arguments))
                for old, new in zip(saved, arguments):
                    if hasattr(new, "_inventory_refs") and hasattr(old, "_inventory_refs"):
                        joined = old._inventory_refs | new._inventory_refs
                        self._protocol_changed |= joined != old._inventory_refs
                        old._inventory_refs = joined
                arguments = list(saved)
                projected = ast.copy_location(ast.Call(func=function, args=arguments, keywords=[]), node)
                projected._inventory_unknown_layout = unknown_layout
                projected._inventory_file = getattr(node, "_inventory_file", "inventory.py")
                protocol_records.extend(project(projected))
            if found:
                protocol_records.extend(_Invocation(key, self.unknown_environment(key, node, context)) for key in sorted(self._capability_callables(hook_refs)))
        # Protocol results may be consumed by another implicit step (for
        # example __iter__ returning a different iterator). Retain every
        # capability returned by a hook instead of treating the producer's
        # declared class as proof of the result's identity.
        for record in tuple(protocol_records):
            function = self.functions.get(record.target)
            if function is not None:
                returned = set().union(*(self.refs(item.value, record.target) for item in _owned_nodes(function)
                                         if isinstance(item, (ast.Return, ast.Yield))))
                protocol_records.extend(_Invocation(key, self.unknown_environment(key, node, context)) for key in sorted(self._capability_callables(returned)))
        if protocol_records:
            uncertain = True
        specifications.extend(protocol_records)
        if unknown_target:
            specifications.append(_Invocation(UNKNOWN_CALL_TARGET))
            uncertain = True
        status = "UNKNOWN" if uncertain else "EXACT"
        callbacks = [record for record in (*registered, *protocol_records) if record.target in self.refusing]
        if unknown_target:
            callbacks.append(_Invocation(UNKNOWN_CALL_TARGET))
        if status == "UNKNOWN" and isinstance(node, (ast.Compare, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            if not isinstance(node, ast.Compare):
                specifications.extend(_Invocation(key, self.unknown_environment(key, node, context)) for key in sorted(self._capability_callables(refs)))
            callbacks.extend(item for item in specifications if item.target in self.refusing)
        if call is not None:
            if refs & {"builtin:isinstance", "builtin:issubclass"} and status == "UNKNOWN":
                callbacks.extend(item for item in specifications if item.target in self.refusing)
            for argument in [*node.args, *(item.value for item in node.keywords)]:
                if native_methods and all(ref in self.native_methods or ref.startswith("native:") for ref in refs):
                    continue  # Stored/read values flow through the receiver projection.
                if refs and refs <= self.MODELLED_WRAPPERS.keys():
                    continue  # Proven native wrappers store their callable; bindings retain it.
                if refs and refs <= self.REGISTERED_CONSUMERS.keys():
                    continue  # The registration contract already transported this argument.
                if refs == {"ext:contextlib.ExitStack.enter_context"} and isinstance(argument, ast.Call):
                    managers = self.resolve(argument, context, invocation=True).invocations
                    if managers and all(record.target in self.functions and
                            any(isinstance(item, (ast.Yield, ast.YieldFrom)) for item in _owned_nodes(self.functions[record.target])) and
                            any(self.resolve(decorator, self.scope[self.functions[record.target]]).status == "EXACT" and
                                self.resolve(decorator, self.scope[self.functions[record.target]]).candidates == {"ext:contextlib.contextmanager"}
                                for decorator in self.functions[record.target].decorator_list)
                            for record in managers):
                        continue  # The wrapped generator body is already an ordinary invocation edge.
                argument_refs = self.refs(argument, context)
                # These resolved native consumers invoke only the hooks already
                # projected above, never an arbitrary callback held by an operand.
                native_operands = {"builtin:" + name for name in self.BUILTIN_PROTOCOLS
                                   if name not in ("sorted", "min", "max", "iter")}
                if refs - {"unresolved:"} and refs - {"unresolved:"} <= native_operands:
                    continue
                if refs == {"ext:dataclasses.dataclass"} and all(
                        ref.startswith("class:") and self.key(ref) in self.generated_fields for ref in argument_refs):
                    continue
                # A carrier transported to a modeled parameter is followed at
                # the consumer's concrete member invocations, not invoked as
                # though the namespace itself were an arbitrary callback.
                if not self._actual_callable(argument_refs) and specifications and all(
                        (record.target in self.functions or record.target in self.generated_fields) and
                        any(value is argument for _name, value, _owner in record.arguments)
                        for record in specifications):
                    continue
                argument_callbacks = self._capability_callables(argument_refs)
                if not argument_callbacks:
                    continue
                consumers = [record for record in specifications if record.target in self.functions]
                if consumers and all(self.callable(ref) for ref in refs) and len(consumers) == len(specifications):
                    parameters = [[name for name, value, _owner in record.arguments if value is argument]
                                  for record in consumers]
                    if all(parameters) and all(not any(isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
                            and item.id in names for item in _owned_nodes(self.functions[record.target]))
                            for record, names in zip(consumers, parameters)):
                        continue  # Every possible in-repo consumer proves this argument unused.
                # Identity-only introspection never invokes its operand.
                if refs <= {"builtin:callable", "builtin:type", "builtin:isinstance", "builtin:issubclass"} and status == "EXACT":
                    continue
                for callback in sorted(argument_callbacks):
                    if callback in ("format.require", "format.CodecError", "_builtin.ValueError"):
                        unpacked = isinstance(argument, ast.Starred) or any(
                            item.arg is None and item.value is argument for item in call.keywords)
                        transported = specifications and all(
                            record.target in self.functions or record.target in self.generated_fields for record in specifications)
                        if unpacked and positional is not None and keywords is not None and transported and not any(
                                ref.startswith(("ext:", "builtin:", "opaque:")) for ref in refs):
                            continue  # The concrete projected arguments are already binding edges.
                        modeled_consumers = specifications and all(
                            (record.target in self.functions or record.target in self.generated_fields) and
                            any(value is argument or any(source is argument or isinstance(argument, ast.Starred) and source is argument.value
                                                        for source, _scope in getattr(value, "_inventory_values", ()))
                                for _name, value, _owner in record.arguments)
                            for record in specifications) and not any(
                                ref.startswith(("ext:", "builtin:", "opaque:")) for ref in refs)
                        identity_query = refs <= {"builtin:callable", "builtin:type", "builtin:isinstance", "builtin:issubclass"}
                        if modeled_consumers or identity_query:
                            continue  # Concrete in-repo calls already transport the arguments.
                    callbacks.append(_Invocation(callback, self.unknown_environment(callback, node, context)))
        result = _Resolution(status, frozenset(refs), tuple(dict.fromkeys(specifications)), tuple(dict.fromkeys(callbacks)),
                             tuple(dict.fromkeys([*specifications, *registered])),
                             tuple(dict.fromkeys(literal_bindings)))
        for record in (*result.invocations, *result.callbacks):
            if record.target == UNKNOWN_CALL_TARGET:
                continue
            self.known_contributors.setdefault(record.target, (
                getattr(node, "_inventory_file", self.MODULES.get(context.split(".")[0], ("inventory.py", ""))[0]),
                getattr(node, "lineno", 1)))
        self._resolution_cache[marker] = result
        return result

    def invocations(self, call, context):
        resolution = self.resolve(call, context, invocation=True)
        return {"fn:" + item.target for item in (*resolution.invocations, *resolution.callbacks)}

    def _refs(self, node, context, seen):
        if hasattr(node, "_inventory_attribute_source"):
            return self.stored_attribute_refs(node)
        if hasattr(node, "_inventory_refs"):
            return node._inventory_refs
        if hasattr(node, "_inventory_symbol"):
            return {"fn:" + node._inventory_symbol}
        if isinstance(node, ast.Constant):
            # Literal builtins have no user descriptor protocol. Keep this
            # proof separate from data:, whose stored kind is unproved.
            return {"native:" + type(node.value).__name__}
        if isinstance(node, ast.Name):
            result = set().union(*(self.read_attribute(ref, context, form="namespace")
                                   for value, owner in self.bindings(node.id, context, node)
                                   for ref in self.refs(value, owner, seen)))
            # These are the already-validated adapter interfaces summarized by
            # the inventory, not arbitrary CLI or ROOT connection objects.
            interfaces = {"connection": "inst:mcp.Connection", "mailbox": "inst:mailbox.Mailbox",
                          "codec": "mod:codec", "store": "inst:store.Store",
                          "access": "inst:records._RecordAccess", "_access": "inst:records._RecordAccess"}
            if (node.id in self.parameters.get(context, ()) and node.id in interfaces
                    and not self.binding_is_unknown(node.id, context)
                    and context.split(".")[0] in ("records", "guidance")
                    and not any(self.callable(ref) or ref.startswith(("inst:", "mod:", "ext:")) for ref in result)):
                return {interfaces[node.id]}
            return result
        if isinstance(node, ast.Lambda):
            key = self.locations[(context.split(".")[0], node.lineno, node.col_offset,
                                  "_inventory_lambda_" + context.split(".")[0] + "_" + str(node.lineno) + "_" + str(node.col_offset))]
            return {"fn:" + key}
        if isinstance(node, ast.Attribute):
            base = self.refs(node.value, context, seen)
            result = set()
            if node.attr in self.CONTAINER_STORES | self.CONTAINER_READS and (
                    any(ref.startswith("native:") and "." not in self.key(ref) for ref in base)
                    or self._opaque_receiver(node.value, context, seen)
                    or "unresolved:" in base
                    or node.attr == "fromkeys" and base == {"builtin:dict"}):
                token = "container:" + context + ":" + str(node.lineno) + ":" + str(node.col_offset) + ":" + node.attr
                self.native_methods[token] = (node.value, context, node.attr)
                result.update(self.read_attribute(token, context, form="namespace"))
            for ref in sorted(base):
                key = self.key(ref)
                if ref.startswith("mod:"):
                    result.update(self._global(key, node.attr, seen))
                elif ref.startswith(("inst:", "class:")):
                    for event in self.inherited_fields(key, node.attr) if ref.startswith("inst:") else ():
                        result.update(self.field_refs(node, context, event, ref))
                    for _site, value, owner in self.members(key, node.attr):
                        for member in self.refs(value, owner, seen):
                            result.update(self.read_attribute(member, ref))
                elif ref.startswith("super:"):
                    receiver = ref.partition("|")[2]
                    members, uncertain = self.super_members(key, receiver, node.attr)
                    for _site, value, owner in members:
                        for member in self.refs(value, owner, seen):
                            result.update(self.read_attribute(member, receiver))
                    if uncertain:
                        result.add("unknown:" + context.split(".")[0])
                elif self.callable(ref) and node.attr == "__func__":
                    result.update(self.read_attribute("rawfn:" + key, ref, form="namespace"))
                elif self.callable(ref) and node.attr == "__code__":
                    result.update(self.read_attribute("code:" + key, ref, form="namespace"))
                elif ref.startswith(("ext:", "extdata:")):
                    member = key + "." + node.attr
                    module = self.module(member)
                    if key == "builtins" and node.attr in self.BUILTINS:
                        result.update(self.read_attribute("builtin:" + node.attr, ref, form="namespace"))
                    else:
                        result.update(self.read_attribute("mod:" + module if module else "ext:" + member, ref,
                                                          form="namespace"))
                elif ref.startswith("native:"):
                    result.update(self.read_attribute(ref + "." + node.attr, ref, form="namespace"))
            if result and (all(ref.startswith(("mod:", "inst:", "class:", "extdata:")) or
                               ref.startswith("ext:") and self.key(ref).split(".")[0] in self.EXTERNAL_DATA for ref in base) or
                           all(ref.startswith("builtin:") for ref in result)):
                return result
            if self._opaque_receiver(node.value, context, seen):
                # Tail candidates include the class's final binding, so an
                # annotated alias contributes the same identity as a method.
                found = set()
                for candidate in sorted(self.tail.get(node.attr, ())):
                    for event in self.fields.get((candidate, node.attr), ()):
                        found.update(self.field_refs(node, context, event, "inst:" + candidate))
                    for _site, value, owner in self.members(candidate, node.attr):
                        for member in self.refs(value, owner, seen):
                            found.update(self.read_attribute(member, "inst:" + candidate,
                                                            form="descriptor" if candidate in self.classes else "namespace"))
                return result | found or {"data:"}
            return result or {"data:"}
        if isinstance(node, ast.Call):
            targets = self.refs(node.func, context, seen)
            if (isinstance(node.func, ast.Attribute) and self._opaque_receiver(node.func.value, context, seen)
                    and not any(ref in self.native_methods for ref in targets)):
                return {"opaque:"}
            result = set()
            for ref in sorted(targets):
                key = self.key(ref)
                if ref in self.native_methods:
                    receiver, owner, method = self.native_methods[ref]
                    if method in self.CONTAINER_READS or method == "setdefault":
                        result.update(self.refs(receiver, owner, seen))
                        for value, scope in self.storage_values(receiver, owner, container=True):
                            result.update(self.refs(value, scope, seen))
                        result.update(set().union(*(self.refs(value, context, seen) for value in
                                                    [*node.args, *(item.value for item in node.keywords)])))
                    else:
                        result.add("data:")
                elif ref.startswith("class:"):
                    result.add("inst:" + key)
                    if key in self.classes and (self.classes[key].decorator_list or self.members(key, "__new__") or any(
                            not meta.startswith(("class:", "builtin:")) or self.members(self.key(meta), "__call__")
                            for meta in self.metaclasses(key))):
                        result.add("opaque:")
                elif ref.startswith("ext:") and key.split(".")[0] in self.EXTERNAL_DATA:
                    if ref == "ext:json.loads":
                        result.update({"native:dict", "native:list", "native:str", "data:"})
                        for keyword in node.keywords:
                            if keyword.arg is None:
                                result.add("opaque:")
                            if keyword.arg is None or keyword.arg in self.CALLBACK_KEYWORDS[ref]:
                                for callback in self.refs(keyword.value, context, seen):
                                    functions = [self.key(callback)] if self.key(callback) in self.functions else []
                                    if callback.startswith(("class:", "inst:")):
                                        methods = ("decode",) if keyword.arg == "cls" else ("__call__",)
                                        functions.extend(self.key(member) for method in methods
                                                         for _site, value, owner in self.members(self.key(callback), method)
                                                         for stored in self.refs(value, owner, seen)
                                                         for member in self.read_attribute(stored, "inst:" + self.key(callback))
                                                         if self.key(member) in self.functions)
                                    for target in functions:
                                        result.update(set().union(*(self.refs(item.value, target, seen)
                                                                   for item in _owned_nodes(self.functions[target])
                                                                   if isinstance(item, ast.Return))))
                        continue
                    if ref == "ext:dataclasses.dataclass" and not node.args:
                        result.add(ref)
                        continue
                    if ref in ("ext:contextlib.ExitStack", "ext:re.compile"):
                        result.add("extdata:" + key)
                        continue
                    if ref in ("ext:copy.deepcopy", "ext:importlib.import_module", "ext:types.FunctionType",
                               "ext:contextlib.ExitStack.enter_context"):
                        pass
                    else:
                        result.add("data:")
                        continue
                if ref in self.MODELLED_WRAPPERS and node.args:
                    prefix = self.MODELLED_WRAPPERS[ref]
                    wrapped = self.refs(node.args[0], context, seen)
                    result.update(prefix + self.key(item) if item.startswith(("fn:", "rawfn:")) else item
                                  for item in wrapped)
                    if not wrapped or any(not item.startswith(("fn:", "rawfn:")) for item in wrapped):
                        result.add("unknown:" + context.split(".")[0])
                elif ref == "ext:copy.deepcopy" and node.args:
                    result.update(self.refs(node.args[0], context, seen))
                elif ref == "ext:importlib.import_module" and node.args and isinstance(node.args[0], ast.Constant):
                    module = self.module(node.args[0].value)
                    if module:
                        result.add("mod:" + module)
                elif ref == "ext:types.FunctionType" and len(node.args) >= 2:
                    for code in self.refs(node.args[0], context, seen):
                        if code.startswith("code:"):
                            original = self.key(code)
                            result.add("fn:" + original)
                            source = node.args[1]
                            if isinstance(source, ast.Call) and isinstance(source.func, ast.Name) and source.func.id == "dict":
                                for keyword in source.keywords:
                                    if keyword.arg is not None:
                                        self.overrides.setdefault(original, {}).setdefault(keyword.arg, set()).add((keyword.value, context))
                elif ref == "builtin:super":
                    current = {"class:" + self.method_class[context]} if context in self.method_class else set()
                    receivers = set()
                    if not node.args and context in self.functions:
                        function = self.functions[context]
                        positional = [*function.args.posonlyargs, *function.args.args]
                        if positional:
                            receivers.update(self.refs(ast.Name(id=positional[0].arg, ctx=ast.Load()), context, seen))
                    elif len(node.args) == 2 and not node.keywords:
                        current = self.refs(node.args[0], context, seen)
                        receivers = self.refs(node.args[1], context, seen)
                    for start in current:
                        for receiver in receivers:
                            if start.startswith("class:") and receiver.startswith(("inst:", "class:")):
                                result.add("super:" + self.key(start) + "|" + receiver)
                            else:
                                result.add("unknown:" + context.split(".")[0])
                    if not current or not receivers:
                        result.add("unknown:" + context.split(".")[0])
                elif ref in {"builtin:" + kind for kind in ("list", "dict", "tuple", "set", "frozenset", "str", "bytes")}:
                    result.add("native:" + key)
                    if key in ("list", "dict", "tuple", "set", "frozenset"):
                        result.update(set().union(*(self.refs(value, context, seen) for value in
                                                    [*node.args, *(keyword.value for keyword in node.keywords)])))
                elif ref in ("builtin:sorted", "builtin:min", "builtin:max"):
                    result.update(set().union(*(self.refs(value, context, seen) for value in node.args)))
                    result.update(set().union(*(self.refs(item.value, context, seen) for item in node.keywords if item.arg == "default")))
                elif ref in ("builtin:iter", "builtin:next") and node.args:
                    result.update(self.refs(node.args[0], context, seen))
                elif ref == "ext:contextlib.ExitStack.enter_context" and node.args:
                    result.update(self.refs(node.args[0], context, seen))
                elif ref == "builtin:getattr" and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                    attribute = ast.copy_location(ast.Attribute(value=node.args[0], attr=node.args[1].value, ctx=ast.Load()), node)
                    members = self.refs(attribute, context, seen)
                    result.update(members)
                    if self._opaque_receiver(node.args[0], context, seen):
                        result.add("opaque:")
                elif ref.startswith("ext:_external.") and key.rsplit(".", 1)[-1] not in self.DATA_BUILTINS:
                    result.add("opaque:")
                elif ref.startswith("ext:") and key.split(".")[0] not in self.EXTERNAL_DATA:
                    result.add("opaque:")
                elif key in self.functions:
                    fn = self.functions[key]
                    for statement in _owned_nodes(fn):
                        if isinstance(statement, (ast.Return, ast.Yield)):
                            result.update(self.refs(statement.value, key, seen))
            returned = set()
            for identity in targets:
                if not identity.startswith("class:"):
                    continue
                key = self.key(identity)
                returned.update(self.key(ref) for _site, value, owner in self.members(key, "__new__")
                                for stored in self.refs(value, owner, seen)
                                for ref in self.read_attribute(stored, "class:" + key) if self.key(ref) in self.functions)
                metas = self.metaclasses(key)
                owners = {self.key(meta) for meta in metas if meta.startswith("class:")}
                if any(not meta.startswith(("class:", "builtin:")) for meta in metas):
                    owners.update(self.classes)
                returned.update(self.key(ref) for owner in owners for _site, value, scope in self.members(owner, "__call__")
                                for stored in self.refs(value, scope, seen)
                                for ref in self.read_attribute(stored, identity, form="metaclass") if self.key(ref) in self.functions)
            for target in sorted(returned):
                result.update(set().union(*(self.refs(item.value, target, seen)
                                            for item in _owned_nodes(self.functions[target]) if isinstance(item, (ast.Return, ast.Yield)))))
            return result or {"data:"}
        if isinstance(node, (ast.Compare, ast.BinOp, ast.UnaryOp, ast.JoinedStr, ast.FormattedValue)):
            # Identity comparison returns a bool and cannot dispatch user code.
            # Its operands still pass the same occurrence gate individually.
            return {"data:"}
        if isinstance(node, ast.IfExp):
            return self.refs(node.body, context, seen) | self.refs(node.orelse, context, seen)
        if isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Constant) and type(node.slice.value) is int:
                return self._project_refs(node.value, node.slice.value, context, seen)
            if "opaque:" in self.refs(node.value, context, seen):
                return {"opaque:"}
        if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            kind = {ast.List: "list", ast.Tuple: "tuple", ast.Set: "set", ast.Dict: "dict"}[type(node)]
            return {"native:" + kind} | set().union(*(self.refs(child, context, seen) for child in ast.iter_child_nodes(node)
                                                      if isinstance(child, ast.expr)))
        # Containers retain their member references. Unknown expressions retain
        # operands so the escape gate can refuse a capable value flowing in.
        return set().union(*(self.refs(child, context, seen) for child in ast.iter_child_nodes(node)
                             if isinstance(child, ast.expr))) | {"data:"}

    def _project_refs(self, value, index, context, seen):
        return self._query("projection", value, context, index)

    def _collect_project_refs(self, value, index, context, seen):
        marker = ("projection", value, index, context)
        seen = seen | {marker}
        if isinstance(value, (ast.Tuple, ast.List)):
            return self.refs(value.elts[index], context, seen) if -len(value.elts) <= index < len(value.elts) else {"data:"}
        if isinstance(value, ast.Name):
            return set().union(*(self._project_refs(item, index, owner, seen)
                                 for item, owner in self.bindings(value.id, context, value))) or {"data:"}
        if isinstance(value, ast.Call):
            if self.refs(value.func, context, seen) == {"ext:contextlib.ExitStack.enter_context"} and value.args:
                return self._project_refs(value.args[0], index, context, seen)
            result = set()
            for ref in self.refs(value.func, context, seen):
                key = self.key(ref)
                if key in self.functions:
                    for statement in _owned_nodes(self.functions[key]):
                        if isinstance(statement, (ast.Return, ast.Yield)) and statement.value is not None:
                            result.update(self._project_refs(statement.value, index, key, seen))
            if result:
                return result
        refs = self.refs(value, context, seen)
        return {"opaque:"} if "opaque:" in refs else set(refs) or {"data:"}

    def literal_values(self, node, context, seen=None):
        return self._query("literals", node, context)

    def _collect_literal_values(self, node, context, seen=None):
        if isinstance(node, ast.Constant) and (node.value is None or type(node.value) is str):
            return {node.value}
        root = seen is None
        seen = set() if seen is None else seen
        marker = (id(node), context)
        if marker in seen:
            return set()
        seen = seen | {marker}
        if getattr(node, "_inventory_values_unknown", False):
            return None
        if hasattr(node, "_inventory_attribute_source") and any(ref.startswith("unknown:") for ref in self.refs(node, context)):
            return None
        if hasattr(node, "_inventory_values"):
            values = [self.literal_values(value, owner, seen) for value, owner in node._inventory_values]
        elif isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
            resolution = self.resolve(node, context)
            if any(ref.startswith("unknown:") for ref in resolution.candidates):
                return None
            values = [self.literal_values(value, owner, seen) if not isinstance(value, str) else None
                      for value, owner in resolution.values]
        elif isinstance(node, ast.IfExp):
            values = [self.literal_values(node.body, context, seen), self.literal_values(node.orelse, context, seen)]
        else:
            return None
        result = set().union(*values) if values and all(value is not None for value in values) else None
        return result if result or not root else None

    def _actual_callable(self, refs):
        return {ref for ref in refs if ref.startswith("unknown:") or self.callable(ref) and self.potential({ref})}

    def _capability_callables(self, refs, seen=None):
        """Expand a carrier to concrete callable definitions, without a site list."""
        cache_key = frozenset(refs)
        if seen is None and cache_key in self._capability_cache:
            return self._capability_cache[cache_key]
        visited, pending = set() if seen is None else set(seen), list(refs)
        result = set()
        while pending:
            ref = pending.pop()
            if ref.startswith("unknown:"):
                result.add(UNKNOWN_CALL_TARGET)
                continue
            if ref in visited or not self.potential({ref}):
                continue
            visited.add(ref)
            key = self.key(ref)
            if self.callable(ref) and (key in self.functions or key == "format.require"):
                result.add(key)
            elif ref.startswith("class:"):
                result.update([key] if key in ("format.CodecError", "_builtin.ValueError") else self.constructors(key))
            values = []
            if self.callable(ref) and key in self.functions:
                values.extend((item.value, key) for item in _owned_nodes(self.functions[key])
                              if isinstance(item, (ast.Return, ast.Yield)))
            if ref.startswith(("class:", "inst:")):
                values.extend((value, owner) for _site, value, owner in self.class_values(key))
            elif ref.startswith("mod:"):
                values = [(value, owner) for (scope, _name), events in self.events.items() if scope == key
                          for _site, value, owner in events]
            for value, owner in values:
                pending.extend(self.refs(value, owner))
        # Primitive emitters are already expanded at their concrete invocation
        # sites, with those sites' code/detail arguments, rather than defaults.
        if seen is None:
            self._capability_cache[cache_key] = result
        return result

    def _opaque_receiver(self, node, context, seen=None):
        refs = self.refs(node, context, seen)
        return not refs or any(ref.startswith(("opaque:", "data:")) or
                               ref.startswith("ext:") and self.key(ref).split(".")[0] not in self.EXTERNAL_DATA
                               for ref in refs)

    ORDINARY_EXPRESSIONS = frozenset({
        ast.Name, ast.Attribute, ast.Constant, ast.Call, ast.Lambda, ast.List, ast.Tuple, ast.Set, ast.Dict,
        ast.Subscript, ast.Slice, ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare, ast.IfExp, ast.NamedExpr,
        ast.JoinedStr, ast.FormattedValue, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
        ast.Starred, ast.Yield, ast.YieldFrom,
    })
    ORDINARY_CONTEXTS = frozenset({
        ast.Module, ast.Expr, ast.Assign, ast.AnnAssign, ast.AugAssign, ast.If, ast.While, ast.For, ast.AsyncFor,
        ast.With, ast.AsyncWith, ast.withitem, ast.Try, ast.ExceptHandler, ast.Return, ast.Raise,
        ast.Assert, ast.Delete, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.arguments,
        ast.arg, ast.keyword, ast.comprehension, ast.Import, ast.ImportFrom,
    })

    def _escape_unknown_ast(self, node, parent, refs):
        return (parent is not None and type(parent) not in self.ORDINARY_EXPRESSIONS
                and type(parent) not in self.ORDINARY_CONTEXTS)

    def audit(self):
        """Every capable occurrence is resolved before either domain traverses it."""
        failures = []
        def related(key, ancestor, seen=None):
            if key == ancestor:
                return True
            seen = set() if seen is None else seen
            if key in seen or key not in self.classes:
                return False
            return any(ref == ancestor or ref.startswith("class:") and related(self.key(ref), ancestor, seen | {key})
                       for base in self.classes[key].bases for ref in self.refs(base, self.scope[self.classes[key]]))
        metas = {key for key in self.classes if related(key, "builtin:type")}
        for (owner, name), events in self.events.items():
            if owner in self.classes and name in ("__init__", "__new__"):
                for site, _value, _scope in events:
                    if not isinstance(site, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        failures.append(self.diagnostic(site))
                    elif name == "__new__" and any(self.refs(item, self.scope[site]) != {"builtin:staticmethod"}
                                                    for item in site.decorator_list):
                        failures.append(self.diagnostic(site))
            if owner in metas:
                for site, value, scope in events:
                    refs = self.refs(value, scope)
                    plain = name in self.META_HOOKS and isinstance(site, (ast.FunctionDef, ast.AsyncFunctionDef)) and not site.decorator_list
                    if not plain and (any(self.callable(ref) for ref in refs) or self.potential(refs)):
                        failures.append(self.diagnostic(site))
        sites = set(self.invocation_sites)
        for tree in self.trees.values():
            for node in sorted(ast.walk(tree), key=lambda item: (getattr(item, "lineno", 0), getattr(item, "col_offset", 0))):
                context = self.scope.get(node)
                if context is None:
                    continue
                if context.split(".")[0] in ("mailbox", "mcp", "pager") and context not in self.active:
                    continue
                stores = [child for child in ast.iter_child_nodes(node)
                          if isinstance(child, ast.expr) and isinstance(getattr(child, "ctx", None), ast.Store)]
                if stores and isinstance(node, (ast.stmt, ast.NamedExpr, ast.comprehension)) and not isinstance(node, self.MODELLED_STORES):
                    self._widen(("binding", node, context, None), "unmodelled_store")
                    return
                if isinstance(node, ast.ClassDef):
                    for keyword in node.keywords:
                        if keyword.arg != "metaclass":
                            continue
                        values = self.refs(keyword.value, context)
                        if values == {"builtin:type"}:
                            continue
                        hints = {self.key(ref) for part in ast.walk(keyword.value) if isinstance(part, ast.expr)
                                 for ref in self.refs(part, context) if ref.startswith("class:")}
                        if (not hints or not hints <= metas or any(self.callable(ref) and not ref.startswith("class:") for ref in values)
                                or any(meta != "builtin:type" for hint in hints for meta in self.metaclasses(hint))):
                            failures.append(self.diagnostic(node))
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    known = {hook for _mode, _kinds, hooks in self.CALL_PROTOCOLS.values() for hook in hooks}
                    known.update(hook for hooks in self.BUILTIN_PROTOCOLS.values() for hook in hooks)
                    key = self.definition_keys[node]
                    if node.name.startswith("__") and node.name.endswith("__") and node.name not in known and key in self.refusing:
                        failures.append(self.diagnostic(node, "FunctionDef"))
                if not isinstance(node, (ast.expr, *{kind for _mode, kinds, _hooks in self.CALL_PROTOCOLS.values() for kind in kinds})):
                    continue
                if hasattr(node, "ctx") and not isinstance(node.ctx, ast.Load) and not isinstance(node, (ast.Attribute, ast.Subscript)):
                    continue
                resolution = self.resolve(node, context, invocation=node in sites)
                if self.widened:
                    return
                native_storage = any(ref.startswith("native:") and ref.rsplit(".", 1)[-1] in self.NATIVE_STORAGE_METHODS
                                     for ref in resolution.candidates)
                if any(ref in self.native_methods for ref in resolution.candidates):
                    native_storage = False
                attribute = node.func if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) else node
                if isinstance(attribute, ast.Attribute) and attribute.attr in self.CONTAINER_STORES | self.CONTAINER_READS:
                    roots = self._storage_roots(attribute.value, context)
                    proven_container = bool(roots) and all(isinstance(root, tuple) and isinstance(
                        root[0], (ast.List, ast.Tuple, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)) for root in roots)
                    opaque = self._opaque_receiver(attribute.value, context) or "unresolved:" in self.refs(attribute.value, context)
                    if not proven_container and opaque and any(self.potential(self.refs(value, owner))
                            for candidate in self.tail.get(attribute.attr, ())
                            for _site, value, owner in [*self.members(candidate, attribute.attr),
                                                        *self.fields.get((candidate, attribute.attr), ())]):
                        parent_call = self.parent.get(node)
                        if isinstance(node, ast.Call) or not isinstance(parent_call, ast.Call) or parent_call.func is not node:
                            failures.append(self.diagnostic(node))
                if isinstance(node, ast.Attribute) and native_storage and self.potential(self.refs(node.value, context)):
                    failures.append(self.diagnostic(node))
                if isinstance(node, ast.Call) and native_storage and any(
                        self.potential(self.refs(value, context)) for value in [*node.args, *(item.value for item in node.keywords)]):
                    failures.append(self.diagnostic(node))
                if (isinstance(node, ast.Call) and "builtin:type" in resolution.candidates
                        and (len(node.args) != 1 or node.keywords)):
                    failures.append(self.diagnostic(node))
                parent = self.parent.get(node)
                for handling, kinds, _hooks in self.CALL_PROTOCOLS.values():
                    if handling == "ESCAPE-GATED" and isinstance(node, kinds) and any(self.potential(self.refs(child, context)) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)):
                        failures.append(self.diagnostic(node))
                if self.potential(resolution.candidates) and self._escape_unknown_ast(node, parent, resolution.candidates):
                    failures.append(self.diagnostic(node, type(parent).__name__))
                invocations = [*resolution.callbacks]
                if context not in self.functions and node in sites:
                    invocations.extend(record for record in resolution.invocations if record.target in self.refusing)
                if invocations:
                    site = self.callback_sites.setdefault((context, node.lineno, node.col_offset),
                                                          {"call": node, "targets": set(), "invocations": set()})
                    site["invocations"].update(invocations)
                    site["targets"].update(item.target for item in invocations)
        if failures:
            raise RefusalInventoryError(failures)


class _CallableAliases:
    """A domain view of the shared, audited callable model."""

    def __init__(self, functions, modules, model=None, canonical_names=False):
        self.functions = functions
        self.model = model or _CallableModel({(_CallableModel.module(name) or name): ast.unparse(tree)
                                             for name, tree in modules.items()})
        for name, tree in modules.items():
            tag = _CallableModel.module(name) or name
            for node in ast.walk(tree):
                node._inventory_file = _CallableModel.MODULES.get(tag, ("inventory.py", ""))[0]
        tags = {_CallableModel.module(name) or name: name for name in modules}
        self.canonical, self.local = {}, {}
        functions.clear()
        for canonical, node in self.model.functions.items():
            tag = canonical.split(".")[0]
            if tag not in tags:
                continue
            key = canonical if canonical_names or tag != "records" else canonical.partition(".")[2]
            functions[key] = node
            self.canonical[key] = canonical
            self.local[canonical] = key
        self.refusing = {key for key, canonical in self.canonical.items() if canonical in self.model.refusing}

    def _context(self, owner):
        return self.canonical.get(owner, owner)

    def references(self, node, owner, *, invocation=False):
        resolution = self.model.resolve(node, self._context(owner), invocation=invocation)
        result = []
        for invocation_record in resolution.invocations:
            target = invocation_record.target
            reference = ast.copy_location(ast.Name(id=self.local.get(target, target), ctx=ast.Load()), node)
            reference._inventory_symbol = target
            reference._inventory_invocation = invocation_record
            result.append(reference)
        return result

    def callees(self, call, owner):
        return self.references(call, owner, invocation=True)

    def callbacks(self, call, owner):
        site = self.model.callback_sites.get((self._context(owner), getattr(call, "lineno", 0), getattr(call, "col_offset", 0)))
        if site is None:
            return []
        return [(item.target, self.model.callback_summaries[item], getattr(site["call"], "_inventory_file", "inventory.py"), call.lineno)
                for item in sorted(site["invocations"], key=lambda value: value.sort_key())]

    def literal_values(self, node, owner):
        return self.model.literal_values(node, self._context(owner))

    @staticmethod
    def unsupported(node):
        _CallableModel.unsupported(node)


def _callable_sources(adapter, codec):
    sources = {key: (_REPO / path).read_text(encoding="utf-8")
               for key, (path, _module) in _CallableModel.MODULES.items()}
    if adapter is not None:
        if isinstance(adapter, dict):
            sources.update((_CallableModel.module(name) or name, text) for name, text in adapter.items())
        else:
            sources.update((name, source) for name, source in
                           (("records" if index == 0 else "guidance" if index == 1 else "source_" + str(index), source)
                            for index, source in enumerate(adapter)))
    if codec is not None:
        sources.update(codec)
    return sources


def codec_refusal_pairs(local_functions, local_edges, roots, sources=None, trace=None, local_aliases=None, model=None,
                        callback_roots=None, callback_trace=None):
    """Follow actual codec imports, method calls and the closed read context.

    Constant public options prune unavailable CLI/span/cursor/format branches.
    Store paths and full IDs have already passed the adapter's lexical/grant
    gates; their validated shapes, rather than arbitrary Store API inputs, enter
    this graph. Other storage branches (including concurrent mode/IO failures)
    remain live. No refusal-code/detail allowlist is used.
    """
    module_names = {"codec": "aegis_core.message_codec", "format": "aegis_core.message_codec_format",
                    "store": "aegis_core.message_codec_store", "views": "aegis_core.message_codec_views"}
    if model is not None:
        sources = model.sources
    if model is not None:
        module_names = {key: module for key, (_path, module) in _CallableModel.MODULES.items()}
    if sources is None:
        sources = {name: (_REPO / "aegis_core" / (module.rsplit(".", 1)[-1] + ".py")).read_text(encoding="utf-8")
                   for name, module in module_names.items()}
    functions, imports, constants, patterns, external_names, modules = {}, {}, {}, {}, {}, {}
    for namespace, source in sources.items():
        tree = model.trees[namespace] if model is not None else ast.parse(source)
        modules[namespace] = tree
        imports[namespace] = {}
        constants[namespace], patterns[namespace], external_names[namespace] = {}, {}, set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                external_names[namespace].update(alias.asname or alias.name.split(".")[0] for alias in node.names)
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if isinstance(node.value, ast.Constant):
                    constants[namespace][node.targets[0].id] = node.value.value
                elif (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
                      and node.value.func.attr == "compile" and node.value.args
                      and isinstance(node.value.args[0], ast.Constant)):
                    patterns[namespace][node.targets[0].id] = node.value.args[0].value
                elif callback_roots is not None and isinstance(node.value, (ast.Tuple, ast.List, ast.Dict, ast.Set)):
                    try:
                        constants[namespace][node.targets[0].id] = ast.literal_eval(node.value)
                    except (ValueError, TypeError):
                        pass  # An expression container is not a literal value.
            if isinstance(node, ast.ImportFrom):
                target = next((name for name, module in module_names.items()
                               if node.module and module.endswith(node.module)), None)
                for alias in node.names:
                    if target:
                        imports[namespace][alias.asname or alias.name] = target + "." + alias.name
                    else:
                        found = next((name for name, module in module_names.items() if module.endswith(alias.name)), None)
                        if found:
                            imports[namespace][alias.asname or alias.name] = found
                        else:
                            external_names[namespace].add(alias.asname or alias.name)

    aliases = _CallableAliases(functions, modules, model=model, canonical_names=True)
    unknown, canonical_path = object(), object()
    fixed = {"cli": False, "spans": (), "since": None, "row_limit": None, "format": "json", "unknown": {}}

    def constant(namespace, name, table):
        if name in table[namespace]:
            return table[namespace][name]
        imported = imports[namespace].get(name, "")
        owner, _, member = imported.partition(".")
        return table[owner].get(member, unknown) if owner in table else unknown

    def value(node, env, namespace):
        if not model._spend(node, model.scope.get(node, namespace)):
            return unknown
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if model.binding_is_unknown(node.id, model.scope.get(node, namespace)):
                return unknown
            builtins = {"list": list, "tuple": tuple, "dict": dict, "str": str, "int": int, "bool": bool}
            if model.storage_values(node, model.scope.get(node, namespace)):
                # The scalar evaluator's original literal container does not
                # describe its later writes. Keep the loop/read UNKNOWN.
                return unknown
            if node.id not in env:
                imported = imports[namespace].get(node.id, "")
                module, _, name = imported.partition(".")
                owner = module if module in model.trees else namespace
                name = name if owner == module else node.id
                if len(model.events.get((owner, name), ())) > 1:
                    return unknown
            if node.id in env:
                return env[node.id]
            if node.id in builtins:
                proof = model.resolve(node, model.scope.get(node, namespace))
                if proof.status == "EXACT" and proof.candidates == {"builtin:" + node.id}:
                    return builtins[node.id]
            return constant(namespace, node.id, constants)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            items = [value(item, env, namespace) for item in node.elts]
            if any(item is unknown for item in items):
                return unknown
            return tuple(items) if isinstance(node, ast.Tuple) else items
        if isinstance(node, ast.Dict):
            items = [(value(key, env, namespace), value(item, env, namespace))
                     for key, item in zip(node.keys, node.values) if key is not None]
            return dict(items) if len(items) == len(node.keys) and all(k is not unknown for k, _ in items) else unknown
        if callback_roots is not None and isinstance(node, ast.Subscript):
            owner, index = value(node.value, env, namespace), value(node.slice, env, namespace)
            if type(owner) in (tuple, list) and type(index) is int and -len(owner) <= index < len(owner):
                return owner[index]
            if type(owner) is dict and type(index) is str:
                return owner.get(index, unknown)
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Call) and node.attr == "planned" and env.get("selectors", unknown) == ():
                return {}
            owner = value(node.value, env, namespace)
            if type(owner) is SimpleNamespace and node.attr == "planned":
                return owner.planned
            if owner is canonical_path and node.attr in ("parent", "root"):
                return canonical_path
            if owner is canonical_path and node.attr == "parts":
                return ("trusted", "root")
            if owner is canonical_path and node.attr == "name":
                return "mailbox-records"
            return unknown
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            item = value(node.operand, env, namespace)
            item = unknown if type(item) is frozenset else item
            return not item if item is not unknown else unknown
        if isinstance(node, ast.IfExp):
            condition = value(node.test, env, namespace)
            condition = unknown if type(condition) is frozenset else condition
            return value(node.body if condition else node.orelse, env, namespace) if condition is not unknown else unknown
        if isinstance(node, ast.BoolOp):
            items = [value(item, env, namespace) for item in node.values]
            items = [unknown if type(item) is frozenset else item for item in items]
            known = [bool(item) for item in items if item is not unknown]
            if isinstance(node.op, ast.And):
                return False if False in known else (True if len(known) == len(items) else unknown)
            return True if True in known else (False if len(known) == len(items) else unknown)
        if isinstance(node, ast.Compare):
            items = [value(item, env, namespace) for item in [node.left, *node.comparators]]
            if any(item is unknown or type(item) is frozenset for item in items):
                return unknown
            outcomes = []
            for left, operator, right in zip(items, node.ops, items[1:]):
                if isinstance(operator, ast.Is):
                    outcomes.append(left is right)
                elif isinstance(operator, ast.IsNot):
                    outcomes.append(left is not right)
                elif isinstance(operator, (ast.Eq, ast.NotEq)):
                    outcomes.append((left == right) if isinstance(operator, ast.Eq) else (left != right))
                elif isinstance(operator, (ast.In, ast.NotIn)) and isinstance(right, (tuple, list, dict, str)):
                    outcomes.append((left in right) if isinstance(operator, ast.In) else (left not in right))
                elif isinstance(operator, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)) and type(left) is type(right) and type(left) in (int, str):
                    outcomes.append(left < right if isinstance(operator, ast.Lt) else left <= right if isinstance(operator, ast.LtE)
                                    else left > right if isinstance(operator, ast.Gt) else left >= right)
                else:
                    return unknown
            return all(outcomes)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            iterable = value(node.generators[0].iter, env, namespace)
            return [] if isinstance(iterable, (tuple, list)) and not iterable else unknown
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else None
            args = [value(arg, env, namespace) for arg in node.args]
            proof = model.resolve(node.func, model.scope.get(node, namespace))
            if (name in ("len", "bool", "type", "all", "any") and proof.status == "EXACT" and
                    proof.candidates == {"builtin:" + name} and len(args) == 1 and args[0] is not unknown):
                if name == "type":
                    return type(args[0])
                if isinstance(args[0], (tuple, list, dict, str, bool)):
                    return {"len": len, "bool": bool, "all": all, "any": any}.get(name, bool)(args[0])
            if proof.candidates == {"ext:pathlib.Path"} and args and args[0] is canonical_path:
                return canonical_path
            identities = {record.target for record in proof.invocations}
            if identities == {"codec._read_selectors"} and args and args[0] == ():
                return ()
            if identities & {"codec.preflight_read", "codec.prepare_read"} and env.get("selectors", unknown) == ():
                return SimpleNamespace(planned={})
            if isinstance(node.func, ast.Attribute):
                owner = value(node.func.value, env, namespace)
                if owner is canonical_path:
                    return True if node.func.attr == "is_absolute" else canonical_path
                if node.func.attr == "fullmatch" and args and type(args[0]) is str:
                    pattern = constant(namespace, getattr(node.func.value, "id", ""), patterns)
                    if type(pattern) is str:
                        return re.fullmatch(pattern, args[0]) is not None
        return unknown

    def strings(node, env, namespace, context=None, seen=None):
        if not model._spend(node, context or namespace):
            return {ANY}
        item = value(node, env, namespace)
        if item is None:
            return {""}
        if type(item) is str:
            return {item}
        if type(item) is frozenset:
            return {"" if choice is None else choice for choice in item}
        if isinstance(node, ast.Name) and node.id in env:
            return {ANY}
        if isinstance(node, ast.IfExp):
            test = value(node.test, env, namespace)
            test = unknown if type(test) is frozenset else test
            return (strings(node.body, env, namespace, context, seen) if test is not unknown and test else
                    strings(node.orelse, env, namespace, context, seen) if test is not unknown else
                    strings(node.body, env, namespace, context, seen) | strings(node.orelse, env, namespace, context, seen))
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr"
                and model.resolve(node.func, model.scope.get(node, namespace)).candidates == {"builtin:getattr"}
                and not node.keywords and len(node.args) in (2, 3)
                and isinstance(node.args[1], ast.Constant) and type(node.args[1].value) is str):
            attribute = ast.copy_location(ast.Attribute(value=node.args[0], attr=node.args[1].value, ctx=ast.Load()), node)
            attribute._inventory_file = getattr(node, "_inventory_file", "inventory.py")
            found = strings(attribute, env, namespace, context, seen)
            return found | strings(node.args[2], env, namespace, context, seen) if len(node.args) == 3 else found
        if isinstance(node, (ast.Attribute, ast.Subscript)) and context is not None:
            receiver = node.value
            while isinstance(receiver, (ast.Attribute, ast.Subscript)):
                receiver = receiver.value
            if isinstance(receiver, ast.Name) and env.get(receiver.id) is unknown:
                return {ANY}
            choices = aliases.literal_values(node, context)
            if choices:
                return {"" if choice is None else choice for choice in choices}
        if isinstance(node, ast.Name) and context is not None:
            canonical = aliases.canonical.get(context, context)
            seen = set() if seen is None else seen
            marker = (node.id, canonical)
            if marker not in seen:
                bindings = model.bindings(node.id, canonical, node)
                if callback_roots is not None:
                    default = model.defaults.get(canonical, {}).get(node.id)
                    if default is not None and default not in bindings:
                        bindings = [*bindings, default]
                if bindings and all(not isinstance(expression, str) for expression, _owner in bindings):
                    return set().union(*(strings(expression, env if owner == canonical else {}, owner.split(".")[0],
                                                  aliases.local.get(owner, owner), seen | {marker})
                                         for expression, owner in bindings))
        return {ANY}

    def binding_value(node, state, namespace, context):
        item = value(node, state, namespace)
        if item is unknown:
            return frozenset(strings(node, state, namespace, context))
        return item

    public_options = {}
    pinned_callback_errors = set()
    if model is not None:
        for tree in model.trees.values():
            for statement in tree.body:
                for _message, code, detail in _pinned_rows(statement):
                    if not model._spend(statement, model.scope[statement]):
                        break
                    pinned_callback_errors.update(_refusal_rows({code}, {detail}, model, statement))

    def join_states(destination, *states):
        for name in set().union(*(state.keys() for state in states)):
            choices = [state.get(name, unknown) for state in states]
            if all(choice == choices[0] for choice in choices):
                destination[name] = choices[0]
            elif all(choice is None or type(choice) in (str, int, bool, frozenset) for choice in choices):
                count = sum(len(choice) if type(choice) is frozenset else 1 for choice in choices)
                destination[name] = (frozenset().union(*(choice if type(choice) is frozenset else {choice} for choice in choices))
                                     if count <= 64 else unknown)
            else:
                destination[name] = unknown
        return destination

    def summarize(target, arguments, seen):
        if not model._spend(model.functions.get(target, target), target):
            return RefusalRows({(ANY, ANY)})
        if target == UNKNOWN_CALL_TARGET:
            return RefusalRows({(ANY, ANY)})
        if target in ("format.require", "format.CodecError", "_builtin.ValueError"):
            if target == "_builtin.ValueError":
                return pinned_callback_errors | {("E_FORMAT", "")}
            codes = arguments.get("code", "E_FORMAT")
            details = arguments.get("detail", None)
            if arguments.get("condition") is True and target == "format.require":
                return set()
            codes = codes if type(codes) is frozenset else {codes} if type(codes) is str else None
            details = (details if type(details) is frozenset else {details}
                       if details is None or type(details) is str else None)
            return _refusal_rows(codes, details, model, model.functions.get(target))
        if target not in functions:
            return set()
        fn = functions[target]
        namespace = target.split(".")[0]
        canonical = aliases._context(target)
        defaults = model.resolve("fn:" + canonical, canonical)
        env = {name: binding_value(expression, {}, owner.split(".")[0], aliases.local.get(owner, owner))
               for record in defaults.invocations for name, expression, owner in record.arguments
               if not isinstance(expression, str)}
        env.update(arguments)
        if namespace == "codec" and callback_roots is None:
            env.update(fixed)
            env.update(public_options)
        if target == "store.Store.__init__":
            env["root"] = canonical_path
        if target in ("store.Store.read", "store.Store._verified", "store.Store._resolve"):
            env["reference"] = "0" * 64
        fingerprint = (target, tuple((key, repr(item) if item not in (unknown, canonical_path) else
                                      "unknown" if item is unknown else "canonical")
                                     for key, item in sorted(env.items())))
        if fingerprint in seen:
            return set()
        seen.add(fingerprint)
        pairs = set()

        def checkpoint(node, state):
            # Keep every potentially exceptional expression state, including
            # intermediate effects within one statement, for every enclosing try.
            for partial in snapshots:
                if not model._spend(node, canonical):
                    return
                if partial and partial[-1] == state:
                    continue
                if len(partial) >= INVENTORY_CANDIDATE_BOUND:
                    model._widen(("state", node, canonical, None), "candidates")
                    return
                partial.append(dict(state))

        def active(node, state):
            if not model._spend(node, canonical):
                return
            if isinstance(node, ast.Lambda):
                yield node
                return
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
                iterable = value(node.generators[0].iter, state, namespace)
                if isinstance(iterable, (tuple, list)) and not iterable:
                    yield node
                    return
            if isinstance(node, ast.IfExp):
                yield from active(node.test, state)
                condition = value(node.test, state, namespace)
                condition = unknown if type(condition) is frozenset else condition
                if condition is not unknown:
                    yield from active(node.body if condition else node.orelse, state)
                    yield node
                    return
                yield from active(node.body, state)
                yield from active(node.orelse, state)
            elif isinstance(node, ast.Dict):
                for key, item in zip(node.keys, node.values):
                    if key is not None:
                        yield from active(key, state)
                    yield from active(item, state)
            else:
                for child in ast.iter_child_nodes(node):
                    yield from active(child, state)
            # Calls happen after their operands; walruses bind after their RHS.
            yield node

        def invoke(record, state, seen):
            bindings = {name: (unknown if isinstance(expression, str) else
                               binding_value(expression, state if owner == aliases._context(target) else {},
                                             owner.split(".")[0], aliases.local.get(owner, owner)))
                        for name, expression, owner in record.arguments}
            child = enqueue(aliases.local.get(record.target, record.target), bindings)
            if child is None:
                return RefusalRows({(ANY, ANY)})
            dependencies[current[0]].add(child)
            return set()

        def effects(item, state):
            site = model.callback_sites.get((aliases._context(target), getattr(item, "lineno", 0), getattr(item, "col_offset", 0)))
            if site is not None:
                for record in sorted(site["invocations"], key=lambda value: value.sort_key()):
                    emitted = invoke(record, state, seen) if callback_roots is not None else model.callback_summaries[record]
                    pairs.update(emitted)
                    if callback_roots is None and callback_trace is not None:
                        callback_trace.append((tool, record.target, getattr(item, "_inventory_file", "inventory.py"), item.lineno, sorted(emitted)))
        def calls(node, state):
            for item in active(node, state):
                if isinstance(item, ast.expr):
                    checkpoint(item, state)
                effects(item, state)
                if isinstance(item, ast.NamedExpr) and isinstance(item.target, ast.Name):
                    state[item.target.id] = binding_value(item.value, state, namespace, target)
                if not isinstance(item, ast.Call):
                    continue
                resolution = model.resolve(item, aliases._context(target), invocation=True)
                for record in resolution.invocations:
                    identity = record.target
                    if identity in ("format.require", "format.CodecError"):
                        bindings = {name: expression for name, expression, owner in record.arguments}
                        code = bindings.get("code", ast.Constant("E_FORMAT"))
                        detail = bindings.get("detail", ast.Constant(None))
                        condition = bindings.get("condition")
                        if identity == "format.require" and condition is not None and value(condition, state, namespace) is True:
                            continue
                        pairs.update(_refusal_rows(strings(code, state, namespace, target),
                                                   strings(detail, state, namespace, target), model, item))
                    elif identity == "_builtin.ValueError":
                        pairs.update(pinned_callback_errors | {("E_FORMAT", "")})
                    else:
                        pairs.update(invoke(record, state, seen))

        snapshots = []
        def statements(nodes, state):
            for node in nodes:
                if not model._spend(node, canonical):
                    return
                effects(node, state)
                if isinstance(node, ast.If):
                    calls(node.test, state)
                    condition = value(node.test, state, namespace)
                    condition = unknown if type(condition) is frozenset else condition
                    if condition is not unknown:
                        statements(node.body if condition else node.orelse, state)
                    else:
                        branches = [dict(state), dict(state)]
                        statements(node.body, branches[0])
                        statements(node.orelse, branches[1])
                        join_states(state, *branches)
                elif isinstance(node, (ast.For, ast.AsyncFor)):
                    calls(node.iter, state)
                    iterable = value(node.iter, state, namespace)
                    if callback_roots is not None and iterable is unknown and isinstance(node.iter, ast.Name):
                        owner = aliases._context(target)
                        if node.iter.id not in model.parameters.get(owner, ()):
                            bindings = model.bindings(node.iter.id, owner, node.iter)
                            alternatives = [value(expression, state if context == owner else {}, context.split(".")[0])
                                            for expression, context in bindings if not isinstance(expression, str)]
                            if (alternatives and len(alternatives) == len(bindings)
                                    and all(type(alternative) in (tuple, list) for alternative in alternatives)):
                                iterable = [row for alternative in alternatives for row in alternative]
                    before = dict(state)
                    successors = []
                    if type(iterable) in (tuple, list):
                        running = dict(state)
                        for row in iterable:
                            if not model._spend(node, canonical):
                                return
                            if isinstance(node.target, ast.Name):
                                running[node.target.id] = row
                            elif isinstance(node.target, (ast.Tuple, ast.List)) and type(row) in (tuple, list):
                                running.update((name.id, item) for name, item in zip(node.target.elts, row) if isinstance(name, ast.Name))
                            statements(node.body, running)
                            successors.append(dict(running))
                    else:
                        running = dict(state)
                        while True:
                            if not model._spend(node, canonical):
                                return
                            child = dict(running)
                            for target_name in ast.walk(node.target):
                                if isinstance(target_name, ast.Name):
                                    child[target_name.id] = unknown
                            statements(node.body, child)
                            joined = join_states({}, before, child)
                            if joined == running:
                                break
                            running = joined
                        successors.extend((before, running))
                    join_states(state, *(successors or [before]))
                    statements(node.orelse, state)
                elif isinstance(node, ast.While):
                    calls(node.test, state)
                    before, running = dict(state), dict(state)
                    while True:
                        if not model._spend(node, canonical):
                            return
                        condition = value(node.test, running, namespace)
                        condition = unknown if type(condition) is frozenset else condition
                        if condition is not unknown and not condition:
                            break
                        child = dict(running)
                        statements(node.body, child)
                        joined = join_states({}, before, child)
                        if joined == running:
                            break
                        running = joined
                    join_states(state, before, running)
                    statements(node.orelse, state)
                elif isinstance(node, ast.Try):
                    normal, partial = dict(state), [dict(state)]
                    snapshots.append(partial)
                    statements(node.body, normal)
                    snapshots.pop()
                    handler_entry = join_states({}, *partial, normal)
                    successors = []
                    for handler in node.handlers:
                        child = dict(handler_entry)
                        statements(handler.body, child)
                        successors.append(child)
                    statements(node.orelse, normal)
                    join_states(state, normal, handler_entry, *successors)
                    statements(node.finalbody, state)
                elif isinstance(node, (ast.With, ast.AsyncWith)):
                    for item in node.items:
                        calls(item.context_expr, state)
                    statements(node.body, state)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    headers = ([node.args, *node.decorator_list] if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else
                               [*node.bases, *node.keywords, *node.decorator_list])
                    for header in headers:
                        calls(header, state)
                else:
                    calls(node, state)
                    if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                        for name in node.targets if isinstance(node, ast.Assign) else [node.target]:
                            if isinstance(name, ast.Name):
                                state[name.id] = value(node.value, state, namespace)
                    elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                        state[node.target.id] = unknown
                checkpoint(node, state)
        statements(fn.body, env)
        if model.budget_exhausted:
            return RefusalRows({(ANY, ANY)})
        if target == "store.Store.read":
            pairs = {("E_AUTH", "reference") if code == "E_REF" else (code, detail) for code, detail in pairs}
        return pairs

    # Refusal summaries do not return runtime values to their callers. Evaluate
    # each argument environment once, then union its reachable graph. This keeps
    # mutually recursive UNKNOWN candidates finite without pruning a cycle's
    # refusals or repeatedly interpreting its complete subtree.
    pending, requests, summaries, dependencies, summary_errors = [], {}, {}, {}, {}
    current, environment_counts = [None], {}

    def bounded(item):
        pending, count = [item], 0
        while pending:
            value = pending.pop()
            count += 1
            if count > 64:
                return False
            parts = value.planned if type(value) is SimpleNamespace else value
            if type(parts) in (tuple, list, dict, frozenset):
                size = len(parts) * (2 if type(parts) is dict else 1)
                if size > 64 - count - len(pending):
                    return False
                pending.extend(parts)
                if type(parts) is dict:
                    pending.extend(parts.values())
        return True

    def enqueue(target, arguments):
        if not model._spend(model.functions.get(target, target), target):
            return None
        arguments = {name: item if bounded(item) else unknown for name, item in arguments.items()}
        if environment_counts.get(target, 0) >= 64:
            names = set(model.parameters.get(aliases._context(target), ())) | set(arguments)
            arguments = dict.fromkeys(names, unknown)
        key = (target, tuple((name, "unknown" if item is unknown else "canonical" if item is canonical_path else repr(item))
                             for name, item in sorted(arguments.items())))
        if key not in requests:
            environment_counts[target] = environment_counts.get(target, 0) + 1
            requests[key] = (target, arguments)
            dependencies[key] = set()
            pending.append(key)
        return key

    def explore(target, arguments, seen):
        root = enqueue(target, arguments)
        if root is None:
            return RefusalRows({(ANY, ANY)})
        while pending:
            if model.budget_exhausted:
                pending.clear()
                return RefusalRows({(ANY, ANY)})
            key = pending.pop()
            current[0] = key
            try:
                summaries[key] = summarize(*requests[key], set())
            except RefusalInventoryError as error:
                summaries[key] = set()
                summary_errors[key] = error.sites
        result, failures, visited, todo = set(), [], set(), [root]
        while todo:
            if not model._spend(model.functions.get(target, target), target):
                return RefusalRows({(ANY, ANY)})
            key = todo.pop()
            if key in visited:
                continue
            visited.add(key)
            result.update(summaries[key])
            failures.extend(summary_errors.get(key, ()))
            todo.extend(sorted(dependencies[key]))
        if failures:
            raise RefusalInventoryError(failures)
        return result

    if callback_roots is not None:
        result = {}
        failures, causes = [], []
        for record in sorted(callback_roots, key=lambda item: item.sort_key()):
            if model.budget_exhausted:
                break
            try:
                bindings = {name: unknown for name in model.parameters.get(record.target, ())}
                if record.target in ("format.require", "format.CodecError", "_builtin.ValueError"):
                    bindings.update(code=unknown, detail=unknown)
                    if record.target == "format.require":
                        bindings["condition"] = unknown
                for name, expression, owner in record.arguments:
                    bindings[name] = unknown if isinstance(expression, str) else binding_value(expression, {}, owner.split(".")[0], aliases.local.get(owner, owner))
                result[record] = explore(aliases.local.get(record.target, record.target), bindings, set())
            except RefusalInventoryError as error:
                causes.append((record.target, error.sites))
                failures.extend(_CallableModel.diagnostic(site["call"]) for site in model.callback_sites.values()
                                if record in site["invocations"])
        if failures:
            error = RefusalInventoryError(failures)
            error.callback_causes = tuple(causes)
            raise error
        return result

    def boundaries(entry, writing, seen):
        key = (entry, writing)
        if key in seen:
            return set()
        seen.add(key)
        found = set()
        for call in _owned_nodes(local_functions[entry]):
            if not isinstance(call, ast.Call):
                continue
            for record in model.resolve(call, local_aliases._context(entry), invocation=True).invocations:
                if record.target in functions and record.target.split(".")[0] in ("codec", "format", "store", "views"):
                    found.add(record.target)
        for child, node, gated in local_edges[entry]:
            if not gated or writing:
                child_writing = any(keyword.arg == "write" and isinstance(keyword.value, ast.Constant)
                                    and keyword.value.value is True for keyword in node.keywords)
                found |= boundaries(child, child_writing, seen)
        return found

    # These summaries correspond to the adapter gates, not the unrestricted CLI
    # Store interface: canonical absolute paths and grant-checked full hashes.
    assert "root.is_absolute()" in ast.unparse(local_functions["_store_path"])
    result = {}
    for tool, entries in roots.items():
        public_options = ({"selectors": (), "expand": (), "outline": False} if tool == "mailbox_publish_record"
                          else {"selectors": unknown, "expand": unknown, "outline": unknown})
        pairs = set()
        for boundary in set().union(*(boundaries(entry, False, set()) for entry in entries)):
            emitted = explore(boundary, {}, set())
            if boundary == "store.Store.read":
                emitted = {("E_AUTH", "reference") if code == "E_REF" else (code, detail)
                           for code, detail in emitted}
            if trace is not None:
                trace.append((tool, boundary, sorted(emitted)))
            pairs |= emitted
        result[tool] = pairs
    return result


def _widened_refusal_inventory(model, callback_trace, analysis_stats):
    """Sound symbolic top, retaining source-indexed contributor identities.

    Every indexed callable is a possible module-pool contributor after global
    widening. These are potential targets, not claims of runtime execution.
    Known source rows/identities remain, with separate widened markers.
    """
    pool, history = RefusalRows({(ANY, ANY)}), HistoryRows({ANY})
    potential_sites = []
    for namespace, tree in model.trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                code_values = [value.value for value in [*node.args, *(item.value for item in node.keywords)]
                               if isinstance(value, ast.Constant) and type(value.value) is str
                               and re.fullmatch(r"E_[A-Z0-9_]+", value.value)]
                detail = next((item.value for item in node.keywords if item.arg == "detail"), None)
                for code in code_values:
                    pool.add((code, ANY))
                    pair = (code, ANY)
                    if isinstance(detail, ast.Constant) and (detail.value is None or type(detail.value) is str):
                        pair = (code, "" if detail.value is None else detail.value)
                        pool.add(pair)
                    potential_sites.append((model.MODULES.get(namespace, ("inventory.py", ""))[0], node.lineno, *pair))
            for message, code, detail in _pinned_rows(node):
                pool.add((code, detail))
                if detail == "history":
                    history.add(message)
    tools = {name: pool.copy() for name in ("mailbox_publish_record", "mailbox_read_record", "mailbox_digest")}
    groups = {}
    sites = []
    for marker, reason in sorted(model.widened.items(), key=lambda item: model._graph_order(item[0])):
        kind, node, context, _extra = marker
        namespace = context.split(".")[0]
        file = model.MODULES.get(namespace, ("inventory.py", ""))[0]
        if not hasattr(node, "lineno"):
            key = model.key(node) if isinstance(node, str) and ":" in node else node if isinstance(node, str) else context
            node = model.functions.get(key, model.classes.get(key, model.functions.get(context)))
        line = getattr(node, "lineno", 1)
        groups.setdefault((namespace, reason), (file, line))
        sites.append((kind, context, file, line, reason))
    # Preserve concrete identities known from source indexing and all captured
    # pre-widening resolutions. No golden or runtime evidence supplies names.
    contributors = {key: (model.MODULES.get(key.split(".")[0], ("inventory.py", ""))[0], fn.lineno)
                    for key, fn in model.functions.items()}
    contributors.update({key: (model.MODULES.get(key.split(".")[0], ("inventory.py", ""))[0], cls.lineno)
                         for key, cls in model.classes.items()})
    contributors.update(model.known_contributors)
    if callback_trace is not None:
        for tool in tools:
            for target, (file, line) in sorted(contributors.items()):
                callback_trace.append((tool, target, file, line, sorted(pool)))
            for (namespace, reason), (file, line) in groups.items():
                callback_trace.append((tool, "widened." + namespace + "." + reason, file, line, sorted(pool)))
    if analysis_stats is not None:
        wildcard_count = sum(ANY in row for row in pool)
        analysis_stats.update(status="UNKNOWN", widened_slots=len(model.widened), work_used=model.work_used,
                              budget_exhausted=model.budget_exhausted, pool_pairs=len(pool),
                              pool_complete=True, widened_sites=sites, wildcard_rows=wildcard_count * len(tools),
                              wildcard_rows_per_tool=wildcard_count, history_wildcards=len(tools),
                              concrete_contributors=len(contributors),
                              contributor_kind="source-indexed module-pool candidates",
                              potential_refusal_sites=sorted(set(potential_sites)),
                              widening_groups=[(namespace, reason, file, line)
                                               for (namespace, reason), (file, line) in groups.items()])
    return tools, {name: HistoryRows(history) for name in tools}


def reachable_refusal_pairs(*, sources=None, codec_sources=None, codec_trace=None, callback_trace=None, analysis_stats=None):
    """Every (code, detail) from the adapter and guidance module's error sites.

    The call graph is the source. A hand list of tools cannot drop a pair that a
    tool function reaches. Mailbox history is included where a reachable function
    calls messages(). Binding history is included where call() checks the binding
    through _checked before that tool. A handler that replaces an empty E_LIMIT
    keeps the replacement detail only.
    """
    started = monotonic()
    if sources is None:
        sources = [(_REPO / "tools" / (name + ".py")).read_text(encoding="utf-8")
                   for name in ("hierarchy_mailbox_records", "hierarchy_mailbox_records_guidance")]
    model = _CallableModel(_callable_sources(sources, codec_sources))
    if model.widened:
        result = _widened_refusal_inventory(model, callback_trace, analysis_stats)
        if analysis_stats is not None:
            analysis_stats["runtime_seconds"] = monotonic() - started
        return result
    callbacks = set().union(*(site["invocations"] for site in model.callback_sites.values()))
    model.callback_summaries = codec_refusal_pairs({}, {}, {}, sources=model.sources, model=model, callback_roots=callbacks)
    if model.widened:
        result = _widened_refusal_inventory(model, callback_trace, analysis_stats)
        if analysis_stats is not None:
            analysis_stats["runtime_seconds"] = monotonic() - started
        return result
    names = ("hierarchy_mailbox_records", "hierarchy_mailbox_records_guidance")
    named_sources = (sources.items() if isinstance(sources, dict) else
                     ((names[index] if index < len(names) else "source_" + str(index), source)
                      for index, source in enumerate(sources)))
    modules = {name: model.trees[_CallableModel.module(name) or name] for name, source in named_sources}
    tree = ast.Module(body=[node for module in modules.values() for node in module.body], type_ignores=[])
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    functions = {}
    aliases = _CallableAliases(functions, modules, model=model)
    def const(node):
        return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None

    def assigned(fn, name):
        found = set()
        for node in _owned_nodes(fn):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == name:
                        found |= literal_strings(node.value)
        return found

    def literal_strings(node):
        if const(node) is not None:
            return {const(node)}
        if isinstance(node, ast.IfExp):
            return literal_strings(node.body) | literal_strings(node.orelse)
        return set()

    def detail_values(fn, call):
        context = aliases._context(next(key for key, value in functions.items() if value is fn))
        found = set()
        for record in model.resolve(call, context, invocation=True).invocations:
            if record.target not in ("format.require", "format.CodecError"):
                continue
            detail, owner = next(((value, owner) for name, value, owner in record.arguments if name == "detail"),
                                 (ast.Constant(None), context))
            values = model.literal_values(detail, owner)
            if values is None:
                values = {ANY}
            found.update("" if value is None else value for value in values)
        return found

    def called(node):
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    pinned_history, pinned_history_messages, pinned = set(), [], []
    for node in tree.body:
        for message, code, detail in _pinned_rows(node):
            pinned.append((message, code, detail))
            if detail == "history":
                pinned_history.add((code, "history"))
                pinned_history_messages.append(message)

    def write_gated(node):
        current = node
        while current in parents:
            current = parents[current]
            if isinstance(current, ast.IfExp) and isinstance(current.test, ast.Name) and current.test.id == "write":
                return True
        return False

    def empty_limit_replacement(fn, node):
        current = node
        while current in parents and current is not fn:
            current = parents[current]
            if not isinstance(current, ast.Try):
                continue
            body = ast.Module(body=current.body, type_ignores=[])
            if not any(item is node for item in ast.walk(body)):
                continue
            for handler in current.handlers:
                if handler.name is None:
                    continue
                for statement in handler.body:
                    if not isinstance(statement, ast.If):
                        continue
                    dumped = ast.dump(statement.test)
                    if "E_LIMIT" not in dumped or "detail" not in dumped:
                        continue
                    found = set()
                    branch = ast.Module(body=statement.body, type_ignores=[])
                    for item in ast.walk(branch):
                        if (isinstance(item, ast.Raise) and isinstance(item.exc, ast.Call)
                                and any(record.target == "format.CodecError" for record in
                                        model.resolve(item.exc, model.scope[item.exc], invocation=True).invocations)):
                            found |= detail_values(fn, item.exc)
                    if found:
                        return found
        return None

    direct, edges, sees_messages = {}, {}, set()
    for name, fn in functions.items():
        sites, links = set(), []
        for node in _owned_nodes(fn):
            for _callback, emitted, _file, _line in aliases.callbacks(node, name):
                sites.update((code, detail, node) for code, detail in emitted)
            if not isinstance(node, ast.Call):
                continue
            for reference in aliases.callees(node, name):
                if reference._inventory_symbol == "mailbox.Mailbox.messages":
                    sees_messages.add(name)
                identity = reference._inventory_symbol
                if identity == "_builtin.ValueError":
                    sites.update((code, detail, node) for _message, code, detail in pinned)
                    sites.add(("E_FORMAT", "", node))
                if identity in ("format.require", "format.CodecError"):
                    environment = {key: (value, owner) for key, value, owner in reference._inventory_invocation.arguments}
                    code_value, code_owner = environment.get("code", (ast.Constant("E_FORMAT"), aliases._context(name)))
                    detail_value, detail_owner = environment.get("detail", (ast.Constant(None), aliases._context(name)))
                    codes = model.literal_values(code_value, code_owner)
                    details = model.literal_values(detail_value, detail_owner)
                    sites.update((code, detail, node) for code, detail in _refusal_rows(codes, details, model, node))
                if reference.id in functions and reference.id != name:
                    links.append((reference.id, node, write_gated(node)))
        direct[name] = sites
        edges[name] = links

    def propagate(name, writing, seen, tool=None):
        key = (name, writing)
        if key in seen:
            return set()
        seen.add(key)
        fn = functions[name]
        pairs = set()
        if callback_trace is not None and tool is not None:
            for node in _owned_nodes(fn):
                for callback, emitted, file, line in aliases.callbacks(node, name):
                    callback_trace.append((tool, callback, file, line, sorted(emitted)))
        for code, detail, node in direct[name]:
            if ANY in (code, detail) and callback_trace is not None and tool is not None:
                callback_trace.append((tool, "widened.value", node._inventory_file, node.lineno, [(code, detail)]))
            replacement = empty_limit_replacement(fn, node)
            if replacement is not None and (code, detail) == ("E_LIMIT", ""):
                pairs.update(("E_LIMIT", item) for item in replacement)
            else:
                pairs.add((code, detail))
        for callee, node, gated in edges[name]:
            if gated and not writing:
                continue
            child_writing = any(
                keyword.arg == "write" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                for keyword in node.keywords)
            child = propagate(callee, child_writing, seen, tool)
            replacement = empty_limit_replacement(fn, node)
            for code, detail in child:
                if replacement is not None and (code, detail) == ("E_LIMIT", ""):
                    pairs.update(("E_LIMIT", item) for item in replacement)
                else:
                    pairs.add((code, detail))
        if name in sees_messages:
            pairs.update(pinned_history)
        return pairs

    def root_bindings(name):
        expression = ast.Name(id=name, ctx=ast.Load())
        records = model.resolve(expression, "records").invocations
        return [aliases.local.get(record.target, record.target) for record in records if aliases.local.get(record.target, record.target) in functions]

    direct_names = {tool: root_bindings(root) for tool, root in
                    (("mailbox_publish_record", "publish"), ("mailbox_read_record", "read"), ("mailbox_digest", "digest"))}
    tools = {tool: set().union(*(propagate(entry, False, set(), tool) for entry in entries))
             for tool, entries in direct_names.items()}
    # Module/class consumers execute outside any function root. Their UNKNOWN
    # callbacks remain applicable to every public entry after module loading.
    for (context, _line, _column), site in model.callback_sites.items():
        if context in model.functions:
            continue
        for record in sorted(site["invocations"], key=lambda item: item.sort_key()):
            emitted = model.callback_summaries[record]
            for tool in tools:
                tools[tool].update(emitted)
                if callback_trace is not None:
                    callback_trace.append((tool, record.target, site["call"]._inventory_file,
                                           site["call"].lineno, sorted(emitted)))
    history_messages = {name: set() for name in tools}

    # ValueError adapters carry dynamic code/detail values. Follow their real
    # mailbox/connection callees and match the pinned vocabulary to the source
    # strings, rather than assigning a hand-maintained set of details per tool.
    boundary_functions, boundary_modules = {}, {}
    for namespace, filename in (("mailbox", "hierarchy_mailbox.py"), ("mcp", "hierarchy_mailbox_mcp.py")):
        boundary_modules[namespace] = model.trees[namespace]
    boundary_aliases = _CallableAliases(boundary_functions, boundary_modules, model=model)

    def boundary_strings(entry, seen):
        if entry in seen or entry not in boundary_functions:
            return set()
        seen.add(entry)
        fn = boundary_functions[entry]
        strings = {node.value for node in _owned_nodes(fn)
                   if isinstance(node, ast.Constant) and type(node.value) is str}
        for node in _owned_nodes(fn):
            if not isinstance(node, ast.Call):
                continue
            for reference in boundary_aliases.callees(node, entry):
                if reference.id in boundary_functions:
                    strings |= boundary_strings(reference.id, seen)
        return strings

    def local_boundaries(entry, seen):
        if entry in seen:
            return set()
        seen.add(entry)
        found = set()
        for node in _owned_nodes(functions[entry]):
            if isinstance(node, ast.Call):
                for reference in aliases.callees(node, entry):
                    if isinstance(reference, ast.Name) and reference.id.startswith("mailbox."):
                        found.add(reference.id)
        for callee, _node, _gated in edges[entry]:
            found |= local_boundaries(callee, seen)
        return found

    # A replacement call root is an ordinary graph root, including all of its
    # transitive adapter, codec and ValueError-boundary callees. The shared
    # summary engine indexes every domain here, rather than reading direct sites.
    call_roots = set()
    for entry in root_bindings("call"):
        fn = functions[entry]
        callee = ast.copy_location(ast.Name(id="_replacement_call_root", ctx=ast.Load()), fn)
        callee._inventory_refs = frozenset({"fn:" + aliases._context(entry)})
        projected = ast.copy_location(ast.Call(func=callee, args=[], keywords=[]), fn)
        projected._inventory_file = fn._inventory_file
        projected._inventory_unknown_layout = True
        call_roots.update(model.resolve(projected, aliases._context(entry), invocation=True).invocations)
    call_summaries = codec_refusal_pairs({}, {}, {}, sources=model.sources, model=model, callback_roots=call_roots)
    if model.widened:
        result = _widened_refusal_inventory(model, callback_trace, analysis_stats)
        if analysis_stats is not None:
            analysis_stats["runtime_seconds"] = monotonic() - started
        return result
    for tool, roots in direct_names.items():
        for record, emitted in call_summaries.items():
            tools[tool].update(emitted)
            if callback_trace is not None:
                fn = model.functions[record.target]
                callback_trace.append((tool, record.target, fn._inventory_file, fn.lineno, sorted(emitted)))
        for name in ("_checked", "_store_path"):
            tools[tool].update(set().union(*(propagate(entry, False, set(), tool) for entry in root_bindings(name))))
        # _checked passes E_AUTH as _pinned_error's default: an unmapped
        # binding refusal also has the binding action.
        checked = functions["_checked"]
        for node in ast.walk(checked):
            if isinstance(node, ast.Call) and any(record.target == "guidance._pinned_error" for record in
                    model.resolve(node, model.scope[node], invocation=True).invocations):
                if len(node.args) > 2 and const(node.args[2]) == "E_AUTH":
                    tools[tool].add(("E_AUTH", "binding"))
        entries = set().union(*(local_boundaries(entry, set()) for entry in roots)) | {"mcp.Connection.checked_mailbox"}
        if tool == "mailbox_publish_record":
            assert any(isinstance(node, ast.Call) and called(node) == "writer_lock"
                       for node in ast.walk(functions["call"]))
            entries.add("mailbox.writer_lock")
        strings = set().union(*(boundary_strings(name, set()) for name in entries))
        for message, code, detail in pinned:
            if message == ANY or message in strings:
                tools[tool].add((code, detail))
                if detail == "history":
                    history_messages[tool].add(message)
    for tool, pairs in codec_refusal_pairs(functions, edges, direct_names, codec_sources, codec_trace, aliases, model,
                                         callback_trace=callback_trace).items():
        tools[tool] |= pairs
    if model.widened:
        known_rows = set().union(*tools.values())
        result = _widened_refusal_inventory(model, callback_trace, analysis_stats)
        for rows in result[0].values():
            rows.update(known_rows)
        if analysis_stats is not None:
            analysis_stats["runtime_seconds"] = monotonic() - started
        return result
    wildcards = sum(ANY in row for rows in tools.values() for row in rows)
    for tool, rows in tools.items():
        if any(ANY in row and covers_refusal([row], ("E_LIMIT", "history")) for row in rows):
            history_messages[tool].add(ANY)
    if callback_trace is not None:
        for file, line in sorted(model.scalar_widened):
            for tool, rows in tools.items():
                symbolic = [row for row in sorted(rows) if ANY in row]
                if symbolic:
                    callback_trace.append((tool, "widened.value", file, line, symbolic))
    if analysis_stats is not None:
        analysis_stats.update(status="UNKNOWN" if wildcards else "MODELLED", widened_slots=len(model.scalar_widened),
                              wildcard_rows=wildcards, pool_complete=True, work_used=model.work_used,
                              history_wildcards=sum(ANY in rows for rows in history_messages.values()),
                              budget_exhausted=False, runtime_seconds=monotonic() - started)
    return {tool: RefusalRows(rows) for tool, rows in tools.items()}, {tool: HistoryRows(rows) for tool, rows in history_messages.items()}
